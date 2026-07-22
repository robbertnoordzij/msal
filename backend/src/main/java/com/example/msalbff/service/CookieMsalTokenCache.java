package com.example.msalbff.service;

import com.example.msalbff.config.AppProperties;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.microsoft.aad.msal4j.ITokenCacheAccessContext;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

/**
 * MSAL4J token cache backed by an AES-256-GCM-encrypted HTTP-only cookie.
 *
 * <p>This implementation requires no external infrastructure. It is suitable for
 * single-instance deployments where clustering is not needed.
 *
 * <h3>Storage pipeline (write)</h3>
 * <ol>
 *   <li>Serialize the MSAL token cache to JSON.</li>
 *   <li>GZIP-compress the JSON (reduces typical payloads substantially before encryption).</li>
 *   <li>Encrypt with AES-256-GCM; a fresh 12-byte IV and 128-bit authentication tag
 *       are prepended to the ciphertext.</li>
 *   <li>Base64-encode the result and write it to one or more HTTP-only,
 *       {@code SameSite=Strict} cookies named {@code MSAL_TOKEN_CACHE} (configurable). Large
 *       payloads are split across chunk cookies ({@code MSAL_TOKEN_CACHE_1 … _N}) by
 *       {@link AuthCookieService}, so the persisted cache is never dropped for exceeding the
 *       ~4 KB single-cookie limit.</li>
 * </ol>
 *
 * <h3>Storage pipeline (read)</h3>
 * Reverse of the above. Any error (tampered cookie, rotated key, corrupt data) is
 * logged as a warning and treated as an empty cache; MSAL will then require the user
 * to re-authenticate transparently.
 *
 * <h3>Limitations</h3>
 * <ul>
 *   <li><strong>No clustering</strong> — the token cache is bound to the browser, not
 *       the server. Multiple server instances work, but a user's cache is only stored in
 *       their own browser cookie, not shared across nodes.</li>
 *   <li><strong>Key rotation</strong> — rotating {@code app.token-cache.cookie.encryption-key}
 *       immediately invalidates all existing cache cookies. Affected users must re-authenticate.</li>
 *   <li><strong>Cookie size</strong> — the encrypted payload is split across up to
 *       {@value AuthCookieService#MAX_CHUNKS} chunk cookies. If it would exceed
 *       {@link #MAX_TOTAL_VALUE_BYTES} bytes in total the write is skipped and an error is
 *       logged; the user re-authenticates on the next request. Raise
 *       {@code server.max-http-header-size} if you need a larger budget.</li>
 * </ul>
 *
 * <p>Active when {@code app.token-cache.type=cookie}. For clustered deployments use
 * {@link RedisMsalTokenCache} ({@code app.token-cache.type=redis}, the default).
 */
@Component
@ConditionalOnProperty(name = "app.token-cache.type", havingValue = "cookie")
public class CookieMsalTokenCache implements MsalTokenCacheService {

    private static final Logger logger = LoggerFactory.getLogger(CookieMsalTokenCache.class);

    /**
     * Maximum total size in bytes of the encrypted payload spread across all chunk cookies.
     * The chunked cookie writer ({@link AuthCookieService}) splits the value into
     * {@value AuthCookieService#CHUNK_SIZE_BYTES}-byte cookies, up to
     * {@value AuthCookieService#MAX_CHUNKS} chunks. This ceiling keeps the combined cookie
     * headers within a typical {@code server.max-http-header-size} budget (raise that setting
     * if you increase this value).
     */
    static final int MAX_TOTAL_VALUE_BYTES =
            AuthCookieService.CHUNK_SIZE_BYTES * AuthCookieService.MAX_CHUNKS;

    /**
     * Sections of the MSAL token cache persisted to the cookie.
     * <ul>
     *   <li>{@code RefreshToken} + {@code Account} — required for silent refresh / session restore.</li>
     *   <li>{@code IdToken} — persisted so the user's ID token survives restarts.</li>
     *   <li>{@code AccessToken} — persisted so the on-behalf-of (OBO) flow has a user access
     *       token to present as its {@code UserAssertion} without a fresh round-trip.</li>
     * </ul>
     * {@code AppMetadata} is intentionally omitted. The chunked cookie writer
     * ({@link AuthCookieService#setMsalCacheCookie}) removes the single-cookie 4 KB ceiling,
     * so persisting the larger token sections no longer risks a dropped write.
     */
    private static final List<String> PERSISTED_CACHE_SECTIONS =
            List.of("RefreshToken", "Account", "IdToken", "AccessToken");

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    private final AuthCookieService authCookieService;
    private final TokenCacheEncryption encryption;

    public CookieMsalTokenCache(AppProperties appProperties,
                                AuthCookieService authCookieService) {
        String key = appProperties.getTokenCache().getCookie().getEncryptionKey();
        if (key == null || key.isBlank()) {
            throw new IllegalArgumentException(
                    "app.token-cache.cookie.encryption-key must be set when app.token-cache.type=cookie. "
                    + "Refresh tokens are stored in the browser cookie and MUST be encrypted. "
                    + "Generate a key with: openssl rand -base64 32");
        }
        this.encryption = new TokenCacheEncryption(key);
        this.authCookieService = authCookieService;
    }

    /**
     * Loads the MSAL token cache from the {@code MSAL_TOKEN_CACHE} cookie before MSAL reads it.
     * Any error (missing cookie, decryption failure, corrupt data) is treated as an empty cache.
     */
    @Override
    public void beforeCacheAccess(ITokenCacheAccessContext context) {
        try {
            ServletRequestAttributes attrs = currentRequestAttributes();
            String cookieValue = authCookieService.getMsalCacheCookie(attrs.getRequest()).orElse(null);
            if (cookieValue == null || cookieValue.isBlank()) {
                return;
            }
            String cacheJson = decodeAndDecompress(encryption.decrypt(cookieValue));
            context.tokenCache().deserialize(cacheJson);
            logger.debug("Loaded MSAL token cache from cookie");
        } catch (Exception e) {
            logger.warn("Failed to load MSAL token cache from cookie; proceeding with empty cache: {}",
                    e.getMessage());
        }
    }

    /**
     * Persists the MSAL token cache to the {@code MSAL_TOKEN_CACHE} cookie after MSAL writes it.
     * Skips the write silently when the cache has not changed.
     * Skips the write and logs an error if the encrypted payload would exceed the cookie size limit.
     */
    @Override
    public void afterCacheAccess(ITokenCacheAccessContext context) {
        if (!context.hasCacheChanged()) {
            return;
        }
        try {
            String cookieValue = encryptCache(context);
            if (exceedsCookieSizeLimit(cookieValue)) {
                return;
            }
            writeCookieToResponse(cookieValue);
        } catch (Exception e) {
            logger.warn("Failed to persist MSAL token cache to cookie: {}", e.getMessage());
        }
    }

    private String encryptCache(ITokenCacheAccessContext context) throws Exception {
        String fullJson = context.tokenCache().serialize();
        String slimJson = retainPersistedSections(fullJson);
        return encryption.encrypt(compressAndEncode(slimJson));
    }

    /**
     * Strips sections not needed for the persisted cache ({@code AppMetadata}) from the MSAL
     * cache JSON before it is stored in the cookie. {@code RefreshToken}, {@code Account},
     * {@code IdToken} and {@code AccessToken} are retained — the latter two enable ID-token
     * persistence and the on-behalf-of flow respectively.
     */
    static String retainPersistedSections(String json) throws IOException {
        JsonNode root = OBJECT_MAPPER.readTree(json);
        ObjectNode slim = OBJECT_MAPPER.createObjectNode();
        for (String section : PERSISTED_CACHE_SECTIONS) {
            if (root.has(section)) {
                slim.set(section, root.get(section));
            }
        }
        return OBJECT_MAPPER.writeValueAsString(slim);
    }

    private boolean exceedsCookieSizeLimit(String cookieValue) {
        int byteLength = cookieValue.getBytes(StandardCharsets.UTF_8).length;
        if (byteLength > MAX_TOTAL_VALUE_BYTES) {
            logger.error(
                    "MSAL token cache would exceed {} bytes ({} bytes after encryption) across "
                    + "{} chunk cookies; skipping write to stay within the HTTP header size limit. "
                    + "Consider raising server.max-http-header-size or reducing the persisted token scopes.",
                    MAX_TOTAL_VALUE_BYTES, byteLength, AuthCookieService.MAX_CHUNKS);
            return true;
        }
        return false;
    }

    private void writeCookieToResponse(String cookieValue) {
        ServletRequestAttributes attrs = currentRequestAttributes();
        HttpServletResponse response = attrs.getResponse();
        if (response == null) {
            logger.warn("Cannot persist MSAL token cache: no HTTP response available in current context");
            return;
        }
        authCookieService.setMsalCacheCookie(attrs.getRequest(), response, cookieValue);
        logger.debug("Persisted MSAL token cache to cookie");
    }

    /**
     * Clears the {@code MSAL_TOKEN_CACHE} cookie, immediately revoking access to the cached
     * refresh token. Called during logout.
     *
     * @param homeAccountId unused in this implementation (the cookie is account-agnostic);
     *                      present to satisfy the {@link MsalTokenCacheService} contract
     */
    @Override
    public void evict(String homeAccountId) {
        try {
            ServletRequestAttributes attrs = currentRequestAttributes();
            HttpServletResponse response = attrs.getResponse();
            if (response == null) {
                logger.warn("Cannot evict MSAL token cache cookie: no HTTP response in current context");
                return;
            }
            authCookieService.clearMsalCacheCookie(attrs.getRequest(), response);
            logger.info("Evicted MSAL token cache cookie on logout");
        } catch (Exception e) {
            logger.error("Failed to evict MSAL token cache cookie: {}", e.getMessage());
        }
    }

    private static String compressAndEncode(String text) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (GZIPOutputStream gzip = new GZIPOutputStream(out)) {
            gzip.write(text.getBytes(StandardCharsets.UTF_8));
        }
        return Base64.getEncoder().encodeToString(out.toByteArray());
    }

    private static String decodeAndDecompress(String encoded) throws IOException {
        byte[] compressed = Base64.getDecoder().decode(encoded);
        try (GZIPInputStream gzip = new GZIPInputStream(new ByteArrayInputStream(compressed));
             ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            gzip.transferTo(out);
            return out.toString(StandardCharsets.UTF_8);
        }
    }

    private static ServletRequestAttributes currentRequestAttributes() {
        return (ServletRequestAttributes) RequestContextHolder.currentRequestAttributes();
    }
}
