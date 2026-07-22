package com.example.msalbff.service;

import com.example.msalbff.config.AppProperties;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

/**
 * Centralises all cookie operations so that cookie attributes
 * (HttpOnly, Secure, SameSite, path, maxAge) are configured in one place.
 *
 * <p>Manages three categories of cookies:
 * <ul>
 *   <li><b>AUTH_TOKEN</b> — long-lived HTTP-only cookie holding the user's ID token.</li>
 *   <li><b>OAUTH_STATE / PKCE_VERIFIER</b> — short-lived HTTP-only cookies used during
 *       the OAuth 2.0 / PKCE login flow. They must use {@code SameSite=Lax} so that they
 *       are included in the cross-site top-level redirect from Azure AD back to
 *       {@code /auth/callback}.</li>
 *   <li><b>MSAL_TOKEN_CACHE</b> — the encrypted MSAL token cache. Because the cache can hold
 *       the ID, access and refresh tokens (needed for the on-behalf-of flow) it may exceed the
 *       ~4 KB per-cookie limit mandated by RFC 6265. It is therefore written using a
 *       <em>chunked cookie</em> scheme (see {@link #setMsalCacheCookie}).</li>
 * </ul>
 */
@Service
public class AuthCookieService {

    static final String OAUTH_STATE_COOKIE = "OAUTH_STATE";
    static final String PKCE_VERIFIER_COOKIE = "PKCE_VERIFIER";
    private static final int OAUTH_FLOW_MAX_AGE_SECONDS = 300; // 5 minutes

    /**
     * Maximum number of bytes stored in a single MSAL cache chunk cookie's <em>value</em>.
     * RFC 6265 requires browsers to support at least 4 096 bytes for the whole cookie
     * (name + value + attributes); 3 072 leaves ample headroom for the name and the
     * {@code Path/Max-Age/Secure/HttpOnly/SameSite} attribute string.
     */
    static final int CHUNK_SIZE_BYTES = 3072;

    /**
     * Value written to the primary MSAL cache cookie when the payload is chunked.
     * The suffix is the number of chunk cookies ({@code MSAL_TOKEN_CACHE_1 … _N}) that follow.
     * Mirrors the convention used by ASP.NET Core's {@code ChunkingCookieManager}.
     */
    static final String CHUNK_MARKER_PREFIX = "chunks-";

    /**
     * Hard upper bound on the number of chunk cookies. Guards against a runaway cache
     * blowing past the servlet container's {@code max-http-header-size}. Ten 3 KB chunks
     * ≈ 30 KB, comfortably below a 32 KB header budget.
     */
    static final int MAX_CHUNKS = 10;

    private final AppProperties appProperties;

    public AuthCookieService(AppProperties appProperties) {
        this.appProperties = appProperties;
    }

    /** Writes a new AUTH_TOKEN cookie containing the given ID token. */
    public void setAuthCookie(HttpServletResponse response, String idToken) {
        if (idToken == null || idToken.isBlank()) {
            throw new IllegalArgumentException("ID token cannot be null or empty");
        }
        response.addHeader(HttpHeaders.SET_COOKIE,
                buildAuthCookie(idToken, appProperties.getCookie().getMaxAge()).toString());
    }

    /** Expires the AUTH_TOKEN cookie, causing the browser to delete it. */
    public void clearAuthCookie(HttpServletResponse response) {
        response.addHeader(HttpHeaders.SET_COOKIE, buildAuthCookie("", 0).toString());
    }

    /** Sets a short-lived cookie carrying the OAuth state parameter for CSRF protection. */
    public void setOAuthStateCookie(HttpServletResponse response, String state) {
        if (state == null || state.isBlank()) {
            throw new IllegalArgumentException("OAuth state cannot be null or empty");
        }
        response.addHeader(HttpHeaders.SET_COOKIE,
                buildOAuthFlowCookie(OAUTH_STATE_COOKIE, state, OAUTH_FLOW_MAX_AGE_SECONDS).toString());
    }

    /** Sets a short-lived cookie carrying the PKCE code verifier. */
    public void setPkceVerifierCookie(HttpServletResponse response, String verifier) {
        if (verifier == null || verifier.isBlank()) {
            throw new IllegalArgumentException("PKCE verifier cannot be null or empty");
        }
        response.addHeader(HttpHeaders.SET_COOKIE,
                buildOAuthFlowCookie(PKCE_VERIFIER_COOKIE, verifier, OAUTH_FLOW_MAX_AGE_SECONDS).toString());
    }

    /** Returns the AUTH_TOKEN value from the request cookies, or empty if absent. */
    public Optional<String> getAuthCookie(HttpServletRequest request) {
        return findCookieValue(request, appProperties.getCookie().getName());
    }

    /** Returns the OAuth state value from the request cookies, or empty if absent. */
    public Optional<String> getOAuthStateCookie(HttpServletRequest request) {
        return findCookieValue(request, OAUTH_STATE_COOKIE);
    }

    /** Returns the PKCE verifier value from the request cookies, or empty if absent. */
    public Optional<String> getPkceVerifierCookie(HttpServletRequest request) {
        return findCookieValue(request, PKCE_VERIFIER_COOKIE);
    }

    /** Expires both OAuth flow cookies. Should be called after the callback is processed. */
    public void clearOAuthFlowCookies(HttpServletResponse response) {
        response.addHeader(HttpHeaders.SET_COOKIE,
                buildOAuthFlowCookie(OAUTH_STATE_COOKIE, "", 0).toString());
        response.addHeader(HttpHeaders.SET_COOKIE,
                buildOAuthFlowCookie(PKCE_VERIFIER_COOKIE, "", 0).toString());
    }

    /**
     * Writes the encrypted MSAL token-cache to one or more {@code MSAL_TOKEN_CACHE} cookies.
     *
     * <p>Because the persisted cache can include the ID, access and refresh tokens (so that the
     * on-behalf-of flow has an access token available) the encrypted payload can exceed the
     * ~4 KB per-cookie limit. The value is therefore split into {@value #CHUNK_SIZE_BYTES}-byte
     * chunks:
     * <ul>
     *   <li>When it fits in a single chunk, the primary cookie holds the value directly
     *       (backwards-compatible with the previous single-cookie format).</li>
     *   <li>When it spans multiple chunks, the primary cookie holds a
     *       {@code chunks-N} marker and the chunks are written to {@code MSAL_TOKEN_CACHE_1 … _N}.</li>
     * </ul>
     * Any chunk cookies left over from a previous, larger write are expired so a later read
     * never reassembles a mix of old and new data.
     *
     * <p>All cookies are {@code HttpOnly}, {@code SameSite=Strict} and long-lived (90 days by
     * default) so the refresh token inside survives browser restarts.
     */
    public void setMsalCacheCookie(HttpServletRequest request, HttpServletResponse response, String encryptedValue) {
        long maxAge = appProperties.getTokenCache().getCookie().getMaxAge().getSeconds();
        String baseName = appProperties.getTokenCache().getCookie().getName();
        int previousChunkCount = countExistingChunks(request);

        List<String> chunks = splitIntoChunks(encryptedValue, CHUNK_SIZE_BYTES);
        if (chunks.size() == 1) {
            response.addHeader(HttpHeaders.SET_COOKIE, buildMsalCacheCookie(baseName, encryptedValue, maxAge).toString());
        } else {
            response.addHeader(HttpHeaders.SET_COOKIE,
                    buildMsalCacheCookie(baseName, CHUNK_MARKER_PREFIX + chunks.size(), maxAge).toString());
            for (int i = 0; i < chunks.size(); i++) {
                response.addHeader(HttpHeaders.SET_COOKIE,
                        buildMsalCacheCookie(chunkName(baseName, i + 1), chunks.get(i), maxAge).toString());
            }
        }
        expireStaleChunks(response, baseName, chunks.size() == 1 ? 0 : chunks.size(), previousChunkCount);
    }

    /** Expires the MSAL token-cache cookie and all of its chunk cookies. */
    public void clearMsalCacheCookie(HttpServletRequest request, HttpServletResponse response) {
        String baseName = appProperties.getTokenCache().getCookie().getName();
        response.addHeader(HttpHeaders.SET_COOKIE, buildMsalCacheCookie(baseName, "", 0).toString());
        expireStaleChunks(response, baseName, 0, countExistingChunks(request));
    }

    /**
     * Reassembles and returns the raw (encrypted) MSAL token-cache value from the request cookies,
     * or empty if absent or incompletely chunked.
     */
    public Optional<String> getMsalCacheCookie(HttpServletRequest request) {
        String baseName = appProperties.getTokenCache().getCookie().getName();
        Optional<String> primary = findCookieValue(request, baseName);
        if (primary.isEmpty()) {
            return Optional.empty();
        }
        String value = primary.get();
        if (!value.startsWith(CHUNK_MARKER_PREFIX)) {
            return Optional.of(value); // single, unchunked value
        }
        int chunkCount = parseChunkCount(value);
        if (chunkCount <= 0) {
            return Optional.empty();
        }
        StringBuilder assembled = new StringBuilder();
        for (int i = 1; i <= chunkCount; i++) {
            Optional<String> chunk = findCookieValue(request, chunkName(baseName, i));
            if (chunk.isEmpty()) {
                return Optional.empty(); // missing chunk → treat as corrupt/empty cache
            }
            assembled.append(chunk.get());
        }
        return Optional.of(assembled.toString());
    }

    private static String chunkName(String baseName, int index) {
        return baseName + "_" + index;
    }

    private static List<String> splitIntoChunks(String value, int chunkSize) {
        List<String> chunks = new ArrayList<>();
        for (int start = 0; start < value.length(); start += chunkSize) {
            chunks.add(value.substring(start, Math.min(value.length(), start + chunkSize)));
        }
        if (chunks.isEmpty()) {
            chunks.add("");
        }
        return chunks;
    }

    /** Reads the primary cookie from the request and returns how many chunk cookies currently exist. */
    private int countExistingChunks(HttpServletRequest request) {
        String baseName = appProperties.getTokenCache().getCookie().getName();
        return findCookieValue(request, baseName)
                .filter(v -> v.startsWith(CHUNK_MARKER_PREFIX))
                .map(AuthCookieService::parseChunkCount)
                .orElse(0);
    }

    private static int parseChunkCount(String markerValue) {
        try {
            return Integer.parseInt(markerValue.substring(CHUNK_MARKER_PREFIX.length()));
        } catch (NumberFormatException e) {
            return -1;
        }
    }

    /** Expires chunk cookies whose index is greater than the number of chunks just written. */
    private void expireStaleChunks(HttpServletResponse response, String baseName,
                                   int newChunkCount, int previousChunkCount) {
        for (int i = newChunkCount + 1; i <= previousChunkCount; i++) {
            response.addHeader(HttpHeaders.SET_COOKIE, buildMsalCacheCookie(chunkName(baseName, i), "", 0).toString());
        }
    }

    private ResponseCookie buildAuthCookie(String value, long maxAge) {
        AppProperties.Cookie config = appProperties.getCookie();
        return ResponseCookie.from(config.getName(), value)
                .httpOnly(config.isHttpOnly())
                .secure(config.isSecure())
                .path("/")
                .maxAge(maxAge)
                .sameSite(config.getSameSite())
                .build();
    }

    private ResponseCookie buildMsalCacheCookie(String name, String value, long maxAge) {
        AppProperties.TokenCache.CookieStore cookieStore = appProperties.getTokenCache().getCookie();
        return ResponseCookie.from(name, value)
                .httpOnly(true)
                // secure defaults to true; only set false for local HTTP dev
                .secure(cookieStore.isSecure())
                .path("/")
                .maxAge(maxAge)
                .sameSite("Strict") // SameSite=Strict is required: the MSAL cache cookie is never needed cross-site
                .build();
    }

    private ResponseCookie buildOAuthFlowCookie(String name, String value, long maxAge) {
        return ResponseCookie.from(name, value)
                .httpOnly(true)
                .secure(appProperties.getCookie().isSecure())
                .path("/")
                .maxAge(maxAge)
                .sameSite("Lax") // Must be Lax: Strict would block the cross-site redirect from Azure AD
                .build();
    }

    private Optional<String> findCookieValue(HttpServletRequest request, String name) {
        Cookie[] cookies = request.getCookies();
        if (cookies == null) {
            return Optional.empty();
        }
        return Arrays.stream(cookies)
                .filter(c -> name.equals(c.getName()))
                .map(Cookie::getValue)
                .findFirst();
    }
}
