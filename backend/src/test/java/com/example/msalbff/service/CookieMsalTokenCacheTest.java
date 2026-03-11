package com.example.msalbff.service;

import com.example.msalbff.config.AppProperties;
import com.microsoft.aad.msal4j.ITokenCache;
import com.microsoft.aad.msal4j.ITokenCacheAccessContext;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

import java.util.Optional;

/**
 * Unit tests for {@link CookieMsalTokenCache}.
 *
 * <p>Each test binds a {@link MockHttpServletRequest}/{@link MockHttpServletResponse} pair
 * to {@link RequestContextHolder} so the class under test can access the HTTP context
 * without a running servlet container.
 */
@ExtendWith(MockitoExtension.class)
class CookieMsalTokenCacheTest {

    // ── Encryption keys: valid 32-byte (256-bit) AES keys for unit tests ─────
    // 43 A-characters + '=' decodes to exactly 32 zero bytes
    private static final String VALID_KEY = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    // Different key to simulate key-rotation scenarios
    private static final String OTHER_VALID_KEY = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=";

    // ── MSAL cache JSON that is realistic but compact enough for cookie storage
    private static final String MINIMAL_MSAL_CACHE_JSON = "{\"AccessToken\":{},\"RefreshToken\":{},\"IdToken\":{},\"Account\":{}}";

    @Mock private AuthCookieService authCookieService;
    @Mock private ITokenCacheAccessContext context;
    @Mock private ITokenCache tokenCache;

    private AppProperties appProperties;
    private MockHttpServletRequest request;
    private MockHttpServletResponse response;

    @BeforeEach
    void setUp() {
        appProperties = buildAppProperties(VALID_KEY);
        request = new MockHttpServletRequest();
        response = new MockHttpServletResponse();
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request, response));
    }

    @AfterEach
    void tearDown() {
        RequestContextHolder.resetRequestAttributes();
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Construction
    // ─────────────────────────────────────────────────────────────────────────

    @Test
    void constructor_throwsIllegalArgumentException_whenEncryptionKeyIsBlank() {
        AppProperties props = buildAppProperties("");
        assertThrows(IllegalArgumentException.class,
                () -> new CookieMsalTokenCache(props, authCookieService));
    }

    @Test
    void constructor_throwsIllegalArgumentException_whenEncryptionKeyIsNull() {
        AppProperties props = buildAppProperties(null);
        assertThrows(IllegalArgumentException.class,
                () -> new CookieMsalTokenCache(props, authCookieService));
    }

    @Test
    void constructor_succeedsWithValidKey() {
        assertDoesNotThrow(() -> new CookieMsalTokenCache(appProperties, authCookieService));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // beforeCacheAccess
    // ─────────────────────────────────────────────────────────────────────────

    @Nested
    class BeforeCacheAccess {

        @Test
        void deserializesCache_whenCookieIsPresent() throws Exception {
            CookieMsalTokenCache cache = new CookieMsalTokenCache(appProperties, authCookieService);

            // Produce a valid encrypted cookie value
            String encryptedValue = encryptAndCompress(cache, MINIMAL_MSAL_CACHE_JSON);
            when(authCookieService.getMsalCacheCookie(request)).thenReturn(Optional.of(encryptedValue));
            when(context.tokenCache()).thenReturn(tokenCache);

            cache.beforeCacheAccess(context);

            verify(tokenCache).deserialize(MINIMAL_MSAL_CACHE_JSON);
        }

        @Test
        void isNoOp_whenCookieIsAbsent() {
            CookieMsalTokenCache cache = new CookieMsalTokenCache(appProperties, authCookieService);
            when(authCookieService.getMsalCacheCookie(request)).thenReturn(Optional.empty());

            assertDoesNotThrow(() -> cache.beforeCacheAccess(context));

            verify(context, never()).tokenCache();
        }

        @Test
        void isNoOp_whenCookieIsBlank() {
            CookieMsalTokenCache cache = new CookieMsalTokenCache(appProperties, authCookieService);
            when(authCookieService.getMsalCacheCookie(request)).thenReturn(Optional.of("   "));

            assertDoesNotThrow(() -> cache.beforeCacheAccess(context));

            verify(context, never()).tokenCache();
        }

        @Test
        void isFaultTolerant_whenCookieValueIsTamperedOrCorrupted() {
            CookieMsalTokenCache cache = new CookieMsalTokenCache(appProperties, authCookieService);
            when(authCookieService.getMsalCacheCookie(request)).thenReturn(Optional.of("not-valid-base64!!"));

            assertDoesNotThrow(() -> cache.beforeCacheAccess(context));

            verify(context, never()).tokenCache();
        }

        @Test
        void isFaultTolerant_whenCookieEncryptedWithDifferentKey() throws Exception {
            // Simulate key rotation: the cookie was encrypted with a different key
            AppProperties otherProps = buildAppProperties(OTHER_VALID_KEY);
            CookieMsalTokenCache otherCache = new CookieMsalTokenCache(otherProps, authCookieService);
            String encryptedWithOtherKey = encryptAndCompress(otherCache, MINIMAL_MSAL_CACHE_JSON);

            CookieMsalTokenCache cache = new CookieMsalTokenCache(appProperties, authCookieService);
            when(authCookieService.getMsalCacheCookie(request)).thenReturn(Optional.of(encryptedWithOtherKey));

            assertDoesNotThrow(() -> cache.beforeCacheAccess(context));

            verify(context, never()).tokenCache();
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // afterCacheAccess
    // ─────────────────────────────────────────────────────────────────────────

    @Nested
    class AfterCacheAccess {

        @Test
        void skipsWrite_whenCacheHasNotChanged() {
            CookieMsalTokenCache cache = new CookieMsalTokenCache(appProperties, authCookieService);
            when(context.hasCacheChanged()).thenReturn(false);

            cache.afterCacheAccess(context);

            verify(authCookieService, never()).setMsalCacheCookie(any(), any());
        }

        @Test
        void writesCookie_whenCacheHasChanged() {
            CookieMsalTokenCache cache = new CookieMsalTokenCache(appProperties, authCookieService);
            when(context.hasCacheChanged()).thenReturn(true);
            when(context.tokenCache()).thenReturn(tokenCache);
            when(tokenCache.serialize()).thenReturn(MINIMAL_MSAL_CACHE_JSON);

            cache.afterCacheAccess(context);

            ArgumentCaptor<String> valueCaptor = ArgumentCaptor.forClass(String.class);
            verify(authCookieService).setMsalCacheCookie(eq(response), valueCaptor.capture());
            assertFalse(valueCaptor.getValue().isBlank(), "Encrypted cookie value must not be blank");
        }

        @Test
        void encryptedCookieValue_isBase64AndNotPlainJson() {
            CookieMsalTokenCache cache = new CookieMsalTokenCache(appProperties, authCookieService);
            when(context.hasCacheChanged()).thenReturn(true);
            when(context.tokenCache()).thenReturn(tokenCache);
            when(tokenCache.serialize()).thenReturn(MINIMAL_MSAL_CACHE_JSON);

            cache.afterCacheAccess(context);

            ArgumentCaptor<String> valueCaptor = ArgumentCaptor.forClass(String.class);
            verify(authCookieService).setMsalCacheCookie(eq(response), valueCaptor.capture());
            String cookieValue = valueCaptor.getValue();
            // Must not contain raw JSON (it is encrypted)
            assertFalse(cookieValue.contains("{"), "Cookie must not contain raw JSON");
            assertFalse(cookieValue.contains("RefreshToken"), "Cookie must not expose token type names");
        }

        @Test
        void skipsWrite_whenEncryptedPayloadExceedsMaxSize() {
            CookieMsalTokenCache cache = new CookieMsalTokenCache(appProperties, authCookieService);
            when(context.hasCacheChanged()).thenReturn(true);
            when(context.tokenCache()).thenReturn(tokenCache);
            // Use random-looking (high-entropy) data to defeat GZIP compression.
            // A Base64-encoded block of pseudo-random bytes does not compress and
            // guarantees the final encrypted cookie value exceeds MAX_COOKIE_VALUE_BYTES.
            java.util.Random rng = new java.util.Random(0L);
            byte[] randomBytes = new byte[3000];
            rng.nextBytes(randomBytes);
            String largeHighEntropyJson =
                    "{\"RefreshToken\":\"" + java.util.Base64.getEncoder().encodeToString(randomBytes) + "\"}";
            when(tokenCache.serialize()).thenReturn(largeHighEntropyJson);

            cache.afterCacheAccess(context);

            verify(authCookieService, never()).setMsalCacheCookie(any(), any());
        }

        @Test
        void roundTrip_serializesAndDeserializesCorrectly() throws Exception {
            CookieMsalTokenCache cache = new CookieMsalTokenCache(appProperties, authCookieService);

            // Write phase
            when(context.hasCacheChanged()).thenReturn(true);
            when(context.tokenCache()).thenReturn(tokenCache);
            when(tokenCache.serialize()).thenReturn(MINIMAL_MSAL_CACHE_JSON);
            cache.afterCacheAccess(context);

            ArgumentCaptor<String> valueCaptor = ArgumentCaptor.forClass(String.class);
            verify(authCookieService).setMsalCacheCookie(eq(response), valueCaptor.capture());
            String cookieValue = valueCaptor.getValue();

            // Read phase — inject the written value back as the incoming cookie
            reset(context, tokenCache, authCookieService);
            when(authCookieService.getMsalCacheCookie(request)).thenReturn(Optional.of(cookieValue));
            when(context.tokenCache()).thenReturn(tokenCache);

            cache.beforeCacheAccess(context);

            verify(tokenCache).deserialize(MINIMAL_MSAL_CACHE_JSON);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // evict
    // ─────────────────────────────────────────────────────────────────────────

    @Nested
    class Evict {

        @Test
        void clearsCacheCookie_onEvict() {
            CookieMsalTokenCache cache = new CookieMsalTokenCache(appProperties, authCookieService);

            cache.evict("some-oid.some-tid");

            verify(authCookieService).clearMsalCacheCookie(response);
        }

        @Test
        void evict_doesNotThrow_whenResponseIsUnavailable() {
            // Simulate a context where the response is null (e.g. async dispatch)
            RequestContextHolder.resetRequestAttributes();
            RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));

            CookieMsalTokenCache cache = new CookieMsalTokenCache(appProperties, authCookieService);

            assertDoesNotThrow(() -> cache.evict("some-oid.some-tid"));

            verify(authCookieService, never()).clearMsalCacheCookie(any());
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Helpers
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Uses the package-private compress+encrypt pipeline of the real class to produce
     * a valid cookie value for use in read-path tests.
     */
    private String encryptAndCompress(CookieMsalTokenCache cache, String json) throws Exception {
        // Drive afterCacheAccess to produce an encrypted value, then capture it.
        MockHttpServletResponse captureResponse = new MockHttpServletResponse();
        RequestContextHolder.resetRequestAttributes();
        RequestContextHolder.setRequestAttributes(
                new ServletRequestAttributes(request, captureResponse));

        ArgumentCaptor<String> captor = ArgumentCaptor.forClass(String.class);
        ITokenCacheAccessContext ctx = mock(ITokenCacheAccessContext.class);
        ITokenCache tc = mock(ITokenCache.class);
        when(ctx.hasCacheChanged()).thenReturn(true);
        when(ctx.tokenCache()).thenReturn(tc);
        when(tc.serialize()).thenReturn(json);
        doNothing().when(authCookieService).setMsalCacheCookie(any(), captor.capture());

        cache.afterCacheAccess(ctx);

        RequestContextHolder.resetRequestAttributes();
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request, response));

        return captor.getValue();
    }

    private AppProperties buildAppProperties(String encryptionKey) {
        AppProperties props = new AppProperties();
        props.getCookie().setSecure(false);
        props.getCookie().setSameSite("Strict");
        props.getTokenCache().getCookie().setName("MSAL_TOKEN_CACHE");
        props.getTokenCache().getCookie().setMaxAge(java.time.Duration.ofDays(90));
        props.getTokenCache().getCookie().setEncryptionKey(encryptionKey);
        return props;
    }
}
