package com.example.msalbff.service;

import com.example.msalbff.config.AppProperties;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.time.Duration;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

class AuthCookieServiceTest {

    private static final long NINETY_DAYS_SECONDS = Duration.ofDays(90).getSeconds();

    private AuthCookieService authCookieService;

    @BeforeEach
    void setUp() {
        AppProperties props = new AppProperties();
        props.getCookie().setName("AUTH_TOKEN");
        props.getCookie().setMaxAge(3600);
        props.getCookie().setSecure(false);
        props.getCookie().setSameSite("Strict");
        props.getCookie().setHttpOnly(true);
        props.getTokenCache().getCookie().setName("MSAL_TOKEN_CACHE");
        props.getTokenCache().getCookie().setMaxAge(Duration.ofDays(90));
        props.getTokenCache().getCookie().setSecure(false);
        authCookieService = new AuthCookieService(props);
    }

    // ─── setAuthCookie ────────────────────────────────────────────────────────

    @Test
    void setAuthCookie_addsSetCookieHeader() {
        MockHttpServletResponse response = new MockHttpServletResponse();
        authCookieService.setAuthCookie(response, "some.jwt.token");
        String header = response.getHeader("Set-Cookie");
        assertNotNull(header);
        assertTrue(header.contains("AUTH_TOKEN=some.jwt.token"), "Cookie header: " + header);
        assertTrue(header.contains("HttpOnly"), "Should be HttpOnly");
        assertTrue(header.contains("SameSite=Strict"), "Should be SameSite=Strict");
    }

    @Test
    void setAuthCookie_setsCorrectMaxAge() {
        MockHttpServletResponse response = new MockHttpServletResponse();
        authCookieService.setAuthCookie(response, "some.jwt.token");
        String header = response.getHeader("Set-Cookie");
        assertTrue(header.contains("Max-Age=3600"), "Header: " + header);
    }

    @Test
    void setAuthCookie_throwsOnNullToken() {
        MockHttpServletResponse response = new MockHttpServletResponse();
        assertThrows(IllegalArgumentException.class,
                () -> authCookieService.setAuthCookie(response, null));
    }

    @Test
    void setAuthCookie_throwsOnBlankToken() {
        MockHttpServletResponse response = new MockHttpServletResponse();
        assertThrows(IllegalArgumentException.class,
                () -> authCookieService.setAuthCookie(response, "  "));
    }

    // ─── clearAuthCookie ──────────────────────────────────────────────────────

    @Test
    void clearAuthCookie_setsMaxAgeZero() {
        MockHttpServletResponse response = new MockHttpServletResponse();
        authCookieService.clearAuthCookie(response);
        String header = response.getHeader("Set-Cookie");
        assertNotNull(header);
        assertTrue(header.contains("Max-Age=0"), "Header: " + header);
        assertTrue(header.contains("AUTH_TOKEN="), "Header: " + header);
    }

    // ─── setOAuthStateCookie ──────────────────────────────────────────────────

    @Test
    void setOAuthStateCookie_usesSameSiteLax() {
        MockHttpServletResponse response = new MockHttpServletResponse();
        authCookieService.setOAuthStateCookie(response, "my-state-value");
        String header = response.getHeader("Set-Cookie");
        assertNotNull(header);
        assertTrue(header.contains("OAUTH_STATE=my-state-value"), "Header: " + header);
        assertTrue(header.contains("SameSite=Lax"), "OAuth flow cookies must use SameSite=Lax");
    }

    @Test
    void setOAuthStateCookie_throwsOnNullState() {
        MockHttpServletResponse response = new MockHttpServletResponse();
        assertThrows(IllegalArgumentException.class,
                () -> authCookieService.setOAuthStateCookie(response, null));
    }

    @Test
    void setOAuthStateCookie_throwsOnBlankState() {
        MockHttpServletResponse response = new MockHttpServletResponse();
        assertThrows(IllegalArgumentException.class,
                () -> authCookieService.setOAuthStateCookie(response, ""));
    }

    // ─── setPkceVerifierCookie ────────────────────────────────────────────────

    @Test
    void setPkceVerifierCookie_throwsOnNullVerifier() {
        MockHttpServletResponse response = new MockHttpServletResponse();
        assertThrows(IllegalArgumentException.class,
                () -> authCookieService.setPkceVerifierCookie(response, null));
    }

    // ─── getOAuthStateCookie ──────────────────────────────────────────────────

    @Test
    void getOAuthStateCookie_returnsCookieValue_whenPresent() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setCookies(new Cookie("OAUTH_STATE", "expected-state"));
        assertEquals(Optional.of("expected-state"), authCookieService.getOAuthStateCookie(request));
    }

    @Test
    void getOAuthStateCookie_returnsNull_whenCookieAbsent() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        assertTrue(authCookieService.getOAuthStateCookie(request).isEmpty());
    }

    @Test
    void getOAuthStateCookie_returnsNull_whenNoCookiesAtAll() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        // No cookies set on request (getCookies() returns null for MockHttpServletRequest with no cookies)
        assertTrue(authCookieService.getOAuthStateCookie(request).isEmpty());
    }

    // ─── getPkceVerifierCookie ────────────────────────────────────────────────

    @Test
    void getPkceVerifierCookie_returnsCookieValue_whenPresent() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setCookies(new Cookie("PKCE_VERIFIER", "my-verifier"));
        assertEquals(Optional.of("my-verifier"), authCookieService.getPkceVerifierCookie(request));
    }

    @Test
    void getPkceVerifierCookie_returnsNull_whenCookieAbsent() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setCookies(new Cookie("OTHER_COOKIE", "value"));
        assertTrue(authCookieService.getPkceVerifierCookie(request).isEmpty());
    }

    // ─── clearOAuthFlowCookies ────────────────────────────────────────────────

    @Test
    void clearOAuthFlowCookies_clearsBothCookies() {
        MockHttpServletResponse response = new MockHttpServletResponse();
        authCookieService.clearOAuthFlowCookies(response);
        var headers = response.getHeaders("Set-Cookie");
        assertEquals(2, headers.size(), "Should clear exactly 2 cookies");
        assertTrue(headers.stream().anyMatch(h -> h.contains("OAUTH_STATE=") && h.contains("Max-Age=0")));
        assertTrue(headers.stream().anyMatch(h -> h.contains("PKCE_VERIFIER=") && h.contains("Max-Age=0")));
    }

    // ─── MSAL cache cookie ────────────────────────────────────────────────────

    @Test
    void setMsalCacheCookie_writesHttpOnlySameSiteStrictCookie() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        authCookieService.setMsalCacheCookie(request, response, "encrypted-blob");

        String header = response.getHeader("Set-Cookie");
        assertNotNull(header, "Set-Cookie header must be present");
        assertTrue(header.contains("MSAL_TOKEN_CACHE=encrypted-blob"), "Header: " + header);
        assertTrue(header.contains("HttpOnly"), "Must be HttpOnly; header: " + header);
        assertTrue(header.contains("SameSite=Strict"), "Must be SameSite=Strict; header: " + header);
        assertTrue(header.contains("Max-Age=" + NINETY_DAYS_SECONDS), "MaxAge must be 90 days; header: " + header);
    }

    @Test
    void setMsalCacheCookie_writesSingleCookie_whenValueFitsInOneChunk() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        authCookieService.setMsalCacheCookie(request, response, "small-value");

        var headers = response.getHeaders("Set-Cookie");
        assertEquals(1, headers.size(), "A small value must produce exactly one cookie");
        assertTrue(headers.get(0).contains("MSAL_TOKEN_CACHE=small-value"));
    }

    @Test
    void setMsalCacheCookie_splitsIntoChunks_whenValueExceedsChunkSize() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        String largeValue = "x".repeat(AuthCookieService.CHUNK_SIZE_BYTES * 2 + 100);

        authCookieService.setMsalCacheCookie(request, response, largeValue);

        var headers = response.getHeaders("Set-Cookie");
        // marker + 3 chunk cookies
        assertEquals(4, headers.size(), "Should write a marker cookie plus 3 chunk cookies; headers: " + headers);
        assertTrue(headers.stream().anyMatch(h -> h.contains("MSAL_TOKEN_CACHE=chunks-3")),
                "Primary cookie must carry the chunks-3 marker; headers: " + headers);
        assertTrue(headers.stream().anyMatch(h -> h.contains("MSAL_TOKEN_CACHE_1=")));
        assertTrue(headers.stream().anyMatch(h -> h.contains("MSAL_TOKEN_CACHE_2=")));
        assertTrue(headers.stream().anyMatch(h -> h.contains("MSAL_TOKEN_CACHE_3=")));
    }

    @Test
    void msalCacheCookie_roundTrips_singleChunk() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        authCookieService.setMsalCacheCookie(request, response, "opaque-single");

        MockHttpServletRequest readRequest = requestFromSetCookieHeaders(response);
        assertEquals(Optional.of("opaque-single"), authCookieService.getMsalCacheCookie(readRequest));
    }

    @Test
    void msalCacheCookie_roundTrips_multipleChunks() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        String largeValue = "abcde".repeat(AuthCookieService.CHUNK_SIZE_BYTES); // ~15 KB

        authCookieService.setMsalCacheCookie(request, response, largeValue);

        MockHttpServletRequest readRequest = requestFromSetCookieHeaders(response);
        assertEquals(Optional.of(largeValue), authCookieService.getMsalCacheCookie(readRequest),
                "A chunked value must reassemble byte-for-byte");
    }

    @Test
    void getMsalCacheCookie_returnsEmpty_whenAChunkIsMissing() {
        // Marker claims 2 chunks but only chunk 1 is present → corrupt, treat as empty
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setCookies(
                new Cookie("MSAL_TOKEN_CACHE", "chunks-2"),
                new Cookie("MSAL_TOKEN_CACHE_1", "part1"));
        assertTrue(authCookieService.getMsalCacheCookie(request).isEmpty());
    }

    @Test
    void setMsalCacheCookie_expiresStaleChunks_whenNewWriteHasFewerChunks() {
        // Previous write left a 3-chunk cookie; the new write only needs a single cookie.
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setCookies(
                new Cookie("MSAL_TOKEN_CACHE", "chunks-3"),
                new Cookie("MSAL_TOKEN_CACHE_1", "a"),
                new Cookie("MSAL_TOKEN_CACHE_2", "b"),
                new Cookie("MSAL_TOKEN_CACHE_3", "c"));
        MockHttpServletResponse response = new MockHttpServletResponse();

        authCookieService.setMsalCacheCookie(request, response, "now-small");

        var headers = response.getHeaders("Set-Cookie");
        assertTrue(headers.stream().anyMatch(h -> h.contains("MSAL_TOKEN_CACHE=now-small")));
        // Chunks 1..3 must be expired
        assertTrue(headers.stream().anyMatch(h -> h.contains("MSAL_TOKEN_CACHE_1=") && h.contains("Max-Age=0")));
        assertTrue(headers.stream().anyMatch(h -> h.contains("MSAL_TOKEN_CACHE_2=") && h.contains("Max-Age=0")));
        assertTrue(headers.stream().anyMatch(h -> h.contains("MSAL_TOKEN_CACHE_3=") && h.contains("Max-Age=0")));
    }

    @Test
    void clearMsalCacheCookie_setsMaxAgeZero() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        authCookieService.clearMsalCacheCookie(request, response);

        String header = response.getHeader("Set-Cookie");
        assertNotNull(header, "Set-Cookie header must be present");
        assertTrue(header.contains("MSAL_TOKEN_CACHE="), "Header: " + header);
        assertTrue(header.contains("Max-Age=0"), "Must expire cookie; header: " + header);
    }

    @Test
    void clearMsalCacheCookie_expiresAllChunkCookies() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setCookies(
                new Cookie("MSAL_TOKEN_CACHE", "chunks-2"),
                new Cookie("MSAL_TOKEN_CACHE_1", "a"),
                new Cookie("MSAL_TOKEN_CACHE_2", "b"));
        MockHttpServletResponse response = new MockHttpServletResponse();

        authCookieService.clearMsalCacheCookie(request, response);

        var headers = response.getHeaders("Set-Cookie");
        assertTrue(headers.stream().anyMatch(h -> h.contains("MSAL_TOKEN_CACHE=") && h.contains("Max-Age=0")));
        assertTrue(headers.stream().anyMatch(h -> h.contains("MSAL_TOKEN_CACHE_1=") && h.contains("Max-Age=0")));
        assertTrue(headers.stream().anyMatch(h -> h.contains("MSAL_TOKEN_CACHE_2=") && h.contains("Max-Age=0")));
    }

    @Test
    void getMsalCacheCookie_returnsCookieValue_whenPresent() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setCookies(new Cookie("MSAL_TOKEN_CACHE", "my-encrypted-value"));
        assertEquals(Optional.of("my-encrypted-value"), authCookieService.getMsalCacheCookie(request));
    }

    @Test
    void getMsalCacheCookie_returnsNull_whenCookieAbsent() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        assertTrue(authCookieService.getMsalCacheCookie(request).isEmpty());
    }

    /**
     * Builds a request whose cookies mirror the {@code Set-Cookie} headers a response wrote,
     * so a write can be round-tripped through a subsequent read.
     */
    private static MockHttpServletRequest requestFromSetCookieHeaders(MockHttpServletResponse response) {
        MockHttpServletRequest request = new MockHttpServletRequest();
        var cookies = response.getHeaders("Set-Cookie").stream()
                .map(h -> h.split(";", 2)[0])
                .map(nv -> nv.split("=", 2))
                .filter(nv -> nv.length == 2 && !nv[1].isEmpty())
                .map(nv -> new Cookie(nv[0], nv[1]))
                .toArray(Cookie[]::new);
        request.setCookies(cookies);
        return request;
    }
}
