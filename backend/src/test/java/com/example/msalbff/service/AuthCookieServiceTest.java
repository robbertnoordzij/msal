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
        MockHttpServletResponse response = new MockHttpServletResponse();
        authCookieService.setMsalCacheCookie(response, "encrypted-blob");

        String header = response.getHeader("Set-Cookie");
        assertNotNull(header, "Set-Cookie header must be present");
        assertTrue(header.contains("MSAL_TOKEN_CACHE=encrypted-blob"), "Header: " + header);
        assertTrue(header.contains("HttpOnly"), "Must be HttpOnly; header: " + header);
        assertTrue(header.contains("SameSite=Strict"), "Must be SameSite=Strict; header: " + header);
        assertTrue(header.contains("Max-Age=" + NINETY_DAYS_SECONDS), "MaxAge must be 90 days; header: " + header);
    }

    @Test
    void clearMsalCacheCookie_setsMaxAgeZero() {
        MockHttpServletResponse response = new MockHttpServletResponse();
        authCookieService.clearMsalCacheCookie(response);

        String header = response.getHeader("Set-Cookie");
        assertNotNull(header, "Set-Cookie header must be present");
        assertTrue(header.contains("MSAL_TOKEN_CACHE="), "Header: " + header);
        assertTrue(header.contains("Max-Age=0"), "Must expire cookie; header: " + header);
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
}
