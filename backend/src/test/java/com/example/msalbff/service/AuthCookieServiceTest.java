package com.example.msalbff.service;

import com.example.msalbff.config.AppProperties;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import static org.junit.jupiter.api.Assertions.*;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class AuthCookieServiceTest {

    @Mock
    private AppProperties appProperties;

    private AppProperties.Cookie cookieConfig;
    private AuthCookieService authCookieService;

    @BeforeEach
    void setUp() {
        cookieConfig = new AppProperties.Cookie();
        cookieConfig.setName("AUTH_TOKEN");
        cookieConfig.setMaxAge(3600);
        cookieConfig.setSecure(false);
        cookieConfig.setSameSite("Strict");
        cookieConfig.setHttpOnly(true);

        org.mockito.Mockito.when(appProperties.getCookie()).thenReturn(cookieConfig);
        authCookieService = new AuthCookieService(appProperties);
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
        assertEquals("expected-state", authCookieService.getOAuthStateCookie(request));
    }

    @Test
    void getOAuthStateCookie_returnsNull_whenCookieAbsent() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        assertNull(authCookieService.getOAuthStateCookie(request));
    }

    @Test
    void getOAuthStateCookie_returnsNull_whenNoCookiesAtAll() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        // No cookies set on request (getCookies() returns null for MockHttpServletRequest with no cookies)
        assertNull(authCookieService.getOAuthStateCookie(request));
    }

    // ─── getPkceVerifierCookie ────────────────────────────────────────────────

    @Test
    void getPkceVerifierCookie_returnsCookieValue_whenPresent() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setCookies(new Cookie("PKCE_VERIFIER", "my-verifier"));
        assertEquals("my-verifier", authCookieService.getPkceVerifierCookie(request));
    }

    @Test
    void getPkceVerifierCookie_returnsNull_whenCookieAbsent() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setCookies(new Cookie("OTHER_COOKIE", "value"));
        assertNull(authCookieService.getPkceVerifierCookie(request));
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
}
