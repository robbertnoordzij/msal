package com.example.msalbff.security;

import com.example.msalbff.config.AppProperties;
import com.example.msalbff.service.TokenExchangeService;
import com.example.msalbff.service.TokenValidationService;
import com.microsoft.aad.msal4j.IAuthenticationResult;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;

import java.time.Instant;
import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class CookieAuthenticationFilterTest {

    @Mock private TokenValidationService tokenValidationService;
    @Mock private TokenExchangeService tokenExchangeService;
    @Mock private AppProperties appProperties;
    @Mock private AppProperties.Cookie cookieProperties;
    @Mock private AppProperties.AzureAd azureAdProperties;
    @Mock private HttpServletRequest request;
    @Mock private HttpServletResponse response;
    @Mock private FilterChain filterChain;
    @Mock private HttpSession session;
    @Mock private Jwt jwt;

    private CookieAuthenticationFilter filter;

    private static final String VALID_TOKEN = "valid-token";
    private static final String ACCOUNT_ID = "oid.tid";

    @BeforeEach
    void setup() {
        SecurityContextHolder.clearContext();
        lenient().when(appProperties.getCookie()).thenReturn(cookieProperties);
        lenient().when(appProperties.getAzureAd()).thenReturn(azureAdProperties);
        lenient().when(cookieProperties.getName()).thenReturn("AUTH_TOKEN");
        lenient().when(azureAdProperties.getScopes()).thenReturn("openid profile offline_access");
        filter = new CookieAuthenticationFilter(tokenValidationService, tokenExchangeService, appProperties);
    }

    @Test
    void validToken_setsAuthentication() throws Exception {
        givenAuthCookie(VALID_TOKEN);
        when(request.getRequestURI()).thenReturn("/api/hello");
        when(tokenValidationService.validateToken(VALID_TOKEN)).thenReturn(true);
        when(tokenValidationService.parseToken(VALID_TOKEN)).thenReturn(jwt);
        when(tokenValidationService.getUserName(jwt)).thenReturn("user@example.com");
        when(jwt.getExpiresAt()).thenReturn(Instant.now().plusSeconds(3600));

        filter.doFilter(request, response, filterChain);

        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        assertNotNull(auth);
        assertEquals("user@example.com", auth.getName());
        verify(filterChain).doFilter(request, response);
    }

    @Test
    void invalidToken_noSession_leavesContextEmpty() throws Exception {
        givenAuthCookie("invalid-token");
        when(request.getRequestURI()).thenReturn("/api/hello");
        when(tokenValidationService.validateToken("invalid-token")).thenReturn(false);
        when(request.getSession(false)).thenReturn(null);

        filter.doFilter(request, response, filterChain);

        assertNull(SecurityContextHolder.getContext().getAuthentication());
        verify(filterChain).doFilter(request, response);
    }

    @Test
    void invalidToken_withSession_attemptsRefresh() throws Exception {
        givenAuthCookie("expired-token");
        when(request.getRequestURI()).thenReturn("/api/hello");
        when(tokenValidationService.validateToken("expired-token")).thenReturn(false);
        givenSessionWithAccountId(ACCOUNT_ID);

        IAuthenticationResult refreshResult = mock(IAuthenticationResult.class);
        when(refreshResult.idToken()).thenReturn("new-id-token");
        when(tokenExchangeService.acquireTokenSilently(eq(ACCOUNT_ID), any()))
                .thenReturn(Optional.of(refreshResult));
        when(tokenValidationService.validateToken("new-id-token")).thenReturn(true);
        when(tokenValidationService.parseToken("new-id-token")).thenReturn(jwt);
        when(tokenValidationService.getUserName(jwt)).thenReturn("user@example.com");

        filter.doFilter(request, response, filterChain);

        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        assertNotNull(auth);
        assertEquals("user@example.com", auth.getName());
        verify(response).addCookie(argThat(c -> "AUTH_TOKEN".equals(c.getName()) && "new-id-token".equals(c.getValue())));
    }

    @Test
    void validToken_expiringSoon_triggersProactiveRefresh() throws Exception {
        givenAuthCookie(VALID_TOKEN);
        when(request.getRequestURI()).thenReturn("/api/hello");
        when(tokenValidationService.validateToken(VALID_TOKEN)).thenReturn(true);
        when(tokenValidationService.parseToken(VALID_TOKEN)).thenReturn(jwt);
        when(tokenValidationService.getUserName(jwt)).thenReturn("user@example.com");
        // Expires within the proactive threshold
        when(jwt.getExpiresAt()).thenReturn(Instant.now().plusSeconds(60));
        givenSessionWithAccountId(ACCOUNT_ID);
        when(tokenExchangeService.acquireTokenSilently(eq(ACCOUNT_ID), any()))
                .thenReturn(Optional.empty()); // refresh attempt made but empty is fine for this test

        filter.doFilter(request, response, filterChain);

        // Auth was set from the still-valid original token
        assertNotNull(SecurityContextHolder.getContext().getAuthentication());
        // And a silent refresh was attempted
        verify(tokenExchangeService).acquireTokenSilently(eq(ACCOUNT_ID), any());
    }

    @Test
    void validToken_notExpiringSoon_doesNotTriggerRefresh() throws Exception {
        givenAuthCookie(VALID_TOKEN);
        when(request.getRequestURI()).thenReturn("/api/hello");
        when(tokenValidationService.validateToken(VALID_TOKEN)).thenReturn(true);
        when(tokenValidationService.parseToken(VALID_TOKEN)).thenReturn(jwt);
        when(tokenValidationService.getUserName(jwt)).thenReturn("user@example.com");
        when(jwt.getExpiresAt()).thenReturn(Instant.now().plusSeconds(3600));

        filter.doFilter(request, response, filterChain);

        verifyNoInteractions(tokenExchangeService);
    }

    @Test
    void authEndpoint_skipsFilterCompletely() throws Exception {
        when(request.getRequestURI()).thenReturn("/api/auth/login");

        filter.doFilter(request, response, filterChain);

        assertNull(SecurityContextHolder.getContext().getAuthentication());
        verify(filterChain).doFilter(request, response);
        verifyNoInteractions(tokenValidationService);
    }

    @Test
    void silentRefreshFails_leavesContextEmpty() throws Exception {
        givenAuthCookie("expired-token");
        when(request.getRequestURI()).thenReturn("/api/hello");
        when(tokenValidationService.validateToken("expired-token")).thenReturn(false);
        givenSessionWithAccountId(ACCOUNT_ID);
        when(tokenExchangeService.acquireTokenSilently(eq(ACCOUNT_ID), any()))
                .thenReturn(Optional.empty());

        filter.doFilter(request, response, filterChain);

        assertNull(SecurityContextHolder.getContext().getAuthentication());
        verify(filterChain).doFilter(request, response);
    }

    // --- helpers ---

    private void givenAuthCookie(String token) {
        when(request.getCookies()).thenReturn(new Cookie[]{new Cookie("AUTH_TOKEN", token)});
    }

    private void givenSessionWithAccountId(String accountId) {
        when(request.getSession(false)).thenReturn(session);
        when(session.getAttribute("msal_account_id")).thenReturn(accountId);
    }
}
