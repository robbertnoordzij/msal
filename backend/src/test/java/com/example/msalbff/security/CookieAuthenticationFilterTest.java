package com.example.msalbff.security;

import com.example.msalbff.config.AppProperties;
import com.example.msalbff.service.AuthCookieService;
import com.example.msalbff.service.TokenExchangeService;
import com.example.msalbff.service.TokenValidationService;
import com.microsoft.aad.msal4j.IAuthenticationResult;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;

import java.time.Instant;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class CookieAuthenticationFilterTest {

    @Mock private TokenValidationService tokenValidationService;
    @Mock private TokenExchangeService tokenExchangeService;
    @Mock private AuthCookieService authCookieService;
    @Mock private AppProperties appProperties;
    @Mock private AppProperties.Cookie cookieProperties;
    @Mock private AppProperties.AzureAd azureAdProperties;
    @Mock private HttpServletRequest request;
    @Mock private HttpServletResponse response;
    @Mock private FilterChain filterChain;
    @Mock private Jwt jwt;

    private CookieAuthenticationFilter filter;

    private static final String VALID_TOKEN = "valid-token";
    private static final String ACCOUNT_ID = "oid.tid";
    private static final String COOKIE_NAME = "AUTH_TOKEN";

    @BeforeEach
    void setUp() {
        SecurityContextHolder.clearContext();
        lenient().when(appProperties.getCookie()).thenReturn(cookieProperties);
        lenient().when(appProperties.getAzureAd()).thenReturn(azureAdProperties);
        lenient().when(cookieProperties.getName()).thenReturn("AUTH_TOKEN");
        lenient().when(azureAdProperties.getScopes()).thenReturn("openid profile offline_access");
        filter = new CookieAuthenticationFilter(tokenValidationService, tokenExchangeService, authCookieService, appProperties);
    }

    @Test
    void validToken_setsAuthentication() throws Exception {
        givenAuthCookie(VALID_TOKEN);
        when(request.getServletPath()).thenReturn("/hello");
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
    void invalidToken_noAccountClaims_leavesContextEmpty() throws Exception {
        givenAuthCookie("invalid-token");
        when(request.getServletPath()).thenReturn("/hello");
        when(tokenValidationService.validateToken("invalid-token")).thenReturn(false);
        // parseToken("invalid-token") not stubbed — returns null, extractHomeAccountId returns null

        filter.doFilter(request, response, filterChain);

        assertNull(SecurityContextHolder.getContext().getAuthentication());
        verify(filterChain).doFilter(request, response);
    }

    @Test
    void invalidToken_withAccountClaims_attemptsRefresh() throws Exception {
        givenAuthCookie("expired-token");
        when(request.getServletPath()).thenReturn("/hello");
        when(tokenValidationService.validateToken("expired-token")).thenReturn(false);
        givenTokenWithAccountClaims("expired-token", ACCOUNT_ID);

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
        verify(authCookieService).setAuthCookie(eq(response), eq("new-id-token"));
    }

    @Test
    void validToken_expiringSoon_triggersProactiveRefresh() throws Exception {
        givenAuthCookie(VALID_TOKEN);
        when(request.getServletPath()).thenReturn("/hello");
        when(tokenValidationService.validateToken(VALID_TOKEN)).thenReturn(true);
        when(tokenValidationService.parseToken(VALID_TOKEN)).thenReturn(jwt);
        when(tokenValidationService.getUserName(jwt)).thenReturn("user@example.com");
        // Expires within the proactive threshold
        when(jwt.getExpiresAt()).thenReturn(Instant.now().plusSeconds(60));
        // Account claims needed for extractHomeAccountId from the current token
        when(jwt.getClaimAsString("oid")).thenReturn("oid");
        when(jwt.getClaimAsString("tid")).thenReturn("tid");
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
        when(request.getServletPath()).thenReturn("/hello");
        when(tokenValidationService.validateToken(VALID_TOKEN)).thenReturn(true);
        when(tokenValidationService.parseToken(VALID_TOKEN)).thenReturn(jwt);
        when(tokenValidationService.getUserName(jwt)).thenReturn("user@example.com");
        when(jwt.getExpiresAt()).thenReturn(Instant.now().plusSeconds(3600));

        filter.doFilter(request, response, filterChain);

        verifyNoInteractions(tokenExchangeService);
    }

    @Test
    void authEndpoint_skipsFilterCompletely() throws Exception {
        when(request.getServletPath()).thenReturn("/auth/login");

        filter.doFilter(request, response, filterChain);

        assertNull(SecurityContextHolder.getContext().getAuthentication());
        verify(filterChain).doFilter(request, response);
        verifyNoInteractions(tokenValidationService);
    }

    @Test
    void silentRefreshFails_leavesContextEmpty() throws Exception {
        givenAuthCookie("expired-token");
        when(request.getServletPath()).thenReturn("/hello");
        when(tokenValidationService.validateToken("expired-token")).thenReturn(false);
        givenTokenWithAccountClaims("expired-token", ACCOUNT_ID);
        when(tokenExchangeService.acquireTokenSilently(eq(ACCOUNT_ID), any()))
                .thenReturn(Optional.empty());

        filter.doFilter(request, response, filterChain);

        assertNull(SecurityContextHolder.getContext().getAuthentication());
        verify(filterChain).doFilter(request, response);
    }

    // --- helpers ---

    private void givenAuthCookie(String token) {
        when(request.getCookies()).thenReturn(new Cookie[]{new Cookie(COOKIE_NAME, token)});
    }

    private void givenTokenWithAccountClaims(String token, String accountId) {
        String[] parts = accountId.split("\\.", 2);
        Jwt accountJwt = mock(Jwt.class);
        when(accountJwt.getClaimAsString("oid")).thenReturn(parts[0]);
        when(accountJwt.getClaimAsString("tid")).thenReturn(parts[1]);
        when(tokenValidationService.parseToken(token)).thenReturn(accountJwt);
    }
}
