package com.example.msalbff.controller;

import com.example.msalbff.config.AppProperties;
import com.example.msalbff.service.AuthCookieService;
import com.example.msalbff.service.MsalTokenCacheService;
import com.example.msalbff.service.TokenExchangeService;
import com.example.msalbff.service.TokenValidationService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.oauth2.jwt.Jwt;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Map;
import java.util.Optional;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * Unit tests for {@link AuthController} focusing on the logout flow and
 * the migration from a concrete Redis dependency to the {@link MsalTokenCacheService} interface.
 */
@ExtendWith(MockitoExtension.class)
class AuthControllerTest {

    @Mock private TokenExchangeService tokenExchangeService;
    @Mock private TokenValidationService tokenValidationService;
    @Mock private AuthCookieService authCookieService;
    @Mock private MsalTokenCacheService tokenCacheService;

    private AuthController controller;
    private MockHttpServletRequest request;
    private MockHttpServletResponse response;

    private static final String OID = "object-id-1234";
    private static final String TID = "tenant-id-5678";
    private static final String HOME_ACCOUNT_ID = OID + "." + TID;

    @BeforeEach
    void setUp() {
        AppProperties props = new AppProperties();
        props.getCookie().setName("AUTH_TOKEN");
        props.getAzureAd().setRedirectUri("http://localhost:8080/api/auth/callback");
        props.getCors().setAllowedOrigins(new String[]{"http://localhost:3000"});

        lenient().when(authCookieService.getAuthCookie(any())).thenReturn(Optional.empty());

        controller = new AuthController(
                tokenExchangeService, tokenValidationService,
                authCookieService, tokenCacheService, props);

        request = new MockHttpServletRequest();
        response = new MockHttpServletResponse();
    }

    // ─────────────────────────────────────────────────────────────────────────
    // logout
    // ─────────────────────────────────────────────────────────────────────────

    @Nested
    class Logout {

        @Test
        void evictsTokenCacheUsingOidAndTid_fromAuthCookie() {
            String fakeJwt = "header.payload.signature";
            when(authCookieService.getAuthCookie(request)).thenReturn(Optional.of(fakeJwt));

            Jwt jwt = buildJwt(Map.of("oid", OID, "tid", TID));
            when(tokenValidationService.parseToken(fakeJwt)).thenReturn(jwt);

            controller.logout(request, response);

            verify(tokenCacheService).evict(HOME_ACCOUNT_ID);
        }

        @Test
        void clearsAuthCookie_onLogout() {
            controller.logout(request, response);
            verify(authCookieService).clearAuthCookie(response);
        }

        @Test
        void skipsEviction_whenAuthCookieIsAbsent() {
            // Default stub returns Optional.empty() — no cookie present
            controller.logout(request, response);

            verify(tokenCacheService, never()).evict(any());
            verify(authCookieService).clearAuthCookie(response);
        }

        @Test
        void skipsEviction_whenTokenParsingFails() {
            String fakeJwt = "malformed.token";
            when(authCookieService.getAuthCookie(request)).thenReturn(Optional.of(fakeJwt));
            when(tokenValidationService.parseToken(fakeJwt))
                    .thenThrow(new RuntimeException("Malformed JWT"));

            // Should not propagate the exception; AUTH_TOKEN must still be cleared
            controller.logout(request, response);

            verify(tokenCacheService, never()).evict(any());
            verify(authCookieService).clearAuthCookie(response);
        }

        @Test
        void skipsEviction_whenOidOrTidClaimsAreMissing() {
            String fakeJwt = "header.payload.signature";
            when(authCookieService.getAuthCookie(request)).thenReturn(Optional.of(fakeJwt));

            Jwt jwt = buildJwt(Map.of()); // no oid/tid claims
            when(tokenValidationService.parseToken(fakeJwt)).thenReturn(jwt);

            controller.logout(request, response);

            verify(tokenCacheService, never()).evict(any());
            verify(authCookieService).clearAuthCookie(response);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Helpers
    // ─────────────────────────────────────────────────────────────────────────

    private Jwt buildJwt(Map<String, Object> additionalClaims) {
        Map<String, Object> headers = Map.of("alg", "RS256");
        Instant now = Instant.now();
        Map<String, Object> baseClaims = Map.of(
                "iss", "https://login.microsoftonline.com/test/v2.0",
                "aud", "test-client-id",
                "sub", "test-subject");
        Map<String, Object> claims = new java.util.HashMap<>(baseClaims);
        claims.putAll(additionalClaims);
        return new Jwt("dummy.jwt.value", now, now.plus(1, ChronoUnit.HOURS), headers, claims);
    }
}
