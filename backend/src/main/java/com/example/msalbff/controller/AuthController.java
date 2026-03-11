package com.example.msalbff.controller;

import com.example.msalbff.config.AppProperties;
import com.example.msalbff.service.AuthCookieService;
import com.example.msalbff.service.MsalTokenCacheService;
import com.example.msalbff.service.TokenExchangeService;
import com.example.msalbff.service.TokenValidationService;
import com.microsoft.aad.msal4j.IAuthenticationResult;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Set;
import java.util.UUID;

@RestController
@RequestMapping("/auth")
@CrossOrigin(origins = "${app.cors.allowed-origins}", allowCredentials = "true")
public class AuthController {

    private static final Logger logger = LoggerFactory.getLogger(AuthController.class);
    private static final int MAX_AUTHORIZATION_CODE_LENGTH = 2000;

    private final TokenExchangeService tokenExchangeService;
    private final TokenValidationService tokenValidationService;
    private final AuthCookieService authCookieService;
    private final MsalTokenCacheService tokenCacheService;
    private final AppProperties appProperties;

    public AuthController(TokenExchangeService tokenExchangeService,
                          TokenValidationService tokenValidationService,
                          AuthCookieService authCookieService,
                          MsalTokenCacheService tokenCacheService,
                          AppProperties appProperties) {
        this.tokenExchangeService = tokenExchangeService;
        this.tokenValidationService = tokenValidationService;
        this.authCookieService = authCookieService;
        this.tokenCacheService = tokenCacheService;
        this.appProperties = appProperties;
    }

    @GetMapping("/login")
    public void startLogin(HttpServletResponse response) {
        try {
            Set<String> scopes = appProperties.getAzureAd().scopesAsSet();
            if (!scopes.contains("openid")) {
                logger.error("SECURITY: 'openid' scope is required for ID token. Current scopes: {}", scopes);
                response.setStatus(500);
                return;
            }

            String state = UUID.randomUUID().toString();
            authCookieService.setOAuthStateCookie(response, state);

            String codeVerifier = generateCodeVerifier();
            authCookieService.setPkceVerifierCookie(response, codeVerifier);

            String authUrl = tokenExchangeService.generateAuthorizationUrl(
                appProperties.getAzureAd().getRedirectUri(),
                scopes,
                state,
                generateCodeChallenge(codeVerifier));
            response.sendRedirect(authUrl);
        } catch (Exception e) {
            logger.error("Failed to start login redirect", e);
            response.setStatus(500);
        }
    }

    @GetMapping("/callback")
    public void callback(@RequestParam(name = "code", required = false) String code,
                         @RequestParam(name = "state", required = false) String state,
                         @RequestParam(name = "error", required = false) String error,
                         @RequestParam(name = "error_description", required = false) String errorDescription,
                         HttpServletRequest request,
                         HttpServletResponse response) {
        try {
            if (isAuthorizationServerError(error, errorDescription, response)) return;
            if (!isValidCode(code, response)) return;
            if (!isCsrfStateValid(state, request, response)) return;

            String codeVerifier = resolveVerifierAndClearFlowCookies(request, response);
            if (codeVerifier == null) return;

            String idToken = exchangeCodeForIdToken(code, codeVerifier, response);
            if (idToken == null) return;

            authCookieService.setAuthCookie(response, idToken);
            logger.info("Login successful for user, ID token stored in HTTP-only cookie");
            response.sendRedirect(frontendUrl() + "/?login=success");
        } catch (Exception e) {
            logger.error("Callback processing failed", e);
            redirectToErrorPage(response);
        }
    }

    private boolean isAuthorizationServerError(String error, String errorDescription,
                                               HttpServletResponse response) throws IOException {
        if (error == null) return false;
        logger.warn("Authorization error from Azure AD: {} — {}",
                error, errorDescription != null ? URLEncoder.encode(errorDescription, StandardCharsets.UTF_8) : "");
        response.sendRedirect(frontendUrl() + "/?login=error");
        return true;
    }

    private boolean isValidCode(String code, HttpServletResponse response) throws IOException {
        if (code != null && !code.trim().isEmpty() && code.length() <= MAX_AUTHORIZATION_CODE_LENGTH) {
            return true;
        }
        logger.warn("Invalid authorization code received: length={}", code != null ? code.length() : 0);
        response.sendRedirect(frontendUrl() + "/?login=error");
        return false;
    }

    private boolean isCsrfStateValid(String state, HttpServletRequest request,
                                     HttpServletResponse response) throws IOException {
        String expectedState = authCookieService.getOAuthStateCookie(request).orElse(null);
        if (expectedState != null && expectedState.equals(state)) return true;
        logger.warn("OAuth state mismatch — possible CSRF attempt");
        authCookieService.clearOAuthFlowCookies(response);
        response.sendRedirect(frontendUrl() + "/?login=error");
        return false;
    }

    /** Reads the PKCE verifier cookie, clears all OAuth flow cookies, and returns the verifier. */
    private String resolveVerifierAndClearFlowCookies(HttpServletRequest request,
                                                      HttpServletResponse response) throws IOException {
        String codeVerifier = authCookieService.getPkceVerifierCookie(request).orElse(null);
        authCookieService.clearOAuthFlowCookies(response);
        if (codeVerifier == null) {
            logger.error("No PKCE verifier found in cookie");
            response.sendRedirect(frontendUrl() + "/?login=error");
        }
        return codeVerifier;
    }

    private String exchangeCodeForIdToken(String code, String codeVerifier,
                                          HttpServletResponse response) throws Exception {
        IAuthenticationResult result = tokenExchangeService.exchangeAuthorizationCode(
                code, appProperties.getAzureAd().getRedirectUri(),
                appProperties.getAzureAd().scopesAsSet(), codeVerifier);
        // Store the ID token — aud=clientId, suitable for BFF session validation.
        // The access token targets downstream APIs (e.g. Graph) and is never exposed to the browser.
        String idToken = result.idToken();
        if (idToken == null || idToken.isBlank()) {
            logger.error("No ID token in MSAL result — ensure 'openid' scope is requested");
            response.sendRedirect(frontendUrl() + "/?login=error");
            return null;
        }
        return idToken;
    }

    private void redirectToErrorPage(HttpServletResponse response) {
        try {
            response.sendRedirect(frontendUrl() + "/?login=error");
        } catch (IOException e) {
            logger.error("Failed to send error redirect", e);
            response.setStatus(500);
        }
    }

    @PostMapping("/logout")
    public void logout(HttpServletRequest request, HttpServletResponse response) {
        evictTokenCacheForCurrentUser(request);
        authCookieService.clearAuthCookie(response);
        logger.info("User logged out: AUTH_TOKEN cookie cleared and token cache evicted");
    }

    /**
     * Extracts the homeAccountId (oid.tid) from the current AUTH_TOKEN cookie and
     * evicts the corresponding entry from the token cache, immediately invalidating
     * the server-side refresh token on logout.
     */
    private void evictTokenCacheForCurrentUser(HttpServletRequest request) {
        authCookieService.getAuthCookie(request).ifPresent(token -> {
            try {
                Jwt jwt = tokenValidationService.parseToken(token);
                String oid = jwt.getClaimAsString("oid");
                String tid = jwt.getClaimAsString("tid");
                if (oid != null && tid != null) {
                    tokenCacheService.evict(oid + "." + tid);
                }
            } catch (Exception e) {
                logger.debug("Could not extract account ID from token for cache eviction: {}", e.getMessage());
            }
        });
    }

    private String frontendUrl() {
        String[] origins = appProperties.getCors().getAllowedOrigins();
        return (origins != null && origins.length > 0) ? origins[0] : "";
    }

    private String generateCodeVerifier() {
        byte[] bytes = new byte[32];
        new SecureRandom().nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private String generateCodeChallenge(String verifier) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                .digest(verifier.getBytes(StandardCharsets.US_ASCII));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
        } catch (NoSuchAlgorithmException e) {
            // SHA-256 is mandated by the JCA spec; this branch is unreachable in practice.
            throw new IllegalStateException("SHA-256 digest algorithm unavailable", e);
        }
    }
}
