package com.example.msalbff.controller;

import com.example.msalbff.config.AppProperties;
import com.example.msalbff.service.AuthCookieService;
import com.example.msalbff.service.RedisMsalTokenCache;
import com.example.msalbff.service.TokenExchangeService;
import com.example.msalbff.service.TokenValidationService;
import com.microsoft.aad.msal4j.IAuthenticationResult;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Set;
import java.util.UUID;

@RestController
@RequestMapping("/auth")
@CrossOrigin(origins = "${app.cors.allowed-origins}", allowCredentials = "true")
public class AuthController {

    private static final Logger logger = LoggerFactory.getLogger(AuthController.class);

    private final TokenExchangeService tokenExchangeService;
    private final TokenValidationService tokenValidationService;
    private final AuthCookieService authCookieService;
    private final RedisMsalTokenCache redisMsalTokenCache;
    private final AppProperties appProperties;

    public AuthController(TokenExchangeService tokenExchangeService,
                          TokenValidationService tokenValidationService,
                          AuthCookieService authCookieService,
                          RedisMsalTokenCache redisMsalTokenCache,
                          AppProperties appProperties) {
        this.tokenExchangeService = tokenExchangeService;
        this.tokenValidationService = tokenValidationService;
        this.authCookieService = authCookieService;
        this.redisMsalTokenCache = redisMsalTokenCache;
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
        String frontend = frontendUrl();
        try {
            if (error != null) {
                logger.warn("Authorization error from Azure AD: {} — {}",
                    error, errorDescription != null ? URLEncoder.encode(errorDescription, StandardCharsets.UTF_8) : "");
                response.sendRedirect(frontend + "/?login=error");
                return;
            }
            if (code == null || code.trim().isEmpty() || code.length() > 1000) {
                logger.warn("Invalid authorization code received: length={}", code != null ? code.length() : 0);
                response.sendRedirect(frontend + "/?login=error");
                return;
            }

            String expectedState = authCookieService.getOAuthStateCookie(request);
            if (expectedState == null || !expectedState.equals(state)) {
                logger.warn("OAuth state mismatch — possible CSRF attempt");
                authCookieService.clearOAuthFlowCookies(response);
                response.sendRedirect(frontend + "/?login=error");
                return;
            }

            String codeVerifier = authCookieService.getPkceVerifierCookie(request);
            if (codeVerifier == null) {
                logger.error("No PKCE verifier found in cookie");
                authCookieService.clearOAuthFlowCookies(response);
                response.sendRedirect(frontend + "/?login=error");
                return;
            }

            authCookieService.clearOAuthFlowCookies(response);

            IAuthenticationResult result = tokenExchangeService.exchangeAuthorizationCode(
                code, appProperties.getAzureAd().getRedirectUri(), appProperties.getAzureAd().scopesAsSet(), codeVerifier);

            // Store the ID token — aud=clientId, suitable for BFF session validation.
            // The access token targets downstream APIs (e.g. Graph) and is never exposed to the browser.
            String idToken = result.idToken();
            if (idToken == null || idToken.isBlank()) {
                logger.error("No ID token in MSAL result — ensure 'openid' scope is requested");
                response.sendRedirect(frontend + "/?login=error");
                return;
            }
            authCookieService.setAuthCookie(response, idToken);

            // No server-side state needed: the MSAL account ID for silent refresh is
            // derived from the oid/tid claims embedded in the AUTH_TOKEN cookie itself.

            logger.info("Login successful for user, ID token stored in HTTP-only cookie");
            response.sendRedirect(frontend + "/?login=success");
        } catch (Exception e) {
            logger.error("Callback processing failed", e);
            try {
                response.sendRedirect(frontend + "/?login=error");
            } catch (Exception sendError) {
                logger.error("Failed to send error redirect", sendError);
                response.setStatus(500);
            }
        }
    }

    @PostMapping("/logout")
    public void logout(HttpServletRequest request, HttpServletResponse response) {
        evictTokenCacheForCurrentUser(request);
        authCookieService.clearAuthCookie(response);
        logger.info("User logged out: AUTH_TOKEN cookie cleared and Redis cache evicted");
    }

    /**
     * Extracts the homeAccountId (oid.tid) from the current AUTH_TOKEN cookie and
     * evicts the corresponding entry from the Redis token cache, immediately invalidating
     * the server-side refresh token on logout.
     */
    private void evictTokenCacheForCurrentUser(HttpServletRequest request) {
        String token = extractTokenFromCookie(request);
        if (token == null) {
            return;
        }
        try {
            Jwt jwt = tokenValidationService.parseToken(token);
            String oid = jwt.getClaimAsString("oid");
            String tid = jwt.getClaimAsString("tid");
            if (oid != null && tid != null) {
                redisMsalTokenCache.evict(oid + "." + tid);
            }
        } catch (Exception e) {
            logger.debug("Could not extract account ID from token for cache eviction: {}", e.getMessage());
        }
    }

    private String extractTokenFromCookie(HttpServletRequest request) {
        if (request.getCookies() == null) {
            return null;
        }
        String cookieName = appProperties.getCookie().getName();
        for (Cookie cookie : request.getCookies()) {
            if (cookieName.equals(cookie.getName())) {
                return cookie.getValue();
            }
        }
        return null;
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

    private String generateCodeChallenge(String verifier) throws Exception {
        byte[] digest = MessageDigest.getInstance("SHA-256")
            .digest(verifier.getBytes(StandardCharsets.US_ASCII));
        return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
    }
}
