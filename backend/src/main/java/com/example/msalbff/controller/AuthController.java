package com.example.msalbff.controller;

import com.example.msalbff.config.AppProperties;
import com.example.msalbff.service.AuthCookieService;
import com.example.msalbff.service.TokenExchangeService;
import com.microsoft.aad.msal4j.IAuthenticationResult;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.*;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.UUID;

@RestController
@RequestMapping("/auth")
@CrossOrigin(origins = "${app.cors.allowed-origins}", allowCredentials = "true")
public class AuthController {

    private static final Logger logger = LoggerFactory.getLogger(AuthController.class);

    private final TokenExchangeService tokenExchangeService;
    private final AuthCookieService authCookieService;
    private final AppProperties appProperties;

    public AuthController(TokenExchangeService tokenExchangeService,
                          AuthCookieService authCookieService,
                          AppProperties appProperties) {
        this.tokenExchangeService = tokenExchangeService;
        this.authCookieService = authCookieService;
        this.appProperties = appProperties;
    }

    @GetMapping("/login")
    public void startLogin(HttpSession session, HttpServletResponse response) {
        try {
            String state = UUID.randomUUID().toString();
            session.setAttribute("oauth_state", state);

            String codeVerifier = generateCodeVerifier();
            session.setAttribute("pkce_verifier", codeVerifier);

            String authUrl = tokenExchangeService.generateAuthorizationUrl(
                appProperties.getAzureAd().getRedirectUri(),
                appProperties.getAzureAd().scopesAsSet(),
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
                         HttpSession session,
                         HttpServletResponse response) {
        String frontend = frontendUrl();
        try {
            if (error != null) {
                logger.warn("Authorization error from Azure AD: {} — {}",
                    error, errorDescription != null ? URLEncoder.encode(errorDescription, StandardCharsets.UTF_8) : "");
                response.sendRedirect(frontend + "/?login=error");
                return;
            }
            if (code == null || code.isEmpty()) {
                logger.warn("Callback received without authorization code");
                response.sendRedirect(frontend + "/?login=error");
                return;
            }

            String expectedState = (String) session.getAttribute("oauth_state");
            if (expectedState == null || !expectedState.equals(state)) {
                logger.warn("OAuth state mismatch — possible CSRF attempt");
                response.sendRedirect(frontend + "/?login=error");
                return;
            }
            session.removeAttribute("oauth_state");

            String codeVerifier = (String) session.getAttribute("pkce_verifier");
            if (codeVerifier == null) {
                logger.error("No PKCE verifier found in session");
                response.sendRedirect(frontend + "/?login=error");
                return;
            }
            session.removeAttribute("pkce_verifier");

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
            session.setAttribute("msal_account_id", result.account().homeAccountId());

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
    public void logout(HttpSession session, HttpServletResponse response) {
        session.invalidate();
        authCookieService.clearAuthCookie(response);
        logger.info("User logged out, AUTH_TOKEN cookie cleared");
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
