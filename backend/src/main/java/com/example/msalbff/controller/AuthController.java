package com.example.msalbff.controller;

import com.example.msalbff.config.AppProperties;
import com.example.msalbff.service.TokenExchangeService;
import com.microsoft.aad.msal4j.IAuthenticationResult;
import jakarta.servlet.http.Cookie;
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
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

@RestController
@RequestMapping("/auth")
@CrossOrigin(origins = "${app.cors.allowed-origins}", allowCredentials = "true")
public class AuthController {

    private static final Logger logger = LoggerFactory.getLogger(com.example.msalbff.controller.AuthController.class);

    private final TokenExchangeService tokenExchangeService;
    private final AppProperties appProperties;

    public AuthController(TokenExchangeService tokenExchangeService, AppProperties appProperties) {
        this.tokenExchangeService = tokenExchangeService;
        this.appProperties = appProperties;
    }

    @GetMapping("/login")
    public void startLogin(HttpSession session, HttpServletResponse response) {
        try {
            String redirectUri = "http://localhost:3000/api/auth/callback";
            Set<String> scopes = Set.of("openid", "profile", "User.Read");
            String state = "bff"; // simplistic state; in production, persist and validate per user session

            // Generate PKCE verifier and challenge
            String codeVerifier = generateCodeVerifier();
            String codeChallenge = generateCodeChallenge(codeVerifier);

            // Store code verifier in session
            session.setAttribute("pkce_verifier", codeVerifier);

            String authUrl = tokenExchangeService.generateAuthorizationUrl(redirectUri, scopes, state, codeChallenge);
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
        String[] origins = appProperties.getCors().getAllowedOrigins();
        String frontend = (origins != null && origins.length > 0) ? origins[0] : "/";
        try {
            if (error != null) {
                String desc = errorDescription != null ? URLEncoder.encode(errorDescription, StandardCharsets.UTF_8) : "";
                logger.warn("Authorization error: {} - {}", error, desc);
                response.sendRedirect(frontend + "/?login=error");
                return;
            }
            if (code == null || code.isEmpty()) {
                response.sendRedirect(frontend + "/?login=error");
                return;
            }

            String redirectUri = "http://localhost:3000/api/auth/callback";
            Set<String> scopes = Set.of("openid", "profile", "User.Read");

            // Retrieve PKCE verifier from session
            String codeVerifier = (String) session.getAttribute("pkce_verifier");
            if (codeVerifier == null) {
                logger.error("No PKCE verifier found in session");
                response.sendRedirect(frontend + "/?login=error");
                return;
            }
            session.removeAttribute("pkce_verifier");

            IAuthenticationResult result = tokenExchangeService.exchangeAuthorizationCode(code, redirectUri, scopes, codeVerifier);

            // Set cookies
            addCookie(response, appProperties.getCookie().getName(), result.accessToken(), appProperties.getCookie().getMaxAge());

            logger.info("Login successful, tokens stored in HTTP-only cookies");
            response.sendRedirect(frontend + "/?login=success");
        } catch (Exception e) {
            logger.error("Callback processing failed", e);
            try {
                response.sendRedirect(frontend + "/?login=error");
            } catch (Exception ignored) {
                response.setStatus(500);
            }
        }
    }

    private void addCookie(HttpServletResponse response, String name, String value, int maxAge) {
        Cookie cookie = new Cookie(name, value);
        cookie.setHttpOnly(appProperties.getCookie().isHttpOnly());
        cookie.setSecure(appProperties.getCookie().isSecure());
        cookie.setPath("/");
        cookie.setMaxAge(maxAge);
        response.addCookie(cookie);
    }

    private String generateCodeVerifier() {
        SecureRandom secureRandom = new SecureRandom();
        byte[] codeVerifier = new byte[32];
        secureRandom.nextBytes(codeVerifier);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(codeVerifier);
    }

    private String generateCodeChallenge(String verifier) throws Exception {
        byte[] bytes = verifier.getBytes(StandardCharsets.US_ASCII);
        MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
        byte[] digest = messageDigest.digest(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
    }
}
