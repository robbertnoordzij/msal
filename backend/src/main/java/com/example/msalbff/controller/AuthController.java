package com.example.msalbff.controller;

import com.example.msalbff.config.AppProperties;
import com.example.msalbff.dto.ApiResponse;
import com.example.msalbff.dto.LoginRequest;
import com.example.msalbff.service.TokenValidationService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

/**
 * Authentication controller handling login/logout operations
 * 
 * This controller implements the secure token handling pattern:
 * 1. Receives JWT tokens from MSAL frontend
 * 2. Validates tokens using Azure AD
 * 3. Stores tokens in HTTP-only, secure cookies
 * 4. Provides logout functionality to clear cookies
 */
@RestController
@RequestMapping("/auth")
@CrossOrigin(origins = "${app.cors.allowed-origins}", allowCredentials = "true")
public class AuthController {

    private static final Logger logger = LoggerFactory.getLogger(AuthController.class);

    private final TokenValidationService tokenValidationService;
    private final AppProperties appProperties;

    @Autowired
    public AuthController(TokenValidationService tokenValidationService, 
                         AppProperties appProperties) {
        this.tokenValidationService = tokenValidationService;
        this.appProperties = appProperties;
    }

    /**
     * Login endpoint that receives JWT token from frontend and sets it in HTTP-only cookie
     * 
     * @param loginRequest Contains the JWT access token from MSAL
     * @param response HTTP response to set cookie
     * @return Success/error response
     */
    @PostMapping("/login")
    public ResponseEntity<ApiResponse<Void>> login(@Valid @RequestBody LoginRequest loginRequest, 
                                                  HttpServletResponse response) {
        try {
            String accessToken = loginRequest.getAccessToken();
            
            // Validate the JWT token
            if (!tokenValidationService.validateToken(accessToken)) {
                logger.warn("Invalid JWT token received in login request");
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(ApiResponse.error("Invalid access token"));
            }

            // Create HTTP-only cookie with the JWT token
            Cookie authCookie = createAuthCookie(accessToken);
            response.addCookie(authCookie);

            logger.info("Successfully set authentication cookie for user");
            return ResponseEntity.ok(ApiResponse.success("Authentication token set successfully"));

        } catch (Exception e) {
            logger.error("Error during login process", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(ApiResponse.error("Login failed: " + e.getMessage()));
        }
    }

    /**
     * Logout endpoint that clears the authentication cookie
     * 
     * @param response HTTP response to clear cookie
     * @return Success response
     */
    @PostMapping("/logout")
    public ResponseEntity<ApiResponse<Void>> logout(HttpServletResponse response) {
        try {
            // Create expired cookie to clear the authentication
            Cookie expiredCookie = createExpiredAuthCookie();
            response.addCookie(expiredCookie);

            logger.info("Successfully cleared authentication cookie");
            return ResponseEntity.ok(ApiResponse.success("Logged out successfully"));

        } catch (Exception e) {
            logger.error("Error during logout process", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(ApiResponse.error("Logout failed: " + e.getMessage()));
        }
    }

    /**
     * Creates a secure HTTP-only cookie with the JWT token
     */
    private Cookie createAuthCookie(String token) {
        Cookie cookie = new Cookie(appProperties.getCookie().getName(), token);
        cookie.setHttpOnly(appProperties.getCookie().isHttpOnly());
        cookie.setSecure(appProperties.getCookie().isSecure());
        cookie.setPath("/");
        cookie.setMaxAge(appProperties.getCookie().getMaxAge());
        
        // Note: SameSite attribute is not directly supported in Jakarta Servlet API
        // It should be configured at the server level or using response headers
        
        return cookie;
    }

    /**
     * Creates an expired cookie to clear authentication
     */
    private Cookie createExpiredAuthCookie() {
        Cookie cookie = new Cookie(appProperties.getCookie().getName(), "");
        cookie.setHttpOnly(appProperties.getCookie().isHttpOnly());
        cookie.setSecure(appProperties.getCookie().isSecure());
        cookie.setPath("/");
        cookie.setMaxAge(0); // Expire immediately
        
        return cookie;
    }
}