package com.example.msalbff.controller;

import com.example.msalbff.dto.ApiResponse;
import com.example.msalbff.dto.UserInfo;
import com.example.msalbff.service.TokenValidationService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

/**
 * API controller with protected endpoints
 * 
 * This controller demonstrates the secure BFF pattern:
 * - All endpoints require authentication via HTTP-only cookies
 * - JWT tokens are validated by the CookieAuthenticationFilter
 * - User information is extracted from validated JWT tokens
 * - No JWT tokens are exposed to the frontend JavaScript
 */
@RestController
@RequestMapping("/")
@CrossOrigin(origins = "${app.cors.allowed-origins}", allowCredentials = "true")
public class ApiController {

    private static final Logger logger = LoggerFactory.getLogger(ApiController.class);

    private final TokenValidationService tokenValidationService;

    @Autowired
    public ApiController(TokenValidationService tokenValidationService) {
        this.tokenValidationService = tokenValidationService;
    }

    /**
     * Hello World endpoint that returns a greeting for authenticated users
     * 
     * This endpoint demonstrates:
     * - Cookie-based authentication
     * - User information extraction from JWT
     * - Secure API response without exposing tokens
     * 
     * @return Greeting message for the authenticated user
     */
    @GetMapping("/hello")
    public ResponseEntity<ApiResponse<String>> hello() {
        try {
            // Get authentication from security context (set by CookieAuthenticationFilter)
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            
            if (authentication == null || !authentication.isAuthenticated()) {
                logger.warn("Unauthenticated request to /hello endpoint");
                return ResponseEntity.status(401)
                    .body(ApiResponse.error("Authentication required"));
            }

            // Extract user information from authentication
            String username = authentication.getName();
            String greeting = String.format("Hello authenticated user: %s!", username);

            logger.info("Successfully served hello endpoint for user: {}", username);
            return ResponseEntity.ok(ApiResponse.success("Request successful", greeting));

        } catch (Exception e) {
            logger.error("Error processing hello request", e);
            return ResponseEntity.status(500)
                .body(ApiResponse.error("Internal server error"));
        }
    }

    /**
     * User info endpoint that returns detailed user information
     * 
     * @return User information extracted from JWT token
     */
    @GetMapping("/userinfo")
    public ResponseEntity<ApiResponse<UserInfo>> getUserInfo() {
        try {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            
            if (authentication == null || !authentication.isAuthenticated()) {
                return ResponseEntity.status(401)
                    .body(ApiResponse.error("Authentication required"));
            }

            Jwt jwt = (Jwt) authentication.getDetails();
            
            UserInfo userInfo = new UserInfo(
                tokenValidationService.getUserName(jwt),
                tokenValidationService.getUserEmail(jwt),
                jwt.getSubject()
            );

            return ResponseEntity.ok(ApiResponse.success("User information retrieved", userInfo));

        } catch (Exception e) {
            logger.error("Error retrieving user info", e);
            return ResponseEntity.status(500)
                .body(ApiResponse.error("Internal server error"));
        }
    }

    /**
     * Health check endpoint (public, no authentication required)
     */
    @GetMapping("/health")
    public ResponseEntity<ApiResponse<String>> health() {
        return ResponseEntity.ok(ApiResponse.success("Service is healthy", "OK"));
    }
}