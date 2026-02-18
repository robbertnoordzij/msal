package com.example.msalbff.security;

import com.example.msalbff.config.AppProperties;
import com.example.msalbff.service.TokenValidationService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;

import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.ArrayList;

/**
 * Custom authentication filter that reads JWT tokens from HTTP-only cookies
 * 
 * This filter:
 * - Extracts JWT tokens from HTTP-only cookies
 * - Validates tokens using Azure AD
 * - Sets authentication context for Spring Security
 * - Provides protection against XSS attacks (tokens not accessible to JavaScript)
 */
public class CookieAuthenticationFilter extends OncePerRequestFilter {

    private final TokenValidationService tokenValidationService;
    private final AppProperties appProperties;

    public CookieAuthenticationFilter(TokenValidationService tokenValidationService, 
                                    AppProperties appProperties) {
        this.tokenValidationService = tokenValidationService;
        this.appProperties = appProperties;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, 
                                  HttpServletResponse response, 
                                  FilterChain filterChain) throws ServletException, IOException {
        
        // Skip authentication for auth endpoints
        if (request.getRequestURI().startsWith("/api/auth/")) {
            filterChain.doFilter(request, response);
            return;
        }

        // Extract JWT token from cookie
        String token = extractTokenFromCookie(request);
        
        if (token != null && tokenValidationService.validateToken(token)) {
            try {
                // Parse the JWT to get user information
                org.springframework.security.oauth2.jwt.Jwt jwt = tokenValidationService.parseToken(token);
                String username = tokenValidationService.getUserName(jwt);
                
                UsernamePasswordAuthenticationToken authentication = 
                    new UsernamePasswordAuthenticationToken(
                        username, 
                        null, 
                        new ArrayList<>() // No authorities for now
                    );
                
                // Add token as details for potential use in controllers
                authentication.setDetails(token);
                
                // Set authentication in security context
                SecurityContextHolder.getContext().setAuthentication(authentication);
                
                System.out.println("✅ Authentication set for user: " + username);
                
            } catch (Exception e) {
                System.err.println("❌ Error setting authentication: " + e.getMessage());
                // Clear any existing authentication on error
                SecurityContextHolder.clearContext();
            }
        } else {
            System.out.println("❌ No valid token found in cookie");
        }

        filterChain.doFilter(request, response);
    }

    /**
     * Extracts JWT token from HTTP-only cookie
     */
    private String extractTokenFromCookie(HttpServletRequest request) {
        if (request.getCookies() == null) {
            return null;
        }

        for (Cookie cookie : request.getCookies()) {
            if (appProperties.getCookie().getName().equals(cookie.getName())) {
                return cookie.getValue();
            }
        }
        
        return null;
    }
}