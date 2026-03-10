package com.example.msalbff.security;

import com.example.msalbff.config.AppProperties;
import com.example.msalbff.service.TokenValidationService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

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

    private static final Logger logger = LoggerFactory.getLogger(CookieAuthenticationFilter.class);

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
                Jwt jwt = tokenValidationService.parseToken(token);
                String username = tokenValidationService.getUserName(jwt);
                Collection<GrantedAuthority> authorities = extractAuthorities(jwt);

                UsernamePasswordAuthenticationToken authentication =
                    new UsernamePasswordAuthenticationToken(username, null, authorities);
                authentication.setDetails(jwt);

                SecurityContextHolder.getContext().setAuthentication(authentication);
                logger.debug("Authenticated user: {}", username);

            } catch (Exception e) {
                logger.error("Failed to set authentication from token", e);
                SecurityContextHolder.clearContext();
            }
        } else if (token != null) {
            logger.debug("Token present but invalid — clearing context");
        }

        filterChain.doFilter(request, response);
    }

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

    private Collection<GrantedAuthority> extractAuthorities(Jwt jwt) {
        List<String> roles = jwt.getClaimAsStringList("roles");
        if (roles == null) {
            return Collections.emptyList();
        }
        return roles.stream()
            .map(role -> new SimpleGrantedAuthority("ROLE_" + role.toUpperCase()))
            .collect(Collectors.toList());
    }
}