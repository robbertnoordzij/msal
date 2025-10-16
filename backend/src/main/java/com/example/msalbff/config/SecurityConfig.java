package com.example.msalbff.config;

import com.example.msalbff.security.CookieAuthenticationFilter;
import com.example.msalbff.service.TokenValidationService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfigurationSource;

/**
 * Security configuration for the BFF application
 * 
 * Key security features:
 * - Cookie-based authentication using HTTP-only cookies
 * - JWT token validation
 * - CORS configuration for frontend communication  
 * - Stateless session management
 * - Protection against CSRF (via SameSite cookies)
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final CorsConfigurationSource corsConfigurationSource;
    private final TokenValidationService tokenValidationService;
    private final AppProperties appProperties;

    @Autowired
    public SecurityConfig(CorsConfigurationSource corsConfigurationSource, 
                         TokenValidationService tokenValidationService,
                         AppProperties appProperties) {
        this.corsConfigurationSource = corsConfigurationSource;
        this.tokenValidationService = tokenValidationService;
        this.appProperties = appProperties;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            // Enable CORS with our configuration
            .cors(cors -> cors.configurationSource(corsConfigurationSource))
            
            // Disable CSRF as we're using SameSite cookies and stateless authentication
            .csrf(AbstractHttpConfigurer::disable)
            
            // Configure session management to be stateless
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            
            // Configure authorization rules
            .authorizeHttpRequests(authz -> authz
                // Allow authentication endpoints without authentication
                .requestMatchers("/auth/**").permitAll()
                // Allow health endpoint without authentication
                .requestMatchers("/health").permitAll()
                // Require authentication for all other endpoints
                .anyRequest().authenticated()
            )
            
            // Add our custom cookie authentication filter
            .addFilterBefore(cookieAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    /**
     * Custom authentication filter that reads JWT tokens from HTTP-only cookies
     */
    @Bean
    public CookieAuthenticationFilter cookieAuthenticationFilter() {
        return new CookieAuthenticationFilter(tokenValidationService, appProperties);
    }
}