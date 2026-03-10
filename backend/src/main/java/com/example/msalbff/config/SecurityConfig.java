package com.example.msalbff.config;

import com.example.msalbff.security.CookieAuthenticationFilter;
import com.example.msalbff.service.AuthCookieService;
import com.example.msalbff.service.TokenExchangeService;
import com.example.msalbff.service.TokenValidationService;
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
 * Security configuration for the BFF application.
 *
 * <p>Key security features:
 * <ul>
 *   <li>Cookie-based authentication using HTTP-only cookies with SameSite protection</li>
 *   <li>JWT token validation against Azure AD</li>
 *   <li>CORS configuration for frontend communication</li>
 *   <li>CSRF disabled — SameSite=Strict cookies provide equivalent protection</li>
 * </ul>
 *
 * <p>Note: {@link SessionCreationPolicy#STATELESS} prevents Spring Security from creating
 * sessions. The application itself still uses container-managed sessions to store PKCE
 * verifiers and MSAL account identifiers during the OAuth flow.
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final CorsConfigurationSource corsConfigurationSource;
    private final TokenValidationService tokenValidationService;
    private final TokenExchangeService tokenExchangeService;
    private final AuthCookieService authCookieService;
    private final AppProperties appProperties;

    public SecurityConfig(CorsConfigurationSource corsConfigurationSource,
                         TokenValidationService tokenValidationService,
                         TokenExchangeService tokenExchangeService,
                         AuthCookieService authCookieService,
                         AppProperties appProperties) {
        this.corsConfigurationSource = corsConfigurationSource;
        this.tokenValidationService = tokenValidationService;
        this.tokenExchangeService = tokenExchangeService;
        this.authCookieService = authCookieService;
        this.appProperties = appProperties;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .cors(cors -> cors.configurationSource(corsConfigurationSource))
            .csrf(AbstractHttpConfigurer::disable)
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .headers(headers -> headers
                .frameOptions(frameOptions -> frameOptions.deny())
                .contentTypeOptions(contentTypeOptions -> {})
                .httpStrictTransportSecurity(hsts -> hsts
                    .includeSubDomains(true)
                    .maxAgeInSeconds(31536000))
            )
            .authorizeHttpRequests(authz -> authz
                .requestMatchers("/auth/**").permitAll()
                .requestMatchers("/health").permitAll()
                .anyRequest().authenticated()
            )
            .addFilterBefore(cookieAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    public CookieAuthenticationFilter cookieAuthenticationFilter() {
        return new CookieAuthenticationFilter(tokenValidationService, tokenExchangeService, authCookieService, appProperties);
    }
}