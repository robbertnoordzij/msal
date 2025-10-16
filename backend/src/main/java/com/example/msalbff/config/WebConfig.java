package com.example.msalbff.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import java.util.Arrays;

/**
 * Web configuration for CORS and other web-related settings
 */
@Configuration
public class WebConfig implements WebMvcConfigurer {

    private final AppProperties appProperties;

    @Autowired
    public WebConfig(AppProperties appProperties) {
        this.appProperties = appProperties;
    }

    /**
     * Configure CORS to allow frontend communication
     * This is crucial for the BFF pattern where frontend and backend are on different ports
     */
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        
        // Allow specific origins (frontend URL)
        configuration.setAllowedOriginPatterns(Arrays.asList(appProperties.getCors().getAllowedOrigins()));
        
        // Allow specific HTTP methods
        configuration.setAllowedMethods(Arrays.asList(appProperties.getCors().getAllowedMethods()));
        
        // Allow all headers for simplicity (can be restricted in production)
        configuration.setAllowedHeaders(Arrays.asList(appProperties.getCors().getAllowedHeaders()));
        
        // Allow credentials (cookies) to be sent
        configuration.setAllowCredentials(appProperties.getCors().isAllowCredentials());
        
        // Apply CORS configuration to all endpoints
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        
        return source;
    }
}