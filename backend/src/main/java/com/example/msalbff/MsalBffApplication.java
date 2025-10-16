package com.example.msalbff;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Main application class for MSAL Backend for Frontend (BFF)
 * 
 * This application provides secure token handling for React frontend:
 * - Receives JWT tokens from MSAL frontend
 * - Stores tokens in HTTP-only cookies
 * - Validates tokens for protected endpoints
 * - Prevents XSS attacks by not exposing tokens to JavaScript
 */
@SpringBootApplication
public class MsalBffApplication {

    public static void main(String[] args) {
        SpringApplication.run(MsalBffApplication.class, args);
    }
}