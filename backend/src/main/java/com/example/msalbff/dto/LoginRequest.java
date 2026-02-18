package com.example.msalbff.dto;

import jakarta.validation.constraints.NotBlank;

/**
 * Request DTO for login endpoint
 */
public class LoginRequest {
    
    @NotBlank(message = "Access token is required")
    private String accessToken;

    private String refreshToken;

    public LoginRequest() {}

    public LoginRequest(String accessToken) {
        this.accessToken = accessToken;
    }

    public LoginRequest(String accessToken, String refreshToken) {
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
    }

    public String getAccessToken() {
        return accessToken;
    }

    public void setAccessToken(String accessToken) {
        this.accessToken = accessToken;
    }

    public String getRefreshToken() {
        return refreshToken;
    }

    public void setRefreshToken(String refreshToken) {
        this.refreshToken = refreshToken;
    }
}