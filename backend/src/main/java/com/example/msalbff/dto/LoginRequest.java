package com.example.msalbff.dto;

import jakarta.validation.constraints.NotBlank;

/**
 * Request DTO for login endpoint
 */
public class LoginRequest {
    
    @NotBlank(message = "Access token is required")
    private String accessToken;

    public LoginRequest() {}

    public LoginRequest(String accessToken) {
        this.accessToken = accessToken;
    }

    public String getAccessToken() {
        return accessToken;
    }

    public void setAccessToken(String accessToken) {
        this.accessToken = accessToken;
    }
}