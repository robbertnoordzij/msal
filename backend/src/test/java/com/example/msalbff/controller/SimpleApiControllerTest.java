package com.example.msalbff.controller;

import com.example.msalbff.dto.ApiResponse;
import com.example.msalbff.service.TokenValidationService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.boot.test.context.SpringBootTest;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for API controller
 */
@ExtendWith(MockitoExtension.class)
@SpringBootTest(properties = {
    "app.azure-ad.tenant-id=test-tenant-id",
    "app.azure-ad.client-id=test-client-id",
    "app.azure-ad.client-secret=test-secret",
    "app.azure-ad.authority=https://login.microsoftonline.com/test-tenant-id",
    "app.azure-ad.jwk-set-uri=https://login.microsoftonline.com/test-tenant-id/discovery/v2.0/keys",
    "app.azure-ad.redirect-uri=http://localhost:8080/api/auth/callback"
})
public class SimpleApiControllerTest {

    @Mock
    private TokenValidationService tokenValidationService;

    @Test
    public void testApiControllerCreation() {
        ApiController controller = new ApiController(tokenValidationService);
        assertNotNull(controller);
    }

    @Test
    public void testApiResponseCreation() {
        ApiResponse<String> response = ApiResponse.success("Test message", "Test data");
        assertTrue(response.isSuccess());
        assertEquals("Test message", response.getMessage());
        assertEquals("Test data", response.getData());
    }

    @Test
    public void testApiResponseError() {
        ApiResponse<String> response = ApiResponse.error("Error message");
        assertFalse(response.isSuccess());
        assertEquals("Error message", response.getMessage());
        assertNull(response.getData());
    }
}