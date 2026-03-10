package com.example.msalbff.controller;

import com.example.msalbff.dto.ApiResponse;
import com.example.msalbff.service.TokenValidationService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * Unit tests for ApiController covering hello, userinfo, and health endpoints.
 */
@ExtendWith(MockitoExtension.class)
class ApiControllerTest {

    @Mock
    private TokenValidationService tokenValidationService;
    @Mock
    private Authentication authentication;
    @Mock
    private SecurityContext securityContext;

    private ApiController controller;

    @BeforeEach
    void setUp() {
        controller = new ApiController(tokenValidationService);
        SecurityContextHolder.setContext(securityContext);
    }

    // ─── /hello ───────────────────────────────────────────────────────────────

    @Test
    void hello_returnsGreeting_forAuthenticatedUser() {
        when(securityContext.getAuthentication()).thenReturn(authentication);
        when(authentication.isAuthenticated()).thenReturn(true);
        when(authentication.getName()).thenReturn("alice@example.com");

        ResponseEntity<ApiResponse<String>> response = controller.hello();

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertTrue(response.getBody().isSuccess());
        assertTrue(response.getBody().getData().contains("alice@example.com"));
    }

    @Test
    void hello_returnsGreeting_withDefaultUsername_whenNameIsNull() {
        when(securityContext.getAuthentication()).thenReturn(authentication);
        when(authentication.isAuthenticated()).thenReturn(true);
        when(authentication.getName()).thenReturn(null);

        ResponseEntity<ApiResponse<String>> response = controller.hello();

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertTrue(response.getBody().getData().contains("User"),
                "Should default to 'User' when name is null");
    }

    @Test
    void hello_returns401_whenNotAuthenticated() {
        when(securityContext.getAuthentication()).thenReturn(authentication);
        when(authentication.isAuthenticated()).thenReturn(false);

        ResponseEntity<ApiResponse<String>> response = controller.hello();

        assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
        assertFalse(response.getBody().isSuccess());
    }

    @Test
    void hello_returns401_whenAuthenticationIsNull() {
        when(securityContext.getAuthentication()).thenReturn(null);

        ResponseEntity<ApiResponse<String>> response = controller.hello();

        assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
    }

    // ─── /userinfo ────────────────────────────────────────────────────────────

    @Test
    void userinfo_returnsUserInfo_fromJwt() {
        Jwt jwt = buildJwt("alice-subject", "Alice", "alice@example.com");
        when(securityContext.getAuthentication()).thenReturn(authentication);
        when(authentication.isAuthenticated()).thenReturn(true);
        when(authentication.getDetails()).thenReturn(jwt);
        when(tokenValidationService.getUserName(jwt)).thenReturn("Alice");
        when(tokenValidationService.getUserEmail(jwt)).thenReturn("alice@example.com");

        ResponseEntity<?> response = controller.getUserInfo();

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertTrue(((ApiResponse<?>) response.getBody()).isSuccess());
    }

    @Test
    void userinfo_returns500_whenDetailsAreNotJwt() {
        when(securityContext.getAuthentication()).thenReturn(authentication);
        when(authentication.isAuthenticated()).thenReturn(true);
        when(authentication.getDetails()).thenReturn("not-a-jwt");
        when(authentication.getName()).thenReturn("alice");

        ResponseEntity<?> response = controller.getUserInfo();

        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
        assertFalse(((ApiResponse<?>) response.getBody()).isSuccess());
    }

    @Test
    void userinfo_returns500_whenDetailsAreNull() {
        when(securityContext.getAuthentication()).thenReturn(authentication);
        when(authentication.isAuthenticated()).thenReturn(true);
        when(authentication.getDetails()).thenReturn(null);
        when(authentication.getName()).thenReturn("alice");

        ResponseEntity<?> response = controller.getUserInfo();

        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
    }

    @Test
    void userinfo_returns401_whenNotAuthenticated() {
        when(securityContext.getAuthentication()).thenReturn(authentication);
        when(authentication.isAuthenticated()).thenReturn(false);

        ResponseEntity<?> response = controller.getUserInfo();

        assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
    }

    // ─── /health ──────────────────────────────────────────────────────────────

    @Test
    void health_returnsOk() {
        ResponseEntity<ApiResponse<String>> response = controller.health();
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertTrue(response.getBody().isSuccess());
        assertEquals("OK", response.getBody().getData());
    }

    // ─── DTO tests ────────────────────────────────────────────────────────────

    @Test
    void apiResponse_successFactory_setsFieldsCorrectly() {
        ApiResponse<String> response = ApiResponse.success("Test message", "Test data");
        assertTrue(response.isSuccess());
        assertEquals("Test message", response.getMessage());
        assertEquals("Test data", response.getData());
    }

    @Test
    void apiResponse_errorFactory_setsFieldsCorrectly() {
        ApiResponse<String> response = ApiResponse.error("Error message");
        assertFalse(response.isSuccess());
        assertEquals("Error message", response.getMessage());
        assertNull(response.getData());
    }

    // ─── Helpers ──────────────────────────────────────────────────────────────

    private Jwt buildJwt(String subject, String name, String email) {
        Map<String, Object> headers = Map.of("alg", "RS256");
        Instant now = Instant.now();
        return new Jwt("dummy.jwt.token", now, now.plus(1, ChronoUnit.HOURS), headers,
                Map.of("sub", subject, "name", name, "email", email,
                        "iss", "https://login.microsoftonline.com/test-tenant/v2.0",
                        "aud", "test-client-id"));
    }
}
