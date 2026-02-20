package com.example.msalbff.security;

import com.example.msalbff.config.AppProperties;
import com.example.msalbff.service.TokenValidationService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class CookieAuthenticationFilterTest {

    @Mock
    private TokenValidationService tokenValidationService;

    @Mock
    private AppProperties appProperties;

    @Mock
    private AppProperties.Cookie cookieProperties;

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    @Mock
    private FilterChain filterChain;

    @Mock
    private Jwt jwt;

    private CookieAuthenticationFilter filter;

    @BeforeEach
    public void setup() {
        SecurityContextHolder.clearContext();
        lenient().when(appProperties.getCookie()).thenReturn(cookieProperties);
        lenient().when(cookieProperties.getName()).thenReturn("AUTH_TOKEN");
        filter = new CookieAuthenticationFilter(tokenValidationService, appProperties);
    }

    @Test
    public void testDoFilterInternal_WithValidToken() throws Exception {
        // Arrange
        Cookie authCookie = new Cookie("AUTH_TOKEN", "valid-token");
        when(request.getCookies()).thenReturn(new Cookie[]{authCookie});
        when(request.getRequestURI()).thenReturn("/api/hello");
        when(tokenValidationService.validateToken("valid-token")).thenReturn(true);
        when(tokenValidationService.parseToken("valid-token")).thenReturn(jwt);
        when(tokenValidationService.getUserName(jwt)).thenReturn("real-user@example.com");

        // Act
        filter.doFilter(request, response, filterChain);

        // Assert
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        assertNotNull(auth);
        assertEquals("real-user@example.com", auth.getName());
        assertSame(jwt, auth.getDetails());
        verify(filterChain).doFilter(request, response);
    }

    @Test
    public void testDoFilterInternal_WithInvalidToken() throws Exception {
        // Arrange
        Cookie authCookie = new Cookie("AUTH_TOKEN", "invalid-token");
        when(request.getCookies()).thenReturn(new Cookie[]{authCookie});
        when(request.getRequestURI()).thenReturn("/api/hello");
        when(tokenValidationService.validateToken("invalid-token")).thenReturn(false);

        // Act
        filter.doFilter(request, response, filterChain);

        // Assert
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        assertNull(auth);
        verify(filterChain).doFilter(request, response);
    }

    @Test
    public void testDoFilterInternal_SkipAuthEndpoint() throws Exception {
        // Arrange
        when(request.getRequestURI()).thenReturn("/api/auth/login");

        // Act
        filter.doFilter(request, response, filterChain);

        // Assert
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        assertNull(auth);
        verify(filterChain).doFilter(request, response);
        verifyNoInteractions(tokenValidationService);
    }
}
