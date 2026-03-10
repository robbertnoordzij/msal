package com.example.msalbff.service;

import com.example.msalbff.config.AppProperties;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Service;

/**
 * Centralises all AUTH_TOKEN cookie operations so that cookie attributes
 * (HttpOnly, Secure, SameSite, path, maxAge) are configured in one place.
 */
@Service
public class AuthCookieService {

    private final AppProperties appProperties;

    public AuthCookieService(AppProperties appProperties) {
        this.appProperties = appProperties;
    }

    /** Writes a new AUTH_TOKEN cookie containing the given ID token. */
    public void setAuthCookie(HttpServletResponse response, String idToken) {
        response.addHeader(HttpHeaders.SET_COOKIE,
                buildCookie(idToken, appProperties.getCookie().getMaxAge()).toString());
    }

    /** Expires the AUTH_TOKEN cookie, causing the browser to delete it. */
    public void clearAuthCookie(HttpServletResponse response) {
        response.addHeader(HttpHeaders.SET_COOKIE, buildCookie("", 0).toString());
    }

    private ResponseCookie buildCookie(String value, long maxAge) {
        AppProperties.Cookie config = appProperties.getCookie();
        return ResponseCookie.from(config.getName(), value)
                .httpOnly(config.isHttpOnly())
                .secure(config.isSecure())
                .path("/")
                .maxAge(maxAge)
                .sameSite(config.getSameSite())
                .build();
    }
}
