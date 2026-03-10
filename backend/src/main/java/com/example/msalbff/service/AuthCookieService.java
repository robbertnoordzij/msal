package com.example.msalbff.service;

import com.example.msalbff.config.AppProperties;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Service;

/**
 * Centralises all cookie operations so that cookie attributes
 * (HttpOnly, Secure, SameSite, path, maxAge) are configured in one place.
 *
 * <p>Manages two categories of cookies:
 * <ul>
 *   <li><b>AUTH_TOKEN</b> — long-lived HTTP-only cookie holding the user's ID token.</li>
 *   <li><b>OAUTH_STATE / PKCE_VERIFIER</b> — short-lived HTTP-only cookies used during
 *       the OAuth 2.0 / PKCE login flow. They must use {@code SameSite=Lax} so that they
 *       are included in the cross-site top-level redirect from Azure AD back to
 *       {@code /auth/callback}.</li>
 * </ul>
 */
@Service
public class AuthCookieService {

    static final String OAUTH_STATE_COOKIE = "OAUTH_STATE";
    static final String PKCE_VERIFIER_COOKIE = "PKCE_VERIFIER";
    private static final int OAUTH_FLOW_MAX_AGE_SECONDS = 300; // 5 minutes

    private final AppProperties appProperties;

    public AuthCookieService(AppProperties appProperties) {
        this.appProperties = appProperties;
    }

    /** Writes a new AUTH_TOKEN cookie containing the given ID token. */
    public void setAuthCookie(HttpServletResponse response, String idToken) {
        response.addHeader(HttpHeaders.SET_COOKIE,
                buildAuthCookie(idToken, appProperties.getCookie().getMaxAge()).toString());
    }

    /** Expires the AUTH_TOKEN cookie, causing the browser to delete it. */
    public void clearAuthCookie(HttpServletResponse response) {
        response.addHeader(HttpHeaders.SET_COOKIE, buildAuthCookie("", 0).toString());
    }

    /** Sets a short-lived cookie carrying the OAuth state parameter for CSRF protection. */
    public void setOAuthStateCookie(HttpServletResponse response, String state) {
        response.addHeader(HttpHeaders.SET_COOKIE,
                buildOAuthFlowCookie(OAUTH_STATE_COOKIE, state, OAUTH_FLOW_MAX_AGE_SECONDS).toString());
    }

    /** Sets a short-lived cookie carrying the PKCE code verifier. */
    public void setPkceVerifierCookie(HttpServletResponse response, String verifier) {
        response.addHeader(HttpHeaders.SET_COOKIE,
                buildOAuthFlowCookie(PKCE_VERIFIER_COOKIE, verifier, OAUTH_FLOW_MAX_AGE_SECONDS).toString());
    }

    /** Returns the OAuth state value from the request cookies, or {@code null} if absent. */
    public String getOAuthStateCookie(HttpServletRequest request) {
        return getCookieValue(request, OAUTH_STATE_COOKIE);
    }

    /** Returns the PKCE verifier value from the request cookies, or {@code null} if absent. */
    public String getPkceVerifierCookie(HttpServletRequest request) {
        return getCookieValue(request, PKCE_VERIFIER_COOKIE);
    }

    /** Expires both OAuth flow cookies. Should be called after the callback is processed. */
    public void clearOAuthFlowCookies(HttpServletResponse response) {
        response.addHeader(HttpHeaders.SET_COOKIE,
                buildOAuthFlowCookie(OAUTH_STATE_COOKIE, "", 0).toString());
        response.addHeader(HttpHeaders.SET_COOKIE,
                buildOAuthFlowCookie(PKCE_VERIFIER_COOKIE, "", 0).toString());
    }

    private ResponseCookie buildAuthCookie(String value, long maxAge) {
        AppProperties.Cookie config = appProperties.getCookie();
        return ResponseCookie.from(config.getName(), value)
                .httpOnly(config.isHttpOnly())
                .secure(config.isSecure())
                .path("/")
                .maxAge(maxAge)
                .sameSite(config.getSameSite())
                .build();
    }

    private ResponseCookie buildOAuthFlowCookie(String name, String value, long maxAge) {
        return ResponseCookie.from(name, value)
                .httpOnly(true)
                .secure(appProperties.getCookie().isSecure())
                .path("/")
                .maxAge(maxAge)
                .sameSite("Lax") // Must be Lax: Strict would block the cross-site redirect from Azure AD
                .build();
    }

    private String getCookieValue(HttpServletRequest request, String name) {
        Cookie[] cookies = request.getCookies();
        if (cookies == null) {
            return null;
        }
        for (Cookie cookie : cookies) {
            if (name.equals(cookie.getName())) {
                return cookie.getValue();
            }
        }
        return null;
    }
}
