package com.example.msalbff.service;

import com.example.msalbff.config.AppProperties;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Service;

import java.util.Arrays;
import java.util.Optional;

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
        if (idToken == null || idToken.isBlank()) {
            throw new IllegalArgumentException("ID token cannot be null or empty");
        }
        response.addHeader(HttpHeaders.SET_COOKIE,
                buildAuthCookie(idToken, appProperties.getCookie().getMaxAge()).toString());
    }

    /** Expires the AUTH_TOKEN cookie, causing the browser to delete it. */
    public void clearAuthCookie(HttpServletResponse response) {
        response.addHeader(HttpHeaders.SET_COOKIE, buildAuthCookie("", 0).toString());
    }

    /** Sets a short-lived cookie carrying the OAuth state parameter for CSRF protection. */
    public void setOAuthStateCookie(HttpServletResponse response, String state) {
        if (state == null || state.isBlank()) {
            throw new IllegalArgumentException("OAuth state cannot be null or empty");
        }
        response.addHeader(HttpHeaders.SET_COOKIE,
                buildOAuthFlowCookie(OAUTH_STATE_COOKIE, state, OAUTH_FLOW_MAX_AGE_SECONDS).toString());
    }

    /** Sets a short-lived cookie carrying the PKCE code verifier. */
    public void setPkceVerifierCookie(HttpServletResponse response, String verifier) {
        if (verifier == null || verifier.isBlank()) {
            throw new IllegalArgumentException("PKCE verifier cannot be null or empty");
        }
        response.addHeader(HttpHeaders.SET_COOKIE,
                buildOAuthFlowCookie(PKCE_VERIFIER_COOKIE, verifier, OAUTH_FLOW_MAX_AGE_SECONDS).toString());
    }

    /** Returns the AUTH_TOKEN value from the request cookies, or empty if absent. */
    public Optional<String> getAuthCookie(HttpServletRequest request) {
        return findCookieValue(request, appProperties.getCookie().getName());
    }

    /** Returns the OAuth state value from the request cookies, or empty if absent. */
    public Optional<String> getOAuthStateCookie(HttpServletRequest request) {
        return findCookieValue(request, OAUTH_STATE_COOKIE);
    }

    /** Returns the PKCE verifier value from the request cookies, or empty if absent. */
    public Optional<String> getPkceVerifierCookie(HttpServletRequest request) {
        return findCookieValue(request, PKCE_VERIFIER_COOKIE);
    }

    /** Expires both OAuth flow cookies. Should be called after the callback is processed. */
    public void clearOAuthFlowCookies(HttpServletResponse response) {
        response.addHeader(HttpHeaders.SET_COOKIE,
                buildOAuthFlowCookie(OAUTH_STATE_COOKIE, "", 0).toString());
        response.addHeader(HttpHeaders.SET_COOKIE,
                buildOAuthFlowCookie(PKCE_VERIFIER_COOKIE, "", 0).toString());
    }

    /**
     * Writes the encrypted MSAL token-cache cookie.
     * The cookie is {@code HttpOnly}, {@code SameSite=Strict}, and long-lived (90 days by default)
     * so that the refresh token stored inside it survives browser restarts.
     */
    public void setMsalCacheCookie(HttpServletResponse response, String encryptedValue) {
        response.addHeader(HttpHeaders.SET_COOKIE,
                buildMsalCacheCookie(encryptedValue, appProperties.getTokenCache().getCookie().getMaxAge().getSeconds()).toString());
    }

    /** Expires the MSAL token-cache cookie, causing the browser to delete it. */
    public void clearMsalCacheCookie(HttpServletResponse response) {
        response.addHeader(HttpHeaders.SET_COOKIE, buildMsalCacheCookie("", 0).toString());
    }

    /**
     * Returns the raw (encrypted) value of the MSAL token-cache cookie, or empty if absent.
     */
    public Optional<String> getMsalCacheCookie(HttpServletRequest request) {
        return findCookieValue(request, appProperties.getTokenCache().getCookie().getName());
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

    private ResponseCookie buildMsalCacheCookie(String value, long maxAge) {
        AppProperties.TokenCache.CookieStore cookieStore = appProperties.getTokenCache().getCookie();
        return ResponseCookie.from(cookieStore.getName(), value)
                .httpOnly(true)
                // secure defaults to true; only set false for local HTTP dev
                .secure(cookieStore.isSecure())
                .path("/")
                .maxAge(maxAge)
                .sameSite("Strict") // SameSite=Strict is required: the MSAL cache cookie is never needed cross-site
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

    private Optional<String> findCookieValue(HttpServletRequest request, String name) {
        Cookie[] cookies = request.getCookies();
        if (cookies == null) {
            return Optional.empty();
        }
        return Arrays.stream(cookies)
                .filter(c -> name.equals(c.getName()))
                .map(Cookie::getValue)
                .findFirst();
    }
}
