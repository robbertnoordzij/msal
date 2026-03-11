package com.example.msalbff.security;

import com.example.msalbff.config.AppProperties;
import com.example.msalbff.service.AuthCookieService;
import com.example.msalbff.service.TokenExchangeService;
import com.example.msalbff.service.TokenValidationService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Instant;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

/**
 * Reads the AUTH_TOKEN HTTP-only cookie on every request, validates the JWT,
 * and populates the Spring Security context.
 *
 * <p>Token refresh strategy:
 * <ol>
 *   <li>If the token is valid and <em>not</em> expiring soon — authenticate normally.</li>
 *   <li>If the token is valid but expiring within {@value #PROACTIVE_REFRESH_THRESHOLD_SECONDS}
 *       seconds — authenticate with the current token and silently refresh it.</li>
 *   <li>If AUTH_TOKEN is absent but the MSAL token-cache cookie ({@code MSAL_TOKEN_CACHE}) is
 *       present — attempt to restore the session by acquiring a new token using the cached
 *       refresh token. If successful, re-sets AUTH_TOKEN. This path is primarily useful with the
 *       cookie-backed MSAL cache ({@code app.token-cache.type=cookie}).</li>
 *   <li>If AUTH_TOKEN is absent and no MSAL cache is available, or the token is invalid —
 *       the request proceeds unauthenticated (Spring Security returns 401).</li>
 * </ol>
 */
public class CookieAuthenticationFilter extends OncePerRequestFilter {

    private static final Logger logger = LoggerFactory.getLogger(CookieAuthenticationFilter.class);
    static final int PROACTIVE_REFRESH_THRESHOLD_SECONDS = 300;

    private final TokenValidationService tokenValidationService;
    private final TokenExchangeService tokenExchangeService;
    private final AuthCookieService authCookieService;
    private final AppProperties appProperties;

    public CookieAuthenticationFilter(TokenValidationService tokenValidationService,
                                      TokenExchangeService tokenExchangeService,
                                      AuthCookieService authCookieService,
                                      AppProperties appProperties) {
        this.tokenValidationService = tokenValidationService;
        this.tokenExchangeService = tokenExchangeService;
        this.authCookieService = authCookieService;
        this.appProperties = appProperties;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        if (request.getServletPath().startsWith("/auth/")) {
            filterChain.doFilter(request, response);
            return;
        }

        String token = extractTokenFromCookie(request);

        if (token != null) {
            if (tokenValidationService.validateToken(token)) {
                Jwt jwt = tokenValidationService.parseToken(token);
                setAuthentication(jwt);

                if (isExpiringSoon(jwt)) {
                    tryRefreshToken(token, response);
                }
            }
            // Invalid/tampered token: do not attempt refresh; let the request proceed unauthenticated.
        } else {
            // AUTH_TOKEN absent — try to restore session from the MSAL token cache.
            tryRefreshTokenFromMsalCache(request, response);
        }

        filterChain.doFilter(request, response);
    }

    /**
     * Attempts a silent token refresh using the MSAL-cached refresh token.
     * The MSAL account ID is derived from the {@code oid} and {@code tid} claims
     * in the current token (even if expired, the claims are still readable).
     * Updates both the Spring Security context and the AUTH_TOKEN cookie on success.
     */
    private void tryRefreshToken(String token, HttpServletResponse response) {
        String homeAccountId = extractHomeAccountId(token);
        if (homeAccountId == null) {
            return;
        }

        tokenExchangeService.acquireTokenSilently(homeAccountId, appProperties.getAzureAd().scopesAsSet()).ifPresent(result -> {
            String newIdToken = result.idToken();
            if (newIdToken != null && tokenValidationService.validateToken(newIdToken)) {
                Jwt jwt = tokenValidationService.parseToken(newIdToken);
                setAuthentication(jwt);
                authCookieService.setAuthCookie(response, newIdToken);
                logger.info("Token silently refreshed for user '{}'", tokenValidationService.getUserName(jwt));
            } else {
                logger.warn("Silent refresh returned result but ID token is missing or invalid");
            }
        });
    }

    /**
     * Attempts to restore an expired or missing session by acquiring a new token from the
     * MSAL token cache without a known homeAccountId.
     * Only triggered when the MSAL cache cookie is present (cookie-cache mode).
     */
    private void tryRefreshTokenFromMsalCache(HttpServletRequest request, HttpServletResponse response) {
        if (authCookieService.getMsalCacheCookie(request).isEmpty()) {
            return;
        }
        tokenExchangeService.acquireTokenSilentlyFromCache(appProperties.getAzureAd().scopesAsSet())
                .ifPresent(result -> {
                    String newIdToken = result.idToken();
                    if (newIdToken != null && tokenValidationService.validateToken(newIdToken)) {
                        Jwt jwt = tokenValidationService.parseToken(newIdToken);
                        setAuthentication(jwt);
                        authCookieService.setAuthCookie(response, newIdToken);
                        logger.info("Session restored from MSAL cache for user '{}'",
                                tokenValidationService.getUserName(jwt));
                    } else {
                        logger.warn("Session restore returned result but ID token is missing or invalid");
                    }
                });
    }

    /**
     * Extracts the MSAL home account ID from the token's {@code oid} and {@code tid} claims.
     * The token is parsed without signature verification since the claims are needed even
     * for expired tokens. Returns {@code null} if the claims are absent or the token
     * cannot be parsed.
     */
    private String extractHomeAccountId(String token) {
        try {
            Jwt jwt = tokenValidationService.parseToken(token);
            if (jwt == null) {
                return null;
            }
            String oid = jwt.getClaimAsString("oid");
            String tid = jwt.getClaimAsString("tid");
            if (oid != null && tid != null) {
                return oid + "." + tid;
            }
        } catch (Exception e) {
            logger.debug("Could not extract account ID from token for silent refresh: {}", e.getMessage());
        }
        return null;
    }

    private void setAuthentication(Jwt jwt) {
        String username = tokenValidationService.getUserName(jwt);
        Collection<GrantedAuthority> authorities = extractAuthorities(jwt);
        UsernamePasswordAuthenticationToken auth =
                new UsernamePasswordAuthenticationToken(username, null, authorities);
        auth.setDetails(jwt);
        SecurityContextHolder.getContext().setAuthentication(auth);
        logger.debug("Authenticated user: {}", username);
    }

    private boolean isExpiringSoon(Jwt jwt) {
        Instant expiry = jwt.getExpiresAt();
        return expiry != null && expiry.isBefore(Instant.now().plusSeconds(PROACTIVE_REFRESH_THRESHOLD_SECONDS));
    }

    private String extractTokenFromCookie(HttpServletRequest request) {
        if (request.getCookies() == null) {
            return null;
        }
        for (Cookie cookie : request.getCookies()) {
            if (appProperties.getCookie().getName().equals(cookie.getName())) {
                return cookie.getValue();
            }
        }
        return null;
    }

    private Collection<GrantedAuthority> extractAuthorities(Jwt jwt) {
        List<String> roles = jwt.getClaimAsStringList("roles");
        if (roles == null) {
            return Collections.emptyList();
        }
        return roles.stream()
                .map(role -> (GrantedAuthority) new SimpleGrantedAuthority("ROLE_" + role.toUpperCase()))
                .toList();
    }
}