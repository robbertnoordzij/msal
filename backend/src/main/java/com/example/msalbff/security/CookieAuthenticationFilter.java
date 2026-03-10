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
import jakarta.servlet.http.HttpSession;
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
 *       seconds — authenticate with the current token and silently refresh in the background.</li>
 *   <li>If the token is expired or otherwise invalid — attempt a silent refresh using the
 *       MSAL-cached refresh token. If that succeeds, set authentication and update the cookie;
 *       otherwise the request proceeds unauthenticated (Spring Security returns 401).</li>
 * </ol>
 *
 * <p>The MSAL account identifier ({@code msal_account_id}) required for silent refresh is
 * stored in the server-side HTTP session by {@code AuthController} after login. It is never
 * sent to the browser.
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
        if (request.getRequestURI().startsWith("/auth/")) {
            filterChain.doFilter(request, response);
            return;
        }

        String token = extractTokenFromCookie(request);

        if (token != null) {
            if (tokenValidationService.validateToken(token)) {
                Jwt jwt = tokenValidationService.parseToken(token);
                setAuthentication(jwt);

                if (isExpiringSoon(jwt)) {
                    tryRefreshToken(request, response);
                }
            } else {
                // Token invalid or expired — attempt silent refresh before giving up
                tryRefreshToken(request, response);
            }
        }

        filterChain.doFilter(request, response);
    }

    /**
     * Attempts a silent token refresh using the MSAL-cached refresh token.
     * Updates both the Spring Security context and the AUTH_TOKEN cookie on success.
     */
    private void tryRefreshToken(HttpServletRequest request, HttpServletResponse response) {
        String homeAccountId = getHomeAccountId(request);
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

    private String getHomeAccountId(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session == null) {
            return null;
        }
        return (String) session.getAttribute("msal_account_id");
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