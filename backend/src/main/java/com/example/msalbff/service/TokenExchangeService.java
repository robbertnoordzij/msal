package com.example.msalbff.service;

import com.example.msalbff.config.AppProperties;
import com.microsoft.aad.msal4j.*;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import java.net.URI;
import java.util.Collections;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.AbstractExecutorService;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/**
 * Handles OAuth 2.0 token acquisition via MSAL4J.
 *
 * <p>The {@link ConfidentialClientApplication} is a singleton and delegates its
 * token cache to {@link MsalTokenCacheService}, which either persists data in Redis
 * ({@link RedisMsalTokenCache}) or in an encrypted HTTP-only cookie
 * ({@link CookieMsalTokenCache}), depending on the active configuration.
 * <ul>
 *   <li>Refresh tokens are <b>never</b> sent to the browser. They live only in
 *       the server-side cache (Redis or encrypted cookie).</li>
 *   <li>On cache unavailability the cache falls back to an empty state for that
 *       operation; the user will be re-authenticated at next request.</li>
 * </ul>
 */
@Service
public class TokenExchangeService {

    private static final Logger logger = LoggerFactory.getLogger(TokenExchangeService.class);
    private static final int TOKEN_EXCHANGE_TIMEOUT_SECONDS = 30;

    /**
     * A "caller-runs" ExecutorService that executes each task synchronously on the submitting thread.
     * This ensures MSAL4J cache callbacks run on the HTTP request thread, where
     * {@link org.springframework.web.context.request.RequestContextHolder} has the request bound.
     * Since we always block on {@code acquireToken(...).get(timeout)}, there is no change in
     * effective concurrency — only which thread executes the work.
     */
    private static final java.util.concurrent.ExecutorService CALLER_RUNS_EXECUTOR =
        new AbstractExecutorService() {
            public void execute(Runnable command) { command.run(); }
            public void shutdown() {}
            public java.util.List<Runnable> shutdownNow() { return Collections.emptyList(); }
            public boolean isShutdown() { return false; }
            public boolean isTerminated() { return false; }
            public boolean awaitTermination(long timeout, TimeUnit unit) { return true; }
        };

    private final AppProperties appProperties;
    private final MsalTokenCacheService tokenCache;

    // Field typed as interface for testability; initialised by @PostConstruct init()
    IConfidentialClientApplication msalClient;

    public TokenExchangeService(AppProperties appProperties, MsalTokenCacheService tokenCache) {
        this.appProperties = appProperties;
        this.tokenCache = tokenCache;
    }

    @PostConstruct
    public void init() throws Exception {
        AppProperties.AzureAd azureAd = appProperties.getAzureAd();
        IClientCredential credential = ClientCredentialFactory.createFromSecret(azureAd.getClientSecret());
        msalClient = ConfidentialClientApplication.builder(azureAd.getClientId(), credential)
            .authority(azureAd.getAuthority())
            .setTokenCacheAccessAspect(tokenCache)
            .executorService(CALLER_RUNS_EXECUTOR)  // Cache callbacks run on the HTTP request thread
            .build();
        logger.info("MSAL ConfidentialClientApplication initialised for tenant {} (token cache: {})",
                azureAd.getTenantId(), tokenCache.getClass().getSimpleName());
    }

    public IAuthenticationResult exchangeAuthorizationCode(String code, String redirectUri, Set<String> scopes, String codeVerifier) throws Exception {
        AuthorizationCodeParameters parameters = AuthorizationCodeParameters
                .builder(code, new URI(redirectUri))
                .scopes(scopes)
                .codeVerifier(codeVerifier)
                .build();

        try {
            IAuthenticationResult result = msalClient.acquireToken(parameters)
                    .get(TOKEN_EXCHANGE_TIMEOUT_SECONDS, TimeUnit.SECONDS);
            logger.info("Exchanged authorization code for tokens, expires at {}", result.expiresOnDate());
            return result;
        } catch (TimeoutException e) {
            throw new RuntimeException("Token exchange timed out after " + TOKEN_EXCHANGE_TIMEOUT_SECONDS + "s", e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new RuntimeException("Token exchange interrupted", e);
        } catch (ExecutionException e) {
            Throwable cause = e.getCause();
            throw new RuntimeException("Token exchange failed: " + Objects.toString(cause, "unknown cause"),
                    cause != null ? cause : e);
        }
    }

    /**
     * Silently acquires a new ID token using the cached refresh token for the given account.
     *
     * <p>MSAL4J automatically uses its internal refresh token when the cached access token
     * has expired. No refresh token handling is needed in application code.
     *
     * @param homeAccountId the MSAL account identifier stored in the HTTP session after login
     * @param scopes        the scopes to request (must include {@code offline_access} for refresh)
     * @return the new authentication result, or empty if the account is not cached or the
     *         refresh token is expired/revoked (requiring the user to re-authenticate)
     */
    public Optional<IAuthenticationResult> acquireTokenSilently(String homeAccountId, Set<String> scopes) {
        try {
            Optional<IAccount> account = msalClient.getAccounts().join().stream()
                    .filter(a -> homeAccountId.equals(a.homeAccountId()))
                    .findFirst();

            if (account.isEmpty()) {
                logger.debug("No cached MSAL account found for homeAccountId ending in '{}'",
                        LogSanitizer.obfuscate(homeAccountId));
                return Optional.empty();
            }

            SilentParameters parameters = SilentParameters.builder(scopes, account.get())
                    .build();

            IAuthenticationResult result = msalClient.acquireTokenSilently(parameters)
                    .get(TOKEN_EXCHANGE_TIMEOUT_SECONDS, TimeUnit.SECONDS);

            logger.info("Silent token refresh succeeded, new token expires at {}", result.expiresOnDate());
            return Optional.of(result);

        } catch (ExecutionException e) {
            if (e.getCause() instanceof MsalInteractionRequiredException) {
                logger.info("Silent refresh requires user interaction — refresh token expired or revoked");
            } else {
                logger.warn("Silent token acquisition failed: {}", Objects.toString(e.getCause(), "unknown cause"));
            }
            return Optional.empty();
        } catch (TimeoutException e) {
            logger.warn("Silent token acquisition timed out after {}s", TOKEN_EXCHANGE_TIMEOUT_SECONDS);
            return Optional.empty();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            logger.warn("Silent token acquisition interrupted");
            return Optional.empty();
        } catch (Exception e) {
            logger.warn("Silent token acquisition failed unexpectedly: {}", e.getMessage());
            return Optional.empty();
        }
    }

    /**
     * Silently acquires a new ID token by looking up the first available account from the MSAL
     * cache without requiring a known {@code homeAccountId} up-front.
     *
     * <p>This is the session-restore path: when the AUTH_TOKEN cookie is absent (e.g. its
     * MaxAge has elapsed) but the MSAL token-cache (Redis entry or encrypted cookie) still
     * holds a valid refresh token, this method discovers the account and exchanges the refresh
     * token for a new ID token transparently.
     *
     * @param scopes the scopes to request (must include {@code offline_access} for refresh)
     * @return the new authentication result, or empty if no cached account is found or the
     *         refresh token has expired / been revoked
     */
    public Optional<IAuthenticationResult> acquireTokenSilentlyFromCache(Set<String> scopes) {
        try {
            Set<IAccount> accounts = msalClient.getAccounts()
                    .get(TOKEN_EXCHANGE_TIMEOUT_SECONDS, TimeUnit.SECONDS);
            if (accounts.isEmpty()) {
                logger.debug("No cached MSAL accounts found; cannot perform session restore");
                return Optional.empty();
            }
            IAccount account = accounts.iterator().next();
            SilentParameters parameters = SilentParameters.builder(scopes, account).build();
            IAuthenticationResult result = msalClient.acquireTokenSilently(parameters)
                    .get(TOKEN_EXCHANGE_TIMEOUT_SECONDS, TimeUnit.SECONDS);
            logger.info("Session restored via cached refresh token, new token expires at {}",
                    result.expiresOnDate());
            return Optional.of(result);
        } catch (ExecutionException e) {
            if (e.getCause() instanceof MsalInteractionRequiredException) {
                logger.info("Session restore requires user interaction — cached refresh token expired or revoked");
            } else {
                logger.warn("Session restore failed: {}", Objects.toString(e.getCause(), "unknown cause"));
            }
            return Optional.empty();
        } catch (TimeoutException e) {
            logger.warn("Session restore timed out after {}s", TOKEN_EXCHANGE_TIMEOUT_SECONDS);
            return Optional.empty();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            logger.warn("Session restore interrupted");
            return Optional.empty();
        } catch (Exception e) {
            logger.warn("Session restore failed unexpectedly: {}", e.getMessage());
            return Optional.empty();
        }
    }

    public String generateAuthorizationUrl(String redirectUri, Set<String> scopes, String state, String codeChallenge) throws Exception {
        if (codeChallenge == null || codeChallenge.length() < 43 || codeChallenge.length() > 128) {
            throw new IllegalArgumentException("Invalid code challenge length: " +
                (codeChallenge != null ? codeChallenge.length() : 0));
        }
        AuthorizationRequestUrlParameters parameters = AuthorizationRequestUrlParameters
                .builder(redirectUri, scopes)
                .responseMode(ResponseMode.QUERY)
                .prompt(Prompt.SELECT_ACCOUNT)
                .state(state != null ? state : UUID.randomUUID().toString())
                .codeChallenge(codeChallenge)
                .codeChallengeMethod("S256")
                .build();

        return msalClient.getAuthorizationRequestUrl(parameters).toString();
    }
}
