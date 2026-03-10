package com.example.msalbff.service;

import com.example.msalbff.config.AppProperties;
import com.microsoft.aad.msal4j.*;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/**
 * Handles OAuth 2.0 token acquisition via MSAL4J.
 *
 * <p>The {@link ConfidentialClientApplication} is a singleton and maintains an
 * in-memory token cache that stores refresh tokens per account. This means:
 * <ul>
 *   <li>Silent token refresh works without any additional storage.</li>
 *   <li>On application restart, the cache is lost — users must re-authenticate.
 *       For production, implement {@link ITokenCacheAccessAspect} backed by
 *       an encrypted Redis or database store.</li>
 *   <li>Refresh tokens are <b>never</b> sent to the browser. They live only in
 *       this server-side cache.</li>
 * </ul>
 */
@Service
public class TokenExchangeService {

    private static final Logger logger = LoggerFactory.getLogger(TokenExchangeService.class);
    private static final int TOKEN_EXCHANGE_TIMEOUT_SECONDS = 30;

    private final AppProperties appProperties;

    // Field typed as interface for testability; initialised by @PostConstruct init()
    IConfidentialClientApplication msalClient;

    public TokenExchangeService(AppProperties appProperties) {
        this.appProperties = appProperties;
    }

    @PostConstruct
    public void init() throws Exception {
        AppProperties.AzureAd azureAd = appProperties.getAzureAd();
        IClientCredential credential = ClientCredentialFactory.createFromSecret(azureAd.getClientSecret());
        msalClient = ConfidentialClientApplication.builder(azureAd.getClientId(), credential)
            .authority(azureAd.getAuthority())
            .build();
        logger.info("MSAL ConfidentialClientApplication initialised for tenant {}", azureAd.getTenantId());
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
            throw new RuntimeException("Token exchange failed: " + e.getCause().getMessage(), e.getCause());
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
            IAccount account = msalClient.getAccounts().join().stream()
                    .filter(a -> homeAccountId.equals(a.homeAccountId()))
                    .findFirst()
                    .orElse(null);

            if (account == null) {
                logger.debug("No cached MSAL account found for homeAccountId ending in '...{}'",
                        trailingCharacters(homeAccountId));
                return Optional.empty();
            }

            SilentParameters parameters = SilentParameters.builder(scopes, account)
                    .build();

            IAuthenticationResult result = msalClient.acquireTokenSilently(parameters)
                    .get(TOKEN_EXCHANGE_TIMEOUT_SECONDS, TimeUnit.SECONDS);

            logger.info("Silent token refresh succeeded, new token expires at {}", result.expiresOnDate());
            return Optional.of(result);

        } catch (ExecutionException e) {
            if (e.getCause() instanceof MsalInteractionRequiredException) {
                logger.info("Silent refresh requires user interaction — refresh token expired or revoked");
            } else {
                logger.warn("Silent token acquisition failed: {}", e.getCause().getMessage());
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

    public String generateAuthorizationUrl(String redirectUri, Set<String> scopes, String state, String codeChallenge) throws Exception {
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

    private String trailingCharacters(String value) {
        return value != null && value.length() > 8 ? value.substring(value.length() - 8) : value;
    }
}
