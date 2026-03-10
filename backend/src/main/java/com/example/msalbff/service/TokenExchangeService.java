package com.example.msalbff.service;

import com.example.msalbff.config.AppProperties;
import com.microsoft.aad.msal4j.*;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

@Service
public class TokenExchangeService {

    private static final Logger logger = LoggerFactory.getLogger(TokenExchangeService.class);
    private static final int TOKEN_EXCHANGE_TIMEOUT_SECONDS = 30;

    private final AppProperties appProperties;
    private ConfidentialClientApplication msalClient;

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
}
