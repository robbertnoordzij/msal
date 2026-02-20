package com.example.msalbff.service;

import com.example.msalbff.config.AppProperties;
import com.microsoft.aad.msal4j.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.UUID;

@Service
public class TokenExchangeService {

    private static final Logger logger = LoggerFactory.getLogger(TokenExchangeService.class);

    private final AppProperties appProperties;
    private final Environment environment;

    public TokenExchangeService(AppProperties appProperties, Environment environment) {
        this.appProperties = appProperties;
        this.environment = environment;
    }

    public ConfidentialClientApplication buildClient() throws Exception {

        String clientId = environment.getProperty("azure.activedirectory.client-id");
        String clientSecret = environment.getProperty("app.azure-ad.client-secret");
        String authority = "https://login.microsoftonline.com/" + environment.getProperty("azure.activedirectory.tenant-id");

        IClientCredential credential = ClientCredentialFactory.createFromSecret(clientSecret);

        return ConfidentialClientApplication.builder(clientId, credential)
            .authority(authority)
            .build();
    }

    public IAuthenticationResult exchangeAuthorizationCode(String code, String redirectUri, Set<String> scopes, String codeVerifier) throws Exception {
        ConfidentialClientApplication app = buildClient();

        AuthorizationCodeParameters parameters = AuthorizationCodeParameters
                .builder(code, new URI(redirectUri))
                .scopes(scopes)
                .codeVerifier(codeVerifier)
                .build();

        CompletableFuture<IAuthenticationResult> future;
        future = app.acquireToken(parameters);

        IAuthenticationResult result = future.join();
        logger.info("Exchanged authorization code for tokens, expires at {}", result.expiresOnDate());
        return result;
    }

    public String generateAuthorizationUrl(String redirectUri, Set<String> scopes, String state, String codeChallenge) throws Exception {
        ConfidentialClientApplication app = buildClient();

        AuthorizationRequestUrlParameters parameters = AuthorizationRequestUrlParameters
                .builder(redirectUri, scopes)
                .responseMode(ResponseMode.QUERY)
                .prompt(Prompt.SELECT_ACCOUNT)
                .state(state != null ? state : UUID.randomUUID().toString())
                .codeChallenge(codeChallenge)
                .codeChallengeMethod("S256")
                .build();

        return app.getAuthorizationRequestUrl(parameters).toString();
    }
}
