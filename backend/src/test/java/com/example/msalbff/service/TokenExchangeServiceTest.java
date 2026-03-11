package com.example.msalbff.service;

import com.azure.core.credential.AccessToken;
import com.azure.core.credential.TokenCredential;
import com.azure.core.credential.TokenRequestContext;
import com.example.msalbff.config.AppProperties;
import com.microsoft.aad.msal4j.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import reactor.core.publisher.Mono;

import java.lang.reflect.Field;
import java.time.OffsetDateTime;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CompletableFuture;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class TokenExchangeServiceTest {

    @Mock
    private AppProperties appProperties;

    @Mock
    private MsalTokenCacheService tokenCache;

    @Mock
    private IConfidentialClientApplication msalClient;

    @Mock
    private IAccount mockAccount;

    @Mock
    private IAuthenticationResult mockResult;

    private TokenExchangeService service;

    private static final String HOME_ACCOUNT_ID = "object-id.tenant-id";
    private static final Set<String> SCOPES = Set.of("openid", "profile", "offline_access");

    @BeforeEach
    void setUp() throws Exception {
        service = new TokenExchangeService(appProperties, tokenCache);

        // Bypass @PostConstruct by injecting the mock directly
        Field field = TokenExchangeService.class.getDeclaredField("msalClient");
        field.setAccessible(true);
        field.set(service, msalClient);
    }

    @Test
    void acquireTokenSilently_returnsResult_whenAccountFoundAndRefreshSucceeds() throws Exception {
        when(mockAccount.homeAccountId()).thenReturn(HOME_ACCOUNT_ID);
        when(msalClient.getAccounts()).thenReturn(CompletableFuture.completedFuture(Set.of(mockAccount)));
        when(mockResult.idToken()).thenReturn("new-id-token");
        when(msalClient.acquireTokenSilently(any(SilentParameters.class)))
                .thenReturn(CompletableFuture.completedFuture(mockResult));

        Optional<IAuthenticationResult> result = service.acquireTokenSilently(HOME_ACCOUNT_ID, SCOPES);

        assertTrue(result.isPresent());
        assertEquals("new-id-token", result.get().idToken());
    }

    @Test
    void acquireTokenSilently_returnsEmpty_whenAccountNotInCache() {
        when(msalClient.getAccounts()).thenReturn(CompletableFuture.completedFuture(Set.of()));

        Optional<IAuthenticationResult> result = service.acquireTokenSilently("unknown-account-id", SCOPES);

        assertTrue(result.isEmpty());
    }

    @Test
    void acquireTokenSilently_returnsEmpty_whenRefreshTokenExpired() throws Exception {
        when(mockAccount.homeAccountId()).thenReturn(HOME_ACCOUNT_ID);
        when(msalClient.getAccounts()).thenReturn(CompletableFuture.completedFuture(Set.of(mockAccount)));

        MsalInteractionRequiredException interactionRequired =
                mock(MsalInteractionRequiredException.class);
        when(msalClient.acquireTokenSilently(any(SilentParameters.class)))
                .thenReturn(CompletableFuture.failedFuture(interactionRequired));

        Optional<IAuthenticationResult> result = service.acquireTokenSilently(HOME_ACCOUNT_ID, SCOPES);

        assertTrue(result.isEmpty());
    }

    @Test
    void acquireTokenSilently_returnsEmpty_onGenericExecutionException() throws Exception {
        when(mockAccount.homeAccountId()).thenReturn(HOME_ACCOUNT_ID);
        when(msalClient.getAccounts()).thenReturn(CompletableFuture.completedFuture(Set.of(mockAccount)));

        RuntimeException networkError = new RuntimeException("Network error");
        when(msalClient.acquireTokenSilently(any(SilentParameters.class)))
                .thenReturn(CompletableFuture.failedFuture(networkError));

        Optional<IAuthenticationResult> result = service.acquireTokenSilently(HOME_ACCOUNT_ID, SCOPES);

        assertTrue(result.isEmpty());
    }

    @Test
    void acquireTokenSilently_callsMsalSilentMethod_notInteractiveMethod() throws Exception {
        when(mockAccount.homeAccountId()).thenReturn(HOME_ACCOUNT_ID);
        when(msalClient.getAccounts()).thenReturn(CompletableFuture.completedFuture(Set.of(mockAccount)));
        when(msalClient.acquireTokenSilently(any(SilentParameters.class)))
                .thenReturn(CompletableFuture.completedFuture(mockResult));

        service.acquireTokenSilently(HOME_ACCOUNT_ID, SCOPES);

        verify(msalClient).acquireTokenSilently(any(SilentParameters.class));
        verify(msalClient, never()).acquireToken(any(AuthorizationCodeParameters.class));
    }

    // ── acquireTokenSilentlyFromCache ─────────────────────────────────────────

    @Test
    void acquireTokenSilentlyFromCache_returnsResult_whenCachedAccountExists() throws Exception {
        when(msalClient.getAccounts()).thenReturn(CompletableFuture.completedFuture(Set.of(mockAccount)));
        when(mockResult.idToken()).thenReturn("restored-id-token");
        when(msalClient.acquireTokenSilently(any(SilentParameters.class)))
                .thenReturn(CompletableFuture.completedFuture(mockResult));

        Optional<IAuthenticationResult> result = service.acquireTokenSilentlyFromCache(SCOPES);

        assertTrue(result.isPresent());
        assertEquals("restored-id-token", result.get().idToken());
        verify(msalClient).acquireTokenSilently(any(SilentParameters.class));
    }

    @Test
    void acquireTokenSilentlyFromCache_returnsEmpty_whenNoCachedAccount() throws Exception {
        when(msalClient.getAccounts()).thenReturn(CompletableFuture.completedFuture(Set.of()));

        Optional<IAuthenticationResult> result = service.acquireTokenSilentlyFromCache(SCOPES);

        assertTrue(result.isEmpty());
        verify(msalClient, never()).acquireTokenSilently(any());
    }

    @Test
    void acquireTokenSilentlyFromCache_returnsEmpty_whenRefreshTokenExpired() throws Exception {
        when(msalClient.getAccounts()).thenReturn(CompletableFuture.completedFuture(Set.of(mockAccount)));
        MsalInteractionRequiredException interactionRequired =
                mock(MsalInteractionRequiredException.class);
        when(msalClient.acquireTokenSilently(any(SilentParameters.class)))
                .thenReturn(CompletableFuture.failedFuture(interactionRequired));

        Optional<IAuthenticationResult> result = service.acquireTokenSilentlyFromCache(SCOPES);

        assertTrue(result.isEmpty());
    }

    // ── buildCredential ───────────────────────────────────────────────────────

    @Nested
    @MockitoSettings(strictness = Strictness.LENIENT)
    class BuildCredential {

        @Mock
        private AppProperties.AzureAd azureAd;

        @Test
        void secret_mode_returnsClientSecretCredential() {
            when(azureAd.getCredentialType()).thenReturn("secret");
            when(azureAd.getClientSecret()).thenReturn("super-secret");

            IClientCredential credential = service.buildCredential(azureAd);

            assertNotNull(credential);
        }

        @Test
        void secret_mode_throwsWhenClientSecretBlank() {
            when(azureAd.getCredentialType()).thenReturn("secret");
            when(azureAd.getClientSecret()).thenReturn("");

            assertThrows(IllegalStateException.class, () -> service.buildCredential(azureAd));
        }

        @Test
        void managedIdentity_systemAssigned_buildsCredentialWithoutClientId() throws Exception {
            when(azureAd.getCredentialType()).thenReturn("managed-identity");
            when(azureAd.getManagedIdentityClientId()).thenReturn("");

            AccessToken token = new AccessToken("mi-assertion-token", OffsetDateTime.now().plusMinutes(5));
            TokenCredential mockMiCredential = mock(TokenCredential.class);
            when(mockMiCredential.getToken(any())).thenReturn(Mono.just(token));

            TokenExchangeService spyService = spy(service);
            doReturn(mockMiCredential).when(spyService).buildManagedIdentityTokenCredential(azureAd);

            IClientCredential credential = spyService.buildCredential(azureAd);

            assertNotNull(credential);
            verify(spyService).buildManagedIdentityTokenCredential(azureAd);
        }

        @Test
        void managedIdentity_userAssigned_passesClientIdToTokenCredential() throws Exception {
            when(azureAd.getCredentialType()).thenReturn("managed-identity");
            when(azureAd.getManagedIdentityClientId()).thenReturn("user-mi-client-id");

            AccessToken token = new AccessToken("mi-assertion-token", OffsetDateTime.now().plusMinutes(5));
            TokenCredential mockMiCredential = mock(TokenCredential.class);
            when(mockMiCredential.getToken(any())).thenReturn(Mono.just(token));

            TokenExchangeService spyService = spy(service);
            doReturn(mockMiCredential).when(spyService).buildManagedIdentityTokenCredential(azureAd);

            IClientCredential credential = spyService.buildCredential(azureAd);

            assertNotNull(credential);
            verify(spyService).buildManagedIdentityTokenCredential(azureAd);
        }
    }
}

