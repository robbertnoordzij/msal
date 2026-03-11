package com.example.msalbff.service;

import com.example.msalbff.config.AppProperties;
import com.microsoft.aad.msal4j.IAccount;
import com.microsoft.aad.msal4j.ITokenCache;
import com.microsoft.aad.msal4j.ITokenCacheAccessContext;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;

import java.time.Duration;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class RedisMsalTokenCacheTest {

    @Mock private StringRedisTemplate redisTemplate;
    @Mock private ValueOperations<String, String> valueOps;
    @Mock private TokenCacheEncryption encryption;
    @Mock private AppProperties appProperties;
    @Mock private AppProperties.Redis redisProps;
    @Mock private ITokenCacheAccessContext context;
    @Mock private ITokenCache tokenCache;
    @Mock private IAccount account;

    private static final String CLIENT_ID       = "test-client-id";
    private static final String HOME_ACCOUNT_ID = "oid-1234.tid-5678";
    private static final String CACHE_JSON      = "{\"AccessToken\":{}}";
    private static final Duration TTL           = Duration.ofSeconds(3600);

    private RedisMsalTokenCache cache;

    @BeforeEach
    void setUp() {
        when(appProperties.getRedis()).thenReturn(redisProps);
        when(redisProps.getTtl()).thenReturn(TTL);
        lenient().when(redisTemplate.opsForValue()).thenReturn(valueOps);
        lenient().when(encryption.isEnabled()).thenReturn(false);
        cache = new RedisMsalTokenCache(redisTemplate, encryption, appProperties);
    }

    // -----------------------------------------------------------------------
    // beforeCacheAccess
    // -----------------------------------------------------------------------

    @Nested
    class BeforeCacheAccess {

        @Test
        void loadsAndDeserializesCache_whenKeyExistsInRedis() {
            givenAccountOnContext();
            when(valueOps.get("msal:token-cache:" + HOME_ACCOUNT_ID)).thenReturn(CACHE_JSON);
            when(context.tokenCache()).thenReturn(tokenCache);

            cache.beforeCacheAccess(context);

            verify(tokenCache).deserialize(CACHE_JSON);
        }

        @Test
        void skipsDeserialization_whenKeyAbsentFromRedis() {
            givenAccountOnContext();
            when(valueOps.get(anyString())).thenReturn(null);

            cache.beforeCacheAccess(context);

            verify(context, never()).tokenCache();
        }

        @Test
        void usesHomeAccountIdAsPartitionKey() {
            givenAccountOnContext();
            when(valueOps.get("msal:token-cache:" + HOME_ACCOUNT_ID)).thenReturn(CACHE_JSON);
            when(context.tokenCache()).thenReturn(tokenCache);

            cache.beforeCacheAccess(context);

            verify(valueOps).get("msal:token-cache:" + HOME_ACCOUNT_ID);
        }

        @Test
        void usesClientIdFallbackKey_whenNoAccountOnContext() {
            when(context.account()).thenReturn(null);
            when(context.clientId()).thenReturn(CLIENT_ID);
            when(valueOps.get("msal:token-cache:app:" + CLIENT_ID)).thenReturn(CACHE_JSON);
            when(context.tokenCache()).thenReturn(tokenCache);

            cache.beforeCacheAccess(context);

            verify(valueOps).get("msal:token-cache:app:" + CLIENT_ID);
            verify(tokenCache).deserialize(CACHE_JSON);
        }

        @Test
        void decryptsCacheJson_whenEncryptionEnabled() throws Exception {
            when(encryption.isEnabled()).thenReturn(true);
            givenAccountOnContext();
            String encryptedValue = "encrypted-blob";
            when(valueOps.get("msal:token-cache:" + HOME_ACCOUNT_ID)).thenReturn(encryptedValue);
            when(encryption.decrypt(encryptedValue)).thenReturn(CACHE_JSON);
            when(context.tokenCache()).thenReturn(tokenCache);

            cache.beforeCacheAccess(context);

            verify(encryption).decrypt(encryptedValue);
            verify(tokenCache).deserialize(CACHE_JSON);
        }

        @Test
        void doesNotThrow_whenRedisIsUnavailable() {
            givenAccountOnContext();
            when(valueOps.get(anyString())).thenThrow(new RuntimeException("Connection refused"));

            assertDoesNotThrow(() -> cache.beforeCacheAccess(context));
        }

        @Test
        void doesNotThrow_whenDecryptionFails() throws Exception {
            when(encryption.isEnabled()).thenReturn(true);
            givenAccountOnContext();
            when(valueOps.get(anyString())).thenReturn("corrupted-data");
            when(encryption.decrypt(anyString())).thenThrow(new RuntimeException("Bad ciphertext"));

            assertDoesNotThrow(() -> cache.beforeCacheAccess(context));
        }
    }

    // -----------------------------------------------------------------------
    // afterCacheAccess
    // -----------------------------------------------------------------------

    @Nested
    class AfterCacheAccess {

        @Test
        void writesToRedisWithCorrectKeyAndTtl_whenCacheChanged() {
            when(context.hasCacheChanged()).thenReturn(true);
            givenAccountOnContext();
            when(context.tokenCache()).thenReturn(tokenCache);
            when(tokenCache.serialize()).thenReturn(CACHE_JSON);

            cache.afterCacheAccess(context);

            verify(valueOps).set(
                    eq("msal:token-cache:" + HOME_ACCOUNT_ID),
                    eq(CACHE_JSON),
                    eq(TTL)
            );
        }

        @Test
        void skipsWrite_whenCacheUnchanged() {
            when(context.hasCacheChanged()).thenReturn(false);

            cache.afterCacheAccess(context);

            verifyNoInteractions(valueOps);
        }

        @Test
        void usesClientIdFallbackKey_whenNoAccountOnContext() {
            when(context.hasCacheChanged()).thenReturn(true);
            when(context.account()).thenReturn(null);
            when(context.clientId()).thenReturn(CLIENT_ID);
            when(context.tokenCache()).thenReturn(tokenCache);
            when(tokenCache.serialize()).thenReturn(CACHE_JSON);

            cache.afterCacheAccess(context);

            verify(valueOps).set(
                    eq("msal:token-cache:app:" + CLIENT_ID),
                    eq(CACHE_JSON),
                    eq(TTL)
            );
        }

        @Test
        void encryptsCacheJson_beforeWriting_whenEncryptionEnabled() throws Exception {
            when(encryption.isEnabled()).thenReturn(true);
            when(context.hasCacheChanged()).thenReturn(true);
            givenAccountOnContext();
            when(context.tokenCache()).thenReturn(tokenCache);
            when(tokenCache.serialize()).thenReturn(CACHE_JSON);
            String encryptedValue = "encrypted-blob";
            when(encryption.encrypt(CACHE_JSON)).thenReturn(encryptedValue);

            cache.afterCacheAccess(context);

            verify(encryption).encrypt(CACHE_JSON);
            verify(valueOps).set(
                    eq("msal:token-cache:" + HOME_ACCOUNT_ID),
                    eq(encryptedValue),
                    eq(TTL)
            );
        }

        @Test
        void doesNotThrow_whenRedisIsUnavailable() {
            when(context.hasCacheChanged()).thenReturn(true);
            givenAccountOnContext();
            when(context.tokenCache()).thenReturn(tokenCache);
            when(tokenCache.serialize()).thenReturn(CACHE_JSON);
            doThrow(new RuntimeException("Connection refused"))
                    .when(valueOps).set(anyString(), anyString(), any(Duration.class));

            assertDoesNotThrow(() -> cache.afterCacheAccess(context));
        }
    }

    // -----------------------------------------------------------------------
    // evict
    // -----------------------------------------------------------------------

    @Nested
    class Evict {

        @Test
        void deletesCorrectKeyFromRedis() {
            cache.evict(HOME_ACCOUNT_ID);

            verify(redisTemplate).delete("msal:token-cache:" + HOME_ACCOUNT_ID);
        }

        @Test
        void doesNotThrow_whenRedisIsUnavailable() {
            doThrow(new RuntimeException("Connection refused"))
                    .when(redisTemplate).delete(anyString());

            assertDoesNotThrow(() -> cache.evict(HOME_ACCOUNT_ID));
        }
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    private void givenAccountOnContext() {
        when(context.account()).thenReturn(account);
        when(account.homeAccountId()).thenReturn(HOME_ACCOUNT_ID);
    }

    // -----------------------------------------------------------------------
    // MsalTokenCacheService interface compliance
    // -----------------------------------------------------------------------

    @Test
    void implementsMsalTokenCacheService_allowsAssignmentToInterface() {
        // This compile-time check confirms RedisMsalTokenCache satisfies
        // the shared MsalTokenCacheService contract used by AuthController and
        // TokenExchangeService.
        MsalTokenCacheService service = cache;
        org.junit.jupiter.api.Assertions.assertNotNull(service);
    }
}
