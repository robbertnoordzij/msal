package com.example.msalbff.service;

import com.example.msalbff.config.AppProperties;
import com.microsoft.aad.msal4j.IAccount;
import com.microsoft.aad.msal4j.ITokenCacheAccessAspect;
import com.microsoft.aad.msal4j.ITokenCacheAccessContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;

import java.time.Duration;

/**
 * MSAL4J token cache backed by Redis, enabling shared token state across all
 * application instances in a cluster (e.g. AKS).
 *
 * <p>MSAL4J calls {@link #beforeCacheAccess} before reading the cache and
 * {@link #afterCacheAccess} after writing. Each user's token cache is stored as a
 * separate Redis entry under {@code msal:token-cache:{homeAccountId}}.
 * When {@link TokenCacheEncryption} is configured, the cache JSON is encrypted
 * with AES-256-GCM before storage, protecting refresh tokens at rest.
 *
 * <p>Both methods are fault-tolerant: a Redis outage is logged as a warning and
 * causes MSAL to fall back to an empty in-memory cache for the current request,
 * which may require the user to re-authenticate if the silent refresh fails.
 */
@Component
public class RedisMsalTokenCache implements ITokenCacheAccessAspect {

    private static final Logger logger = LoggerFactory.getLogger(RedisMsalTokenCache.class);
    private static final String KEY_PREFIX = "msal:token-cache:";
    private static final String APP_PARTITION_PREFIX = "app:";

    private final StringRedisTemplate redisTemplate;
    private final TokenCacheEncryption encryption;
    private final Duration ttl;

    public RedisMsalTokenCache(StringRedisTemplate redisTemplate,
                               TokenCacheEncryption encryption,
                               AppProperties appProperties) {
        this.redisTemplate = redisTemplate;
        this.encryption = encryption;
        this.ttl = appProperties.getRedis().getTtl();
    }

    @Override
    public void beforeCacheAccess(ITokenCacheAccessContext context) {
        String redisKey = KEY_PREFIX + partitionKey(context);
        try {
            String stored = redisTemplate.opsForValue().get(redisKey);
            if (stored == null) {
                return;
            }
            String cacheJson = encryption.isEnabled() ? encryption.decrypt(stored) : stored;
            context.tokenCache().deserialize(cacheJson);
            logger.debug("Loaded MSAL token cache from Redis for key '{}'", LogSanitizer.obfuscate(redisKey));
        } catch (Exception e) {
            logger.warn("Redis read failed for key '{}'; proceeding with empty cache: {}",
                    LogSanitizer.obfuscate(redisKey), e.getMessage());
        }
    }

    @Override
    public void afterCacheAccess(ITokenCacheAccessContext context) {
        if (!context.hasCacheChanged()) {
            return;
        }
        String redisKey = KEY_PREFIX + partitionKey(context);
        try {
            String cacheJson = context.tokenCache().serialize();
            String toStore = encryption.isEnabled() ? encryption.encrypt(cacheJson) : cacheJson;
            redisTemplate.opsForValue().set(redisKey, toStore, ttl);
            logger.debug("Persisted MSAL token cache to Redis for key '{}'", LogSanitizer.obfuscate(redisKey));
        } catch (Exception e) {
            logger.warn("Redis write failed for key '{}'; token cache not persisted: {}",
                    LogSanitizer.obfuscate(redisKey), e.getMessage());
        }
    }

    /**
     * Removes the cached token data for the given account from Redis.
     * Called on logout to immediately invalidate the refresh token cache.
     */
    public void evict(String homeAccountId) {
        String redisKey = KEY_PREFIX + homeAccountId;
        try {
            redisTemplate.delete(redisKey);
            logger.info("Evicted MSAL token cache from Redis for account '{}'",
                    LogSanitizer.obfuscate(homeAccountId));
        } catch (Exception e) {
            logger.error("Failed to evict token cache from Redis for account '{}': {}",
                    LogSanitizer.obfuscate(homeAccountId), e.getMessage());
        }
    }

    private String partitionKey(ITokenCacheAccessContext context) {
        IAccount account = context.account();
        return account != null ? account.homeAccountId() : APP_PARTITION_PREFIX + context.clientId();
    }
}
