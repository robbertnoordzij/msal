package com.example.msalbff.config;

import com.example.msalbff.service.TokenCacheEncryption;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.connection.RedisStandaloneConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceClientConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.util.StringUtils;

/**
 * Configures the Redis connection using {@code app.redis.*} properties.
 *
 * <p>Active only when {@code app.token-cache.type=redis} (the default). When
 * {@code app.token-cache.type=cookie} is set, this configuration class is skipped
 * entirely and no Redis beans are created.
 *
 * <p>Lettuce establishes connections lazily, so no network call is made during
 * context startup — only when the first Redis command is executed.
 * {@link org.springframework.data.redis.core.StringRedisTemplate} is auto-configured
 * by Spring Boot from this factory.
 */
@Configuration
@ConditionalOnProperty(name = "app.token-cache.type", havingValue = "redis", matchIfMissing = true)
public class RedisConfig {

    private final AppProperties appProperties;

    public RedisConfig(AppProperties appProperties) {
        this.appProperties = appProperties;
    }

    @Bean
    public TokenCacheEncryption tokenCacheEncryption() {
        return new TokenCacheEncryption(appProperties.getRedis().getEncryptionKey());
    }

    @Bean
    public RedisConnectionFactory redisConnectionFactory() {
        AppProperties.Redis redis = appProperties.getRedis();

        RedisStandaloneConfiguration serverConfig =
                new RedisStandaloneConfiguration(redis.getHost(), redis.getPort());
        if (StringUtils.hasText(redis.getPassword())) {
            serverConfig.setPassword(redis.getPassword());
        }

        LettuceClientConfiguration clientConfig = redis.isTls()
                ? LettuceClientConfiguration.builder().useSsl().build()
                : LettuceClientConfiguration.defaultConfiguration();

        return new LettuceConnectionFactory(serverConfig, clientConfig);
    }
}
