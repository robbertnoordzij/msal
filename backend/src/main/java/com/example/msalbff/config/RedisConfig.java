package com.example.msalbff.config;

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
 * <p>Lettuce establishes connections lazily, so no network call is made during
 * context startup — only when the first Redis command is executed.
 * {@link org.springframework.data.redis.core.StringRedisTemplate} is auto-configured
 * by Spring Boot from this factory.
 */
@Configuration
public class RedisConfig {

    private final AppProperties appProperties;

    public RedisConfig(AppProperties appProperties) {
        this.appProperties = appProperties;
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
