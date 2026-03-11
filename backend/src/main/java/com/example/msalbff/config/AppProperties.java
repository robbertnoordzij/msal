package com.example.msalbff.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;

@Component
@ConfigurationProperties(prefix = "app")
public class AppProperties {

    private final AzureAd azureAd = new AzureAd();
    private final Cookie cookie = new Cookie();
    private final Cors cors = new Cors();
    private final Redis redis = new Redis();
    private final TokenCache tokenCache = new TokenCache();

    public AzureAd getAzureAd() {
        return azureAd;
    }

    public Cookie getCookie() {
        return cookie;
    }

    public Cors getCors() {
        return cors;
    }

    public Redis getRedis() {
        return redis;
    }

    public TokenCache getTokenCache() {
        return tokenCache;
    }

    public static class AzureAd {
        private String tenantId;
        private String clientId;
        /**
         * Client secret used when {@link #credentialType} is {@code "secret"} (the default).
         * Not required — and should be left blank — when {@code credentialType=managed-identity}.
         */
        private String clientSecret;
        /**
         * Credential type the backend uses to authenticate against Azure AD.
         * <ul>
         *   <li>{@code "secret"} (default) — plain client secret; requires {@link #clientSecret}.</li>
         *   <li>{@code "managed-identity"} — obtains a signed JWT assertion from the Azure IMDS
         *       endpoint and presents it as a federated client credential. Requires a
         *       <em>Federated Identity Credential</em> to be configured on the app registration
         *       in the Azure Portal (one-time step; no code needed).</li>
         * </ul>
         */
        private String credentialType = "secret";
        /**
         * Client ID of the user-assigned Managed Identity to use when
         * {@link #credentialType} is {@code "managed-identity"}.
         * Leave empty to use the system-assigned Managed Identity.
         */
        private String managedIdentityClientId = "";
        private String authority;
        private String jwkSetUri;
        private String redirectUri;
        private String scopes = "openid profile offline_access User.Read";

        public String getTenantId() { return tenantId; }
        public void setTenantId(String tenantId) { this.tenantId = tenantId; }

        public String getClientId() { return clientId; }
        public void setClientId(String clientId) { this.clientId = clientId; }

        public String getClientSecret() { return clientSecret; }
        public void setClientSecret(String clientSecret) { this.clientSecret = clientSecret; }

        public String getCredentialType() { return credentialType; }
        public void setCredentialType(String credentialType) { this.credentialType = credentialType; }

        public String getManagedIdentityClientId() { return managedIdentityClientId; }
        public void setManagedIdentityClientId(String managedIdentityClientId) { this.managedIdentityClientId = managedIdentityClientId; }

        public String getAuthority() { return authority; }
        public void setAuthority(String authority) { this.authority = authority; }

        public String getJwkSetUri() { return jwkSetUri; }
        public void setJwkSetUri(String jwkSetUri) { this.jwkSetUri = jwkSetUri; }

        public String getRedirectUri() { return redirectUri; }
        public void setRedirectUri(String redirectUri) { this.redirectUri = redirectUri; }

        public String getScopes() { return scopes; }
        public void setScopes(String scopes) { this.scopes = scopes; }

        /** Returns {@link #scopes} as a set, split on whitespace. */
        public Set<String> scopesAsSet() {
            return Arrays.stream(scopes.trim().split("\\s+"))
                    .filter(s -> !s.isBlank())
                    .collect(Collectors.toSet());
        }
    }

    public static class Cookie {
        private String name = "AUTH_TOKEN";
        private int maxAge = 3600;
        private boolean secure = true;
        private String sameSite = "Strict";
        private boolean httpOnly = true;

        public String getName() { return name; }
        public void setName(String name) { this.name = name; }

        public int getMaxAge() { return maxAge; }
        public void setMaxAge(int maxAge) { this.maxAge = maxAge; }

        public boolean isSecure() { return secure; }
        public void setSecure(boolean secure) { this.secure = secure; }

        public String getSameSite() { return sameSite; }
        public void setSameSite(String sameSite) { this.sameSite = sameSite; }

        public boolean isHttpOnly() { return httpOnly; }
        public void setHttpOnly(boolean httpOnly) { this.httpOnly = httpOnly; }
    }

    public static class Cors {
        private String[] allowedOrigins = {"http://localhost:3000"};
        private String[] allowedMethods = {"GET", "POST", "PUT", "DELETE", "OPTIONS"};
        private String[] allowedHeaders = {"*"};
        private boolean allowCredentials = true;

        public String[] getAllowedOrigins() {
            return allowedOrigins;
        }

        public void setAllowedOrigins(String[] allowedOrigins) {
            this.allowedOrigins = allowedOrigins;
        }

        public String[] getAllowedMethods() {
            return allowedMethods;
        }

        public void setAllowedMethods(String[] allowedMethods) {
            this.allowedMethods = allowedMethods;
        }

        public String[] getAllowedHeaders() {
            return allowedHeaders;
        }

        public void setAllowedHeaders(String[] allowedHeaders) {
            this.allowedHeaders = allowedHeaders;
        }

        public boolean isAllowCredentials() {
            return allowCredentials;
        }

        public void setAllowCredentials(boolean allowCredentials) {
            this.allowCredentials = allowCredentials;
        }
    }

    public static class Redis {
        private String host = "localhost";
        private int port = 6379;
        /** Optional Redis password. Leave empty only for local development. */
        private String password;
        /** TTL for cached MSAL token data. Defaults to 90 days (Azure AD refresh token lifetime). */
        private Duration ttl = Duration.ofDays(90);
        /** Enable TLS. Required for Azure Cache for Redis (port 6380). */
        private boolean tls = false;
        /**
         * Base64-encoded 256-bit AES key for encrypting token cache data at rest in Redis.
         * Strongly recommended for non-local environments. Generate with: {@code openssl rand -base64 32}
         */
        private String encryptionKey;

        public String getHost() { return host; }
        public void setHost(String host) { this.host = host; }

        public int getPort() { return port; }
        public void setPort(int port) { this.port = port; }

        public String getPassword() { return password; }
        public void setPassword(String password) { this.password = password; }

        public Duration getTtl() { return ttl; }
        public void setTtl(Duration ttl) { this.ttl = ttl; }

        public boolean isTls() { return tls; }
        public void setTls(boolean tls) { this.tls = tls; }

        public String getEncryptionKey() { return encryptionKey; }
        public void setEncryptionKey(String encryptionKey) { this.encryptionKey = encryptionKey; }
    }

    /**
     * Selects the MSAL token cache backend and configures the cookie-based implementation.
     *
     * <p>Set {@code app.token-cache.type=redis} (default) for clustered deployments
     * or {@code app.token-cache.type=cookie} for single-instance / infrastructure-free setups.
     *
     * <p><strong>Cookie mode notes:</strong>
     * <ul>
     *   <li>{@code cookie.encryption-key} is mandatory when {@code type=cookie} — startup fails if blank.</li>
     *   <li>Rotating the key invalidates all existing cache cookies; users must re-authenticate.</li>
     *   <li>Clustering is not supported: each browser carries its own token cache.</li>
     *   <li>For extra browser enforcement in production, prefix the cookie name with
     *       {@code __Secure-} (e.g. {@code __Secure-MSAL_TOKEN_CACHE}); the {@code Secure}
     *       attribute must then also be {@code true}.</li>
     * </ul>
     */
    public static class TokenCache {
        /** {@code redis} (default) or {@code cookie}. */
        private String type = "redis";
        private final CookieStore cookie = new CookieStore();

        public String getType() { return type; }
        public void setType(String type) { this.type = type; }

        public CookieStore getCookie() { return cookie; }

        /**
         * Cookie storage settings for the MSAL token cache.
         * Bound from {@code app.token-cache.cookie.*}.
         */
        public static class CookieStore {
            /**
             * Base64-encoded 256-bit AES key. Required when {@code type=cookie}.
             * Generate with: {@code openssl rand -base64 32}
             */
            private String encryptionKey;
            /** Name of the HTTP-only cookie that stores the encrypted MSAL token cache. */
            private String name = "MSAL_TOKEN_CACHE";
            /** Lifetime of the cache cookie; should match Azure AD's refresh-token lifetime. */
            private Duration maxAge = Duration.ofDays(90);
            /**
             * Whether the MSAL cache cookie should have the {@code Secure} flag.
             * Defaults to {@code true}. Only set to {@code false} for local HTTP development —
             * never in production, as the cookie contains an encrypted refresh token.
             */
            private boolean secure = true;

            public String getEncryptionKey() { return encryptionKey; }
            public void setEncryptionKey(String encryptionKey) { this.encryptionKey = encryptionKey; }

            public String getName() { return name; }
            public void setName(String name) { this.name = name; }

            public Duration getMaxAge() { return maxAge; }
            public void setMaxAge(Duration maxAge) { this.maxAge = maxAge; }

            public boolean isSecure() { return secure; }
            public void setSecure(boolean secure) { this.secure = secure; }
        }
    }
}