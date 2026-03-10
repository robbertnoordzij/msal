package com.example.msalbff.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

@Component
@ConfigurationProperties(prefix = "app")
public class AppProperties {

    private final AzureAd azureAd = new AzureAd();
    private final Cookie cookie = new Cookie();
    private final Cors cors = new Cors();
    private final Redis redis = new Redis();

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

    public static class AzureAd {
        private String tenantId;
        private String clientId;
        private String clientSecret;
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
            return new HashSet<>(Arrays.asList(scopes.split(" ")));
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
        private java.time.Duration ttl = java.time.Duration.ofDays(90);
        /** Enable TLS. Required for Azure Cache for Redis (port 6380). */
        private boolean tls = false;

        public String getHost() { return host; }
        public void setHost(String host) { this.host = host; }

        public int getPort() { return port; }
        public void setPort(int port) { this.port = port; }

        public String getPassword() { return password; }
        public void setPassword(String password) { this.password = password; }

        public java.time.Duration getTtl() { return ttl; }
        public void setTtl(java.time.Duration ttl) { this.ttl = ttl; }

        public boolean isTls() { return tls; }
        public void setTls(boolean tls) { this.tls = tls; }
    }
}