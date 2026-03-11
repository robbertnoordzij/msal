# MSAL Secure BFF Authentication — Implementation Instructions

These instructions enable a Copilot instance to implement the **Backend-for-Frontend (BFF) MSAL authentication pattern** into an existing codebase. The pattern uses a Spring Boot backend as the sole token handler, stores the Azure AD ID token in an **HTTP-only cookie**, and caches refresh tokens server-side so that no secrets or refresh tokens are ever sent to the browser.

---

## 🤖 Copilot Instance — Start Here

**Before writing any code, ask the user:**

> "Which token cache backend would you like to use for storing MSAL refresh tokens?
>
> - **Option A: Redis** *(default)* — requires a Redis instance (Docker locally, Azure Cache for Redis in production). Best for clustered / multi-replica deployments where all pods share the same cache.
> - **Option B: Cookie** — no external infrastructure required. The encrypted refresh token is stored in an AES-256-GCM encrypted HTTP-only cookie (`MSAL_TOKEN_CACHE`). Best for single-instance / no-Redis deployments."

Record the answer and follow the sections marked **[Redis only]** or **[Cookie only]** throughout this guide. Sections with no tag apply to both.

---

## Architecture Overview

```
Browser (React / any SPA)
    │  Cookie: AUTH_TOKEN (HttpOnly, Secure, SameSite)
    ▼
Spring Boot BFF  (/api/auth/*)
    │  PKCE + Authorization Code Flow
    ▼
Azure Entra ID (Azure AD)

Spring Boot BFF  (token cache — choose one)
    │  AES-256-GCM encrypted MSAL cache per user
    ├─[Redis]──▶ Redis  (key: msal:token-cache:{oid.tid})
    └─[Cookie]─▶ MSAL_TOKEN_CACHE cookie (HttpOnly, SameSite=Strict)
```

**Key security properties (both backends):**
- The browser **never** sees access tokens or refresh tokens in plain text.
- JWT ID token is validated on every request against Azure AD's JWK Set endpoint.
- Refresh tokens are encrypted at rest with AES-256-GCM before storage.
- PKCE (S256) and a random `state` cookie prevent CSRF and code-injection attacks.
- `SameSite=Strict` on `AUTH_TOKEN` provides CSRF protection; `SameSite=Lax` on OAuth flow cookies is required so the Azure AD redirect carries them back.

**Cookie cache additional notes:**
- Only the `RefreshToken` and `Account` sections of the MSAL cache are stored in the cookie (access tokens and ID tokens are stripped to keep the payload within the 4 KB browser cookie limit).
- Cookie cache is bound to the user's browser — no clustering support.
- Requires a unique `app.token-cache.cookie.encryption-key` (startup fails if absent).

---

## Prerequisites

### 1. Azure AD App Registration

In the [Azure Portal → Entra ID → App registrations](https://portal.azure.com):

1. **New registration**: give it a name, choose "Single tenant" (or as appropriate).
2. **Note the values**: `Application (client) ID` → `AZURE_CLIENT_ID`, `Directory (tenant) ID` → `AZURE_TENANT_ID`.
3. **Certificates & Secrets → New client secret**: note the value → `AZURE_CLIENT_SECRET`.
4. **Authentication → Add a platform → Web**:
   - Redirect URI: `{FRONTEND_URL}{BACKEND_CONTEXT_PATH}/auth/callback`
     - Example: `http://localhost:3000/api/auth/callback` (local dev)
     - Example: `https://myapp.example.com/api/auth/callback` (production)
   - Enable **ID tokens** under Implicit grant (optional; not required for auth-code flow).
5. **API permissions**: `openid`, `profile`, `offline_access`, `User.Read` (delegated).

### 2. Redis **[Redis only]**

- **Local dev**: use the provided `docker-compose.yml` — it starts Redis 7 with a password.
- **Production**: Azure Cache for Redis (set `REDIS_TLS=true`, port 6380) or equivalent.
- Redis is **required** for silent token refresh across multiple backend replicas. Without it, token refresh still works on a single instance (MSAL falls back to in-memory cache with a WARN log).

### 2. Encryption key **[Cookie only]**

Generate a 32-byte AES-256 key and keep it secret:

```sh
openssl rand -base64 32
```

Store it as `TOKEN_CACHE_COOKIE_ENCRYPTION_KEY` in your `.env` / secret manager. **The backend refuses to start without it when cookie mode is active.**

---

## Backend Repository — Spring Boot

### 1. Maven Dependencies (`pom.xml`)

Add the following to `<dependencies>`:

```xml
<!-- Spring Security + JWT resource server -->
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-security</artifactId>
</dependency>
<dependency>
    <groupId>org.springframework.security</groupId>
    <artifactId>spring-security-oauth2-resource-server</artifactId>
</dependency>
<dependency>
    <groupId>org.springframework.security</groupId>
    <artifactId>spring-security-oauth2-jose</artifactId>
</dependency>

<!-- Redis for distributed MSAL token cache [Redis only] -->
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-data-redis</artifactId>
</dependency>

<!-- MSAL4J — server-side OAuth code exchange and silent refresh -->
<dependency>
    <groupId>com.microsoft.azure</groupId>
    <artifactId>msal4j</artifactId>
    <version>1.17.2</version>
</dependency>

<!-- Validation -->
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-validation</artifactId>
</dependency>
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-configuration-processor</artifactId>
    <optional>true</optional>
</dependency>
```

> **[Cookie only]** The Redis dependency above can be omitted. Jackson (`com.fasterxml.jackson.databind`) is already present via `spring-boot-starter-web` and is used to strip large token sections before encryption.

Add to `<build><plugins>` (required for Mockito on JDK 21+; keep if tests are added):

```xml
<plugin>
    <groupId>org.apache.maven.plugins</groupId>
    <artifactId>maven-surefire-plugin</artifactId>
    <configuration>
        <argLine>
            -XX:+EnableDynamicAgentLoading
            --add-opens java.base/java.lang=ALL-UNNAMED
        </argLine>
    </configuration>
</plugin>
```

### 2. Configuration Properties

#### `application.properties` (adapt values from environment)

```properties
# Server — adjust port and context path to match your deployment
server.port=8080
server.servlet.context-path=/api

# Azure AD
app.azure-ad.tenant-id=${AZURE_TENANT_ID}
app.azure-ad.client-id=${AZURE_CLIENT_ID}
app.azure-ad.client-secret=${AZURE_CLIENT_SECRET}
app.azure-ad.authority=https://login.microsoftonline.com/${app.azure-ad.tenant-id}
app.azure-ad.jwk-set-uri=${app.azure-ad.authority}/discovery/v2.0/keys
# Must exactly match the redirect URI registered in Azure AD
app.azure-ad.redirect-uri=${FRONTEND_URL}/api/auth/callback
app.azure-ad.scopes=openid profile offline_access User.Read

# Cookie
app.cookie.name=AUTH_TOKEN
app.cookie.max-age=3600
app.cookie.secure=true          # false only for local HTTP dev
app.cookie.same-site=Strict     # Lax only if redirect-based SSO is needed
app.cookie.http-only=true

# CORS — list every frontend origin that the browser will make requests from
app.cors.allowed-origins=${FRONTEND_URL}
app.cors.allowed-methods=GET,POST,PUT,DELETE,OPTIONS
app.cors.allowed-headers=*
app.cors.allow-credentials=true

# Token cache backend: "redis" (default, requires Redis) | "cookie" (no infrastructure needed)
app.token-cache.type=${TOKEN_CACHE_TYPE:redis}

# [Redis only] Redis connection
app.redis.host=${REDIS_HOST:localhost}
app.redis.port=${REDIS_PORT:6379}
app.redis.password=${REDIS_PASSWORD}
app.redis.ttl=90d               # Spring Duration: "90d", "24h", "3600s"
app.redis.tls=false             # true for Azure Cache for Redis (port 6380)
# AES-256-GCM key for Redis token cache encryption. Generate: openssl rand -base64 32
app.redis.encryption-key=${REDIS_ENCRYPTION_KEY:}

# [Cookie only] Cookie cache settings
# Required when app.token-cache.type=cookie (startup fails if blank)
app.token-cache.cookie.encryption-key=${TOKEN_CACHE_COOKIE_ENCRYPTION_KEY:}
app.token-cache.cookie.name=MSAL_TOKEN_CACHE
app.token-cache.cookie.max-age=90d
app.token-cache.cookie.secure=${COOKIE_SECURE:true}
```

### 3. Source Files to Create

Use the **exact package structure** that matches your project's base package. All examples below use `com.example.msalbff` — **replace with your own base package**.

---

#### `config/AppProperties.java`

Binds all `app.*` properties. Contains nested static classes: `AzureAd`, `Cookie`, `Cors`, `Redis`, `TokenCache`.

```java
@Component
@ConfigurationProperties(prefix = "app")
public class AppProperties {
    private final AzureAd azureAd = new AzureAd();
    private final Cookie cookie = new Cookie();
    private final Cors cors = new Cors();
    private final Redis redis = new Redis();
    private final TokenCache tokenCache = new TokenCache();

    // getters for each nested class ...

    public static class AzureAd {
        private String tenantId, clientId, clientSecret, authority, jwkSetUri, redirectUri;
        private String scopes = "openid profile offline_access User.Read";

        public Set<String> scopesAsSet() {
            // split on whitespace, trim, filter blanks
            return Arrays.stream(scopes.split("\\s+"))
                         .map(String::trim)
                         .filter(s -> !s.isEmpty())
                         .collect(Collectors.toSet());
        }
        // standard getters/setters ...
    }

    public static class Cookie {
        private String name = "AUTH_TOKEN";
        private int maxAge = 3600;
        private boolean secure = true;
        private String sameSite = "Strict";
        private boolean httpOnly = true;
        // standard getters/setters ...
    }

    public static class Cors {
        private String[] allowedOrigins = {"http://localhost:3000"};
        private String[] allowedMethods = {"GET","POST","PUT","DELETE","OPTIONS"};
        private String[] allowedHeaders = {"*"};
        private boolean allowCredentials = true;
        // standard getters/setters ...
    }

    public static class Redis {
        private String host = "localhost";
        private int port = 6379;
        private String password;
        private java.time.Duration ttl = java.time.Duration.ofDays(90);
        private boolean tls = false;
        private String encryptionKey;  // base64-encoded 32-byte AES key
        // standard getters/setters ...
    }

    /** Selects between Redis and Cookie cache backends; binds app.token-cache.* */
    public static class TokenCache {
        private String type = "redis";  // "redis" | "cookie"
        private final CookieStore cookie = new CookieStore();
        // standard getters/setters ...

        /** Binds app.token-cache.cookie.* — required only when type=cookie */
        public static class CookieStore {
            private String name = "MSAL_TOKEN_CACHE";
            private java.time.Duration maxAge = java.time.Duration.ofDays(90);
            private String encryptionKey;  // required; startup fails if blank
            private boolean secure = true;
            // standard getters/setters ...
        }
    }
}
```

> **Important:** `TokenCache.CookieStore` uses a nested dot in the property name
> (`app.token-cache.cookie.*`). Spring Boot binds the `cookie` sub-object correctly
> because `CookieStore` is a nested static class with its own `@ConfigurationProperties`-style
> binding. **Do not** flatten these as `cookieName`, `cookieEncryptionKey` etc. on
> `TokenCache` directly — Spring would try to bind `app.token-cache.cookie-name` (hyphen),
> which would mismatch the intended dot-notation keys.

---

#### `config/RedisConfig.java` **[Redis only]**

Creates a `RedisConnectionFactory` from `AppProperties.Redis`. Spring Boot auto-configures `StringRedisTemplate` from it. Guard with `@ConditionalOnProperty` so no Redis beans are created in cookie mode.

```java
@Configuration
@ConditionalOnProperty(name = "app.token-cache.type", havingValue = "redis", matchIfMissing = true)
public class RedisConfig {
    private final AppProperties appProperties;
    public RedisConfig(AppProperties appProperties) { this.appProperties = appProperties; }

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

    @Bean
    public TokenCacheEncryption tokenCacheEncryption() {
        return new TokenCacheEncryption(appProperties.getRedis().getEncryptionKey());
    }
}
```

---

#### `config/TokenCacheConfig.java`

Selects the active `MsalTokenCacheService` implementation based on `app.token-cache.type`. Both beans carry their own `@ConditionalOnProperty`, so only one is ever instantiated.

```java
@Configuration
public class TokenCacheConfig {
    // No @Bean factory method needed here when both implementations
    // carry @ConditionalOnProperty themselves — Spring picks the right one.
    // Add a @Bean method only if you prefer explicit wiring over annotation scanning.
}
```

In practice, the selection is entirely handled by `@ConditionalOnProperty` on `RedisMsalTokenCache` and `CookieMsalTokenCache` (see below). `TokenCacheConfig` exists as an extension point and to make the intent explicit.

---

#### `config/WebConfig.java`

Exposes `CorsConfigurationSource` as a bean so both `SecurityConfig` and Spring MVC share the same CORS policy.

```java
@Configuration
public class WebConfig implements WebMvcConfigurer {
    private final AppProperties appProperties;
    public WebConfig(AppProperties appProperties) { this.appProperties = appProperties; }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOriginPatterns(Arrays.asList(appProperties.getCors().getAllowedOrigins()));
        config.setAllowedMethods(Arrays.asList(appProperties.getCors().getAllowedMethods()));
        config.setAllowedHeaders(Arrays.asList(appProperties.getCors().getAllowedHeaders()));
        config.setAllowCredentials(appProperties.getCors().isAllowCredentials());
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }
}
```

---

#### `config/SecurityConfig.java`

Key decisions:
- **CSRF disabled** — `SameSite=Strict` cookies provide equivalent protection.
- **`STATELESS`** — no Spring session; PKCE verifier and OAuth state are stored in short-lived cookies instead.
- `/auth/**` and `/health` are public; everything else requires authentication.

```java
@Configuration
@EnableWebSecurity
public class SecurityConfig {
    // inject: CorsConfigurationSource, TokenValidationService, TokenExchangeService,
    //         AuthCookieService, AppProperties

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .cors(cors -> cors.configurationSource(corsConfigurationSource))
            .csrf(AbstractHttpConfigurer::disable)
            .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(authz -> authz
                .requestMatchers("/auth/**").permitAll()
                .requestMatchers("/health").permitAll()
                .anyRequest().authenticated()
            )
            .addFilterBefore(cookieAuthenticationFilter(),
                UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }

    @Bean
    public CookieAuthenticationFilter cookieAuthenticationFilter() {
        return new CookieAuthenticationFilter(
            tokenValidationService, tokenExchangeService,
            authCookieService, appProperties);
    }
}
```

---

#### `service/TokenCacheEncryption.java`

AES-256-GCM encryption/decryption for the MSAL token cache.
Key is passed in as a constructor argument (base64-encoded 32-byte value).

- **Redis mode**: instantiated as a `@Bean` by `RedisConfig` using `app.redis.encryption-key`. If no key is configured, encryption is disabled (suitable for local dev only — logs a `WARN`).
- **Cookie mode**: instantiated directly by `CookieMsalTokenCache` using `app.token-cache.cookie.encryption-key`. A missing key causes a startup `IllegalArgumentException`.

Do **not** annotate this class with `@Service` or `@Value` — it is a plain utility and is instantiated explicitly to support both key sources.

Important implementation details:
- Each call to `encrypt()` generates a fresh 12-byte random IV.
- The encoded output is `base64(iv || ciphertext)`.
- `decrypt()` splits out the IV prefix before decrypting.
- Tag length is 128 bits (GCM default).

---

#### `service/MsalTokenCacheService.java`

Common interface implemented by both cache backends. Extend `ITokenCacheAccessAspect` (MSAL4J) and add the `evict` method so `AuthController` can invalidate a specific user's cache on logout without knowing the concrete implementation.

```java
public interface MsalTokenCacheService extends ITokenCacheAccessAspect {
    /**
     * Removes the cached tokens for the given user on logout.
     * @param homeAccountId MSAL account identifier in the form {@code oid.tid}
     */
    void evict(String homeAccountId);
}
```

Both `RedisMsalTokenCache` and `CookieMsalTokenCache` implement this interface. `AuthController` and `TokenExchangeService` depend only on `MsalTokenCacheService`.

---

#### `service/RedisMsalTokenCache.java` **[Redis only]**

Implements `MsalTokenCacheService`. Guard with `@ConditionalOnProperty` so it is only created in Redis mode.

```java
@Component
@ConditionalOnProperty(name = "app.token-cache.type", havingValue = "redis", matchIfMissing = true)
public class RedisMsalTokenCache implements MsalTokenCacheService {
    private static final String KEY_PREFIX = "msal:token-cache:";
    // inject: StringRedisTemplate, TokenCacheEncryption, AppProperties

    @Override
    public void beforeCacheAccess(ITokenCacheAccessContext ctx) {
        String key = redisKey(ctx);
        try {
            String stored = redisTemplate.opsForValue().get(key);
            if (stored == null) return;
            String json = encryption.isEnabled() ? encryption.decrypt(stored) : stored;
            ctx.tokenCache().deserialize(json);
        } catch (Exception e) { /* log WARN, proceed with empty cache */ }
    }

    @Override
    public void afterCacheAccess(ITokenCacheAccessContext ctx) {
        if (!ctx.hasCacheChanged()) return;
        String key = redisKey(ctx);
        try {
            String json = ctx.tokenCache().serialize();
            String toStore = encryption.isEnabled() ? encryption.encrypt(json) : json;
            redisTemplate.opsForValue().set(key, toStore, ttl);
        } catch (Exception e) { /* log WARN */ }
    }

    @Override
    public void evict(String homeAccountId) {
        try {
            redisTemplate.delete(KEY_PREFIX + homeAccountId);
        } catch (Exception e) { /* log WARN */ }
    }

    private String redisKey(ITokenCacheAccessContext ctx) {
        IAccount account = ctx.account();
        return KEY_PREFIX + (account != null ? account.homeAccountId() : "app:" + ctx.clientId());
    }
}
```

---

#### `service/CookieMsalTokenCache.java` **[Cookie only]**

Implements `MsalTokenCacheService`. Guard with `@ConditionalOnProperty`. Requires `RequestContextHolder` to be populated (i.e., called from an HTTP request thread). Ensure the MSAL client is built with a caller-runs executor (see `TokenExchangeService` below) so MSAL cache callbacks run on the HTTP request thread.

```java
@Component
@ConditionalOnProperty(name = "app.token-cache.type", havingValue = "cookie")
public class CookieMsalTokenCache implements MsalTokenCacheService {

    static final int MAX_COOKIE_VALUE_BYTES = 4090;

    /**
     * Only these sections are persisted to the cookie.
     * AccessToken / IdToken / AppMetadata are stripped to stay within the 4 KB limit.
     */
    private static final List<String> PERSISTED_CACHE_SECTIONS = List.of("RefreshToken", "Account");
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    private final AuthCookieService authCookieService;
    private final TokenCacheEncryption encryption;

    public CookieMsalTokenCache(AppProperties appProperties, AuthCookieService authCookieService) {
        String key = appProperties.getTokenCache().getCookie().getEncryptionKey();
        if (key == null || key.isBlank()) {
            throw new IllegalArgumentException(
                "app.token-cache.cookie.encryption-key must be set when app.token-cache.type=cookie. "
                + "Generate: openssl rand -base64 32");
        }
        this.encryption = new TokenCacheEncryption(key);
        this.authCookieService = authCookieService;
    }

    @Override
    public void beforeCacheAccess(ITokenCacheAccessContext context) {
        try {
            ServletRequestAttributes attrs = currentRequestAttributes();
            String cookieValue = authCookieService.getMsalCacheCookie(attrs.getRequest()).orElse(null);
            if (cookieValue == null || cookieValue.isBlank()) return;
            String cacheJson = decodeAndDecompress(encryption.decrypt(cookieValue));
            context.tokenCache().deserialize(cacheJson);
        } catch (Exception e) {
            logger.warn("Failed to load MSAL token cache from cookie; proceeding with empty cache: {}",
                e.getMessage());
        }
    }

    @Override
    public void afterCacheAccess(ITokenCacheAccessContext context) {
        if (!context.hasCacheChanged()) return;
        try {
            String slimJson = retainPersistedSections(context.tokenCache().serialize());
            String cookieValue = encryption.encrypt(compressAndEncode(slimJson));
            if (cookieValue.getBytes(StandardCharsets.UTF_8).length > MAX_COOKIE_VALUE_BYTES) {
                logger.error("MSAL token cache cookie would exceed {} bytes; skipping write. "
                    + "Consider switching to Redis.", MAX_COOKIE_VALUE_BYTES);
                return;
            }
            HttpServletResponse response = currentRequestAttributes().getResponse();
            if (response != null) authCookieService.setMsalCacheCookie(response, cookieValue);
        } catch (Exception e) {
            logger.warn("Failed to persist MSAL token cache to cookie: {}", e.getMessage());
        }
    }

    @Override
    public void evict(String homeAccountId) {
        try {
            HttpServletResponse response = currentRequestAttributes().getResponse();
            if (response != null) authCookieService.clearMsalCacheCookie(response);
        } catch (Exception e) {
            logger.error("Failed to evict MSAL token cache cookie: {}", e.getMessage());
        }
    }

    /** Keeps only RefreshToken + Account sections; strips AccessToken, IdToken, AppMetadata. */
    static String retainPersistedSections(String json) throws IOException {
        JsonNode root = OBJECT_MAPPER.readTree(json);
        ObjectNode slim = OBJECT_MAPPER.createObjectNode();
        for (String section : PERSISTED_CACHE_SECTIONS) {
            if (root.has(section)) slim.set(section, root.get(section));
        }
        return OBJECT_MAPPER.writeValueAsString(slim);
    }

    private static String compressAndEncode(String text) throws IOException { /* GZIP + Base64 */ }
    private static String decodeAndDecompress(String encoded) throws IOException { /* Base64 + GUNZIP */ }
    private static ServletRequestAttributes currentRequestAttributes() {
        return (ServletRequestAttributes) RequestContextHolder.currentRequestAttributes();
    }
}
```

**`AuthCookieService` additions** — add these three methods to `AuthCookieService` to handle the MSAL cache cookie:

```java
/** Writes the encrypted MSAL cache as an HttpOnly cookie. */
public void setMsalCacheCookie(HttpServletResponse response, String encryptedValue) { ... }

/** Clears the MSAL cache cookie (Max-Age=0). */
public void clearMsalCacheCookie(HttpServletResponse response) { ... }

/** Returns the MSAL cache cookie value, or empty if absent. */
public Optional<String> getMsalCacheCookie(HttpServletRequest request) { ... }
```

Cookie attributes: `HttpOnly`, `SameSite=Strict`, `Secure` from `app.token-cache.cookie.secure`, `Max-Age` from `app.token-cache.cookie.max-age`.

---

#### `service/TokenExchangeService.java`

Wraps `ConfidentialClientApplication` (MSAL4J singleton). Initialized with `@PostConstruct`. Inject `MsalTokenCacheService` (not the concrete implementation).

**Critical: caller-runs executor.** MSAL4J's cache callbacks (`beforeCacheAccess` / `afterCacheAccess`) run on MSAL's internal executor threads by default. `CookieMsalTokenCache` reads/writes HTTP cookies via `RequestContextHolder`, which uses thread-locals. Unless the callbacks run on the HTTP request thread, `RequestContextHolder.currentRequestAttributes()` throws `IllegalStateException: No thread-bound request found`.

Fix: pass a caller-runs `ExecutorService` to the MSAL builder so all MSAL tasks run synchronously on the calling (HTTP request) thread. Since all callers already block with `.get(timeout)`, there is no change in effective concurrency.

```java
private static final ExecutorService CALLER_RUNS_EXECUTOR =
    new AbstractExecutorService() {
        public void execute(Runnable command) { command.run(); }
        public void shutdown() {}
        public List<Runnable> shutdownNow() { return Collections.emptyList(); }
        public boolean isShutdown()  { return false; }
        public boolean isTerminated() { return false; }
        public boolean awaitTermination(long t, TimeUnit u) { return true; }
    };

@PostConstruct
public void init() throws Exception {
    IClientCredential credential = ClientCredentialFactory.createFromSecret(clientSecret);
    msalClient = ConfidentialClientApplication.builder(clientId, credential)
        .authority(authority)
        .setTokenCacheAccessAspect(tokenCache)
        .executorService(CALLER_RUNS_EXECUTOR)   // ← required for cookie cache
        .build();
}
```

Provides four methods:
1. **`generateAuthorizationUrl(redirectUri, scopes, state, codeChallenge)`** — builds the Azure AD authorization URL with PKCE S256 and `prompt=select_account`.
2. **`exchangeAuthorizationCode(code, redirectUri, scopes, codeVerifier)`** — exchanges the authorization code for tokens; returns `IAuthenticationResult`.
3. **`acquireTokenSilently(homeAccountId, scopes)`** — looks up the MSAL account by `homeAccountId` in the loaded cache and calls `acquireTokenSilently`. Returns `Optional.empty()` on any failure (expired/revoked, cache miss, timeout).
4. **`acquireTokenSilentlyFromCache(scopes)`** *(new)* — calls `msalClient.getAccounts()` (which triggers `beforeCacheAccess` to load the persistent cache), picks the first cached account, then calls `acquireTokenSilently` with that account. Used for the **session restore path** (AUTH_TOKEN absent, MSAL cache present). Returns `Optional.empty()` if no accounts are cached or the refresh token has expired.

All blocking MSAL calls use `.get(30, TimeUnit.SECONDS)` to prevent thread exhaustion.

---

#### `service/TokenValidationService.java`

Validates Azure AD JWT ID tokens using `NimbusJwtDecoder` (initialized with the JWK Set URI).

**`validateToken(token)`** checks:
1. Signature via JWK Set.
2. `exp` — not expired.
3. `iss` — must equal `https://login.microsoftonline.com/{tenantId}/v2.0`.
4. `aud` — must contain `clientId`.

**`parseToken(token)`** — parses a raw JWT string into a Spring `Jwt` object **without** re-validating the signature. Used for reading claims from expired tokens (e.g., to extract `oid`/`tid` for silent refresh).

**`getUserName(jwt)`** — returns the first non-null value of `name`, `preferred_username`, or `upn` claims; falls back to `sub`.

**`getUserEmail(jwt)`** — returns `email` or `preferred_username`.

---

#### `service/AuthCookieService.java`

Centralizes all cookie creation. Uses Spring's `ResponseCookie` builder and writes via `response.addHeader(HttpHeaders.SET_COOKIE, ...)`.

Two cookie categories:
- **`AUTH_TOKEN`** — long-lived, configured from `AppProperties.Cookie` (`HttpOnly`, `Secure`, `SameSite=Strict`).
- **`OAUTH_STATE` + `PKCE_VERIFIER`** — short-lived (5 min), `SameSite=Lax` (required for the cross-site Azure AD redirect to carry them back).

Public API:
```
setAuthCookie(response, idToken)
clearAuthCookie(response)
setOAuthStateCookie(response, state)
setPkceVerifierCookie(response, verifier)
getOAuthStateCookie(request) → String|null
getPkceVerifierCookie(request) → String|null
clearOAuthFlowCookies(response)
```

---

#### `security/CookieAuthenticationFilter.java`

Extends `OncePerRequestFilter`. Skips `/auth/**` paths entirely.

**Token refresh strategy** (per request):

1. **AUTH_TOKEN present and valid, not expiring within 300 s** → authenticate from current token, no refresh.
2. **AUTH_TOKEN present and valid, expiring within 300 s** → authenticate from current token AND trigger `tryRefreshToken()` (proactive refresh). The `homeAccountId` is derived from `oid` + `tid` claims in the current JWT.
3. **AUTH_TOKEN present but invalid/tampered** → do **not** attempt refresh; proceed unauthenticated (Spring returns 401).
4. **AUTH_TOKEN absent, MSAL cache cookie present** → call `tryRefreshTokenFromMsalCache()` which calls `tokenExchangeService.acquireTokenSilentlyFromCache()`. On success, set `AUTH_TOKEN` cookie and authenticate. This path is primarily for **cookie cache mode**: the `MSAL_TOKEN_CACHE` cookie outlives the shorter-lived `AUTH_TOKEN` cookie.
5. **AUTH_TOKEN absent, no MSAL cache** → proceed unauthenticated.

```java
@Override
protected void doFilterInternal(HttpServletRequest request,
                                HttpServletResponse response,
                                FilterChain filterChain) throws ServletException, IOException {
    if (request.getServletPath().startsWith("/auth/")) {
        filterChain.doFilter(request, response);
        return;
    }

    String token = extractTokenFromCookie(request);

    if (token != null) {
        if (tokenValidationService.validateToken(token)) {
            Jwt jwt = tokenValidationService.parseToken(token);
            setAuthentication(jwt);

            if (isExpiringSoon(jwt)) {
                tryRefreshToken(token, response);  // proactive refresh only
            }
        }
        // Invalid/tampered token: no refresh attempt
    } else {
        // No AUTH_TOKEN — attempt session restore from MSAL cache
        tryRefreshTokenFromMsalCache(request, response);
    }

    filterChain.doFilter(request, response);
}

private void tryRefreshToken(String token, HttpServletResponse response) {
    String homeAccountId = extractHomeAccountId(token);  // reads oid+tid from JWT claims
    if (homeAccountId == null) return;
    tokenExchangeService.acquireTokenSilently(homeAccountId, scopes).ifPresent(result -> {
        Jwt jwt = tokenValidationService.parseToken(result.idToken());
        setAuthentication(jwt);
        authCookieService.setAuthCookie(response, result.idToken());
    });
}

private void tryRefreshTokenFromMsalCache(HttpServletRequest request,
                                          HttpServletResponse response) {
    if (authCookieService.getMsalCacheCookie(request).isEmpty()) return;
    tokenExchangeService.acquireTokenSilentlyFromCache(scopes).ifPresent(result -> {
        Jwt jwt = tokenValidationService.parseToken(result.idToken());
        setAuthentication(jwt);
        authCookieService.setAuthCookie(response, result.idToken());
    });
}
```

Roles are mapped from the `roles` claim as `ROLE_{ROLE_NAME_UPPERCASE}` `GrantedAuthority` entries.

---

#### `controller/AuthController.java`

Handles the OAuth 2.0 PKCE login flow. Annotate with `@RequestMapping("/auth")`.

**`GET /auth/login`**:
1. Generate random `state` UUID → set `OAUTH_STATE` cookie.
2. Generate PKCE verifier (32 random bytes, base64url-encoded) → set `PKCE_VERIFIER` cookie.
3. Compute PKCE challenge: `base64url(SHA-256(verifier))`.
4. Call `tokenExchangeService.generateAuthorizationUrl(...)` → `302` redirect to Azure AD.

**`GET /auth/callback`** (registered as redirect URI in Azure AD):
1. Handle `error` query param → redirect to `{frontendUrl}/?login=error`.
2. Validate `state` against `OAUTH_STATE` cookie → reject mismatches (CSRF protection).
3. Read `PKCE_VERIFIER` cookie.
4. Call `tokenExchangeService.exchangeAuthorizationCode(code, redirectUri, scopes, verifier)`.
5. Extract `result.idToken()` → store in `AUTH_TOKEN` cookie via `authCookieService.setAuthCookie(response, idToken)`.
6. Clear OAuth flow cookies.
7. Redirect to `{frontendUrl}/?login=success`.

**`POST /auth/logout`**:
1. Parse `oid` + `tid` from `AUTH_TOKEN` cookie → call `msalTokenCacheService.evict(oid + "." + tid)` (works for both Redis and Cookie cache).
2. Call `authCookieService.clearAuthCookie(response)`.

**`frontendUrl()` helper**: returns `appProperties.getCors().getAllowedOrigins()[0]`.

**PKCE helpers** (private):
```java
private String generateCodeVerifier() {
    byte[] bytes = new byte[32];
    new SecureRandom().nextBytes(bytes);
    return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
}

private String generateCodeChallenge(String verifier) throws Exception {
    byte[] digest = MessageDigest.getInstance("SHA-256")
        .digest(verifier.getBytes(StandardCharsets.US_ASCII));
    return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
}
```

---

#### `controller/ApiController.java` (example protected endpoint)

Shows how to use the authentication set by `CookieAuthenticationFilter`:

```java
@GetMapping("/hello")
public ResponseEntity<ApiResponse<String>> hello() {
    Authentication auth = SecurityContextHolder.getContext().getAuthentication();
    if (auth == null || !auth.isAuthenticated()) {
        return ResponseEntity.status(401).body(ApiResponse.error("Authentication required"));
    }
    return ResponseEntity.ok(ApiResponse.success("OK", "Hello " + auth.getName() + "!"));
}

@GetMapping("/userinfo")
public ResponseEntity<ApiResponse<UserInfo>> getUserInfo() {
    Authentication auth = SecurityContextHolder.getContext().getAuthentication();
    Jwt jwt = (Jwt) auth.getDetails();
    UserInfo info = new UserInfo(
        tokenValidationService.getUserName(jwt),
        tokenValidationService.getUserEmail(jwt),
        jwt.getSubject());
    return ResponseEntity.ok(ApiResponse.success("OK", info));
}
```

---

#### `service/LogSanitizer.java` (utility)

```java
final class LogSanitizer {
    private LogSanitizer() {}
    static String obfuscate(String value) {
        if (value == null || value.length() < 4) return "***";
        int tail = Math.min(8, value.length() / 4);
        return "…" + value.substring(value.length() - tail);
    }
}
```

Use wherever `homeAccountId` or Redis keys appear in log statements.

---

## Tests

Write tests alongside each source file. The project uses **JUnit 5 + Mockito** (provided by `spring-boot-starter-test`). Do **not** add `mockito-inline` — use the patterns below to stay within what the starter provides.

### Unit test structure

Place tests under `src/test/java` mirroring the source package. Use `@ExtendWith(MockitoExtension.class)` for pure unit tests and `@SpringBootTest` only when Spring context wiring must be verified.

```
src/test/java/com/example/msalbff/
├── config/
│   └── AppPropertiesTest.java          ← validates property defaults & validation
├── security/
│   ├── CookieAuthenticationFilterTest.java
│   └── TokenCookieHelperTest.java
├── service/
│   ├── TokenExchangeServiceTest.java
│   ├── CookieMsalTokenCacheServiceTest.java
│   └── RedisMsalTokenCacheServiceTest.java
└── controller/
    └── AuthControllerTest.java
```

### What to test per class

#### `TokenExchangeService`

Cover every credential path in `buildCredential()`:

```java
@ExtendWith(MockitoExtension.class)
class TokenExchangeServiceTest {

    @Nested
    @MockitoSettings(strictness = Strictness.LENIENT) // required: createFromCallback is eager
    class BuildCredential {

        @Test
        void secret_mode_returnsClientSecretCredential() {
            // arrange: credentialType="secret", clientSecret="my-secret"
            // act: service.init()
            // assert: no exception, confidentialClientApplication is non-null
        }

        @Test
        void secret_mode_throwsWhenClientSecretBlank() {
            // arrange: credentialType="secret", clientSecret=""
            // assert: throws IllegalStateException mentioning "azure-ad.client-secret"
        }

        @Test
        void managedIdentity_systemAssigned_buildsCredentialWithoutClientId() {
            // arrange: credentialType="managed-identity", managedIdentityClientId=""
            // spy on service; doReturn(mockMiCredential).when(spy).buildManagedIdentityTokenCredential(...)
            // assert: buildManagedIdentityTokenCredential called with empty clientId
        }

        @Test
        void managedIdentity_userAssigned_passesClientIdToTokenCredential() {
            // arrange: credentialType="managed-identity", managedIdentityClientId="mi-client-id"
            // spy on service; doReturn(mockMiCredential).when(spy).buildManagedIdentityTokenCredential(...)
            // assert: buildManagedIdentityTokenCredential called with correct clientId
        }
    }

    @Nested
    class AcquireToken { /* test exchangeCodeForTokens, acquireTokenSilently */ }
}
```

> **Why `@MockitoSettings(LENIENT)` on the MI tests?**
> `ClientCredentialFactory.createFromCallback(Callable)` is **eager**: it submits the callable to an internal executor and calls `future.get()` synchronously. The callable may (or may not) be observed by Mockito's stub accounting depending on thread scheduling. `LENIENT` prevents a spurious `UnnecessaryStubbing` failure.

> **Why a protected factory method?**
> `MockedConstruction<ManagedIdentityCredentialBuilder>` requires `mockito-inline`, which is not on the classpath. Extracting `protected buildManagedIdentityTokenCredential(AzureAd)` lets a `spy(service)` override the method directly without constructor mocking.

#### `CookieMsalTokenCacheService`

```java
@ExtendWith(MockitoExtension.class)
class CookieMsalTokenCacheServiceTest {

    // Inject a mock HttpServletRequest / HttpServletResponse via
    // MockHttpServletRequest / MockHttpServletResponse (spring-test provides these)

    @Test void beforeCacheAccess_loadsFromCookie_whenCookiePresent() { ... }
    @Test void beforeCacheAccess_usesEmptyCache_whenCookieAbsent() { ... }
    @Test void afterCacheAccess_writesCookie_whenCacheChanged() { ... }
    @Test void afterCacheAccess_skipsWrite_whenCacheUnchanged() { ... }
    @Test void afterCacheAccess_skipsWrite_whenSerializedExceedsSizeLimit() { ... }
    @Test void afterCacheAccess_skipsWrite_outsideRequestScope() { ... }
    @Test void evict_clearsCookie() { ... }
}
```

Always test the **size-limit guard**: serialize a realistic token cache string that exceeds 4 090 bytes and assert no cookie is written (and a warning is logged).

#### `RedisMsalTokenCacheService`

```java
@ExtendWith(MockitoExtension.class)
class RedisMsalTokenCacheServiceTest {

    @Mock RedisTemplate<String, String> redisTemplate;
    @Mock ValueOperations<String, String> valueOps;

    @Test void beforeCacheAccess_loadsFromRedis_whenKeyExists() { ... }
    @Test void beforeCacheAccess_usesEmptyCache_whenKeyAbsent() { ... }
    @Test void afterCacheAccess_writesToRedis_whenCacheChanged() { ... }
    @Test void afterCacheAccess_skipsWrite_whenCacheUnchanged() { ... }
    @Test void evict_deletesRedisKey() { ... }
}
```

#### `CookieAuthenticationFilter`

Use `MockHttpServletRequest` / `MockHttpServletResponse` and a `MockFilterChain`. Test both the **happy path** (valid JWT → SecurityContext populated) and the edge cases:

```java
@Test void validToken_populatesSecurityContext() { ... }
@Test void expiredToken_clearsSecurityContext_returns401() { ... }
@Test void missingAuthToken_withMsalCache_triggersSessionRestore() { ... }
@Test void missingAuthToken_withoutMsalCache_doesNotCallSilentRefresh() { ... }
@Test void nearExpiryToken_triggersProactiveRefresh() { ... }
@Test void farFromExpiryToken_skipsRefresh() { ... }
```

#### `AuthController`

Use `@WebMvcTest(AuthController.class)` with mocked services to test HTTP-level behavior:

```java
@Test void login_redirectsToAzureAdUrl() { ... }
@Test void callback_setsAuthCookie_onSuccess() { ... }
@Test void callback_redirectsToErrorPage_onStateMismatch() { ... }
@Test void logout_clearsCookiesAndEvictsCache() { ... }
```

### Running tests

```bash
cd backend
mvn test                          # run all tests
mvn test -pl . -Dtest=TokenExchangeServiceTest   # single class
mvn verify                        # tests + integration checks
```

All tests must pass (`BUILD SUCCESS`) before committing. The CI pipeline treats a failing test as a blocking error.

---

## Frontend Repository — React (or any SPA)

The frontend has **no MSAL library dependency**. It only needs to:
1. Redirect the browser to the backend login endpoint.
2. Call backend API endpoints with `credentials: 'include'` (so cookies are sent).
3. Handle the `?login=success` / `?login=error` query params after the OAuth redirect returns.

### 1. Dependencies

```json
{
  "dependencies": {
    "axios": "^1.6.0"
  }
}
```

No `@azure/msal-browser` or `@azure/msal-react` required.

### 2. `src/config/apiConfig.js` (or equivalent)

```js
export const apiConfig = {
  baseUrl: "/api",        // proxied to backend in dev; same origin in production
  endpoints: {
    hello: "/hello",
    login: "/auth/login",
    logout: "/auth/logout",
  },
};
```

> **Note**: In production, the frontend and backend share the same origin via a reverse proxy (e.g., nginx, Azure Front Door). In dev, use the proxy setup below.

### 3. `src/services/authService.js`

```js
import axios from 'axios';
import { apiConfig } from '../config/apiConfig';

const api = axios.create({
  baseURL: apiConfig.baseUrl,
  withCredentials: true,       // ensures cookies are sent on every request
  headers: { 'Content-Type': 'application/json' },
});

export const authService = {
  startLogin: () => {
    // Full page redirect — the backend drives the entire OAuth flow
    window.location.href = `${apiConfig.baseUrl}${apiConfig.endpoints.login}`;
  },

  logout: () => api.post(apiConfig.endpoints.logout),

  // Any protected API call — just use `api` with withCredentials: true
  getHelloMessage: () => api.get(apiConfig.endpoints.hello),
};
```

### 4. Handling login redirect result

On the page that Azure AD redirects back to (typically `/`):

```js
useEffect(() => {
  const params = new URLSearchParams(window.location.search);
  const loginStatus = params.get('login');
  if (loginStatus === 'success') {
    // User is now authenticated — call any protected API
    fetchUserData();
    window.history.replaceState({}, '', window.location.pathname);
  } else if (loginStatus === 'error') {
    setError('Login failed. Please try again.');
    window.history.replaceState({}, '', window.location.pathname);
  } else {
    // Check silent auth on page load
    fetchUserData().catch(() => { /* not authenticated yet */ });
  }
}, []);
```

### 5. Development proxy

**Create React App** (`src/setupProxy.js`):

```js
const { createProxyMiddleware } = require('http-proxy-middleware');

module.exports = function(app) {
  app.use('/api', createProxyMiddleware({
    target: 'http://127.0.0.1:8080',
    changeOrigin: true,
  }));
};
```

**Vite** (`vite.config.js`):

```js
export default {
  server: {
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:8080',
        changeOrigin: true,
      },
    },
  },
};
```

> The proxy makes all `/api/*` requests appear same-origin to the browser in dev, so cookies work without relaxing `SameSite`.

---

## Separate Repository Setup

When FE and BE are in different repositories, no code changes are required — only configuration:

### Backend repository

- Set `app.cors.allowed-origins` to the **exact** frontend origin(s), e.g. `https://myapp.example.com`.
- Set `app.azure-ad.redirect-uri` to `{frontend_origin}/api/auth/callback` (or the full public URL if the backend has its own domain and the callback is served directly by the backend without a proxy).
- `app.cookie.secure=true` in all non-local environments.
- `app.cookie.same-site=Strict` for same-origin cookie delivery via a reverse proxy; use `Lax` only if the OAuth callback originates from a different domain than the cookie domain.

### Frontend repository

- Point `apiConfig.baseUrl` to the **relative** path `/api` if a reverse proxy serves both on the same origin.
- If FE and BE are on different origins (no shared reverse proxy), set `apiConfig.baseUrl` to the absolute backend URL (e.g., `https://api.myapp.example.com/api`) and ensure `withCredentials: true` is set on every request. The backend `CORS` config must explicitly list the frontend origin.
- Remove the dev proxy (`setupProxy.js` / Vite proxy) when running against a deployed backend.

### Production reverse proxy (nginx example)

```nginx
location /api/ {
    proxy_pass http://backend:8080/api/;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
}

location / {
    proxy_pass http://frontend:3000/;
}
```

With this setup, browser requests to `https://myapp.example.com/api/auth/login` reach the backend seamlessly, cookies are set on `.myapp.example.com`, and `SameSite=Strict` works correctly.

---

## Environment Variable Reference

| Variable | Description | Example | Required |
|---|---|---|---|
| `AZURE_CLIENT_ID` | App registration client ID | `a69071ff-...` | Always |
| `AZURE_TENANT_ID` | Azure AD directory tenant ID | `64458159-...` | Always |
| `AZURE_CLIENT_SECRET` | Client secret from app registration | `2bB8Q~...` | Always |
| `FRONTEND_URL` | Full origin of the frontend | `http://localhost:3000` | Always |
| `BACKEND_PORT` | Backend listen port | `8080` | Always |
| `BACKEND_CONTEXT_PATH` | Spring context path prefix | `/api` | Always |
| `COOKIE_NAME` | Name of the auth cookie | `AUTH_TOKEN` | Always |
| `COOKIE_MAX_AGE` | Cookie lifetime in seconds | `3600` | Always |
| `COOKIE_SECURE` | Require HTTPS (`false` for local dev) | `true` | Always |
| `COOKIE_SAME_SITE` | SameSite policy (`Strict` / `Lax`) | `Strict` | Always |
| `TOKEN_CACHE_TYPE` | Cache backend: `redis` or `cookie` | `redis` | Always |
| `REDIS_HOST` | Redis hostname | `localhost` | Redis only |
| `REDIS_PORT` | Redis port | `6379` | Redis only |
| `REDIS_PASSWORD` | Redis password | `changeme-in-dev` | Redis only |
| `REDIS_TTL` | MSAL cache TTL (Spring Duration) | `90d` | Redis only |
| `REDIS_TLS` | Enable TLS for Redis | `false` | Redis only |
| `REDIS_ENCRYPTION_KEY` | AES-256-GCM key (base64, 32 bytes) | `openssl rand -base64 32` | Redis only |
| `TOKEN_CACHE_COOKIE_ENCRYPTION_KEY` | AES-256-GCM key for cookie cache | `openssl rand -base64 32` | Cookie only |
| `TOKEN_CACHE_COOKIE_SECURE` | `Secure` flag on MSAL cache cookie | `true` | Cookie only |

---

## Token Flow Summary

```
1. GET /api/auth/login
   → Backend generates state + PKCE verifier/challenge
   → Sets OAUTH_STATE + PKCE_VERIFIER cookies (SameSite=Lax, 5 min TTL)
   → Redirects browser to Azure AD authorization URL

2. User authenticates at Azure AD
   → Azure AD redirects browser to /api/auth/callback?code=...&state=...
   → Browser sends OAUTH_STATE + PKCE_VERIFIER cookies with the request

3. GET /api/auth/callback
   → Backend validates state cookie (CSRF check)
   → Backend exchanges code + verifier for tokens via MSAL4J
   → ID token stored in AUTH_TOKEN cookie (HttpOnly, Secure, SameSite=Strict)
   → [Redis]  Refresh token stored encrypted in Redis — never sent to browser
   → [Cookie] Refresh token stored encrypted in MSAL_TOKEN_CACHE cookie — HttpOnly
   → Browser redirected to /?login=success

4. Subsequent API calls (e.g., GET /api/hello)
   → Browser auto-sends AUTH_TOKEN cookie (+ MSAL_TOKEN_CACHE in cookie mode)
   → CookieAuthenticationFilter validates JWT, sets SecurityContext
   → If token expiring within 5 min: proactive silent refresh via cached refresh token
   → If token invalid/tampered: no refresh; request proceeds unauthenticated (401)

5. Session restore (AUTH_TOKEN absent, MSAL_TOKEN_CACHE present) — [Cookie only]
   → AUTH_TOKEN cookie MaxAge has elapsed; browser no longer sends it
   → CookieAuthenticationFilter detects MSAL_TOKEN_CACHE cookie is present
   → Calls acquireTokenSilentlyFromCache() → discovers cached account via getAccounts()
   → Exchanges refresh token → issues fresh AUTH_TOKEN → request authenticated

6. POST /api/auth/logout
   → [Redis]  Redis cache entry evicted (refresh token invalidated immediately)
   → [Cookie] MSAL_TOKEN_CACHE cookie cleared (Max-Age=0)
   → AUTH_TOKEN cookie cleared (Max-Age=0)
```

---

## Security Checklist

Before deploying to production:

**Both backends:**
- [ ] `app.cookie.secure=true`
- [ ] `app.cookie.same-site=Strict` (or `Lax` with documented justification)
- [ ] `app.cors.allowed-origins` lists only known frontend origins (no wildcards)
- [ ] `AZURE_CLIENT_SECRET` is rotated and stored in a secret manager (Key Vault, etc.)
- [ ] Backend logs do not contain raw `homeAccountId` values (use `LogSanitizer.obfuscate()`)
- [ ] `logging.level.com.example=INFO` (not `DEBUG`) in production
- [ ] Azure AD redirect URI list contains only production URIs (remove `localhost`)

**[Redis only]:**
- [ ] `REDIS_ENCRYPTION_KEY` set to a unique 32-byte base64 key (`openssl rand -base64 32`)
- [ ] `REDIS_PASSWORD` set to a strong password
- [ ] `REDIS_TLS=true` for Azure Cache for Redis

**[Cookie only]:**
- [ ] `TOKEN_CACHE_COOKIE_ENCRYPTION_KEY` set to a unique 32-byte base64 key (`openssl rand -base64 32`)
- [ ] `app.token-cache.cookie.secure=true` in all non-local environments
- [ ] `AUTH_TOKEN` cookie `MaxAge` is intentionally shorter than the MSAL cache cookie `MaxAge` so the session-restore path can recover without re-login
- [ ] Understand that key rotation (`TOKEN_CACHE_COOKIE_ENCRYPTION_KEY` change) silently invalidates all active cookie caches — users must re-authenticate once (graceful degradation, no 500 error)
- [ ] Understand that cookie cache is **not cluster-safe** — each user's cache is bound to their browser, not a shared store
