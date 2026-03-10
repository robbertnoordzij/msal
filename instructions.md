# MSAL Secure BFF Authentication — Implementation Instructions

These instructions enable a Copilot instance to implement the **Backend-for-Frontend (BFF) MSAL authentication pattern** into an existing codebase. The pattern uses a Spring Boot backend as the sole token handler, stores the Azure AD ID token in an **HTTP-only cookie**, and uses **Redis** to cache refresh tokens server-side so that no secrets or refresh tokens are ever sent to the browser.

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

Spring Boot BFF  (token cache)
    │  AES-256-GCM encrypted MSAL cache per user
    ▼
Redis  (key: msal:token-cache:{oid.tid})
```

**Key security properties:**
- The browser **never** sees access tokens or refresh tokens.
- JWT ID token is validated on every request against Azure AD's JWK Set endpoint.
- Refresh tokens live only in Redis, encrypted at rest with AES-256-GCM.
- PKCE (S256) and a random `state` cookie prevent CSRF and code-injection attacks.
- `SameSite=Strict` on `AUTH_TOKEN` provides CSRF protection; `SameSite=Lax` on OAuth flow cookies is required so the Azure AD redirect carries them back.

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

### 2. Redis

- **Local dev**: use the provided `docker-compose.yml` — it starts Redis 7 with a password.
- **Production**: Azure Cache for Redis (set `REDIS_TLS=true`, port 6380) or equivalent.
- Redis is **required** for silent token refresh across multiple backend replicas. Without it, token refresh still works on a single instance (MSAL falls back to in-memory cache with a WARN log).

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

<!-- Redis for distributed MSAL token cache -->
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

# Redis
app.redis.host=${REDIS_HOST:localhost}
app.redis.port=${REDIS_PORT:6379}
app.redis.password=${REDIS_PASSWORD}
app.redis.ttl=90d               # Spring Duration: "90d", "24h", "3600s"
app.redis.tls=false             # true for Azure Cache for Redis (port 6380)
# AES-256-GCM key for token cache encryption. Generate: openssl rand -base64 32
# Leave empty only for local dev (a WARN will be logged).
app.redis.encryption-key=${REDIS_ENCRYPTION_KEY:}
```

### 3. Source Files to Create

Use the **exact package structure** that matches your project's base package. All examples below use `com.example.msalbff` — **replace with your own base package**.

---

#### `config/AppProperties.java`

Binds all `app.*` properties. Contains nested static classes: `AzureAd`, `Cookie`, `Cors`, `Redis`.

```java
@Component
@ConfigurationProperties(prefix = "app")
public class AppProperties {
    private final AzureAd azureAd = new AzureAd();
    private final Cookie cookie = new Cookie();
    private final Cors cors = new Cors();
    private final Redis redis = new Redis();

    // getters for each nested class ...

    public static class AzureAd {
        private String tenantId, clientId, clientSecret, authority, jwkSetUri, redirectUri;
        private String scopes = "openid profile offline_access User.Read";

        public Set<String> scopesAsSet() {
            return new HashSet<>(Arrays.asList(scopes.split(" ")));
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
        // standard getters/setters ...
    }
}
```

---

#### `config/RedisConfig.java`

Creates a `RedisConnectionFactory` from `AppProperties.Redis`. Spring Boot auto-configures `StringRedisTemplate` from it.

```java
@Configuration
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
}
```

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

AES-256-GCM encryption/decryption for the MSAL token cache stored in Redis.  
Key is injected from `${app.redis.encryption-key}` (base64-encoded 32-byte value).  
If no key is configured, encryption is disabled (suitable for local dev only — logs a `WARN`).

Important implementation details:
- Each call to `encrypt()` generates a fresh 12-byte random IV.
- The encoded output is `base64(iv || ciphertext)`.
- `decrypt()` splits out the IV prefix before decrypting.
- Tag length is 128 bits (GCM default).

---

#### `service/RedisMsalTokenCache.java`

Implements `ITokenCacheAccessAspect` (MSAL4J interface). MSAL4J calls:
- `beforeCacheAccess(ctx)` — load the per-user cache from Redis and call `ctx.tokenCache().deserialize(json)`.
- `afterCacheAccess(ctx)` — if `ctx.hasCacheChanged()`, serialize and write back to Redis.

**Redis key schema**: `msal:token-cache:{homeAccountId}` where `homeAccountId = oid.tid`.  
For app-level (no user account) keys: `msal:token-cache:app:{clientId}`.

Key implementation points:
- Read/write failures are caught and logged as `WARN`; they never throw — MSAL falls back to an empty cache.
- TTL is set on every write to `app.redis.ttl` (default 90 days, matching Azure AD refresh token lifetime).
- `evict(homeAccountId)` deletes the Redis key on logout.

```java
@Component
public class RedisMsalTokenCache implements ITokenCacheAccessAspect {
    private static final String KEY_PREFIX = "msal:token-cache:";
    // inject: StringRedisTemplate, TokenCacheEncryption, AppProperties

    @Override
    public void beforeCacheAccess(ITokenCacheAccessContext ctx) {
        String key = KEY_PREFIX + partitionKey(ctx);
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
        String key = KEY_PREFIX + partitionKey(ctx);
        try {
            String json = ctx.tokenCache().serialize();
            String toStore = encryption.isEnabled() ? encryption.encrypt(json) : json;
            redisTemplate.opsForValue().set(key, toStore, ttl);
        } catch (Exception e) { /* log WARN */ }
    }

    public void evict(String homeAccountId) {
        redisTemplate.delete(KEY_PREFIX + homeAccountId);
    }

    private String partitionKey(ITokenCacheAccessContext ctx) {
        IAccount account = ctx.account();
        return account != null ? account.homeAccountId() : "app:" + ctx.clientId();
    }
}
```

---

#### `service/TokenExchangeService.java`

Wraps `ConfidentialClientApplication` (MSAL4J singleton). Initialized with `@PostConstruct`.

Provides three methods:
1. **`generateAuthorizationUrl(redirectUri, scopes, state, codeChallenge)`** — builds the Azure AD authorization URL with PKCE S256 and `prompt=select_account`.
2. **`exchangeAuthorizationCode(code, redirectUri, scopes, codeVerifier)`** — exchanges the authorization code for tokens; returns `IAuthenticationResult`.
3. **`acquireTokenSilently(homeAccountId, scopes)`** — looks up the MSAL account by `homeAccountId` in the loaded cache and calls `acquireTokenSilently`. Returns `Optional.empty()` on any failure (expired/revoked, Redis miss, timeout).

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
1. Extract `AUTH_TOKEN` cookie.
2. If valid and **not expiring within 300 s** → authenticate from current token.
3. If valid but **expiring within 300 s** → authenticate from current token AND trigger silent refresh in the background, updating the cookie on success.
4. If invalid/expired → attempt silent refresh first; if successful, authenticate from new token; otherwise proceed unauthenticated (Spring returns 401).

Silent refresh reads `oid` and `tid` from the (possibly expired) token and calls `tokenExchangeService.acquireTokenSilently(oid + "." + tid, scopes)`.

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
1. Parse `oid` + `tid` from `AUTH_TOKEN` cookie → call `redisMsalTokenCache.evict(oid + "." + tid)`.
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

| Variable | Description | Example |
|---|---|---|
| `AZURE_CLIENT_ID` | App registration client ID | `a69071ff-...` |
| `AZURE_TENANT_ID` | Azure AD directory tenant ID | `64458159-...` |
| `AZURE_CLIENT_SECRET` | Client secret from app registration | `2bB8Q~...` |
| `FRONTEND_URL` | Full origin of the frontend | `http://localhost:3000` |
| `BACKEND_PORT` | Backend listen port | `8080` |
| `BACKEND_CONTEXT_PATH` | Spring context path prefix | `/api` |
| `COOKIE_NAME` | Name of the auth cookie | `AUTH_TOKEN` |
| `COOKIE_MAX_AGE` | Cookie lifetime in seconds | `3600` |
| `COOKIE_SECURE` | Require HTTPS (`false` for local dev) | `true` |
| `COOKIE_SAME_SITE` | SameSite policy (`Strict` / `Lax`) | `Strict` |
| `REDIS_HOST` | Redis hostname | `localhost` |
| `REDIS_PORT` | Redis port | `6379` |
| `REDIS_PASSWORD` | Redis password | `changeme-in-dev` |
| `REDIS_TTL` | MSAL cache TTL (Spring Duration) | `90d` |
| `REDIS_TLS` | Enable TLS for Redis | `false` |
| `REDIS_ENCRYPTION_KEY` | AES-256-GCM key (base64, 32 bytes) | `openssl rand -base64 32` |

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
   → Refresh token stored in Redis (encrypted) — never sent to browser
   → Browser redirected to /?login=success

4. Subsequent API calls (e.g., GET /api/hello)
   → Browser auto-sends AUTH_TOKEN cookie
   → CookieAuthenticationFilter validates JWT, sets SecurityContext
   → If token expiring soon: silent refresh via Redis-cached refresh token
   → If token expired: silent refresh attempt; 401 if refresh token revoked

5. POST /api/auth/logout
   → Redis cache entry evicted (refresh token invalidated)
   → AUTH_TOKEN cookie cleared (maxAge=0)
```

---

## Security Checklist

Before deploying to production:

- [ ] `app.cookie.secure=true`
- [ ] `app.cookie.same-site=Strict` (or `Lax` with documented justification)
- [ ] `REDIS_ENCRYPTION_KEY` set to a unique 32-byte base64 key (`openssl rand -base64 32`)
- [ ] `REDIS_PASSWORD` set to a strong password
- [ ] `REDIS_TLS=true` for Azure Cache for Redis
- [ ] `app.cors.allowed-origins` lists only known frontend origins (no wildcards)
- [ ] `AZURE_CLIENT_SECRET` is rotated and stored in a secret manager (Key Vault, etc.)
- [ ] Backend logs do not contain raw `homeAccountId` values (use `LogSanitizer.obfuscate()`)
- [ ] `logging.level.com.example=INFO` (not `DEBUG`) in production
- [ ] Azure AD redirect URI list contains only production URIs (remove `localhost`)
