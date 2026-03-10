# Copilot Instructions

## Project Overview

Azure AD authentication demo using the Backend-for-Frontend (BFF) pattern. The React SPA handles sign-in UX via MSAL popup; the Spring Boot backend validates tokens and issues HTTP-only cookies — tokens are never stored client-side.

## Architecture

```
React          → GET  /api/auth/login
                ← Spring Boot redirects browser to Entra ID (PKCE + state)
Browser        → GET  /api/auth/callback?code=...&state=... (Entra ID redirect)
                ← Spring Boot validates code, sets HTTP-only AUTH_TOKEN cookie,
                   redirects to frontend /?login=success
React          → GET  /api/hello (or any protected route)
                ← Spring CookieAuthenticationFilter validates JWT via Azure AD JWK Set
                   (silent token refresh via MSAL server-side cache on near-expiry)
```

> **Path note:** `server.servlet.context-path=/api` is set in `application.properties`; `AuthController` maps to `/auth`. `CookieAuthenticationFilter` uses `getServletPath()` (context-stripped path) to exclude `/auth/**` requests.

> See [`docs/token-flow.puml`](../docs/token-flow.puml) for the full sequence diagram.

**Config is auto-generated.** The `.env` file is the single source of truth. Run `./configure.sh` (or `configure.ps1`) to regenerate:
- `frontend/src/config/msalConfig.js`
- `backend/src/main/resources/application.properties`

Both generated files are `.gitignored`. Never edit them directly.

## Commands

### Starting the project

```bash
./runall.sh              # Full setup: configure + install deps + start both services
npm run dev              # Start both services concurrently (requires prior install)
npm run install-all      # Install frontend (npm) and backend (mvn) deps
```

### Frontend (port 3000)

```bash
cd frontend
npm start                # Dev server with hot reload
npm run build            # Production build → frontend/build/
npm test                 # Jest test suite (watch mode)
npm test -- --testNamePattern="TestName"   # Single test by name
npm test -- src/path/to/file.test.js       # Single test file
```

### Backend (port 8080, context path `/api`)

```bash
cd backend
mvn spring-boot:run                        # Dev server
mvn clean package                          # Build JAR → target/
mvn test                                   # Full test suite
mvn test -Dtest=SimpleApiControllerTest    # Single test class
mvn test -Dtest=ClassName#methodName       # Single test method
```

## Key Conventions

### Backend package structure

```
com.example.msalbff/
  config/       # @Configuration classes (Security, CORS, properties binding)
  controller/   # @RestController — AuthController, ApiController
  dto/          # Request/Response POJOs (LoginRequest, UserInfo, etc.)
  security/     # CookieAuthenticationFilter
  service/      # TokenValidationService, TokenExchangeService
```

Naming: `*Controller`, `*Service`, `*Filter`, `*Config`, `*Properties`, `*Request`, `*Response`.

### API surface

| Endpoint | Method | Auth | Purpose |
|---|---|---|---|
| `/api/health` | GET | Public | Liveness check |
| `/api/auth/login` | GET | Public | Start PKCE flow — generates state + challenge, redirects browser to Entra ID |
| `/api/auth/callback` | GET | Public | OAuth callback — validates state/code, exchanges code for tokens, sets HTTP-only cookie, redirects to `/?login=success` |
| `/api/auth/logout` | POST | Public | Invalidate HTTP session, clear cookie (Max-Age=0) |
| `/api/hello` | GET | Cookie | Sample protected endpoint |
| `/api/userinfo` | GET | Cookie | Return JWT claims |

### Security pattern

- **Never** store tokens in `localStorage` or expose them to JavaScript.
- Cookies: `HttpOnly`, `SameSite=Lax` (dev) / `Strict` (prod), `Secure=true` (prod).
- `CookieAuthenticationFilter` extracts the JWT from the `AUTH_TOKEN` cookie and populates `SecurityContextHolder`.
- Access the authenticated user in controllers via `SecurityContextHolder.getContext().getAuthentication()`; the raw `Jwt` object is in `authentication.getDetails()`.

### Frontend patterns

- All API calls use `axios` with `withCredentials: true` (cookie forwarding).
- Dev proxy in `setupProxy.js` forwards `/api` → `http://localhost:8080`.
- MSAL config (client ID, tenant, scopes) lives in `frontend/src/config/msalConfig.js` (generated).
- Auth logic is encapsulated in `frontend/src/services/authService.js`.

### Environment variables

Defined in `.env` (copy from `.env.example`). Key variables:

```
AZURE_CLIENT_ID, AZURE_TENANT_ID, AZURE_CLIENT_SECRET
FRONTEND_URL=http://localhost:3000
BACKEND_URL=http://localhost:8080
COOKIE_NAME=AUTH_TOKEN
COOKIE_SECURE=false        # set true in production
COOKIE_SAME_SITE=Lax       # set Strict in production
COOKIE_MAX_AGE=3600
LOG_LEVEL=DEBUG
```

## Custom Agents

Two specialist agents are available in `.github/agents/`:

### `security-researcher`

Focuses on OAuth/OIDC token handling, BFF pattern correctness, secure cookie
configuration, and OWASP Top 10 risks. Use it to review any change that touches
authentication, authorisation, cookie settings, CORS/CSRF config, or JWT
validation logic. It expects you to scope the review (file, PR diff, or specific
concern) and returns findings classified by severity (🔴 Critical → 🔵 Low).

### `clean-code-reviewer`

Applies Robert C. Martin's Clean Code principles (naming, functions, comments,
SOLID, error handling, tests) to both the Java backend and JavaScript frontend.
Use it when refactoring, adding new classes/components, or before merging a PR.
Security improvements must never be sacrificed for cleanliness — the agent is
aware of this constraint.

### `codebase-assessor`

Provides a structured quality assessment across three dimensions: **code
quality**, **test quality**, and **architecture**. Each dimension is scored
out of 10 with evidence-based findings classified by severity (🔴 Critical →
🔵 Suggestion). Use it for periodic quality reviews, before major refactors,
when onboarding new team members, or when building a technical debt backlog.
Outputs an executive summary, scored dimensions, and a prioritised action list.
Can also run in focused mode on a single file, PR diff, or dimension.
