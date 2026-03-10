# Copilot Instructions

## Project Overview

Azure AD authentication demo using the Backend-for-Frontend (BFF) pattern. The React SPA handles sign-in UX via MSAL popup; the Spring Boot backend validates tokens and issues HTTP-only cookies — tokens are never stored client-side.

## Architecture

```
React (MSAL.js) → POST /api/auth/login (with Azure AD token)
                ← Spring Boot sets HTTP-only AUTH_TOKEN cookie
React          → GET /api/* (cookie sent automatically)
                ← Spring CookieAuthenticationFilter validates JWT via Azure AD JWK Set
```

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
| `/api/auth/login` | POST | Public | Exchange MSAL token → cookie |
| `/api/auth/logout` | POST | Public | Clear cookie (Max-Age=0) |
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
