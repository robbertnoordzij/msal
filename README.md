<!-- Simplified README (previous detailed reference removed) -->
<br />

# MSAL Secure Authentication Demo

A minimal, secure example of Azure AD authentication using:
- React + MSAL.js (SPA)
- Spring Boot (Backend for Frontend gateway)
- HTTP‑only cookie session (no tokens in localStorage)

> Goal: Show a production-aligned pattern with the smallest set of moving parts.

## 1. Features (Why This Pattern)
- No JWT in `localStorage` / `sessionStorage`
- HTTP-only, SameSite cookie for API calls
- Backend validates Azure AD tokens (issuer, audience, expiry)
- Clean separation: Frontend handles sign-in UX, backend enforces trust

```
┌──────────────┐  Auth Popup  ┌──────────────┐  JWK Validate  ┌──────────────┐
│ React (MSAL) │─────────────▶│ Spring BFF   │──────────────▶│  Azure AD     │
│              │◀─────────────│ (Sets Cookie)│◀──────────────│               │
└──────────────┘  Cookie Call  └──────────────┘  Protected API └──────────────┘
```

## 2. Tech Stack (Concise)
| Layer    | Tech |
|----------|------|
| Frontend | React 18, MSAL.js |
| Backend  | Spring Boot 3, Spring Security (Resource Server) |
| Auth     | Azure AD (OIDC) |

## 3. Quick Start
Prereqs: Node 16+, Java 17+, Maven, Azure AD app (SPA redirect: `http://localhost:3000`).

```powershell
# 1. Clone & enter
git clone https://github.com/your-org/your-repo.git
cd msal

# 2. Create env file
Copy-Item .env.example .env
notepad .env   # Fill AZURE_CLIENT_ID + AZURE_TENANT_ID

# 3. Launch everything
./runall.ps1   # Generates config, builds backend, starts both apps
```
Visit: http://localhost:3000 → Sign In → Call Hello endpoint.

## 4. Configuration (Single Source: `.env`)
Edit `.env` only. Running `./runall.ps1` (or `./configure.ps1`) regenerates:
- `frontend/src/config/msalConfig.js`
- `backend/src/main/resources/application.properties`

Key vars (typical dev values):
| Var | Example | Notes |
|-----|---------|-------|
| AZURE_CLIENT_ID | GUID | From Azure AD app registration |
| AZURE_TENANT_ID | GUID | Directory (tenant) ID |
| FRONTEND_URL | http://localhost:3000 | SPA origin |
| BACKEND_URL | http://localhost:8080 | API origin |
| COOKIE_SECURE | false (dev) / true (prod) | Must be true under HTTPS |
| COOKIE_SAME_SITE | Lax (dev) / Strict (prod) | CSRF hardening |

Production switch example:
```powershell
Copy-Item .env.production .env
./configure.ps1
```

## 5. Auth Flow (Condensed)
1. User clicks Sign In → MSAL popup
2. Azure AD returns ID/Access token to SPA
3. SPA POSTs access token to `/api/auth/login`
4. Backend validates & sets HTTP-only cookie
5. Subsequent `/api/*` calls rely on cookie
6. Logout clears cookie + MSAL session

## 6. API Endpoints (Minimal)
| Endpoint | Method | Auth | Purpose |
|----------|--------|------|---------|
| `/api/health` | GET | No  | Liveness check |
| `/api/auth/login` | POST | No  | Exchange token → cookie |
| `/api/auth/logout` | POST | No  | Clear cookie |
| `/api/hello` | GET | Yes | Sample protected message |
| `/api/userinfo` | GET | Yes | Claims-derived user info |

## 7. Project Structure (Essentials)
```
frontend/
  src/
    config/ msalConfig.js (generated)
    services/ authService.js
    App.js
backend/
  src/main/java/com/example/msalbff/
    config/ controller/ security/ service/
  src/main/resources/application.properties (generated)
```
Generated files (`msalConfig.js`, `application.properties`) are excluded from git—edit `.env` instead.

## 8. Security Summary
| Aspect | Approach |
|--------|----------|
| Token storage | Never persisted client-side; cookie only |
| Cookie flags | HTTP-only, SameSite, Secure (prod) |
| Validation | Azure AD JWKs (issuer, audience, expiry) |
| CSRF | SameSite + origin restriction |
| XSS | No token exposure to JS |

## 9. Troubleshooting (Top 5)
| Symptom | Quick Fix |
|---------|-----------|
| Sign-in loop | Clear cookies; redirect URI matches FRONTEND_URL |
| 401 on protected API | Check cookie + `COOKIE_SECURE` vs protocol |
| CORS error | FRONTEND_URL / BACKEND_URL mismatch; regenerate config |
| AADSTS50011 | Redirect URI mismatch in Azure AD |
| Cookie missing (dev) | Set `COOKIE_SECURE=false` |

Regenerate configs anytime:
```powershell
./configure.ps1
```

## 10. Production Notes (Essentials)
- Set `COOKIE_SECURE=true`, `COOKIE_SAME_SITE=Strict`, `LOG_LEVEL=INFO`
- Enforce HTTPS + security headers (CSP, HSTS, X-Content-Type-Options)
- Optionally define custom scopes & request audience-specific tokens
- Consider Application Insights for monitoring

## 11. Scripts
| Script | Purpose |
|--------|---------|
| `./runall.ps1` | Generate config, build backend, start both apps |
| `./configure.ps1` | Regenerate config only |

## 12. Extend Ideas
- Silent token refresh / rotation
- Role / group-based authorization
- Central error & telemetry layer
- CI/CD pipeline example

## 13. Useful Docs
- MSAL.js: https://learn.microsoft.com/azure/active-directory/develop/msal-overview
- Spring Security Resource Server: https://docs.spring.io/spring-security/reference/

---
Minimal surface. Clear responsibilities. Secure defaults.

**Happy Authenticating!** 🔐