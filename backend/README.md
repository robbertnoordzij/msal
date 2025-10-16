# Java Backend for Frontend (BFF)

This Spring Boot application serves as a Backend for Frontend (BFF) API that handles JWT tokens securely using HTTP-only cookies, preventing XSS attacks while maintaining secure authentication.

## Features

- 🔐 JWT token validation using Azure AD public keys
- 🍪 HTTP-only cookie-based authentication
- 🛡️ CORS configuration for frontend communication
- 🔍 Token parsing and user information extraction
- 📝 Comprehensive logging and error handling

## Architecture

```
Frontend (MSAL) → Backend (BFF) → Azure AD
     │                 │              │
     └─── HTTP Cookie ──┴── JWT ──────┘
```

## Security Features

### Cookie Configuration
- **HTTP-Only**: Prevents JavaScript access (XSS protection)
- **Secure**: Only sent over HTTPS in production
- **SameSite**: CSRF protection
- **Max-Age**: Configurable expiration

### JWT Validation
- Uses Azure AD's public keys (JWK Set)
- Validates issuer, audience, and expiration
- Extracts user claims safely
- Handles token errors gracefully

## API Endpoints

| Endpoint | Method | Description | Auth Required |
|----------|---------|-------------|---------------|
| `POST /api/auth/login` | POST | Set JWT token in HTTP-only cookie | ❌ |
| `POST /api/auth/logout` | POST | Clear authentication cookie | ❌ |
| `GET /api/hello` | GET | Hello world for authenticated users | ✅ |
| `GET /api/userinfo` | GET | Get user information from JWT | ✅ |
| `GET /api/health` | GET | Health check endpoint | ❌ |

## Configuration

### Application Properties

Update `src/main/resources/application.properties`:

```properties
# Azure AD Configuration
azure.activedirectory.tenant-id=YOUR_TENANT_ID
azure.activedirectory.client-id=YOUR_CLIENT_ID

# Cookie Settings
app.cookie.name=AUTH_TOKEN
app.cookie.max-age=3600
app.cookie.secure=true
app.cookie.same-site=Strict
app.cookie.http-only=true

# CORS Settings
app.cors.allowed-origins=http://localhost:3000
app.cors.allow-credentials=true
```

### Environment Variables

For production, use environment variables:
```bash
export AZURE_TENANT_ID=your_tenant_id
export AZURE_CLIENT_ID=your_client_id
export CORS_ALLOWED_ORIGINS=https://yourdomain.com
```

## Building and Running

### Development
```bash
mvn spring-boot:run
```

### Production Build
```bash
mvn clean package
java -jar target/msal-bff-1.0.0.jar
```

### Docker (Optional)
```dockerfile
FROM openjdk:17-jre-slim
COPY target/msal-bff-1.0.0.jar app.jar
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "/app.jar"]
```

## Security Components

### CookieAuthenticationFilter
Custom filter that:
- Extracts JWT from HTTP-only cookies
- Validates tokens using Azure AD
- Sets Spring Security authentication context
- Handles authentication errors gracefully

### TokenValidationService
Service that:
- Decodes JWT using Azure AD public keys
- Validates token claims (issuer, audience, expiration)
- Extracts user information from tokens
- Provides token parsing utilities

### Security Configuration
Spring Security setup:
- CORS configuration for frontend communication
- Stateless session management
- Cookie-based authentication
- Public endpoints for auth and health

## Request/Response Flow

### Login Flow
1. Frontend sends JWT to `/api/auth/login`
2. Backend validates JWT with Azure AD
3. If valid, sets HTTP-only cookie
4. Returns success response

### Authenticated Request Flow
1. Frontend makes request with cookie
2. `CookieAuthenticationFilter` extracts JWT from cookie
3. JWT validated and user authenticated
4. Controller processes request with user context
5. Response sent back with user data

### Logout Flow
1. Frontend calls `/api/auth/logout`
2. Backend sets expired cookie
3. Authentication cleared

## Error Handling

- **401 Unauthorized**: Invalid or missing token
- **403 Forbidden**: Valid token but insufficient permissions
- **500 Internal Server Error**: Server-side validation errors

## Logging

Structured logging for:
- Authentication attempts
- Token validation results
- API access patterns
- Security events

## Production Considerations

1. **HTTPS Only**: Set `app.cookie.secure=true`
2. **Proper CORS**: Restrict origins to your domains
3. **Monitoring**: Add metrics and health checks
4. **Secrets**: Use Azure Key Vault for sensitive config
5. **Rate Limiting**: Implement request throttling
6. **Security Headers**: Add HSTS, CSP, etc.