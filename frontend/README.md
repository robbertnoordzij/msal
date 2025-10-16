# React Frontend with MSAL Authentication

This React application demonstrates secure authentication using MSAL.js with Azure Active Directory, implementing the BFF pattern for secure token handling.

## Features

- 🔐 Azure AD authentication with MSAL.js
- 🍪 Secure token storage using HTTP-only cookies
- 🛡️ No JWT exposure to browser JavaScript
- 🔄 Token refresh handling
- 📱 Responsive UI with authentication status

## Setup

1. Install dependencies:
```bash
npm install
```

2. Configure MSAL in `src/config/msalConfig.js`:
```javascript
export const msalConfig = {
  auth: {
    clientId: "YOUR_CLIENT_ID",           // From Azure AD
    authority: "https://login.microsoftonline.com/YOUR_TENANT_ID",
    redirectUri: "http://localhost:3000", // Must match Azure AD config
  },
};
```

3. Start the development server:
```bash
npm start
```

## Environment Variables (Optional)

Create `.env.local`:
```
REACT_APP_CLIENT_ID=your_client_id
REACT_APP_TENANT_ID=your_tenant_id
REACT_APP_API_BASE_URL=http://localhost:8080/api
```

## Authentication Flow

1. User clicks "Sign In with Azure AD"
2. MSAL popup opens for authentication
3. After login, user can "Set Token Cookie" (sends JWT to backend)
4. Backend validates token and sets HTTP-only cookie
5. Subsequent API calls use cookie authentication
6. User can "Sign Out" to clear session

## Security Benefits

- ✅ JWT tokens never stored in localStorage/sessionStorage
- ✅ HTTP-only cookies prevent XSS attacks
- ✅ Secure communication with backend API
- ✅ Automatic token validation
- ✅ Clean separation of authentication concerns

## API Integration

The frontend communicates with the backend using:
- Axios with `withCredentials: true` for cookie handling
- Proxy configuration to forward `/api` requests
- Error handling for authentication failures
- Automatic retry logic for token refresh

## Development

- Frontend: `http://localhost:3000`
- Backend API: `http://localhost:8080/api`
- Proxy forwards API requests to backend