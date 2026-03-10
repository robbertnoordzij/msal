import React, { useState, useEffect } from 'react';
import { authService } from './services/authService';

/**
 * Returns a user-friendly error message based on the Axios error type.
 */
function getErrorMessage(error) {
  if (error.response) {
    if (error.response.status === 401) {
      return 'Authentication expired. Please sign in again.';
    }
    return `API error: ${error.response.status}`;
  } else if (error.request) {
    return 'Network error: Could not reach backend. Is it running?';
  } else if (error.code === 'ECONNABORTED') {
    return 'Request timeout. Backend is slow to respond.';
  }
  return error.message || 'Unknown error';
}

function App() {
  const [apiMessage, setApiMessage] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState('');
  const [cookieSet, setCookieSet] = useState(false);

  // Automatically handle login result from URL parameters or check initial auth status
  useEffect(() => {
    const queryParams = new URLSearchParams(window.location.search);
    const loginStatus = queryParams.get('login');

    if (loginStatus === 'success') {
      callHelloEndpoint();
      window.history.replaceState({}, document.title, window.location.pathname);
    } else if (loginStatus === 'error') {
      setError('Login failed. Please try again.');
      window.history.replaceState({}, document.title, window.location.pathname);
    } else if (loginStatus != null) {
      // Unexpected value — clean up URL and proceed
      console.warn('Unexpected login status parameter:', loginStatus);
      window.history.replaceState({}, document.title, window.location.pathname);
      callHelloEndpoint(true);
    } else {
      // No login parameters, check if already authenticated silently
      callHelloEndpoint(true);
    }
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  const handleLogin = () => {
    authService.startLogin();
  };

  const handleLogout = async () => {
    try {
      setIsLoading(true);
      await authService.logout();
      setCookieSet(false);
      setApiMessage('');
    } catch (err) {
      // authService.logout() no longer throws; this is a safety net
      console.error('Logout failed:', err);
      setError('Logout failed: ' + getErrorMessage(err));
    } finally {
      setIsLoading(false);
    }
  };

  // Call protected API endpoint
  const callHelloEndpoint = async (isInitialCheck = false) => {
    try {
      setIsLoading(true);
      if (!isInitialCheck) setError('');

      const response = await authService.getHelloMessage();
      if (typeof response === 'object' && response !== null) {
        setApiMessage(JSON.stringify(response, null, 2));
      } else {
        setApiMessage(String(response));
      }
      setCookieSet(true);
    } catch (err) {
      if (!isInitialCheck) {
        setError(getErrorMessage(err));
      }
      if (err.response?.status === 401) {
        setCookieSet(false);
      }
    } finally {
      setIsLoading(false);
    }
  };


  return (
    <div className="app">
      <div className="container">
        <header className="header">
          <h1>MSAL React Authentication Demo</h1>
          <p>Secure token handling with HTTP-only cookies</p>
        </header>

        {/* Loading indicator */}
        {isLoading && (
          <div className="loading">
            Processing request...
          </div>
        )}

        {/* Error display */}
        {error && (
          <div className="error">
            <strong>Error:</strong> {error}
            <button 
              className="button" 
              onClick={() => setError('')}
              style={{ marginLeft: '10px', padding: '5px 10px', fontSize: '12px' }}
            >
              Clear
            </button>
          </div>
        )}

        {/* Authentication section */}
        <div>
          <div>
            <p>Please sign in to continue</p>
            <button 
              className="button" 
              onClick={handleLogin}
              disabled={isLoading}
            >
              Sign In with Azure AD
            </button>
          </div>

          {/* Authentication Status */}
          <div style={{ marginTop: '20px' }}>
            <h3>Authentication Status</h3>
            {cookieSet ? (
              <div>
                <p style={{ color: 'green' }}>✓ Secure authentication established</p>
                <p style={{ fontSize: '14px', color: '#666' }}>Your token is securely stored in an HTTP-only cookie</p>
              </div>
            ) : (
              <p style={{ color: '#666' }}>Not authenticated</p>
            )}
          </div>

          {/* API calls */}
          <div style={{ marginTop: '30px' }}>
            <h3>Protected API Access</h3>
            <p>Call protected endpoints using secure cookie-based authentication.</p>
            <button 
              className="button" 
              onClick={callHelloEndpoint}
              disabled={isLoading}
            >
              Call Hello Endpoint
            </button>
            <p style={{ fontSize: '13px', color: '#666', marginTop: '8px' }}>
              🔒 <strong>AUTH_TOKEN is HTTP-only</strong> — it cannot be read by JavaScript, protecting it from XSS attacks.
            </p>
          </div>

          {/* API response */}
          {apiMessage && (
            <div className="api-response">
              <h4>API Response:</h4>
              {apiMessage}
            </div>
          )}

          {/* Logout */}
          <div style={{ marginTop: '30px' }}>
            <button 
              className="button secondary" 
              onClick={handleLogout}
              disabled={isLoading}
            >
              Sign Out
            </button>
          </div>
        </div>

        {/* Information section */}
        <div style={{ marginTop: '40px', textAlign: 'left', fontSize: '14px', color: '#666' }}>
          <h4>Secure Authentication Flow (Backend-Only Token Exchange):</h4>
          <ol style={{ marginBottom: '20px' }}>
            <li>User clicks Sign In</li>
            <li>Frontend redirects to backend login endpoint</li>
            <li>Backend redirects to Microsoft for authentication</li>
            <li>Backend receives authorization code and exchanges it for tokens</li>
            <li>Backend stores tokens in HTTP-only secure cookies</li>
            <li>Frontend calls APIs; cookies are sent automatically</li>
          </ol>
          <h4>Security Features:</h4>
          <ul>
            <li>✓ Frontend never handles access or refresh tokens</li>
            <li>✓ Tokens are stored in HTTP-only cookies set by the backend</li>
            <li>✓ Cookies are secure and not accessible to JavaScript</li>
            <li>✓ CSRF protection through SameSite cookie attributes</li>
            <li>✓ Token validation happens on the backend</li>
          </ul>
        </div>
      </div>
    </div>
  );
}

export default App;