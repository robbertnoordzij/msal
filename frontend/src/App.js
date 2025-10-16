import React, { useState, useEffect, useCallback } from 'react';
import { useMsal } from '@azure/msal-react';
import { loginRequest } from './config/msalConfig';
import { authService } from './services/authService';

function App() {
  // Function to read a cookie by name
  function getCookie(name) {
    const value = `; ${document.cookie}`;
    const parts = value.split(`; ${name}=`);
    if (parts.length === 2) return parts.pop().split(';').shift();
    return null;
  }

  // Handler to read AUTH_TOKEN cookie and show it
  const handleReadAuthToken = () => {
    const token = getCookie('AUTH_TOKEN');
    if (token) {
      alert(`AUTH_TOKEN: ${token}`);
    } else {
      alert('AUTH_TOKEN cookie not found or not accessible.');
    }
  };
  const { instance, accounts, inProgress } = useMsal();
  const [apiMessage, setApiMessage] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState('');
  const [cookieSet, setCookieSet] = useState(false);

  const isAuthenticated = accounts.length > 0;

  // Automatically set token cookie when user becomes authenticated
  useEffect(() => {
    const handleAuthenticationComplete = async () => {
      // Only proceed if user is authenticated and we haven't set the cookie yet
      if (isAuthenticated && !cookieSet && !isLoading && inProgress === 'none') {
        console.log('Authentication detected, setting token cookie automatically...');
        await setTokenCookie();
      }
    };

    handleAuthenticationComplete();
  }, [isAuthenticated, cookieSet, isLoading, inProgress]);

  // Handle login
  const handleLogin = () => {
    instance.loginPopup(loginRequest).catch((error) => {
      console.error('Login failed:', error);
      setError('Login failed: ' + error.message);
    });
  };

  // Handle logout
  const handleLogout = async () => {
    try {
      setIsLoading(true);
      // First clear the backend cookie
      await authService.logout();
      setCookieSet(false);
      setApiMessage('');
      
      // Then logout from MSAL
      instance.logoutPopup({
        postLogoutRedirectUri: window.location.origin,
      });
    } catch (error) {
      console.error('Logout failed:', error);
      setError('Logout failed: ' + error.message);
    } finally {
      setIsLoading(false);
    }
  };

  // Set token in backend cookie
  const setTokenCookie = useCallback(async () => {
    try {
      setIsLoading(true);
      setError('');

      if (!accounts[0]) {
        throw new Error('No authenticated account found');
      }

      // Get access token
      const response = await instance.acquireTokenSilent({
        ...loginRequest,
        account: accounts[0],
      });

      console.log('Acquired token, sending to backend...');
      
      // Send token to backend
      await authService.setTokenCookie(response.accessToken);
      setCookieSet(true);
      setApiMessage('Token successfully set in HTTP-only cookie');
    } catch (error) {
      console.error('Failed to set token cookie:', error);
      
      // Provide more detailed error information
      let errorMessage = error.message;
      if (error.response) {
        errorMessage = `HTTP ${error.response.status}: ${error.response.data?.message || error.response.statusText}`;
      }
      
      setError('Failed to set token cookie: ' + errorMessage);
      setCookieSet(false);
    } finally {
      setIsLoading(false);
    }
  }, [instance, accounts, setIsLoading, setError, setCookieSet, setApiMessage]);

  // Call protected API endpoint
  const callHelloEndpoint = async () => {
    try {
      setIsLoading(true);
      setError('');

      const response = await authService.getHelloMessage();
      setApiMessage(JSON.stringify(response, null, 2));
    } catch (error) {
      console.error('API call failed:', error);
      setError('API call failed: ' + error.message);
      if (error.response?.status === 401) {
        setCookieSet(false);
        setError('Authentication required. Please set token cookie first.');
      }
    } finally {
      setIsLoading(false);
    }
  };

  // Clear messages when authentication state changes to unauthenticated
  useEffect(() => {
    if (!isAuthenticated) {
      setApiMessage('');
      setError('');
      setCookieSet(false);
    }
  }, [isAuthenticated]);

  return (
    <div className="app">
      <div className="container">
        <header className="header">
          <h1>MSAL React Authentication Demo</h1>
          <p>Secure token handling with HTTP-only cookies</p>
        </header>

        {/* Loading indicator */}
        {inProgress === 'login' && (
          <div className="loading">
            Signing in...
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
        {!isAuthenticated ? (
          <div>
            <p>Please sign in to continue</p>
            <button 
              className="button" 
              onClick={handleLogin}
              disabled={inProgress === 'login'}
            >
              Sign In with Azure AD
            </button>
          </div>
        ) : (
          <div>
            {/* User info */}
            <div className="user-info">
              <h3>Welcome, {accounts[0].name || accounts[0].username}!</h3>
              <p><strong>Account:</strong> {accounts[0].username}</p>
              <p><strong>Tenant:</strong> {accounts[0].tenantId}</p>
            </div>

            {/* Authentication Status */}
            <div>
              <h3>Authentication Status</h3>
              {isLoading && (
                <p style={{ color: 'orange' }}>Setting up secure authentication...</p>
              )}
              {cookieSet ? (
                <div>
                  <p style={{ color: 'green' }}>✓ Secure authentication established</p>
                  <p style={{ fontSize: '14px', color: '#666' }}>Your token is securely stored in an HTTP-only cookie</p>
                </div>
              ) : (
                <p style={{ color: '#666' }}>Authenticating and setting up secure session...</p>
              )}
            </div>

            {/* API calls */}
            <div style={{ marginTop: '30px' }}>
              <h3>Protected API Access</h3>
              <p>Call protected endpoints using secure cookie-based authentication.</p>
              <button 
                className="button" 
                onClick={callHelloEndpoint}
                disabled={isLoading || !cookieSet}
              >
                Call Hello Endpoint
              </button>
              {/* Button to read AUTH_TOKEN cookie */}
              <button
                className="button"
                style={{ marginLeft: '10px' }}
                onClick={handleReadAuthToken}
                disabled={isLoading}
              >
                Read AUTH_TOKEN Cookie
              </button>
              {!cookieSet && !isLoading && (
                <p style={{ color: 'orange', fontSize: '14px' }}>
                  Waiting for secure authentication setup...
                </p>
              )}
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
        )}

        {/* Loading indicator for API calls */}
        {isLoading && inProgress !== 'login' && (
          <div className="loading">
            Processing request...
          </div>
        )}

        {/* Information section */}
        <div style={{ marginTop: '40px', textAlign: 'left', fontSize: '14px', color: '#666' }}>
          <h4>Automatic Secure Authentication Flow:</h4>
          <ol style={{ marginBottom: '20px' }}>
            <li>User signs in with Azure AD</li>
            <li>Token is automatically acquired from MSAL</li>
            <li>Token is immediately sent to backend securely</li>
            <li>Backend sets HTTP-only cookie automatically</li>
            <li>User can now access protected endpoints</li>
          </ol>
          <h4>Security Features:</h4>
          <ul>
            <li>✓ JWT tokens are not stored in browser localStorage/sessionStorage</li>
            <li>✓ Tokens are stored in HTTP-only cookies on the backend</li>
            <li>✓ Cookies are secure and not accessible to JavaScript</li>
            <li>✓ CSRF protection through SameSite cookie attributes</li>
            <li>✓ Token validation happens on the backend</li>
            <li>✓ Automatic token setup - no manual steps required</li>
          </ul>
        </div>
      </div>
    </div>
  );
}

export default App;