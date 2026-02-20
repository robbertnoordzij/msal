import React, { useState, useEffect } from 'react';
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
  const [apiMessage, setApiMessage] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState('');
  const [cookieSet, setCookieSet] = useState(false);

  // Automatically handle login result from URL parameters or check initial auth status
  useEffect(() => {
    const queryParams = new URLSearchParams(window.location.search);
    const loginStatus = queryParams.get('login');

    if (loginStatus === 'success') {
      console.log('Login successful, calling hello endpoint...');
      callHelloEndpoint();
      // Remove query parameter from URL without refreshing
      window.history.replaceState({}, document.title, window.location.pathname);
    } else if (loginStatus === 'error') {
      console.error('Login failed');
      setError('Login failed. Please try again.');
      // Remove query parameter from URL without refreshing
      window.history.replaceState({}, document.title, window.location.pathname);
    } else {
      // No login parameters, check if already authenticated silently
      console.log('No login status in URL, checking current auth status...');
      callHelloEndpoint(true);
    }
  }, []);

  const handleLogin = () => {
    authService.startLogin();
  };

  const handleLogout = async () => {
    try {
      setIsLoading(true);
      await authService.logout();
      setCookieSet(false);
      setApiMessage('');
    } catch (error) {
      console.error('Logout failed:', error);
      setError('Logout failed: ' + error.message);
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
      setApiMessage(JSON.stringify(response, null, 2));
      setCookieSet(true);
    } catch (error) {
      console.error('API call failed:', error);
      if (!isInitialCheck) {
        setError('API call failed: ' + error.message);
      }
      if (error.response?.status === 401) {
        setCookieSet(false);
        if (!isInitialCheck) {
          setError('Authentication required. Please sign in first.');
        }
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
            {isLoading && (
              <p style={{ color: 'orange' }}>Processing...</p>
            )}
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
            {/* Button to read AUTH_TOKEN cookie */}
            <button
              className="button"
              style={{ marginLeft: '10px' }}
              onClick={handleReadAuthToken}
              disabled={isLoading}
            >
              Read AUTH_TOKEN Cookie
            </button>
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

        {/* Loading indicator for API calls */}
        {isLoading && (
          <div className="loading">
            Processing request...
          </div>
        )}

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