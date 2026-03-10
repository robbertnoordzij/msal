import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App';
import './index.css';

// In the BFF pattern the backend drives the entire OAuth2 flow.
// No MSAL instance is needed in the browser.
const root = ReactDOM.createRoot(document.getElementById('root'));
root.render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
