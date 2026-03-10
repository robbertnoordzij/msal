import axios from 'axios';
import { apiConfig } from '../config/msalConfig';

// Create axios instance with default configuration
const api = axios.create({
  baseURL: apiConfig.baseUrl,
  withCredentials: true, // Important: This ensures cookies are sent with requests
  headers: {
    'Content-Type': 'application/json',
  },
  timeout: 30000, // Abort if backend doesn't respond within 30 seconds
});

// API service for authentication
export const authService = {
  // Start login by redirecting to backend (BFF) which handles auth code flow
  startLogin: () => {
    window.location.href = `${apiConfig.baseUrl}/auth/login`;
  },

  // Call protected endpoint using cookie authentication
  getHelloMessage: async () => {
    try {
      const response = await api.get(apiConfig.endpoints.hello);
      if (!response.data) {
        throw new Error('Empty response from server');
      }
      return response.data;
    } catch (error) {
      console.error('Error calling hello endpoint:', error);
      throw error;
    }
  },

  // Logout by clearing cookie
  logout: async () => {
    try {
      const response = await api.post('/auth/logout');
      return response.data;
    } catch (error) {
      // Don't re-throw on logout failure: the cookie may already be cleared
      // or the session may have expired. The caller should proceed.
      console.warn('Logout error (session may already be invalid):', error.message);
      return { success: false, message: error.message };
    }
  },
};