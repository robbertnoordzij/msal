import axios from 'axios';
import { apiConfig } from '../config/msalConfig';

// Create axios instance with default configuration
const api = axios.create({
  baseURL: apiConfig.baseUrl,
  withCredentials: true, // Important: This ensures cookies are sent with requests
  headers: {
    'Content-Type': 'application/json',
  },
});

// API service for authentication
export const authService = {
  // Send token to backend to set in HTTP-only cookie
  setTokenCookie: async (accessToken) => {
    try {
      const response = await api.post(apiConfig.endpoints.login, {
        accessToken,
      });
      return response.data;
    } catch (error) {
      console.error('Error setting token cookie:', error);
      throw error;
    }
  },

  // Call protected endpoint using cookie authentication
  getHelloMessage: async () => {
    try {
      const response = await api.get(apiConfig.endpoints.hello);
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
      console.error('Error during logout:', error);
      throw error;
    }
  },
};