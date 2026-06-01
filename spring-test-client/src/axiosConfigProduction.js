import axios from 'axios';

// --- PRODUCTION STORAGE HARDENING ---
// In production, we keep the access token strictly in-memory (inside a standard JS variable).
// This prevents XSS attacks from reading it via 'sessionStorage' or 'localStorage'.
let inMemoryAccessToken = null;

export const setInMemoryToken = (token) => {
    inMemoryAccessToken = token;
};

export const getInMemoryToken = () => {
    return inMemoryAccessToken;
};

// Create axios instance
const apiProduction = axios.create({
    baseURL: 'http://localhost:8080/api',
    withCredentials: true // Sends/receives secure HttpOnly refresh cookies automatically
});

// Outgoing request interceptor
apiProduction.interceptors.request.use((config) => {
    // 1. Bypass auth header for authentication endpoints
    if (config.url && (config.url.includes('/auth/login') || config.url.includes('/auth/register') || config.url.includes('/auth/refresh'))) {
        return config;
    }

    // 2. Read token from memory instead of sessionStorage
    const token = getInMemoryToken();
    if (token) {
        config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
}, (error) => {
    return Promise.reject(error);
});

// Incoming response interceptor for automatic silent refreshes
apiProduction.interceptors.response.use(
    (response) => response,
    async (error) => {
        const originalRequest = error.config;

        // If the server returns 401 Unauthorized (Access Token expired)
        if (error.response && error.response.status === 401 && !originalRequest._retry) {
            // Avoid loops on refresh/login routes
            if (originalRequest.url.includes('/auth/refresh') || originalRequest.url.includes('/auth/login')) {
                return Promise.reject(error);
            }

            originalRequest._retry = true;

            try {
                // Post to refresh endpoint. Browser automatically includes the HttpOnly cookie.
                const res = await axios.post('http://localhost:8080/api/auth/refresh', {}, {
                    withCredentials: true
                });

                const newToken = res.data.accessToken;
                if (newToken) {
                    // Update in-memory token
                    setInMemoryToken(newToken);

                    // Retry original request with the new access token
                    originalRequest.headers['Authorization'] = `Bearer ${newToken}`;
                    return apiProduction(originalRequest);
                }
            } catch (refreshError) {
                // If refresh fails, it means the refresh token cookie has expired or been revoked.
                // Clear the in-memory token and redirect/prompt user to log in again.
                setInMemoryToken(null);
                window.dispatchEvent(new Event('auth-expired'));
                return Promise.reject(refreshError);
            }
        }
        return Promise.reject(error);
    }
);

export default apiProduction;
