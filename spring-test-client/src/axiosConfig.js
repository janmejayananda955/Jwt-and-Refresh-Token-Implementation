import axios from 'axios';

const api = axios.create({
    baseURL: 'http://localhost:8080/api',
    withCredentials: true // Essential for sending/receiving refresh cookies
});

let logCallback = null;
let tokenRefreshedCallback = null;
let tokenExpiredCallback = null;

// Allow registering callbacks from the React UI to update the logger and active token state
export const registerAxiosCallbacks = ({ onLog, onRefreshed, onExpired }) => {
    logCallback = onLog;
    tokenRefreshedCallback = onRefreshed;
    tokenExpiredCallback = onExpired;
};

const log = (type, message) => {
    if (logCallback) {
        logCallback({ type, message, timestamp: new Date().toLocaleTimeString() });
    }
};

api.interceptors.request.use((config) => {
    if (config.url && (config.url.includes('/auth/login') || config.url.includes('/auth/register') || config.url.includes('/auth/refresh') || config.url.includes('/auth/logout'))) {
        log('request', `➡️ Outgoing request: ${config.method.toUpperCase()} ${config.url} | Auth Header: BYPASSED`);
        return config;
    }

    const token = sessionStorage.getItem('accessToken');
    if (token) {
        config.headers.Authorization = `Bearer ${token}`;
        log('request', `➡️ Outgoing request: ${config.method.toUpperCase()} ${config.url} | Auth Header: Bearer ...${token.slice(-10)}`);
    } else {
        log('request', `➡️ Outgoing request: ${config.method.toUpperCase()} ${config.url} | Auth Header: NONE`);
    }
    return config;
}, (error) => {
    log('error', `❌ Request Error: ${error.message}`);
    return Promise.reject(error);
});

api.interceptors.response.use(
    (response) => {
        log('response', `✅ Incoming response: ${response.config.url} | Status: ${response.status}`);
        return response;
    },
    async (error) => {
        const originalRequest = error.config;
        
        // Log the response error
        const status = error.response ? error.response.status : 'Network Error';
        const errorMsg = error.response?.data?.message || error.response?.data || error.message;
        log('error', `❌ Response Error: ${originalRequest.url} | Status: ${status} | Detail: ${JSON.stringify(errorMsg)}`);

        // Check if error is 401 and we haven't retried yet
        if (error.response && error.response.status === 401 && !originalRequest._retry) {
            if (originalRequest.url.includes('/auth/refresh') || originalRequest.url.includes('/auth/login')) {
                // Do not retry refresh or login requests to avoid infinite loops
                return Promise.reject(error);
            }

            originalRequest._retry = true;
            log('warn', `⚠️ Access Token expired (401 Unauthorized). Attempting automatic refresh using Refresh Token Cookie...`);

            try {
                // Call refresh token endpoint
                const res = await axios.post('http://localhost:8080/api/auth/refresh', {}, {
                    withCredentials: true
                });

                const newToken = res.data.accessToken;
                if (newToken) {
                    sessionStorage.setItem('accessToken', newToken);
                    
                    // Callback to update react state
                    if (tokenRefreshedCallback) {
                        tokenRefreshedCallback(newToken);
                    }

                    log('success', `🔄 Silent Refresh successful! Received new Access Token: ...${newToken.slice(-10)}`);
                    
                    // Update headers for instance and retry request
                    api.defaults.headers.common['Authorization'] = `Bearer ${newToken}`;
                    originalRequest.headers['Authorization'] = `Bearer ${newToken}`;
                    
                    log('info', `🔁 Retrying original request to ${originalRequest.url} with new Access Token...`);
                    return api(originalRequest);
                }
            } catch (refreshError) {
                const refreshStatus = refreshError.response ? refreshError.response.status : 'Network Error';
                log('error', `🛑 Automatic Refresh failed with Status: ${refreshStatus}. Refresh Token might be expired or revoked. Logging out.`);
                
                sessionStorage.removeItem('accessToken');
                if (tokenExpiredCallback) {
                    tokenExpiredCallback();
                }
                return Promise.reject(refreshError);
            }
        }
        return Promise.reject(error);
    }
);

export default api;
