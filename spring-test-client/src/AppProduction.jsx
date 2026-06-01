import React, { useState, useEffect } from 'react';
import apiProduction, { setInMemoryToken, getInMemoryToken } from './axiosConfigProduction';

function AppProduction() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [accessToken, setAccessToken] = useState(null); // Kept strictly in memory state
  const [loggedInUser, setLoggedInUser] = useState(null);
  const [protectedData, setProtectedData] = useState(null);
  const [status, setStatus] = useState('Initializing...');

  // --- PRODUCTION SILENT LOGIN ON PAGE LOAD ---
  // On startup, we check if a valid session exists by calling the refresh endpoint.
  // Since the refresh token is in an HttpOnly cookie, we do not need local storage!
  useEffect(() => {
    const silentLogin = async () => {
      try {
        const res = await apiProduction.post('/auth/refresh');
        const token = res.data.accessToken;
        if (token) {
          setAccessToken(token);
          setInMemoryToken(token);
          
          // Decode user email from token payload
          const payload = JSON.parse(window.atob(token.split('.')[1]));
          setLoggedInUser(payload.sub);
          setStatus('Logged in silently via secure cookie.');
        }
      } catch (err) {
        setStatus('No active session. Please log in.');
      }
    };
    silentLogin();

    // Listen for auth-expired event from axios config
    const handleAuthExpired = () => {
      setAccessToken(null);
      setInMemoryToken(null);
      setLoggedInUser(null);
      setProtectedData(null);
      setStatus('Session expired. Please log in again.');
    };
    window.addEventListener('auth-expired', handleAuthExpired);
    return () => window.removeEventListener('auth-expired', handleAuthExpired);
  }, []);

  const handleLogin = async (e) => {
    e.preventDefault();
    try {
      setStatus('Logging in...');
      const res = await apiProduction.post('/auth/login', { email, password });
      const token = res.data.accessToken;
      if (token) {
        setAccessToken(token);
        setInMemoryToken(token);
        const payload = JSON.parse(window.atob(token.split('.')[1]));
        setLoggedInUser(payload.sub);
        setStatus('Login successful!');
        setPassword('');
      }
    } catch (err) {
      setStatus('Login failed: ' + (err.response?.data?.message || err.message));
    }
  };

  const handleLogout = async () => {
    try {
      setStatus('Logging out...');
      await apiProduction.post('/auth/logout');
    } catch (err) {
      // ignore
    } finally {
      setAccessToken(null);
      setInMemoryToken(null);
      setLoggedInUser(null);
      setProtectedData(null);
      setStatus('Logged out.');
    }
  };

  const fetchProtectedData = async () => {
    try {
      setStatus('Requesting protected data...');
      const res = await apiProduction.get('/demo');
      setProtectedData(res.data);
      setStatus('Data retrieved.');
    } catch (err) {
      setStatus('Failed to fetch: ' + (err.response?.data?.message || err.message));
    }
  };

  return (
    <div style={{ fontFamily: 'sans-serif', padding: '20px', maxWidth: '600px', margin: '0 auto' }}>
      <h1>Production Hardened App (Reference)</h1>
      <p style={{ color: '#555' }}>
        In-memory access token + HttpOnly cookie authentication flow. No local browser storage vulnerability.
      </p>

      <div style={{ background: '#eee', padding: '10px', margin: '15px 0', border: '1px solid #ccc' }}>
        <strong>Status:</strong> {status}
      </div>

      {!loggedInUser ? (
        <form onSubmit={handleLogin} style={{ border: '1px solid #333', padding: '15px' }}>
          <h3>Sign In</h3>
          <input 
            type="email" 
            placeholder="Email" 
            value={email} 
            onChange={e => setEmail(e.target.value)} 
            required 
            style={{ display: 'block', margin: '10px 0', padding: '8px', width: '90%' }}
          />
          <input 
            type="password" 
            placeholder="Password" 
            value={password} 
            onChange={e => setPassword(e.target.value)} 
            required 
            style={{ display: 'block', margin: '10px 0', padding: '8px', width: '90%' }}
          />
          <button type="submit" style={{ padding: '8px 16px', cursor: 'pointer' }}>Sign In</button>
        </form>
      ) : (
        <div style={{ border: '1px solid #333', padding: '15px' }}>
          <h3>Welcome, {loggedInUser}!</h3>
          <p>Your access token is held securely in local component memory state.</p>
          
          <button onClick={fetchProtectedData} style={{ marginRight: '10px', padding: '8px 16px' }}>
            Get Protected Data
          </button>
          
          <button onClick={handleLogout} style={{ padding: '8px 16px' }}>
            Log Out
          </button>

          {protectedData && (
            <pre style={{ background: '#f8f8f8', padding: '10px', marginTop: '10px', border: '1px solid #ddd' }}>
              {JSON.stringify(protectedData, null, 2)}
            </pre>
          )}
        </div>
      )}
    </div>
  );
}

export default AppProduction;
