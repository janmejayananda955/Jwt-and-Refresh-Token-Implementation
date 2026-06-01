import React, { useState, useEffect, useRef } from 'react';
import api, { registerAxiosCallbacks } from './axiosConfig';

function App() {
  const [email, setEmail] = useState('');
  const [fullName, setFullName] = useState('');
  const [password, setPassword] = useState('');
  const [accessToken, setAccessToken] = useState(sessionStorage.getItem('accessToken') || null);
  const [authTab, setAuthTab] = useState('login'); // 'login' or 'register'
  
  const [status, setStatus] = useState('Welcome! Please sign in or register.');
  const [protectedData, setProtectedData] = useState(null);
  const [logs, setLogs] = useState([]);
  
  const [remainingTime, setRemainingTime] = useState(null);
  const consoleEndRef = useRef(null);

  // Decode JWT payload
  const decodeToken = (token) => {
    if (!token) return null;
    try {
      const base64Url = token.split('.')[1];
      const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
      return JSON.parse(window.atob(base64));
    } catch (e) {
      return null;
    }
  };

  useEffect(() => {
    if (accessToken) {
      const claims = decodeToken(accessToken);
      if (claims && claims.exp) {
        const calculateRemaining = () => {
          const rem = claims.exp - Math.floor(Date.now() / 1000);
          setRemainingTime(Math.max(0, rem));
        };
        calculateRemaining();
        const interval = setInterval(calculateRemaining, 1000);
        return () => clearInterval(interval);
      }
    } else {
      setRemainingTime(null);
    }
  }, [accessToken]);

  // Register Axios callbacks to stream events directly to our log panel
  useEffect(() => {
    registerAxiosCallbacks({
      onLog: (logEntry) => {
        setLogs((prev) => [...prev, logEntry]);
      },
      onRefreshed: (newToken) => {
        setAccessToken(newToken);
        setStatus('Access Token refreshed automatically!');
      },
      onExpired: () => {
        setAccessToken(null);
        setStatus('Session expired. Please log in again.');
      }
    });
  }, []);

  useEffect(() => {
    if (consoleEndRef.current) {
      consoleEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [logs]);

  const handleRegister = async (e) => {
    e.preventDefault();
    try {
      setStatus('Registering...');
      await api.post('/auth/register', { fullName, email, password });
      setStatus('Registration successful! You can now log in.');
      setAuthTab('login');
    } catch (err) {
      setStatus('Registration failed: ' + (err.response?.data?.message || err.message));
    }
  };

  const handleLogin = async (e) => {
    e.preventDefault();
    try {
      setStatus('Logging in...');
      const res = await api.post('/auth/login', { email, password });
      const token = res.data.accessToken;
      if (token) {
        setAccessToken(token);
        sessionStorage.setItem('accessToken', token);
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
      await api.post('/auth/logout');
    } catch (err) {
      // ignore errors during logout
    } finally {
      setAccessToken(null);
      sessionStorage.removeItem('accessToken');
      setProtectedData(null);
      setStatus('Logged out.');
    }
  };

  const testProtectedEndpoint = async () => {
    try {
      setStatus('Calling protected endpoint...');
      const res = await api.get('/demo');
      setProtectedData(res.data);
      setStatus('Protected data retrieved successfully.');
    } catch (err) {
      setStatus('Request failed: ' + (err.response?.data?.message || err.message));
    }
  };

  const manualRefresh = async () => {
    try {
      setStatus('Refreshing token manually...');
      const res = await api.post('/auth/refresh');
      const token = res.data.accessToken;
      if (token) {
        setAccessToken(token);
        sessionStorage.setItem('accessToken', token);
        setStatus('Token refreshed manually.');
      }
    } catch (err) {
      setStatus('Manual refresh failed: ' + (err.response?.data?.message || err.message));
    }
  };

  const deleteLocalToken = () => {
    sessionStorage.removeItem('accessToken');
    setAccessToken(null);
    setStatus('Access token deleted locally.');
  };

  const corruptLocalToken = () => {
    if (!accessToken) return;
    const corrupted = accessToken.substring(0, accessToken.length - 20) + "corrupted";
    setAccessToken(corrupted);
    sessionStorage.setItem('accessToken', corrupted);
    setStatus('Access token corrupted locally.');
  };

  return (
    <div>
      <h1>Access & Refresh Token Explorer</h1>
      <p style={{ margin: '10px 0 20px 0' }}>
        A minimal playground to observe token expiration and automatic refreshing using Axios interceptors.
      </p>

      <div className="box" style={{ background: '#f9f9f9', fontWeight: 'bold' }}>
        Status: {status}
      </div>

      {/* Real-time Flow Visualizer */}
      <div className="box" style={{ background: '#fafafa' }}>
        <h3>Real-time Token Flow Visualizer</h3>
        <div style={{ display: 'flex', gap: '10px', flexWrap: 'wrap', marginBottom: '10px' }}>
          
          <div style={{ 
            flex: '1 1 180px', 
            border: '2px solid #333', 
            padding: '10px', 
            background: !accessToken ? '#ffffdd' : '#fff',
            opacity: !accessToken ? 1 : 0.6,
            transition: 'all 0.3s ease'
          }}>
            <strong>1. Auth / Login</strong>
            <div style={{ fontSize: '11px', marginTop: '5px' }}>
              POST /auth/login. Server sets Refresh Token cookie & returns Access Token.
            </div>
            <div style={{ fontSize: '11px', fontWeight: 'bold', marginTop: '8px', color: !accessToken ? '#aa7700' : '#888' }}>
              {!accessToken ? '● CURRENT STATE' : '○ LOGGED IN'}
            </div>
          </div>

          <div style={{ 
            flex: '1 1 180px', 
            border: '2px solid #333', 
            padding: '10px', 
            background: accessToken && remainingTime > 0 ? '#ddffdd' : '#fff',
            opacity: accessToken && remainingTime > 0 ? 1 : 0.6,
            transition: 'all 0.3s ease'
          }}>
            <strong>2. Access API</strong>
            <div style={{ fontSize: '11px', marginTop: '5px' }}>
              Access Token in state. Protected requests attach `Authorization: Bearer [token]`.
            </div>
            <div style={{ fontSize: '11px', fontWeight: 'bold', marginTop: '8px', color: accessToken && remainingTime > 0 ? 'green' : '#888' }}>
              {accessToken && remainingTime > 0 ? '● CURRENT STATE' : '○ INACTIVE'}
            </div>
          </div>

          <div style={{ 
            flex: '1 1 180px', 
            border: '2px solid #333', 
            padding: '10px', 
            background: accessToken && remainingTime === 0 ? '#ffdddd' : '#fff',
            opacity: accessToken && remainingTime === 0 ? 1 : 0.6,
            transition: 'all 0.3s ease'
          }}>
            <strong>3. Expiration / 401</strong>
            <div style={{ fontSize: '11px', marginTop: '5px' }}>
              Token expires in 30s. Next endpoint call fails with HTTP 401.
            </div>
            <div style={{ fontSize: '11px', fontWeight: 'bold', marginTop: '8px', color: accessToken && remainingTime === 0 ? 'red' : '#888' }}>
              {accessToken && remainingTime === 0 ? '● CURRENT STATE' : '○ INACTIVE'}
            </div>
          </div>

          <div style={{ 
            flex: '1 1 180px', 
            border: '2px solid #333', 
            padding: '10px', 
            background: status.includes('refreshed') || status.includes('Refreshing') ? '#ddeeff' : '#fff',
            opacity: status.includes('refreshed') || status.includes('Refreshing') ? 1 : 0.6,
            transition: 'all 0.3s ease'
          }}>
            <strong>4. Silent Refresh</strong>
            <div style={{ fontSize: '11px', marginTop: '5px' }}>
              Interceptor sends cookie to /refresh, receives new token & retries original call.
            </div>
            <div style={{ fontSize: '11px', fontWeight: 'bold', marginTop: '8px', color: status.includes('refreshed') || status.includes('Refreshing') ? 'blue' : '#888' }}>
              {status.includes('refreshed') || status.includes('Refreshing') ? '● ACTIVE REFRESH' : '○ INACTIVE'}
            </div>
          </div>

        </div>
      </div>

      {!accessToken ? (
        <div className="box">
          <div>
            <button onClick={() => setAuthTab('login')} style={{ fontWeight: authTab === 'login' ? 'bold' : 'normal' }}>Login</button>
            <button onClick={() => setAuthTab('register')} style={{ fontWeight: authTab === 'register' ? 'bold' : 'normal' }}>Register</button>
          </div>
          <hr style={{ margin: '15px 0' }} />

          <form onSubmit={authTab === 'login' ? handleLogin : handleRegister}>
            {authTab === 'register' && (
              <div>
                <label>Full Name:</label>
                <input type="text" value={fullName} onChange={e => setFullName(e.target.value)} required />
              </div>
            )}
            <div>
              <label>Email:</label>
              <input type="email" value={email} onChange={e => setEmail(e.target.value)} required />
            </div>
            <div>
              <label>Password:</label>
              <input type="password" value={password} onChange={e => setPassword(e.target.value)} required />
            </div>
            <button type="submit">{authTab === 'login' ? 'Sign In' : 'Register'}</button>
          </form>
        </div>
      ) : (
        <div>
          <div className="flex-container">
            {/* Access Token Details */}
            <div className="box flex-child">
              <h2>Access Token</h2>
              <div className="timer">
                Countdown: {remainingTime !== null ? `${remainingTime}s` : 'Expired'}
              </div>
              <p>Raw Token:</p>
              <pre>{accessToken}</pre>
              <p>Decoded Payload:</p>
              <pre>{JSON.stringify(decodeToken(accessToken), null, 2)}</pre>
            </div>

            {/* Controls and Actions */}
            <div className="box flex-child">
              <h2>Refresh Token & API Actions</h2>
              <p>Stored securely in an HttpOnly cookie. Browser will send it automatically.</p>
              
              <hr style={{ margin: '10px 0' }} />
              
              <h3>Actions:</h3>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                <div>
                  <button onClick={testProtectedEndpoint}>Test Protected Endpoint (/demo)</button>
                </div>
                <div>
                  <button onClick={manualRefresh}>Manual Token Refresh</button>
                </div>
                <div>
                  <button onClick={deleteLocalToken}>Delete Local Access Token</button>
                </div>
                <div>
                  <button onClick={corruptLocalToken}>Corrupt Access Token</button>
                </div>
                <div>
                  <button onClick={handleLogout}>Log Out</button>
                </div>
              </div>

              {protectedData && (
                <div style={{ marginTop: '15px' }}>
                  <strong>Protected Response:</strong>
                  <pre>{JSON.stringify(protectedData, null, 2)}</pre>
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Terminal event log console */}
      <div className="box">
        <h2>Live Event Log (Axios Console)</h2>
        <div className="log-console">
          {logs.map((log, index) => (
            <div key={index} className="log-entry">
              [{log.timestamp}] {log.message}
            </div>
          ))}
          <div ref={consoleEndRef} />
        </div>
        <button onClick={() => setLogs([])} style={{ marginTop: '10px' }}>Clear Logs</button>
      </div>

      <div className="box" style={{ background: '#fcfcfc', fontSize: '13px' }}>
        <h3>Lab Guide</h3>
        <p>
          1. The Access Token expires in 30 seconds.
          <br />
          2. Log in, wait for the countdown to expire (0s), then click "Test Protected Endpoint".
          <br />
          3. Watch the Live Event Log: you will see the 401 error, the automatic background refresh request using the HTTP-only cookie, and the retried original request.
        </p>
      </div>
    </div>
  );
}

export default App;
