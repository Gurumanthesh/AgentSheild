import React, { useEffect, useState } from 'react';
import ReactDOM from 'react-dom/client';
import './styles.css';

const API_URL = 'https://agentsheild-br.onrender.com/api/analyze';

function App() {
  const [text, setText] = useState('Your account will be suspended immediately. Verify now with your password and OTP.');
  const [url, setUrl] = useState('https://example-fake-login.com/security/verify');
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  async function handleAnalyze() {
    setLoading(true);
    setError('');
    try {
      const response = await fetch(API_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          url,
          text,
          links: [{ text: 'Verify account', url }],
        }),
      });

      if (!response.ok) {
        throw new Error(`Request failed: ${response.status}`);
      }

      const data = await response.json();
      setResult(data);
    } catch (err) {
      setError('The backend is unavailable. Start the FastAPI server to use live analysis.');
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    handleAnalyze();
  }, []);

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand-block">
          <div className="brand-mark">🛡️</div>
          <div>
            <p className="eyebrow">Security console</p>
            <h1>AgentShield</h1>
          </div>
        </div>

        <nav className="nav">
          <span className="nav-item active">Overview</span>
          <span className="nav-item">Analyze Content</span>
          <span className="nav-item">History</span>
          <span className="nav-item">Threat Details</span>
          <span className="nav-item">Settings</span>
        </nav>
      </aside>

      <main className="main-panel">
        <header className="topbar">
          <div>
            <p className="eyebrow">Threat overview</p>
            <h2>Dashboard</h2>
          </div>
          <button className="primary-button" onClick={handleAnalyze} disabled={loading}>
            {loading ? 'Analyzing...' : 'Analyze'}
          </button>
        </header>

        <section className="stats-grid">
          <div className="stat-card">
            <span>Total analyses</span>
            <strong>128</strong>
          </div>
          <div className="stat-card warning">
            <span>Suspicious</span>
            <strong>19</strong>
          </div>
          <div className="stat-card danger">
            <span>High risk</span>
            <strong>6</strong>
          </div>
          <div className="stat-card safe">
            <span>Low risk</span>
            <strong>103</strong>
          </div>
        </section>

        <section className="content-grid">
          <div className="panel">
            <h3>Analyze content</h3>
            <label className="field-label">URL</label>
            <input value={url} onChange={(e) => setUrl(e.target.value)} />
            <label className="field-label">Text</label>
            <textarea value={text} onChange={(e) => setText(e.target.value)} rows="6" />
          </div>

          <div className="panel result-panel">
            <h3>Current assessment</h3>
            {error ? <p className="error-text">{error}</p> : null}
            {result ? (
              <>
                <div className="result-header">
                  <span className="result-badge">{result.status.replace(/_/g, ' ')}</span>
                  <strong>{result.risk_score}/100</strong>
                </div>
                <p className="summary">{result.summary}</p>
                <ul>
                  {result.indicators?.slice(0, 3).map((indicator, index) => (
                    <li key={index}>{indicator.evidence}</li>
                  ))}
                </ul>
              </>
            ) : (
              <p className="summary">Waiting for analysis.</p>
            )}
          </div>
        </section>
      </main>
    </div>
  );
}

ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
