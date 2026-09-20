import React, { useState, useEffect } from 'react';
import { BrowserRouter as Router, Routes, Route, Link } from 'react-router-dom';
import './App.css';
import Dashboard from './pages/Dashboard';
import ScanResults from './pages/ScanResults';
import GraphView from './pages/GraphView';
import Findings from './pages/Findings';

function App() {
  const [scans, setScans] = useState<any[]>([]);
  const [, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Fetch recent scans on mount
  useEffect(() => {
    fetchScans();
  }, []);

  const fetchScans = async () => {
    try {
      setLoading(true);
      setError(null);
      const response = await fetch('/api/scans/?limit=20');
      if (!response.ok) throw new Error('Failed to fetch scans');
      const data = await response.json();
      setScans(data || []);
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <Router>
      <div className="App">
        <nav className="navbar">
          <div className="navbar-brand">
            <h1>🛡️ AI ARCHITECTURE AUDITOR</h1>
          </div>
          <ul className="nav-links">
            <li><Link to="/">Dashboard</Link></li>
            <li><Link to="/scans">Scans</Link></li>
            <li><Link to="/graph">Architecture Graph</Link></li>
            <li><Link to="/findings">Findings</Link></li>
            <li>
              <a
                href="/docs"
                target="_blank"
                rel="noreferrer"
                className="btn-primary btn-small"
                style={{ textDecoration: 'none' }}
              >
                API Docs ↗
              </a>
            </li>
          </ul>
        </nav>

        <main className="main-content">
          {error && <div className="alert alert-error">{error}</div>}
          
          <Routes>
            <Route path="/" element={<Dashboard scans={scans} />} />
            <Route path="/scans" element={<ScanResults scans={scans} onRefresh={fetchScans} />} />
            <Route path="/graph" element={<GraphView />} />
            <Route path="/scans/:scanId" element={<GraphView />} />
            <Route path="/findings" element={<Findings />} />
            <Route path="/findings/:scanId" element={<Findings />} />
          </Routes>
        </main>

        <footer className="footer">
          <p>
            AI Architecture Risk Auditor v0.1.0 | Microservices Architecture Security & Risk Analysis |{' '}
            <a href="/docs" target="_blank" rel="noreferrer">OpenAPI Documentation</a>
          </p>
        </footer>
      </div>
    </Router>
  );
}

export default App;
