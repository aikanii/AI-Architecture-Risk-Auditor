import React, { useState, useEffect } from 'react';
import { BrowserRouter as Router, Routes, Route, Link } from 'react-router-dom';
import './App.css';
import Dashboard from './pages/Dashboard';
import ScanResults from './pages/ScanResults';
import GraphView from './pages/GraphView';
import Findings from './pages/Findings';

function App() {
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  // Fetch recent scans on mount
  useEffect(() => {
    fetchScans();
  }, []);

  const fetchScans = async () => {
    try {
      setLoading(true);
      const response = await fetch('/api/scans/?limit=10');
      if (!response.ok) throw new Error('Failed to fetch scans');
      const data = await response.json();
      setScans(data);
    } catch (err) {
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
            <h1>🏛️ AI Architecture Risk Auditor</h1>
          </div>
          <ul className="nav-links">
            <li><Link to="/">Dashboard</Link></li>
            <li><Link to="/scans">Recent Scans</Link></li>
            <li><Link to="/findings">Findings</Link></li>
            <li><button className="btn-primary" onClick={() => window.location.href = '/docs'}>API Docs</button></li>
          </ul>
        </nav>

        <main className="main-content">
          {error && <div className="alert alert-error">{error}</div>}
          
          <Routes>
            <Route path="/" element={<Dashboard scans={scans} />} />
            <Route path="/scans" element={<ScanResults scans={scans} onRefresh={fetchScans} />} />
            <Route path="/scans/:scanId" element={<GraphView />} />
            <Route path="/findings/:scanId" element={<Findings />} />
          </Routes>
        </main>

        <footer className="footer">
          <p>AI Architecture Risk Auditor v0.1.0 | <a href="https://github.com">GitHub</a> | <a href="/docs">Documentation</a></p>
        </footer>
      </div>
    </Router>
  );
}

export default App;
