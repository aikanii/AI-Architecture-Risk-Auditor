import React, { useState, useEffect } from 'react';
import { BrowserRouter as Router, Routes, Route, Link } from 'react-router-dom';
import { ShieldCheck, Activity, Layers, Network, AlertTriangle, ExternalLink } from 'lucide-react';
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
            <ShieldCheck size={24} color="#38bdf8" />
            <h1>AI ARCHITECTURE AUDITOR</h1>
          </div>
          <ul className="nav-links">
            <li>
              <Link to="/">
                <Activity size={15} style={{ verticalAlign: 'middle', marginRight: '6px' }} />
                Dashboard
              </Link>
            </li>
            <li>
              <Link to="/scans">
                <Layers size={15} style={{ verticalAlign: 'middle', marginRight: '6px' }} />
                Scans
              </Link>
            </li>
            <li>
              <Link to="/graph">
                <Network size={15} style={{ verticalAlign: 'middle', marginRight: '6px' }} />
                Architecture Graph
              </Link>
            </li>
            <li>
              <Link to="/findings">
                <AlertTriangle size={15} style={{ verticalAlign: 'middle', marginRight: '6px' }} />
                Findings
              </Link>
            </li>
            <li>
              <a
                href="/docs"
                target="_blank"
                rel="noreferrer"
                className="btn-primary btn-small"
                style={{ textDecoration: 'none' }}
              >
                API Docs
                <ExternalLink size={13} style={{ marginLeft: '4px' }} />
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
            <a href="/docs" target="_blank" rel="noreferrer">
              OpenAPI Documentation <ExternalLink size={12} style={{ verticalAlign: 'middle' }} />
            </a>
          </p>
        </footer>
      </div>
    </Router>
  );
}

export default App;
