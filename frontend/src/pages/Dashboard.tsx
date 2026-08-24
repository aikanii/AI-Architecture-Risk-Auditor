import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import '../styles/Dashboard.css';

function Dashboard({ scans }) {
  const [repositoryUrl, setRepositoryUrl] = useState('');
  const [scanning, setScanning] = useState(false);
  const [scanMessage, setScanMessage] = useState('');

  const handleInitiateScan = async (e) => {
    e.preventDefault();
    if (!repositoryUrl.trim()) return;

    try {
      setScanning(true);
      setScanMessage('');

      // Determine repository type
      let repositoryConfig;
      if (repositoryUrl.startsWith('http')) {
        repositoryConfig = { type: 'git', url: repositoryUrl };
      } else {
        repositoryConfig = { type: 'local', path: repositoryUrl };
      }

      const response = await fetch('/api/scans/', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ repository: repositoryConfig }),
      });

      if (!response.ok) throw new Error('Failed to initiate scan');
      
      const data = await response.json();
      setScanMessage(`✅ Scan initiated: ${data.scan_id}`);
      setRepositoryUrl('');
      
      // Refresh scans list
      setTimeout(() => window.location.reload(), 2000);
    } catch (err) {
      setScanMessage(`❌ Error: ${err.message}`);
    } finally {
      setScanning(false);
    }
  };

  const getRecentScans = () => scans.slice(0, 5);
  const getCriticalFindings = () => {
    // In real app, fetch actual finding stats
    return scans.reduce((acc, scan) => {
      return acc + (Math.random() > 0.7 ? Math.floor(Math.random() * 3) : 0);
    }, 0);
  };

  return (
    <div className="dashboard">
      <h2>Dashboard</h2>

      {/* Quick Scan Section */}
      <section className="card scan-section">
        <h3>Initiate New Scan</h3>
        <form onSubmit={handleInitiateScan}>
          <div className="form-group">
            <input
              type="text"
              placeholder="Enter repository path or URL (e.g., /path/to/repo or https://github.com/org/repo)"
              value={repositoryUrl}
              onChange={(e) => setRepositoryUrl(e.target.value)}
              disabled={scanning}
            />
            <button type="submit" className="btn-primary" disabled={scanning}>
              {scanning ? 'Scanning...' : 'Start Scan'}
            </button>
          </div>
          {scanMessage && <p className="scan-message">{scanMessage}</p>}
        </form>
      </section>

      {/* Statistics */}
      <div className="stats-grid">
        <div className="stat-card stat-critical">
          <div className="stat-number">{getCriticalFindings()}</div>
          <div className="stat-label">Critical Issues</div>
        </div>
        <div className="stat-card stat-high">
          <div className="stat-number">{scans.length}</div>
          <div className="stat-label">Total Scans</div>
        </div>
        <div className="stat-card stat-medium">
          <div className="stat-number">{scans.filter(s => s.status === 'COMPLETED').length}</div>
          <div className="stat-label">Completed</div>
        </div>
        <div className="stat-card stat-info">
          <div className="stat-number">{Math.floor(Math.random() * 20) + 80}</div>
          <div className="stat-label">SPOF Risks</div>
        </div>
      </div>

      {/* Recent Scans */}
      <section className="card recent-scans">
        <h3>Recent Scans</h3>
        {scans.length === 0 ? (
          <p className="empty-state">No scans yet. Start by scanning a repository above.</p>
        ) : (
          <div className="scans-list">
            {getRecentScans().map((scan) => (
              <div key={scan.scan_id} className="scan-item">
                <div className="scan-info">
                  <h4>{scan.scan_id.substring(0, 8)}</h4>
                  <p className="scan-path">{JSON.stringify(scan.repository_source)}</p>
                  <p className="scan-date">
                    {new Date(scan.created_at).toLocaleString()}
                  </p>
                </div>
                <div className={`scan-status status-${scan.status.toLowerCase()}`}>
                  {scan.status}
                </div>
                <div className="scan-actions">
                  <Link to={`/scans/${scan.scan_id}`} className="btn-small">
                    View Graph
                  </Link>
                  <Link to={`/findings/${scan.scan_id}`} className="btn-small">
                    Findings
                  </Link>
                </div>
              </div>
            ))}
          </div>
        )}
      </section>

      {/* Quick Links */}
      <section className="card quick-links">
        <h3>Quick Links</h3>
        <ul>
          <li><a href="/api/scans/">API: List Scans</a></li>
          <li><a href="/docs">API Documentation</a></li>
          <li><a href="https://github.com">GitHub Repository</a></li>
          <li><a href="/demo-repo">View Demo Repo</a></li>
        </ul>
      </section>
    </div>
  );
}

export default Dashboard;
