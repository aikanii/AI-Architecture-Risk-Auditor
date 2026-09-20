import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import '../styles/Dashboard.css';

interface DashboardProps {
  scans: any[];
}

function Dashboard({ scans }: DashboardProps) {
  const [repositoryUrl, setRepositoryUrl] = useState('');
  const [scanning, setScanning] = useState(false);
  const [scanMessage, setScanMessage] = useState('');
  const [stats, setStats] = useState<{
    criticalCount: number;
    highCount: number;
    spofCount: number;
    serviceCount: number;
  }>({
    criticalCount: 0,
    highCount: 0,
    spofCount: 0,
    serviceCount: 0,
  });

  useEffect(() => {
    if (scans.length > 0) {
      const latestCompleted = scans.find((s) => s.status === 'COMPLETED');
      if (latestCompleted) {
        fetch(`/api/graph/${latestCompleted.scan_id}/stats`)
          .then((r) => r.json())
          .then((data) => {
            if (data) {
              setStats({
                criticalCount: data.findings_by_severity?.CRITICAL || 0,
                highCount: data.findings_by_severity?.HIGH || 0,
                spofCount: data.findings_by_severity?.HIGH || 0,
                serviceCount: data.service_count || 0,
              });
            }
          })
          .catch(() => {});
      }
    }
  }, [scans]);

  const handleInitiateScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!repositoryUrl.trim()) return;

    try {
      setScanning(true);
      setScanMessage('⏳ Scanning in progress...');

      let repositoryConfig: Record<string, string>;
      if (repositoryUrl.startsWith('http://') || repositoryUrl.startsWith('https://')) {
        repositoryConfig = { type: 'git', url: repositoryUrl.trim() };
      } else {
        repositoryConfig = { type: 'local', path: repositoryUrl.trim() };
      }

      const response = await fetch('/api/scans/', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ repository: repositoryConfig }),
      });

      if (!response.ok) {
        const errData = await response.json().catch(() => ({}));
        throw new Error(errData.detail || 'Failed to initiate scan');
      }
      
      const data = await response.json();
      setScanMessage(`✅ Scan initiated: ${data.scan_id}`);
      setRepositoryUrl('');
      
      setTimeout(() => window.location.reload(), 1500);
    } catch (err: any) {
      setScanMessage(`❌ Error: ${err.message}`);
    } finally {
      setScanning(false);
    }
  };

  const getRecentScans = () => scans.slice(0, 5);

  return (
    <div className="dashboard">
      <h2>Architectural Risk Dashboard</h2>

      {/* Quick Scan Section */}
      <section className="card scan-section">
        <h3>Initiate New Scan</h3>
        <p style={{ color: '#64748b', fontSize: '0.9rem', marginBottom: '1rem' }}>
          Scan local directories or git repositories for microservice architectural vulnerabilities, SPOFs, shared datastores, unencrypted traffic, and access control risks.
        </p>
        <form onSubmit={handleInitiateScan}>
          <div className="form-group">
            <input
              type="text"
              placeholder="Enter repository path or URL (e.g. /home/user/AI-Architecture-Risk-Auditor/test-fixtures/demo-repo)"
              value={repositoryUrl}
              onChange={(e) => setRepositoryUrl(e.target.value)}
              disabled={scanning}
            />
            <button type="submit" className="btn-primary" disabled={scanning}>
              {scanning ? 'Scanning...' : '🚀 Start Scan'}
            </button>
          </div>
          {scanMessage && <p className="scan-message">{scanMessage}</p>}
        </form>
      </section>

      {/* Statistics */}
      <div className="stats-grid">
        <div className="stat-card stat-critical">
          <div className="stat-number">{stats.criticalCount}</div>
          <div className="stat-label">Critical Findings</div>
        </div>
        <div className="stat-card stat-high">
          <div className="stat-number">{scans.length}</div>
          <div className="stat-label">Total Scans</div>
        </div>
        <div className="stat-card stat-medium">
          <div className="stat-number">{scans.filter((s) => s.status === 'COMPLETED').length}</div>
          <div className="stat-label">Completed Scans</div>
        </div>
        <div className="stat-card stat-info">
          <div className="stat-number">{stats.serviceCount}</div>
          <div className="stat-label">Audited Services</div>
        </div>
      </div>

      {/* Recent Scans */}
      <section className="card recent-scans">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
          <h3>Recent Scans</h3>
          <Link to="/scans" className="btn-small btn-secondary">
            View All Scans
          </Link>
        </div>
        {scans.length === 0 ? (
          <p className="empty-state">No scans recorded yet. Enter a repository path above to run your first architectural audit.</p>
        ) : (
          <div className="scans-list">
            {getRecentScans().map((scan) => {
              const repoPath = scan.repository_source?.path || scan.repository_source?.url || 'Demo Repository';
              return (
                <div key={scan.scan_id} className="scan-item">
                  <div className="scan-info">
                    <h4>{scan.scan_id.substring(0, 12)}</h4>
                    <p className="scan-path">{repoPath}</p>
                    <p className="scan-date">
                      {new Date(scan.created_at).toLocaleString()}
                    </p>
                  </div>
                  <div className={`scan-status status-${scan.status.toLowerCase()}`}>
                    {scan.status}
                  </div>
                  <div className="scan-actions">
                    <Link to={`/scans/${scan.scan_id}`} className="btn-small btn-primary">
                      🕸️ Graph
                    </Link>
                    <Link to={`/findings/${scan.scan_id}`} className="btn-small btn-secondary">
                      🔍 Findings
                    </Link>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </section>

      {/* Quick Links */}
      <section className="card quick-links">
        <h3>Architecture Analysis Features</h3>
        <ul>
          <li><span>⚡ Deterministic SPOF & Bottleneck Graph Detection</span></li>
          <li><span>🔒 Static AST & Semgrep Security Pattern Scanning</span></li>
          <li><span>📦 Multi-Writer Shared Datastore Detection</span></li>
          <li><span>🌐 Inter-Service Unencrypted HTTP Traffic Tracing</span></li>
          <li><span>📊 SARIF, JSON & Interactive Cytoscape Visualizations</span></li>
        </ul>
      </section>
    </div>
  );
}

export default Dashboard;
