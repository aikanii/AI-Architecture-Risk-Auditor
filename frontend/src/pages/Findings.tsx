import React, { useEffect, useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import '../styles/Findings.css';

interface FindingItem {
  id: string;
  title: string;
  description: string;
  severity: string;
  confidence: number;
  source: string;
  affected_components?: string[];
  remediation_steps?: string[];
  cwe_ids?: string[];
  owasp_categories?: string[];
  references?: string[];
  [key: string]: any;
}

interface ScanSummary {
  scan_id: string;
  findings_count: number;
  findings_by_severity?: Record<string, number>;
}

function Findings() {
  const { scanId: paramScanId } = useParams<{ scanId?: string }>();
  const [activeScanId, setActiveScanId] = useState<string | null>(paramScanId || null);
  const [availableScans, setAvailableScans] = useState<any[]>([]);
  const [findings, setFindings] = useState<FindingItem[]>([]);
  const [summary, setSummary] = useState<ScanSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedSeverity, setSelectedSeverity] = useState('ALL');
  const [expandedFinding, setExpandedFinding] = useState<string | null>(null);

  // Load available scans if scanId is not in params or to populate scan switcher
  useEffect(() => {
    fetch('/api/scans/?limit=20')
      .then((res) => res.json())
      .then((scans) => {
        setAvailableScans(scans || []);
        if (!paramScanId && scans && scans.length > 0) {
          setActiveScanId(scans[0].scan_id);
        } else if (paramScanId) {
          setActiveScanId(paramScanId);
        } else {
          setLoading(false);
        }
      })
      .catch((err) => {
        setError(err.message);
        setLoading(false);
      });
  }, [paramScanId]);

  useEffect(() => {
    if (!activeScanId) return;
    fetchFindings();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeScanId, selectedSeverity]);

  const fetchFindings = async () => {
    if (!activeScanId) return;
    try {
      setLoading(true);
      setError(null);
      const severityParam = selectedSeverity === 'ALL' ? '' : `&severity=${selectedSeverity}`;
      const response = await fetch(`/api/findings/${activeScanId}?limit=1000${severityParam}`);
      
      if (!response.ok) throw new Error('Failed to fetch findings');
      
      const data = await response.json();
      setFindings(data.findings || []);

      // Also fetch summary
      const summaryRes = await fetch(`/api/reports/${activeScanId}/summary`);
      if (summaryRes.ok) {
        setSummary(await summaryRes.json());
      }
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const getSeverityClass = (severity: string) => {
    const classes: Record<string, string> = {
      CRITICAL: 'severity-critical',
      HIGH: 'severity-high',
      MEDIUM: 'severity-medium',
      LOW: 'severity-low',
      INFO: 'severity-info',
    };
    return classes[severity] || 'severity-default';
  };

  const getSeverityColor = (severity: string) => {
    const colors: Record<string, string> = {
      CRITICAL: '#ff3366',
      HIGH: '#fb923c',
      MEDIUM: '#facc15',
      LOW: '#34d399',
      INFO: '#38bdf8',
    };
    return colors[severity] || '#94a3b8';
  };

  const handleDismissFinding = async (findingId: string) => {
    try {
      const response = await fetch(`/api/findings/${findingId}/dismiss`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ reason: 'User dismissed' }),
      });
      
      if (response.ok) {
        setFindings(findings.filter((f) => f.id !== findingId));
      }
    } catch (err: any) {
      alert(`Error dismissing finding: ${err.message}`);
    }
  };

  const handleExportReport = async (format: string) => {
    if (!activeScanId) return;
    try {
      const response = await fetch(`/api/reports/${activeScanId}/export?format=${format}`);
      if (!response.ok) throw new Error('Failed to export report');
      
      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      const ext = format === 'sarif' ? 'sarif' : (format === 'html' ? 'html' : 'json');
      a.download = `scan_${activeScanId.substring(0, 8)}.${ext}`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
    } catch (err: any) {
      alert(`Error exporting report: ${err.message}`);
    }
  };

  if (!activeScanId && !loading) {
    return (
      <div className="findings card empty-state">
        <p>No scans found to display findings. Please run a scan first.</p>
        <Link to="/" className="btn-primary">Go to Dashboard</Link>
      </div>
    );
  }

  return (
    <div className="findings">
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.5rem', flexWrap: 'wrap', gap: '1rem' }}>
        <h2>Findings - {activeScanId?.substring(0, 8)}</h2>

        {availableScans.length > 1 && (
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <label style={{ fontSize: '0.9rem', fontWeight: 600 }}>Scan:</label>
            <select
              value={activeScanId || ''}
              onChange={(e) => setActiveScanId(e.target.value)}
              style={{ padding: '0.4rem 0.8rem' }}
            >
              {availableScans.map((s) => (
                <option key={s.scan_id} value={s.scan_id}>
                  {s.scan_id.substring(0, 8)} - {s.status} ({new Date(s.created_at).toLocaleDateString()})
                </option>
              ))}
            </select>
          </div>
        )}

        {activeScanId && (
          <div>
            <Link to={`/scans/${activeScanId}`} className="btn-primary">
              🕸️ View Architecture Graph
            </Link>
          </div>
        )}
      </div>

      {/* Summary Cards */}
      {summary && (
        <div className="summary-cards">
          <div className="card summary-card summary-stat critical">
            <div className="number">{summary.findings_by_severity?.CRITICAL || 0}</div>
            <div className="label">Critical</div>
          </div>
          <div className="card summary-card summary-stat high">
            <div className="number">{summary.findings_by_severity?.HIGH || 0}</div>
            <div className="label">High</div>
          </div>
          <div className="card summary-card summary-stat medium">
            <div className="number">{summary.findings_by_severity?.MEDIUM || 0}</div>
            <div className="label">Medium</div>
          </div>
          <div className="card summary-card summary-stat low">
            <div className="number">{summary.findings_by_severity?.LOW || 0}</div>
            <div className="label">Low</div>
          </div>
        </div>
      )}

      {/* Controls */}
      <div className="controls card">
        <div className="filter-group">
          <label>Filter by Severity:</label>
          <select value={selectedSeverity} onChange={(e) => setSelectedSeverity(e.target.value)}>
            <option value="ALL">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
            <option value="INFO">Info</option>
          </select>
        </div>

        <div className="action-group">
          <button className="btn-secondary" onClick={() => handleExportReport('json')}>
            📥 Export JSON
          </button>
          <button className="btn-secondary" onClick={() => handleExportReport('sarif')}>
            🔗 Export SARIF
          </button>
          <button className="btn-secondary" onClick={() => handleExportReport('html')}>
            📄 Export HTML
          </button>
        </div>
      </div>

      {loading ? (
        <div className="findings card"><p>Loading findings...</p></div>
      ) : error ? (
        <div className="findings card error"><p>Error: {error}</p></div>
      ) : findings.length === 0 ? (
        <div className="empty-state card">
          <p>No findings found for this filter.</p>
        </div>
      ) : (
        <div className="findings-list">
          {findings.map((finding) => (
            <div
              key={finding.id}
              className={`finding-card card ${getSeverityClass(finding.severity)}`}
            >
              <div className="finding-header">
                <div className="finding-title-area">
                  <span
                    className="severity-badge"
                    style={{ backgroundColor: getSeverityColor(finding.severity) }}
                  >
                    {finding.severity}
                  </span>
                  <h3 className="finding-title">{finding.title}</h3>
                  <span className="confidence-badge">
                    {Math.round((finding.confidence || 0.9) * 100)}% confidence
                  </span>
                </div>
                <div className="finding-actions">
                  <button
                    className="btn-small btn-secondary"
                    onClick={() => setExpandedFinding(
                      expandedFinding === finding.id ? null : finding.id
                    )}
                  >
                    {expandedFinding === finding.id ? '▼ Less' : '▶ Details'}
                  </button>
                  <button
                    className="btn-small btn-warning"
                    onClick={() => handleDismissFinding(finding.id)}
                  >
                    ✓ Dismiss
                  </button>
                </div>
              </div>

              {/* Finding Summary */}
              <div className="finding-summary">
                <p>{finding.description}</p>
                <div className="finding-metadata">
                  <div className="metadata-item">
                    <strong>Source:</strong> {finding.source}
                  </div>
                  {finding.affected_components && finding.affected_components.length > 0 && (
                    <div className="metadata-item">
                      <strong>Components:</strong> {finding.affected_components.join(', ')}
                    </div>
                  )}
                </div>
              </div>

              {/* Expanded Details */}
              {expandedFinding === finding.id && (
                <div className="finding-details">
                  {finding.cwe_ids && finding.cwe_ids.length > 0 && (
                    <div className="detail-section">
                      <h4>CWE References</h4>
                      <div className="cwe-list">
                        {finding.cwe_ids.map((cwe) => {
                          const num = cwe.replace(/^CWE-?/i, '');
                          return (
                            <a
                              key={cwe}
                              href={`https://cwe.mitre.org/data/definitions/${num}.html`}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="cwe-link"
                            >
                              {cwe.startsWith('CWE') ? cwe : `CWE-${cwe}`}
                            </a>
                          );
                        })}
                      </div>
                    </div>
                  )}

                  {finding.owasp_categories && finding.owasp_categories.length > 0 && (
                    <div className="detail-section">
                      <h4>OWASP Categories</h4>
                      <ul>
                        {finding.owasp_categories.map((cat) => (
                          <li key={cat}>{cat}</li>
                        ))}
                      </ul>
                    </div>
                  )}

                  {finding.remediation_steps && finding.remediation_steps.length > 0 && (
                    <div className="detail-section">
                      <h4>Remediation Steps</h4>
                      <ol>
                        {finding.remediation_steps.map((step, idx) => (
                          <li key={idx}>{step}</li>
                        ))}
                      </ol>
                    </div>
                  )}

                  {finding.references && finding.references.length > 0 && (
                    <div className="detail-section">
                      <h4>References</h4>
                      <ul>
                        {finding.references.map((ref) => {
                          let label = ref;
                          try {
                            label = new URL(ref).hostname;
                          } catch (_) {}
                          return (
                            <li key={ref}>
                              <a href={ref} target="_blank" rel="noopener noreferrer">
                                {label}
                              </a>
                            </li>
                          );
                        })}
                      </ul>
                    </div>
                  )}
                </div>
              )}
            </div>
          ))}
        </div>
      )}

      <p className="results-info">
        Showing {findings.length} findings
      </p>
    </div>
  );
}

export default Findings;
