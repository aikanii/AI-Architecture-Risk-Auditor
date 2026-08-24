import React, { useEffect, useState } from 'react';
import { useParams } from 'react-router-dom';
import '../styles/Findings.css';

function Findings() {
  const { scanId } = useParams();
  const [findings, setFindings] = useState([]);
  const [summary, setSummary] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [selectedSeverity, setSelectedSeverity] = useState('ALL');
  const [expandedFinding, setExpandedFinding] = useState(null);

  useEffect(() => {
    fetchFindings();
  }, [scanId, selectedSeverity]);

  const fetchFindings = async () => {
    try {
      setLoading(true);
      const severityParam = selectedSeverity === 'ALL' ? '' : `&severity=${selectedSeverity}`;
      const response = await fetch(`/api/findings/${scanId}?limit=1000${severityParam}`);
      
      if (!response.ok) throw new Error('Failed to fetch findings');
      
      const data = await response.json();
      setFindings(data.findings || []);

      // Also fetch summary
      const summaryRes = await fetch(`/api/reports/${scanId}/summary`);
      if (summaryRes.ok) {
        setSummary(await summaryRes.json());
      }
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const getSeverityClass = (severity) => {
    const classes = {
      CRITICAL: 'severity-critical',
      HIGH: 'severity-high',
      MEDIUM: 'severity-medium',
      LOW: 'severity-low',
      INFO: 'severity-info',
    };
    return classes[severity] || 'severity-default';
  };

  const getSeverityColor = (severity) => {
    const colors = {
      CRITICAL: '#d32f2f',
      HIGH: '#f57c00',
      MEDIUM: '#fbc02d',
      LOW: '#388e3c',
      INFO: '#1976d2',
    };
    return colors[severity] || '#757575';
  };

  const handleDismissFinding = async (findingId) => {
    try {
      const response = await fetch(`/api/findings/${findingId}/dismiss`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ reason: 'User dismissed' }),
      });
      
      if (response.ok) {
        setFindings(findings.filter(f => f.id !== findingId));
      }
    } catch (err) {
      alert(`Error dismissing finding: ${err.message}`);
    }
  };

  const handleExportReport = async (format) => {
    try {
      const response = await fetch(`/api/reports/${scanId}/export?format=${format}`);
      if (!response.ok) throw new Error('Failed to export report');
      
      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `scan_${scanId}.${format === 'json' ? 'json' : 'pdf'}`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
    } catch (err) {
      alert(`Error exporting report: ${err.message}`);
    }
  };

  if (loading) {
    return <div className="findings card"><p>Loading findings...</p></div>;
  }

  if (error) {
    return <div className="findings card error"><p>Error: {error}</p></div>;
  }

  return (
    <div className="findings">
      <h2>Findings - {scanId?.substring(0, 8)}</h2>

      {/* Summary Cards */}
      {summary && (
        <div className="summary-cards">
          <div className="card summary-card">
            <div className="summary-stat critical">
              <div className="number">{summary.findings_by_severity?.CRITICAL || 0}</div>
              <div className="label">Critical</div>
            </div>
          </div>
          <div className="card summary-card">
            <div className="summary-stat high">
              <div className="number">{summary.findings_by_severity?.HIGH || 0}</div>
              <div className="label">High</div>
            </div>
          </div>
          <div className="card summary-card">
            <div className="summary-stat medium">
              <div className="number">{summary.findings_by_severity?.MEDIUM || 0}</div>
              <div className="label">Medium</div>
            </div>
          </div>
          <div className="card summary-card">
            <div className="summary-stat low">
              <div className="number">{summary.findings_by_severity?.LOW || 0}</div>
              <div className="label">Low</div>
            </div>
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
          <button className="btn-secondary" onClick={() => handleExportReport('pdf')}>
            📄 Export PDF
          </button>
          <button className="btn-secondary" onClick={() => handleExportReport('sarif')}>
            🔗 Export SARIF
          </button>
        </div>
      </div>

      {/* Findings List */}
      {findings.length === 0 ? (
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
                    {Math.round(finding.confidence * 100)}% confidence
                  </span>
                </div>
                <div className="finding-actions">
                  <button
                    className="btn-small btn-secondary"
                    onClick={() => setExpandedFinding(
                      expandedFinding === finding.id ? null : finding.id
                    )}
                  >
                    {expandedFinding === finding.id ? '▼' : '▶'} Details
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
                  {finding.affected_components?.length > 0 && (
                    <div className="metadata-item">
                      <strong>Components:</strong> {finding.affected_components.join(', ')}
                    </div>
                  )}
                </div>
              </div>

              {/* Expanded Details */}
              {expandedFinding === finding.id && (
                <div className="finding-details">
                  {finding.cwe_ids?.length > 0 && (
                    <div className="detail-section">
                      <h4>CWE References</h4>
                      <div className="cwe-list">
                        {finding.cwe_ids.map((cwe) => (
                          <a
                            key={cwe}
                            href={`https://cwe.mitre.org/data/definitions/${cwe}.html`}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="cwe-link"
                          >
                            CWE-{cwe}
                          </a>
                        ))}
                      </div>
                    </div>
                  )}

                  {finding.owasp_categories?.length > 0 && (
                    <div className="detail-section">
                      <h4>OWASP Categories</h4>
                      <ul>
                        {finding.owasp_categories.map((cat) => (
                          <li key={cat}>{cat}</li>
                        ))}
                      </ul>
                    </div>
                  )}

                  {finding.remediation_steps?.length > 0 && (
                    <div className="detail-section">
                      <h4>Remediation Steps</h4>
                      <ol>
                        {finding.remediation_steps.map((step, idx) => (
                          <li key={idx}>{step}</li>
                        ))}
                      </ol>
                    </div>
                  )}

                  {finding.references?.length > 0 && (
                    <div className="detail-section">
                      <h4>References</h4>
                      <ul>
                        {finding.references.map((ref) => (
                          <li key={ref}>
                            <a href={ref} target="_blank" rel="noopener noreferrer">
                              {new URL(ref).hostname}
                            </a>
                          </li>
                        ))}
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
