import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import '../styles/ScanResults.css';

function ScanResults({ scans, onRefresh }) {
  const [selectedStatus, setSelectedStatus] = useState('ALL');
  const [sortBy, setSortBy] = useState('date-desc');

  const filteredScans = selectedStatus === 'ALL' 
    ? scans 
    : scans.filter(s => s.status === selectedStatus);

  const sortedScans = [...filteredScans].sort((a, b) => {
    if (sortBy === 'date-desc') {
      return new Date(b.created_at) - new Date(a.created_at);
    } else if (sortBy === 'date-asc') {
      return new Date(a.created_at) - new Date(b.created_at);
    }
    return 0;
  });

  const handleDeleteScan = async (scanId) => {
    if (window.confirm(`Delete scan ${scanId}?`)) {
      try {
        const response = await fetch(`/api/scans/${scanId}`, { method: 'DELETE' });
        if (response.ok) {
          onRefresh();
        }
      } catch (err) {
        alert(`Error deleting scan: ${err.message}`);
      }
    }
  };

  const getStatusBadge = (status) => {
    const colors = {
      QUEUED: 'badge-warning',
      RUNNING: 'badge-info',
      COMPLETED: 'badge-success',
      FAILED: 'badge-danger',
    };
    return colors[status] || 'badge-default';
  };

  return (
    <div className="scan-results">
      <h2>Scan Results</h2>

      {/* Filters */}
      <div className="filters card">
        <div className="filter-group">
          <label>Status:</label>
          <select value={selectedStatus} onChange={(e) => setSelectedStatus(e.target.value)}>
            <option value="ALL">All</option>
            <option value="QUEUED">Queued</option>
            <option value="RUNNING">Running</option>
            <option value="COMPLETED">Completed</option>
            <option value="FAILED">Failed</option>
          </select>
        </div>

        <div className="filter-group">
          <label>Sort:</label>
          <select value={sortBy} onChange={(e) => setSortBy(e.target.value)}>
            <option value="date-desc">Newest First</option>
            <option value="date-asc">Oldest First</option>
          </select>
        </div>

        <button className="btn-secondary" onClick={onRefresh}>
          🔄 Refresh
        </button>
      </div>

      {/* Results Table */}
      {sortedScans.length === 0 ? (
        <div className="empty-state card">
          <p>No scans found. <Link to="/">Start a new scan</Link></p>
        </div>
      ) : (
        <div className="table-responsive card">
          <table className="scans-table">
            <thead>
              <tr>
                <th>Scan ID</th>
                <th>Repository</th>
                <th>Status</th>
                <th>Created</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {sortedScans.map((scan) => (
                <tr key={scan.scan_id}>
                  <td className="scan-id">
                    <code>{scan.scan_id.substring(0, 12)}</code>
                  </td>
                  <td className="repo-info">
                    {scan.repository_source?.path || scan.repository_source?.url || 'Unknown'}
                  </td>
                  <td>
                    <span className={`badge ${getStatusBadge(scan.status)}`}>
                      {scan.status}
                    </span>
                  </td>
                  <td className="date">
                    {new Date(scan.created_at).toLocaleDateString()} 
                    {' '}
                    {new Date(scan.created_at).toLocaleTimeString()}
                  </td>
                  <td className="actions">
                    <Link to={`/scans/${scan.scan_id}`} className="btn-small btn-primary">
                      Graph
                    </Link>
                    <Link to={`/findings/${scan.scan_id}`} className="btn-small btn-secondary">
                      Findings
                    </Link>
                    <button 
                      className="btn-small btn-danger"
                      onClick={() => handleDeleteScan(scan.scan_id)}
                    >
                      Delete
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <p className="results-info">
        Showing {sortedScans.length} of {scans.length} scans
      </p>
    </div>
  );
}

export default ScanResults;
