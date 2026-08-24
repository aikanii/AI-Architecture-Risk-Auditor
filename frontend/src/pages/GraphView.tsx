import React, { useEffect, useState } from 'react';
import { useParams } from 'react-router-dom';
import '../styles/GraphView.css';

function GraphView() {
  const { scanId } = useParams();
  const [nodes, setNodes] = useState([]);
  const [edges, setEdges] = useState([]);
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [selectedNode, setSelectedNode] = useState(null);

  useEffect(() => {
    fetchGraphData();
  }, [scanId]);

  const fetchGraphData = async () => {
    try {
      setLoading(true);
      const [nodesRes, edgesRes, statsRes] = await Promise.all([
        fetch(`/api/graph/${scanId}/nodes`),
        fetch(`/api/graph/${scanId}/edges`),
        fetch(`/api/graph/${scanId}/stats`),
      ]);

      if (!nodesRes.ok || !edgesRes.ok || !statsRes.ok) {
        throw new Error('Failed to fetch graph data');
      }

      setNodes(await nodesRes.json());
      setEdges(await edgesRes.json());
      setStats(await statsRes.json());
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const getNodeColor = (nodeType) => {
    const colors = {
      Service: '#4CAF50',
      Endpoint: '#2196F3',
      DataStore: '#FF9800',
      ExternalDependency: '#9C27B0',
    };
    return colors[nodeType] || '#757575';
  };

  const getRiskColor = (riskLevel) => {
    const colors = {
      CRITICAL: '#d32f2f',
      HIGH: '#f57c00',
      MEDIUM: '#fbc02d',
      LOW: '#388e3c',
      INFO: '#1976d2',
    };
    return colors[riskLevel] || '#757575';
  };

  if (loading) {
    return <div className="graph-view card"><p>Loading graph...</p></div>;
  }

  if (error) {
    return <div className="graph-view card error"><p>Error: {error}</p></div>;
  }

  return (
    <div className="graph-view">
      <h2>Architecture Graph - {scanId?.substring(0, 8)}</h2>

      {/* Statistics */}
      {stats && (
        <div className="stats-grid">
          <div className="stat">
            <span className="stat-label">Services</span>
            <span className="stat-value">{stats.service_count || 0}</span>
          </div>
          <div className="stat">
            <span className="stat-label">Endpoints</span>
            <span className="stat-value">{stats.endpoint_count || 0}</span>
          </div>
          <div className="stat">
            <span className="stat-label">Datastores</span>
            <span className="stat-value">{stats.datastore_count || 0}</span>
          </div>
          <div className="stat">
            <span className="stat-label">Relationships</span>
            <span className="stat-value">{edges.length}</span>
          </div>
        </div>
      )}

      {/* Graph Canvas */}
      <div className="graph-container card">
        <div className="graph-legend">
          <h4>Legend</h4>
          <div className="legend-item">
            <div className="legend-box" style={{ backgroundColor: getNodeColor('Service') }}></div>
            <span>Service</span>
          </div>
          <div className="legend-item">
            <div className="legend-box" style={{ backgroundColor: getNodeColor('Endpoint') }}></div>
            <span>Endpoint</span>
          </div>
          <div className="legend-item">
            <div className="legend-box" style={{ backgroundColor: getNodeColor('DataStore') }}></div>
            <span>Data Store</span>
          </div>
          <div className="legend-item">
            <div className="legend-box" style={{ backgroundColor: getNodeColor('ExternalDependency') }}></div>
            <span>External</span>
          </div>
        </div>

        <div className="graph-canvas-placeholder">
          <p className="info-text">
            ℹ️ Graph visualization would be rendered here using Cytoscape.js or React Flow
          </p>
          <p className="info-text">
            Nodes: {nodes.length} | Edges: {edges.length}
          </p>

          {/* Simple node list instead of graph rendering */}
          <div className="simple-graph-view">
            <h4>Architecture Components</h4>
            <div className="nodes-list">
              {nodes.map((node) => (
                <div
                  key={node.id}
                  className={`node-card ${node.type?.toLowerCase()}`}
                  style={{ borderColor: getNodeColor(node.type) }}
                  onClick={() => setSelectedNode(node)}
                >
                  <strong>{node.name}</strong>
                  <p className="node-type">{node.type}</p>
                  {node.risk_level && (
                    <span
                      className="risk-badge"
                      style={{ backgroundColor: getRiskColor(node.risk_level) }}
                    >
                      {node.risk_level}
                    </span>
                  )}
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* Selected Node Details */}
      {selectedNode && (
        <div className="node-details card">
          <h3>Component Details: {selectedNode.name}</h3>
          <div className="details-grid">
            <div><strong>Type:</strong> {selectedNode.type}</div>
            <div><strong>ID:</strong> {selectedNode.id}</div>
            {selectedNode.language && <div><strong>Language:</strong> {selectedNode.language}</div>}
            {selectedNode.protocol && <div><strong>Protocol:</strong> {selectedNode.protocol}</div>}
            {selectedNode.risk_level && <div><strong>Risk Level:</strong> {selectedNode.risk_level}</div>}
          </div>
          <button className="btn-secondary" onClick={() => setSelectedNode(null)}>
            Close
          </button>
        </div>
      )}
    </div>
  );
}

export default GraphView;
