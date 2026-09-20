import React, { useEffect, useState, useRef } from 'react';
import { useParams, Link } from 'react-router-dom';
import cytoscape, { Core } from 'cytoscape';
import '../styles/GraphView.css';

interface NodeData {
  id: string;
  name: string;
  type: string;
  language?: string;
  protocol?: string;
  risk_level?: string;
  has_health_check?: boolean;
  has_redundancy?: boolean;
  has_auth?: boolean;
  path?: string;
  method?: string;
  [key: string]: any;
}

interface EdgeData {
  source: string;
  target: string;
  type: string;
  properties?: Record<string, any>;
}

interface GraphStats {
  total_nodes?: number;
  total_edges?: number;
  service_count?: number;
  endpoint_count?: number;
  datastore_count?: number;
  finding_count?: number;
  findings_by_severity?: Record<string, number>;
}

function GraphView() {
  const { scanId: paramScanId } = useParams<{ scanId?: string }>();
  const [activeScanId, setActiveScanId] = useState<string | null>(paramScanId || null);
  const [nodes, setNodes] = useState<NodeData[]>([]);
  const [edges, setEdges] = useState<EdgeData[]>([]);
  const [stats, setStats] = useState<GraphStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedNode, setSelectedNode] = useState<NodeData | null>(null);
  const [viewMode, setViewMode] = useState<'cytoscape' | 'list'>('cytoscape');
  const [layoutName, setLayoutName] = useState<'cose' | 'breadthfirst' | 'circle' | 'concentric'>('cose');
  const [filterType, setFilterType] = useState<string>('ALL');

  const containerRef = useRef<HTMLDivElement>(null);
  const cyRef = useRef<Core | null>(null);

  // If no scanId in params, fetch latest scan
  useEffect(() => {
    if (!paramScanId) {
      fetch('/api/scans/?limit=1')
        .then((res) => res.json())
        .then((scans) => {
          if (scans && scans.length > 0) {
            setActiveScanId(scans[0].scan_id);
          } else {
            setError('No scans available. Run a scan first.');
            setLoading(false);
          }
        })
        .catch((err) => {
          setError(err.message);
          setLoading(false);
        });
    } else {
      setActiveScanId(paramScanId);
    }
  }, [paramScanId]);

  // Fetch graph data
  useEffect(() => {
    if (!activeScanId) return;

    let isMounted = true;
    setLoading(true);
    setError(null);

    Promise.all([
      fetch(`/api/graph/${activeScanId}/nodes`).then((r) => r.json()),
      fetch(`/api/graph/${activeScanId}/edges`).then((r) => r.json()),
      fetch(`/api/graph/${activeScanId}/stats`).then((r) => r.json()),
    ])
      .then(([nodesData, edgesData, statsData]) => {
        if (!isMounted) return;
        setNodes(nodesData || []);
        setEdges(edgesData || []);
        setStats(statsData || null);
        setLoading(false);
      })
      .catch((err) => {
        if (!isMounted) return;
        setError(err.message || 'Failed to fetch graph data');
        setLoading(false);
      });

    return () => {
      isMounted = false;
    };
  }, [activeScanId]);

  const getNodeColor = (nodeType: string) => {
    const colors: Record<string, string> = {
      Service: '#059669',
      Endpoint: '#0284c7',
      DataStore: '#d97706',
      ExternalDependency: '#7c3aed',
    };
    return colors[nodeType] || '#475569';
  };

  const getNodeShape = (nodeType: string): cytoscape.Css.NodeShape => {
    const shapes: Record<string, cytoscape.Css.NodeShape> = {
      Service: 'round-rectangle',
      Endpoint: 'ellipse',
      DataStore: 'barrel',
      ExternalDependency: 'diamond',
    };
    return shapes[nodeType] || 'ellipse';
  };

  // Initialize and update Cytoscape
  useEffect(() => {
    if (viewMode !== 'cytoscape' || loading || !containerRef.current || nodes.length === 0) {
      return;
    }

    if (cyRef.current) {
      cyRef.current.destroy();
      cyRef.current = null;
    }

    const filteredNodes = filterType === 'ALL' 
      ? nodes 
      : nodes.filter((n) => n.type.toUpperCase() === filterType.toUpperCase());

    const nodeIdSet = new Set(filteredNodes.map((n) => n.id));
    const validEdges = edges.filter(
      (e) => nodeIdSet.has(e.source) && nodeIdSet.has(e.target)
    );

    const elements: cytoscape.ElementDefinition[] = [
      ...filteredNodes.map((node) => ({
        data: {
          id: node.id,
          label: node.name,
          type: node.type,
          color: getNodeColor(node.type),
          shape: getNodeShape(node.type),
          raw: node,
        },
      })),
      ...validEdges.map((edge, index) => ({
        data: {
          id: `edge_${index}_${edge.source}_${edge.target}`,
          source: edge.source,
          target: edge.target,
          label: edge.type,
          type: edge.type,
        },
      })),
    ];

    try {
      const cy = cytoscape({
        container: containerRef.current,
        elements,
        style: [
          {
            selector: 'node',
            style: {
              'background-color': 'data(color)',
              'label': 'data(label)',
              'shape': 'data(shape)' as any,
              'color': '#f8fafc',
              'font-family': 'Inter, sans-serif',
              'font-size': '11px',
              'font-weight': 600,
              'text-valign': 'center',
              'text-halign': 'center',
              'text-wrap': 'wrap',
              'text-max-width': '110px',
              'width': 'label',
              'height': '36px',
              'padding': '12px',
              'border-width': 2,
              'border-color': 'rgba(255, 255, 255, 0.3)',
              'overlay-opacity': 0,
            },
          },
          {
            selector: 'node[type = "Service"]',
            style: {
              'height': '44px',
              'padding': '14px',
              'color': '#ffffff',
              'font-size': '12px',
              'border-width': 2,
              'border-color': '#34d399',
            },
          },
          {
            selector: 'node[type = "DataStore"]',
            style: {
              'border-width': 2,
              'border-color': '#fbbf24',
            },
          },
          {
            selector: 'node[type = "Endpoint"]',
            style: {
              'border-width': 2,
              'border-color': '#38bdf8',
            },
          },
          {
            selector: 'node:selected',
            style: {
              'border-color': '#38bdf8',
              'border-width': 4,
            } as any,
          },
          {
            selector: 'edge',
            style: {
              'width': 2,
              'line-color': '#475569',
              'target-arrow-color': '#64748b',
              'target-arrow-shape': 'triangle',
              'curve-style': 'bezier',
              'label': 'data(label)',
              'font-family': 'JetBrains Mono, monospace',
              'font-size': '9px',
              'color': '#94a3b8',
              'text-background-opacity': 0.85,
              'text-background-color': '#0f172a',
              'text-background-padding': '3px',
              'text-background-shape': 'round-rectangle',
            },
          },
          {
            selector: 'edge[type = "WRITES_TO"]',
            style: {
              'line-color': '#f59e0b',
              'target-arrow-color': '#f59e0b',
            },
          },
          {
            selector: 'edge[type = "READS_FROM"]',
            style: {
              'line-color': '#38bdf8',
              'target-arrow-color': '#38bdf8',
            },
          },
          {
            selector: 'edge[type = "CALLS"]',
            style: {
              'line-color': '#818cf8',
              'target-arrow-color': '#818cf8',
            },
          },
        ],
        layout: {
          name: layoutName,
          animate: true,
          animationDuration: 500,
          padding: 30,
        } as any,
        wheelSensitivity: 0.2,
      });

      cy.on('tap', 'node', (evt) => {
        const rawNode = evt.target.data('raw');
        setSelectedNode(rawNode);
      });

      cy.on('tap', (evt) => {
        if (evt.target === cy) {
          setSelectedNode(null);
        }
      });

      cyRef.current = cy;
    } catch (e) {
      console.error('Cytoscape render error:', e);
    }

    return () => {
      if (cyRef.current) {
        cyRef.current.destroy();
        cyRef.current = null;
      }
    };
  }, [viewMode, layoutName, filterType, loading, nodes, edges]);

  const handleZoomIn = () => {
    if (cyRef.current) {
      cyRef.current.zoom(cyRef.current.zoom() * 1.2);
    }
  };

  const handleZoomOut = () => {
    if (cyRef.current) {
      cyRef.current.zoom(cyRef.current.zoom() * 0.8);
    }
  };

  const handleFit = () => {
    if (cyRef.current) {
      cyRef.current.fit(undefined, 30);
    }
  };

  const handleExportPNG = () => {
    if (cyRef.current) {
      const png64 = cyRef.current.png({ full: true, bg: '#ffffff', scale: 2 });
      const a = document.createElement('a');
      a.href = png64;
      a.download = `architecture_graph_${activeScanId?.substring(0, 8)}.png`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
    }
  };

  if (loading) {
    return <div className="graph-view card"><p>Loading graph...</p></div>;
  }

  if (error) {
    return (
      <div className="graph-view card error">
        <p>Error: {error}</p>
        <Link to="/" className="btn-primary" style={{ marginTop: '1rem', display: 'inline-block' }}>
          Back to Dashboard
        </Link>
      </div>
    );
  }

  return (
    <div className="graph-view">
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.5rem' }}>
        <h2>Architecture Graph - {activeScanId?.substring(0, 8)}</h2>
        <div>
          <Link to={`/findings/${activeScanId}`} className="btn-secondary" style={{ marginRight: '0.5rem' }}>
            View Findings
          </Link>
          <button
            className="btn-primary"
            onClick={() => setViewMode(viewMode === 'cytoscape' ? 'list' : 'cytoscape')}
          >
            {viewMode === 'cytoscape' ? '📋 Switch to Grid View' : '🕸️ Switch to Graph View'}
          </button>
        </div>
      </div>

      {/* Statistics */}
      {stats && (
        <div className="stats-grid">
          <div className="stat-card">
            <div className="stat-number">{stats.service_count || 0}</div>
            <div className="stat-label">Services</div>
          </div>
          <div className="stat-card">
            <div className="stat-number">{stats.endpoint_count || 0}</div>
            <div className="stat-label">Endpoints</div>
          </div>
          <div className="stat-card">
            <div className="stat-number">{stats.datastore_count || 0}</div>
            <div className="stat-label">Datastores</div>
          </div>
          <div className="stat-card">
            <div className="stat-number">{edges.length}</div>
            <div className="stat-label">Relationships</div>
          </div>
        </div>
      )}

      {/* Graph Toolbar & Controls */}
      <div className="graph-container card">
        <div className="graph-toolbar">
          <div className="graph-legend">
            <h4>Legend:</h4>
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
          </div>

          <div className="graph-toolbar-controls">
            <select
              value={filterType}
              onChange={(e) => setFilterType(e.target.value)}
              style={{ padding: '0.35rem 0.6rem', fontSize: '0.85rem' }}
            >
              <option value="ALL">All Types</option>
              <option value="SERVICE">Services</option>
              <option value="ENDPOINT">Endpoints</option>
              <option value="DATASTORE">DataStores</option>
            </select>

            {viewMode === 'cytoscape' && (
              <>
                <select
                  value={layoutName}
                  onChange={(e) => setLayoutName(e.target.value as any)}
                  style={{ padding: '0.35rem 0.6rem', fontSize: '0.85rem' }}
                >
                  <option value="cose">CoSE (Force)</option>
                  <option value="breadthfirst">Breadth-First</option>
                  <option value="concentric">Concentric</option>
                  <option value="circle">Circle</option>
                </select>
                <button className="btn-small btn-secondary" onClick={handleZoomIn} title="Zoom In">+</button>
                <button className="btn-small btn-secondary" onClick={handleZoomOut} title="Zoom Out">-</button>
                <button className="btn-small btn-secondary" onClick={handleFit} title="Fit to screen">Fit</button>
                <button className="btn-small btn-secondary" onClick={handleExportPNG} title="Export PNG">📷 Export PNG</button>
              </>
            )}
          </div>
        </div>

        {/* View Mode Canvas */}
        {viewMode === 'cytoscape' ? (
          <div
            ref={containerRef}
            className="cytoscape-canvas"
            style={{ width: '100%', height: '560px', position: 'relative' }}
          />
        ) : (
          <div className="simple-graph-view">
            <h4>Architecture Components ({nodes.length})</h4>
            <div className="nodes-list">
              {nodes
                .filter((n) => filterType === 'ALL' || n.type.toUpperCase() === filterType.toUpperCase())
                .map((node) => (
                  <div
                    key={node.id}
                    className={`node-card ${node.type?.toLowerCase()}`}
                    style={{ borderColor: getNodeColor(node.type) }}
                    onClick={() => setSelectedNode(node)}
                  >
                    <strong>{node.name}</strong>
                    <p className="node-type">{node.type}</p>
                    {node.language && <p style={{ fontSize: '0.8rem', color: '#64748b' }}>Lang: {node.language}</p>}
                    {node.path && <p style={{ fontSize: '0.8rem', color: '#64748b' }}>{node.method} {node.path}</p>}
                  </div>
                ))}
            </div>
          </div>
        )}
      </div>

      {/* Selected Node Details Drawer */}
      {selectedNode && (
        <div className="node-details card">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
            <h3>Component Details: {selectedNode.name}</h3>
            <button className="btn-small btn-secondary" onClick={() => setSelectedNode(null)}>
              ✕ Close
            </button>
          </div>
          <div className="details-grid">
            <div><strong>Type:</strong> {selectedNode.type}</div>
            <div><strong>ID:</strong> {selectedNode.id}</div>
            {selectedNode.language && <div><strong>Language:</strong> {selectedNode.language}</div>}
            {selectedNode.path && <div><strong>Path:</strong> {selectedNode.path}</div>}
            {selectedNode.method && <div><strong>Method:</strong> {selectedNode.method}</div>}
            {selectedNode.store_type && <div><strong>Store Type:</strong> {selectedNode.store_type}</div>}
            {selectedNode.has_auth !== undefined && <div><strong>Authenticated:</strong> {selectedNode.has_auth ? 'Yes' : 'No'}</div>}
            {selectedNode.has_health_check !== undefined && <div><strong>Health Check:</strong> {selectedNode.has_health_check ? 'Yes' : 'No'}</div>}
            {selectedNode.has_redundancy !== undefined && <div><strong>Redundancy:</strong> {selectedNode.has_redundancy ? 'Yes' : 'No'}</div>}
          </div>
        </div>
      )}
    </div>
  );
}

export default GraphView;
