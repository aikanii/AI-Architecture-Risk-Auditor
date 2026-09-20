import React, { useEffect, useState, useRef, useMemo } from 'react';
import { useParams, Link } from 'react-router-dom';
import cytoscape, { Core } from 'cytoscape';
import {
  Network,
  ShieldAlert,
  LayoutGrid,
  ZoomIn,
  ZoomOut,
  Maximize2,
  Camera,
  Server,
  GitBranch,
  Database,
  X,
  Search,
  AlertTriangle,
  CheckCircle2,
  Eye,
  RefreshCw,
  Radio,
  Layers,
} from 'lucide-react';
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
  store_type?: string;
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

interface FindingItem {
  id: string;
  title: string;
  severity: string;
  affected_components?: string[];
  description?: string;
}

type TopologyPreset = 'SERVICE_MESH' | 'ALL' | 'DATA_FLOW' | 'RISK_PATHS';

function GraphView() {
  const { scanId: paramScanId } = useParams<{ scanId?: string }>();
  const [activeScanId, setActiveScanId] = useState<string | null>(paramScanId || null);
  const [nodes, setNodes] = useState<NodeData[]>([]);
  const [edges, setEdges] = useState<EdgeData[]>([]);
  const [stats, setStats] = useState<GraphStats | null>(null);
  const [findings, setFindings] = useState<FindingItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  
  const [selectedNode, setSelectedNode] = useState<NodeData | null>(null);
  const [viewMode, setViewMode] = useState<'cytoscape' | 'list'>('cytoscape');
  const [preset, setPreset] = useState<TopologyPreset>('SERVICE_MESH');
  const [layoutName, setLayoutName] = useState<'cose' | 'breadthfirst' | 'concentric' | 'circle'>('cose');
  const [searchQuery, setSearchQuery] = useState('');
  const [focusMode, setFocusMode] = useState(false);

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

  // Fetch graph data and findings
  useEffect(() => {
    if (!activeScanId) return;

    let isMounted = true;
    setLoading(true);
    setError(null);

    Promise.all([
      fetch(`/api/graph/${activeScanId}/nodes`).then((r) => r.json()),
      fetch(`/api/graph/${activeScanId}/edges`).then((r) => r.json()),
      fetch(`/api/graph/${activeScanId}/stats`).then((r) => r.json()),
      fetch(`/api/findings/${activeScanId}?limit=1000`).then((r) => r.json()),
    ])
      .then(([nodesData, edgesData, statsData, findingsData]) => {
        if (!isMounted) return;
        setNodes(nodesData || []);
        setEdges(edgesData || []);
        setStats(statsData || null);
        setFindings(findingsData?.findings || []);
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

  // Map each component ID to its findings and highest severity
  const componentFindingsMap = useMemo(() => {
    const map: Record<string, { findings: FindingItem[]; highestSeverity?: string }> = {};
    const severityRank: Record<string, number> = {
      CRITICAL: 4,
      HIGH: 3,
      MEDIUM: 2,
      LOW: 1,
      INFO: 0,
    };

    findings.forEach((f) => {
      (f.affected_components || []).forEach((comp) => {
        if (!map[comp]) {
          map[comp] = { findings: [] };
        }
        map[comp].findings.push(f);
        const currentRank = map[comp].highestSeverity ? severityRank[map[comp].highestSeverity!] : -1;
        const newRank = severityRank[f.severity.toUpperCase()] ?? 0;
        if (newRank > currentRank) {
          map[comp].highestSeverity = f.severity.toUpperCase();
        }
      });
    });

    return map;
  }, [findings]);

  // Filtered nodes according to Preset & Search
  const filteredNodes = useMemo(() => {
    let result = [...nodes];

    if (preset === 'SERVICE_MESH') {
      // Focus on Services and Datastores (Architecture level)
      result = result.filter((n) => n.type === 'Service' || n.type === 'DataStore');
    } else if (preset === 'DATA_FLOW') {
      // Datastores and services writing/reading to them
      const dsIds = new Set(nodes.filter((n) => n.type === 'DataStore').map((n) => n.id));
      const connectedServices = new Set<string>();
      edges.forEach((e) => {
        if (dsIds.has(e.target)) connectedServices.add(e.source);
        if (dsIds.has(e.source)) connectedServices.add(e.target);
      });
      result = result.filter((n) => dsIds.has(n.id) || connectedServices.has(n.id));
    } else if (preset === 'RISK_PATHS') {
      // Only components that have Critical or High findings
      result = result.filter((n) => {
        const info = componentFindingsMap[n.id] || componentFindingsMap[n.name];
        return info && (info.highestSeverity === 'CRITICAL' || info.highestSeverity === 'HIGH');
      });
      if (result.length === 0) {
        result = nodes.filter((n) => n.type === 'Service' || n.type === 'DataStore');
      }
    }

    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      result = result.filter(
        (n) =>
          n.name.toLowerCase().includes(q) ||
          n.id.toLowerCase().includes(q) ||
          n.type.toLowerCase().includes(q) ||
          (n.path && n.path.toLowerCase().includes(q))
      );
    }

    return result;
  }, [nodes, edges, preset, searchQuery, componentFindingsMap]);

  // Helper colors
  const getNodeBorderColor = (node: NodeData) => {
    const riskInfo = componentFindingsMap[node.id] || componentFindingsMap[node.name];
    if (riskInfo?.highestSeverity === 'CRITICAL') return '#ff3366';
    if (riskInfo?.highestSeverity === 'HIGH') return '#fb923c';
    if (riskInfo?.highestSeverity === 'MEDIUM') return '#facc15';

    if (node.type === 'Service') return '#10b981';
    if (node.type === 'DataStore') return '#f59e0b';
    if (node.type === 'Endpoint') return '#38bdf8';
    return '#64748b';
  };

  const getNodeBgColor = (node: NodeData) => {
    const riskInfo = componentFindingsMap[node.id] || componentFindingsMap[node.name];
    if (riskInfo?.highestSeverity === 'CRITICAL') return 'rgba(255, 51, 102, 0.2)';
    if (riskInfo?.highestSeverity === 'HIGH') return 'rgba(251, 146, 60, 0.18)';

    if (node.type === 'Service') return 'rgba(16, 185, 129, 0.18)';
    if (node.type === 'DataStore') return 'rgba(245, 158, 11, 0.2)';
    if (node.type === 'Endpoint') return 'rgba(56, 189, 248, 0.15)';
    return 'rgba(30, 41, 59, 0.5)';
  };

  const getNodeShape = (nodeType: string): cytoscape.Css.NodeShape => {
    if (nodeType === 'DataStore') return 'barrel';
    if (nodeType === 'Endpoint') return 'round-rectangle';
    return 'round-rectangle';
  };

  // Render & update Cytoscape instance
  useEffect(() => {
    if (viewMode !== 'cytoscape' || loading || !containerRef.current) {
      return;
    }

    if (cyRef.current) {
      cyRef.current.destroy();
      cyRef.current = null;
    }

    const nodeIdSet = new Set(filteredNodes.map((n) => n.id));
    const validEdges = edges.filter(
      (e) => nodeIdSet.has(e.source) && nodeIdSet.has(e.target)
    );

    const elements: cytoscape.ElementDefinition[] = [
      ...filteredNodes.map((node) => {
        const riskInfo = componentFindingsMap[node.id] || componentFindingsMap[node.name];
        const riskLevel = riskInfo?.highestSeverity || 'CLEAN';
        const isCritical = riskLevel === 'CRITICAL';
        const isHigh = riskLevel === 'HIGH';

        let formattedLabel = node.name;
        if (node.type === 'Service') {
          formattedLabel = `⚙️ ${node.name}\n[${node.language || 'microservice'}]`;
        } else if (node.type === 'DataStore') {
          formattedLabel = `🗄️ ${node.name}\n(${node.store_type || 'database'})`;
        } else if (node.type === 'Endpoint') {
          formattedLabel = `${node.method || 'API'} ${node.path || node.name}`;
        }

        return {
          data: {
            id: node.id,
            label: formattedLabel,
            type: node.type,
            riskLevel,
            isRisk: isCritical || isHigh,
            borderColor: getNodeBorderColor(node),
            bgColor: getNodeBgColor(node),
            shape: getNodeShape(node.type),
            raw: node,
          },
        };
      }),
      ...validEdges.map((edge, index) => {
        const isUnencrypted = edge.properties?.is_encrypted === false;
        let edgeColor = '#64748b';
        let lineStyle: cytoscape.Css.LineStyle = 'solid';

        if (edge.type === 'WRITES_TO') {
          edgeColor = '#f59e0b';
        } else if (edge.type === 'READS_FROM') {
          edgeColor = '#38bdf8';
        } else if (edge.type === 'CALLS') {
          edgeColor = isUnencrypted ? '#fb923c' : '#818cf8';
          if (isUnencrypted) {
            lineStyle = 'dashed';
          }
        }

        return {
          data: {
            id: `edge_${index}_${edge.source}_${edge.target}`,
            source: edge.source,
            target: edge.target,
            label: edge.type + (isUnencrypted ? ' (Plain HTTP)' : ''),
            type: edge.type,
            lineColor: edgeColor,
            lineStyle,
          },
        };
      }),
    ];

    try {
      const cy = cytoscape({
        container: containerRef.current,
        elements,
        style: [
          {
            selector: 'node',
            style: {
              'background-color': 'data(bgColor)',
              'border-color': 'data(borderColor)',
              'border-width': 2,
              'shape': 'data(shape)' as any,
              'label': 'data(label)',
              'color': '#f8fafc',
              'font-family': 'Inter, system-ui, sans-serif',
              'font-size': '11px',
              'font-weight': 600,
              'text-valign': 'center',
              'text-halign': 'center',
              'text-wrap': 'wrap',
              'text-max-width': '140px',
              'width': 'label',
              'height': '46px',
              'padding': '14px',
              'transition-property': 'background-color, border-color, opacity, border-width',
              'transition-duration': 0.25 as any,
              'overlay-opacity': 0,
            },
          },
          {
            selector: 'node[type = "Service"]',
            style: {
              'height': '54px',
              'padding': '16px',
              'font-size': '12px',
              'border-width': 2.5,
            },
          },
          {
            selector: 'node[type = "DataStore"]',
            style: {
              'height': '56px',
              'width': '120px',
              'padding': '14px',
              'font-size': '11px',
              'border-width': 2.5,
            },
          },
          {
            selector: 'node[isRisk]',
            style: {
              'border-width': 3,
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
            selector: 'node.highlighted',
            style: {
              'border-color': '#38bdf8',
              'border-width': 4,
              'opacity': 1,
            } as any,
          },
          {
            selector: 'node.dimmed',
            style: {
              'opacity': 0.2,
            },
          },
          {
            selector: 'edge',
            style: {
              'width': 2.2,
              'line-color': 'data(lineColor)',
              'line-style': 'data(lineStyle)' as any,
              'target-arrow-color': 'data(lineColor)',
              'target-arrow-shape': 'triangle',
              'arrow-scale': 1.1,
              'curve-style': 'bezier',
              'label': 'data(label)',
              'font-family': 'JetBrains Mono, monospace',
              'font-size': '9px',
              'font-weight': 600,
              'color': '#cbd5e1',
              'text-background-opacity': 0.85,
              'text-background-color': '#07090e',
              'text-background-padding': '4px',
              'text-background-shape': 'round-rectangle',
              'transition-property': 'line-color, opacity, width',
              'transition-duration': 0.25 as any,
            },
          },
          {
            selector: 'edge.highlighted',
            style: {
              'width': 3.5,
              'line-color': '#38bdf8',
              'target-arrow-color': '#38bdf8',
              'opacity': 1,
            },
          },
          {
            selector: 'edge.dimmed',
            style: {
              'opacity': 0.12,
            },
          },
        ],
        layout: {
          name: layoutName,
          animate: true,
          animationDuration: 600,
          padding: 40,
          nodeRepulsion: 6500,
          idealEdgeLength: 120,
        } as any,
        wheelSensitivity: 0.2,
      });

      // Hover / Focus blast-radius behavior
      cy.on('tap', 'node', (evt) => {
        const node = evt.target;
        const rawNode = node.data('raw');
        setSelectedNode(rawNode);
        setFocusMode(true);

        // Highlight connected 1st-degree neighbors
        const connectedEdges = node.connectedEdges();
        const connectedNodes = connectedEdges.connectedNodes();

        cy.elements().removeClass('highlighted').addClass('dimmed');
        node.removeClass('dimmed').addClass('highlighted');
        connectedNodes.removeClass('dimmed').addClass('highlighted');
        connectedEdges.removeClass('dimmed').addClass('highlighted');
      });

      // Tap on empty canvas resets focus
      cy.on('tap', (evt) => {
        if (evt.target === cy) {
          setSelectedNode(null);
          setFocusMode(false);
          cy.elements().removeClass('highlighted dimmed');
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
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [viewMode, layoutName, filteredNodes, edges, componentFindingsMap]);

  // Canvas zoom & reset handlers
  const handleZoomIn = () => {
    if (cyRef.current) cyRef.current.zoom(cyRef.current.zoom() * 1.25);
  };

  const handleZoomOut = () => {
    if (cyRef.current) cyRef.current.zoom(cyRef.current.zoom() * 0.8);
  };

  const handleFit = () => {
    if (cyRef.current) {
      cyRef.current.elements().removeClass('highlighted dimmed');
      setFocusMode(false);
      cyRef.current.fit(undefined, 40);
    }
  };

  const handleExportPNG = () => {
    if (cyRef.current) {
      const png64 = cyRef.current.png({ full: true, bg: '#07090e', scale: 2.5 });
      const a = document.createElement('a');
      a.href = png64;
      a.download = `architecture_graph_${activeScanId?.substring(0, 8)}.png`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
    }
  };

  const selectedNodeFindings = useMemo(() => {
    if (!selectedNode) return [];
    const info = componentFindingsMap[selectedNode.id] || componentFindingsMap[selectedNode.name];
    return info?.findings || [];
  }, [selectedNode, componentFindingsMap]);

  if (loading) {
    return (
      <div className="graph-view card" style={{ textAlign: 'center', padding: '3rem' }}>
        <RefreshCw size={28} className="spin" color="#38bdf8" style={{ margin: '0 auto 1rem auto' }} />
        <p style={{ color: 'var(--text-secondary)' }}>Rendering architecture security graph...</p>
      </div>
    );
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
      {/* Top Header Bar */}
      <div className="graph-header-bar">
        <div>
          <h2>Architecture Security Topology</h2>
          <p className="graph-subtitle">
            Scan ID: <code>{activeScanId?.substring(0, 8)}</code> • Live Inter-Service Call Graph & Risk Telemetry
          </p>
        </div>

        <div className="graph-header-actions">
          <Link to={`/findings/${activeScanId}`} className="btn-secondary">
            <ShieldAlert size={14} color="#ff3366" />
            Findings ({findings.length})
          </Link>
          <button
            className="btn-primary"
            onClick={() => setViewMode(viewMode === 'cytoscape' ? 'list' : 'cytoscape')}
          >
            {viewMode === 'cytoscape' ? (
              <>
                <LayoutGrid size={14} />
                Switch to Component Grid
              </>
            ) : (
              <>
                <Network size={14} />
                Switch to Visual Graph
              </>
            )}
          </button>
        </div>
      </div>

      {/* Top Telemetry Stats HUD */}
      {stats && (
        <div className="stats-grid">
          <div className="stat-card">
            <div className="stat-icon-wrap">
              <Server size={18} color="#34d399" />
            </div>
            <div className="stat-number">{stats.service_count || 0}</div>
            <div className="stat-label">Services</div>
          </div>
          <div className="stat-card">
            <div className="stat-icon-wrap">
              <Database size={18} color="#fbbf24" />
            </div>
            <div className="stat-number">{stats.datastore_count || 0}</div>
            <div className="stat-label">Datastores</div>
          </div>
          <div className="stat-card">
            <div className="stat-icon-wrap">
              <GitBranch size={18} color="#38bdf8" />
            </div>
            <div className="stat-number">{stats.endpoint_count || 0}</div>
            <div className="stat-label">Endpoints</div>
          </div>
          <div className="stat-card">
            <div className="stat-icon-wrap">
              <Network size={18} color="#818cf8" />
            </div>
            <div className="stat-number">{edges.length}</div>
            <div className="stat-label">Dependencies</div>
          </div>
        </div>
      )}

      {/* Main Graph Visualization Panel */}
      <div className="graph-container card">
        {/* Professional Control Ribbon */}
        <div className="graph-toolbar">
          {/* Preset Buttons */}
          <div className="preset-toggle-group">
            <button
              className={`preset-btn ${preset === 'SERVICE_MESH' ? 'active' : ''}`}
              onClick={() => setPreset('SERVICE_MESH')}
              title="Clean service mesh & datastore architecture"
            >
              <Server size={13} />
              Service Mesh
            </button>
            <button
              className={`preset-btn ${preset === 'ALL' ? 'active' : ''}`}
              onClick={() => setPreset('ALL')}
              title="Complete architecture including endpoints"
            >
              <Radio size={13} />
              Full Topology
            </button>
            <button
              className={`preset-btn ${preset === 'DATA_FLOW' ? 'active' : ''}`}
              onClick={() => setPreset('DATA_FLOW')}
              title="Datastores and reading/writing microservices"
            >
              <Database size={13} />
              Data Stores
            </button>
            <button
              className={`preset-btn ${preset === 'RISK_PATHS' ? 'active' : ''}`}
              onClick={() => setPreset('RISK_PATHS')}
              title="Filter components with Critical or High risks"
            >
              <AlertTriangle size={13} />
              Vulnerable Nodes
            </button>
          </div>

          {/* Quick Search */}
          <div className="graph-search-wrap">
            <Search size={14} className="search-icon" />
            <input
              type="text"
              placeholder="Find service, datastore, route..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
            />
            {searchQuery && (
              <button className="clear-search-btn" onClick={() => setSearchQuery('')}>
                ✕
              </button>
            )}
          </div>

          {/* Canvas Controls */}
          {viewMode === 'cytoscape' && (
            <div className="graph-canvas-controls">
              <select
                value={layoutName}
                onChange={(e) => setLayoutName(e.target.value as any)}
                className="layout-select"
                title="Graph Layout Algorithm"
              >
                <option value="cose">Force Directed (CoSE)</option>
                <option value="breadthfirst">Hierarchical Flow</option>
                <option value="concentric">Concentric Rings</option>
                <option value="circle">Circular Topology</option>
              </select>

              <div className="tool-btn-group">
                <button className="tool-btn" onClick={handleZoomIn} title="Zoom In">
                  <ZoomIn size={14} />
                </button>
                <button className="tool-btn" onClick={handleZoomOut} title="Zoom Out">
                  <ZoomOut size={14} />
                </button>
                <button className="tool-btn" onClick={handleFit} title="Reset & Fit View">
                  <Maximize2 size={14} />
                  <span>Fit</span>
                </button>
                <button className="tool-btn" onClick={handleExportPNG} title="Export High-Res PNG">
                  <Camera size={14} />
                  <span>PNG</span>
                </button>
              </div>
            </div>
          )}
        </div>

        {/* Legend Bar */}
        <div className="graph-sub-legend">
          <div className="legend-items-wrap">
            <span className="legend-title">Legend:</span>
            <div className="legend-badge service">
              <span className="dot service"></span> Service
            </div>
            <div className="legend-badge datastore">
              <span className="dot datastore"></span> DataStore
            </div>
            {preset === 'ALL' && (
              <div className="legend-badge endpoint">
                <span className="dot endpoint"></span> Endpoint
              </div>
            )}
            <div className="legend-divider"></div>
            <div className="legend-edge-item">
              <span className="edge-sample writes"></span> Writes To
            </div>
            <div className="legend-edge-item">
              <span className="edge-sample reads"></span> Reads From
            </div>
            <div className="legend-edge-item">
              <span className="edge-sample calls"></span> Sync Call
            </div>
            <div className="legend-edge-item">
              <span className="edge-sample unencrypted"></span> Plain HTTP (Risk)
            </div>
          </div>

          {focusMode && (
            <div className="focus-indicator">
              <Eye size={12} />
              <span>Blast Radius Focus (tap background to reset)</span>
            </div>
          )}
        </div>

        {/* View Mode Canvas */}
        {viewMode === 'cytoscape' ? (
          <div className="canvas-wrapper">
            <div ref={containerRef} className="cytoscape-canvas" />

            {/* Quick Component Count Overlay */}
            <div className="canvas-telemetry-pill">
              <span>Nodes: {filteredNodes.length}</span>
              <span className="sep">•</span>
              <span>Links: {edges.length}</span>
            </div>
          </div>
        ) : (
          <div className="simple-graph-view">
            <h4 style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Layers size={18} color="#38bdf8" />
              Architecture Inventory ({filteredNodes.length})
            </h4>
            <div className="nodes-list">
              {filteredNodes.map((node) => {
                const riskInfo = componentFindingsMap[node.id] || componentFindingsMap[node.name];
                return (
                  <div
                    key={node.id}
                    className={`node-card ${node.type?.toLowerCase()}`}
                    style={{ borderColor: getNodeBorderColor(node) }}
                    onClick={() => setSelectedNode(node)}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                      <strong>{node.name}</strong>
                      {riskInfo?.highestSeverity && (
                        <span
                          className="risk-badge"
                          style={{
                            backgroundColor:
                              riskInfo.highestSeverity === 'CRITICAL' ? '#ff3366' : '#fb923c',
                          }}
                        >
                          {riskInfo.highestSeverity}
                        </span>
                      )}
                    </div>
                    <p className="node-type">{node.type}</p>
                    {node.language && <p className="node-prop">Lang: {node.language}</p>}
                    {node.path && <p className="node-prop">{node.method} {node.path}</p>}
                  </div>
                );
              })}
            </div>
          </div>
        )}
      </div>

      {/* Selected Component Inspector Drawer */}
      {selectedNode && (
        <div className="node-details card">
          <div className="inspector-header">
            <div className="inspector-title-wrap">
              {selectedNode.type === 'Service' && <Server size={20} color="#34d399" />}
              {selectedNode.type === 'DataStore' && <Database size={20} color="#fbbf24" />}
              {selectedNode.type === 'Endpoint' && <GitBranch size={20} color="#38bdf8" />}
              <div>
                <h3>{selectedNode.name}</h3>
                <span className="inspector-type-badge">{selectedNode.type}</span>
              </div>
            </div>

            <button className="btn-small btn-secondary" onClick={() => setSelectedNode(null)}>
              <X size={14} />
              Close
            </button>
          </div>

          <div className="details-grid">
            <div>
              <strong>Identifier:</strong>
              <code>{selectedNode.id}</code>
            </div>
            {selectedNode.language && (
              <div>
                <strong>Language:</strong>
                <span>{selectedNode.language}</span>
              </div>
            )}
            {selectedNode.store_type && (
              <div>
                <strong>Storage Engine:</strong>
                <span>{selectedNode.store_type}</span>
              </div>
            )}
            {selectedNode.path && (
              <div>
                <strong>Route:</strong>
                <code>{selectedNode.method} {selectedNode.path}</code>
              </div>
            )}
            {selectedNode.has_auth !== undefined && (
              <div>
                <strong>Authentication:</strong>
                <span className={selectedNode.has_auth ? 'tag-safe' : 'tag-danger'}>
                  {selectedNode.has_auth ? 'Enforced' : 'Unauthenticated'}
                </span>
              </div>
            )}
            {selectedNode.has_redundancy !== undefined && (
              <div>
                <strong>Redundancy:</strong>
                <span className={selectedNode.has_redundancy ? 'tag-safe' : 'tag-warn'}>
                  {selectedNode.has_redundancy ? 'Multi-Replica' : 'Single Instance (SPOF Risk)'}
                </span>
              </div>
            )}
            {selectedNode.has_health_check !== undefined && (
              <div>
                <strong>Health Probe:</strong>
                <span className={selectedNode.has_health_check ? 'tag-safe' : 'tag-muted'}>
                  {selectedNode.has_health_check ? 'Configured' : 'Missing'}
                </span>
              </div>
            )}
          </div>

          {/* Associated Security Findings */}
          {selectedNodeFindings.length > 0 ? (
            <div className="node-findings-section">
              <h4>
                <ShieldAlert size={16} color="#ff3366" />
                Detected Security & Reliability Risks ({selectedNodeFindings.length})
              </h4>
              <div className="node-findings-list">
                {selectedNodeFindings.map((f) => (
                  <div key={f.id} className={`node-finding-item ${f.severity.toLowerCase()}`}>
                    <span className={`finding-sev-pill ${f.severity.toLowerCase()}`}>
                      {f.severity}
                    </span>
                    <span className="finding-title-text">{f.title}</span>
                  </div>
                ))}
              </div>
            </div>
          ) : (
            <div className="node-findings-clean">
              <CheckCircle2 size={16} color="#34d399" />
              <span>No direct architectural vulnerabilities associated with this component.</span>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export default GraphView;
