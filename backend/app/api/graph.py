"""Architecture graph API endpoints."""
from fastapi import APIRouter, HTTPException, Query
from typing import Optional, List, Dict, Any
import logging

from app.models import ArchitectureGraph
from app.graph.db import get_db_connection
from app.graph.repository import GraphRepository

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/graph", tags=["graph"])


@router.get("/{scan_id}", response_model=ArchitectureGraph)
async def get_graph(
    scan_id: str,
    filter_by_severity: Optional[str] = Query(None),
    filter_by_service: Optional[str] = Query(None),
):
    """
    Get the architecture graph for a scan.
    
    Returns architecture as graph with nodes (services, endpoints, datastores)
    and edges (calls, dependencies, data flows).
    
    Nodes include risk metadata (findings affecting them).
    
    Args:
        scan_id: Unique scan identifier
        filter_by_severity: Filter edges by finding severity
        filter_by_service: Filter to specific service and its neighbors
        
    Returns:
        ArchitectureGraph with nodes and edges, ready for visualization
    """
    try:
        db = get_db_connection()
        graph_repo = GraphRepository(db)
        
        # Verify scan exists
        scan = graph_repo.get_scan(scan_id)
        if not scan:
            logger.warning(f"Scan {scan_id} not found")
            raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")
        
        # Get graph structure
        graph = graph_repo.get_architecture_graph(
            scan_id=scan_id,
            filter_severity=filter_by_severity,
            filter_service=filter_by_service,
        )
        
        logger.info(f"Retrieved graph for scan {scan_id}: {len(graph.nodes)} nodes, {len(graph.edges)} edges")
        
        return graph
    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"Error retrieving graph for scan {scan_id}: {e}")
        raise HTTPException(status_code=500, detail=f"Error retrieving graph: {str(e)}")


@router.get("/{scan_id}/nodes", response_model=List[Dict[str, Any]])
async def get_graph_nodes(
    scan_id: str,
    node_type: Optional[str] = Query(None),
):
    """
    Get all nodes in the architecture graph.
    
    Node types: Service, Endpoint, DataStore, ExternalDependency
    
    Args:
        scan_id: Unique scan identifier
        node_type: Filter by node type
        
    Returns:
        List of graph nodes with properties
    """
    try:
        db = get_db_connection()
        graph_repo = GraphRepository(db)
        
        # Verify scan exists
        scan = graph_repo.get_scan(scan_id)
        if not scan:
            logger.warning(f"Scan {scan_id} not found")
            raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")
        
        # Get nodes
        nodes = graph_repo.get_graph_nodes(scan_id, node_type)
        logger.info(f"Retrieved {len(nodes)} nodes for scan {scan_id}")
        
        return nodes
    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"Error retrieving nodes for scan {scan_id}: {e}")
        raise HTTPException(status_code=500, detail=f"Error retrieving nodes: {str(e)}")


@router.get("/{scan_id}/edges", response_model=List[Dict[str, Any]])
async def get_graph_edges(
    scan_id: str,
    edge_type: Optional[str] = Query(None),
):
    """
    Get all edges in the architecture graph.
    
    Edge types: CALLS, DEPENDS_ON, WRITES_TO, READS_FROM, etc.
    
    Args:
        scan_id: Unique scan identifier
        edge_type: Filter by edge/relationship type
        
    Returns:
        List of graph edges with source, target, and properties
    """
    try:
        db = get_db_connection()
        graph_repo = GraphRepository(db)
        
        # Verify scan exists
        scan = graph_repo.get_scan(scan_id)
        if not scan:
            logger.warning(f"Scan {scan_id} not found")
            raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")
        
        # Get edges
        edges = graph_repo.get_graph_edges(scan_id, edge_type)
        logger.info(f"Retrieved {len(edges)} edges for scan {scan_id}")
        
        return edges
    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"Error retrieving edges for scan {scan_id}: {e}")
        raise HTTPException(status_code=500, detail=f"Error retrieving edges: {str(e)}")


@router.get("/{scan_id}/stats", response_model=Dict[str, Any])
async def get_graph_stats(scan_id: str):
    """
    Get statistics about the architecture graph.
    
    Includes node/edge counts, complexity metrics, risk distribution.
    
    Args:
        scan_id: Unique scan identifier
        
    Returns:
        Graph statistics (node counts, edge counts, metrics)
    """
    try:
        db = get_db_connection()
        graph_repo = GraphRepository(db)
        
        # Verify scan exists
        scan = graph_repo.get_scan(scan_id)
        if not scan:
            logger.warning(f"Scan {scan_id} not found")
            raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")
        
        # Calculate stats
        stats = graph_repo.get_graph_statistics(scan_id)
        logger.info(f"Retrieved graph statistics for scan {scan_id}")
        
        return stats
    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"Error retrieving graph stats for scan {scan_id}: {e}")
        raise HTTPException(status_code=500, detail=f"Error retrieving graph stats: {str(e)}")
