"""Findings API endpoints."""
from fastapi import APIRouter, HTTPException, Query
from typing import Optional, List
import logging

from app.models import Finding, FindingsResponse, Severity
from app.graph.db import get_db_connection
from app.graph.repository import GraphRepository

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/findings", tags=["findings"])


@router.get("/{scan_id}", response_model=FindingsResponse)
async def get_findings(
    scan_id: str,
    severity: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    """
    Get findings for a scan with optional filtering.
    
    Args:
        scan_id: Unique scan identifier
        severity: Filter by severity level (CRITICAL|HIGH|MEDIUM|LOW|INFO)
        limit: Maximum results (1-500)
        offset: Pagination offset
        
    Returns:
        Findings list with metadata (total count, etc)
    """
    try:
        db = get_db_connection()
        graph_repo = GraphRepository(db)
        
        # Verify scan exists
        scan = graph_repo.get_scan(scan_id)
        if not scan:
            logger.warning(f"Scan {scan_id} not found")
            raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")
        
        # Get findings
        findings = graph_repo.get_findings_for_scan(
            scan_id=scan_id,
            severity=severity,
            limit=limit,
            offset=offset,
        )
        
        # Count total findings
        total_findings = graph_repo.count_findings_for_scan(scan_id, severity)
        
        logger.info(f"Retrieved {len(findings)} findings for scan {scan_id}")
        
        return FindingsResponse(
            scan_id=scan_id,
            findings=findings,
            total=total_findings,
            limit=limit,
            offset=offset,
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"Error retrieving findings for scan {scan_id}: {e}")
        raise HTTPException(status_code=500, detail=f"Error retrieving findings: {str(e)}")


@router.get("/{finding_id}", response_model=Finding)
async def get_finding(finding_id: str):
    """
    Get a single finding by ID with full details.
    
    Args:
        finding_id: Unique finding identifier
        
    Returns:
        Finding detail with all metadata
    """
    try:
        db = get_db_connection()
        graph_repo = GraphRepository(db)
        
        finding = graph_repo.get_finding(finding_id)
        if not finding:
            logger.warning(f"Finding {finding_id} not found")
            raise HTTPException(status_code=404, detail=f"Finding {finding_id} not found")
        
        return finding
    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"Error retrieving finding {finding_id}: {e}")
        raise HTTPException(status_code=500, detail=f"Error retrieving finding: {str(e)}")


@router.post("/{finding_id}/dismiss")
async def dismiss_finding(finding_id: str, reason: Optional[str] = None):
    """
    Mark a finding as dismissed/acknowledged.
    
    Args:
        finding_id: Finding to dismiss
        reason: Optional reason for dismissal
        
    Returns:
        Updated finding status
    """
    try:
        db = get_db_connection()
        graph_repo = GraphRepository(db)
        
        # Get finding to verify it exists
        finding = graph_repo.get_finding(finding_id)
        if not finding:
            logger.warning(f"Finding {finding_id} not found for dismissal")
            raise HTTPException(status_code=404, detail=f"Finding {finding_id} not found")
        
        # Update finding status
        graph_repo.dismiss_finding(finding_id, reason)
        logger.info(f"Dismissed finding {finding_id}")
        
        return {
            "status": "dismissed",
            "finding_id": finding_id,
            "reason": reason,
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"Error dismissing finding {finding_id}: {e}")
        raise HTTPException(status_code=500, detail=f"Error dismissing finding: {str(e)}")


@router.get("/{finding_id}/provenance")
async def get_finding_provenance(finding_id: str):
    """
    Get detailed provenance for a finding (source signals, rules fired, LLM reasoning).
    
    Provenance explains:
    - Which static analysis rules detected it
    - Which Cypher queries identified it
    - LLM reasoning (if LLM enrichment was used)
    - Component relationships that contributed
    
    Args:
        finding_id: Finding identifier
        
    Returns:
        Detailed provenance information
    """
    try:
        db = get_db_connection()
        graph_repo = GraphRepository(db)
        
        # Get finding
        finding = graph_repo.get_finding(finding_id)
        if not finding:
            logger.warning(f"Finding {finding_id} not found for provenance")
            raise HTTPException(status_code=404, detail=f"Finding {finding_id} not found")
        
        # Get provenance from related nodes/relationships
        provenance = graph_repo.get_finding_provenance(finding_id)
        
        logger.info(f"Retrieved provenance for finding {finding_id}")
        
        return provenance
    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"Error retrieving provenance for {finding_id}: {e}")
        raise HTTPException(status_code=500, detail=f"Error retrieving provenance: {str(e)}")
