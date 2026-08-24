"""Scan management API endpoints."""
from fastapi import APIRouter, HTTPException, Query, BackgroundTasks
from typing import Optional, List
from app.models import (
    ScanRequest, ScanResponse, ScanStatus, ScanMetadata,
    HealthResponse, Scan
)
from datetime import datetime
import uuid
import logging

from app.graph.db import get_db_connection
from app.graph.repository import GraphRepository
from app.pipeline import ScanPipeline

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/scans", tags=["scans"])


@router.post("/", response_model=ScanResponse)
async def initiate_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    """
    Initiate a new architectural scan.
    
    The scan runs asynchronously. Poll GET /{scan_id} for status updates.
    
    Args:
        request: Repository source and scan configuration
        background_tasks: For async job queueing
        
    Returns:
        Scan metadata with ID and initial status (QUEUED)
    """
    try:
        scan_id = str(uuid.uuid4())
        
        # Create scan record in Neo4j
        db = get_db_connection()
        graph_repo = GraphRepository(db)
        
        scan_obj = Scan(
            id=scan_id,
            status=ScanStatus.QUEUED,
            repository_source=request.repository,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
        )
        
        graph_repo.create_scan(scan_obj)
        logger.info(f"Created scan {scan_id} for repository {request.repository}")
        
        # Queue scan in background
        pipeline = ScanPipeline()
        background_tasks.add_task(
            pipeline.scan,
            scan_id=scan_id,
            repository_source=request.repository,
            skip_ai=getattr(request, 'skip_ai', False),
        )
        
        return ScanResponse(
            scan_id=scan_id,
            status=ScanStatus.QUEUED,
            created_at=datetime.utcnow(),
        )
    except Exception as e:
        logger.exception(f"Error initiating scan: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to initiate scan: {str(e)}")


@router.get("/{scan_id}", response_model=ScanMetadata)
async def get_scan(scan_id: str):
    """
    Get status and metadata for a scan.
    
    Args:
        scan_id: Unique scan identifier
        
    Returns:
        Scan metadata and current status
    """
    try:
        db = get_db_connection()
        graph_repo = GraphRepository(db)
        
        scan = graph_repo.get_scan(scan_id)
        if not scan:
            logger.warning(f"Scan {scan_id} not found")
            raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")
        
        # Convert Scan to ScanMetadata
        return ScanMetadata(
            scan_id=scan.id,
            status=scan.status,
            created_at=scan.created_at,
            updated_at=scan.updated_at,
            repository_source=scan.repository_source,
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"Error retrieving scan {scan_id}: {e}")
        raise HTTPException(status_code=500, detail=f"Error retrieving scan: {str(e)}")


@router.get("/", response_model=List[ScanMetadata])
async def list_scans(
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
    status: Optional[str] = None,
):
    """
    List recent scans with optional filtering.
    
    Args:
        limit: Maximum results to return (1-100)
        offset: Pagination offset
        status: Filter by scan status (QUEUED|RUNNING|COMPLETED|FAILED)
        
    Returns:
        List of scan metadata ordered by creation date (newest first)
    """
    try:
        db = get_db_connection()
        graph_repo = GraphRepository(db)
        
        scans = graph_repo.list_scans(limit=limit, offset=offset, status=status)
        
        return [
            ScanMetadata(
                scan_id=scan.id,
                status=scan.status,
                created_at=scan.created_at,
                updated_at=scan.updated_at,
                repository_source=scan.repository_source,
            )
            for scan in scans
        ]
    except Exception as e:
        logger.exception(f"Error listing scans: {e}")
        raise HTTPException(status_code=500, detail=f"Error listing scans: {str(e)}")


@router.delete("/{scan_id}")
async def delete_scan(scan_id: str):
    """
    Delete a scan and its associated data.
    
    Args:
        scan_id: Unique scan identifier
        
    Returns:
        Confirmation message
    """
    try:
        db = get_db_connection()
        graph_repo = GraphRepository(db)
        
        deleted = graph_repo.delete_scan(scan_id)
        if not deleted:
            logger.warning(f"Scan {scan_id} not found for deletion")
            raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")
        
        logger.info(f"Deleted scan {scan_id}")
        return {"status": "deleted", "scan_id": scan_id}
    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"Error deleting scan {scan_id}: {e}")
        raise HTTPException(status_code=500, detail=f"Error deleting scan: {str(e)}")
