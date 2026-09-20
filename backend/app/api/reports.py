"""Report export API endpoints."""
from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import FileResponse, StreamingResponse
from typing import Optional
import json
import logging
import io
from datetime import datetime

from app.models import ExportFormat
from app.graph.db import get_db_connection
from app.graph.repository import GraphRepository
from app.reporting.exporters import ReportExporter

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/reports", tags=["reports"])


@router.get("/{scan_id}/export")
async def export_report(
    scan_id: str,
    format: str = Query("json", pattern="^(json|sarif|html|pdf)$"),
):
    """
    Export a complete report in the specified format.
    
    Formats:
    - json: Raw findings data
    - sarif: GitHub code scanning format
    - html: Interactive HTML report
    - pdf: Formatted PDF document
    
    Args:
        scan_id: Unique scan identifier
        format: Export format (json, sarif, html, pdf)
        
    Returns:
        File download with appropriate MIME type
    """
    try:
        db = get_db_connection()
        graph_repo = GraphRepository(db)
        
        # Verify scan exists
        scan = graph_repo.get_scan(scan_id)
        if not scan:
            logger.warning(f"Scan {scan_id} not found for export")
            raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")
        
        # Get all findings
        findings = graph_repo.get_findings_for_scan(scan_id, limit=10000)
        
        # Export in requested format
        exporter = ReportExporter(scan, findings)
        
        if format.lower() == "json":
            report_data = exporter.export_json()
            return StreamingResponse(
                iter([json.dumps(report_data, indent=2)]),
                media_type="application/json",
                headers={"Content-Disposition": f"attachment; filename=scan_{scan_id}.json"}
            )
        
        elif format.lower() == "sarif":
            report_data = exporter.export_sarif()
            return StreamingResponse(
                iter([json.dumps(report_data, indent=2)]),
                media_type="application/json",
                headers={"Content-Disposition": f"attachment; filename=scan_{scan_id}_sarif.json"}
            )
        
        elif format.lower() == "html":
            report_data = exporter.export_html()
            return StreamingResponse(
                iter([report_data]),
                media_type="text/html",
                headers={"Content-Disposition": f"attachment; filename=scan_{scan_id}.html"}
            )
        
        elif format.lower() == "pdf":
            # PDF export requires reportlab
            try:
                report_data = exporter.export_pdf()
                return StreamingResponse(
                    iter([report_data]),
                    media_type="application/pdf",
                    headers={"Content-Disposition": f"attachment; filename=scan_{scan_id}.pdf"}
                )
            except ImportError:
                logger.warning("reportlab not installed for PDF export")
                raise HTTPException(
                    status_code=503,
                    detail="PDF export not available (reportlab not installed)"
                )
        
        else:
            raise HTTPException(status_code=400, detail=f"Unknown format: {format}")
        
        logger.info(f"Exported scan {scan_id} as {format}")
        
    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"Error exporting scan {scan_id}: {e}")
        raise HTTPException(status_code=500, detail=f"Error exporting report: {str(e)}")


@router.get("/{scan_id}/summary", response_model=dict)
async def get_report_summary(scan_id: str):
    """
    Get a summary report for a scan.
    
    Includes key metrics, top findings, riskiest services.
    
    Args:
        scan_id: Unique scan identifier
        
    Returns:
        Report summary with aggregated findings data
    """
    try:
        db = get_db_connection()
        graph_repo = GraphRepository(db)
        
        # Verify scan exists
        scan = graph_repo.get_scan(scan_id)
        if not scan:
            logger.warning(f"Scan {scan_id} not found for summary")
            raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")
        
        # Get findings summary
        findings = graph_repo.get_findings_for_scan(scan_id, limit=10000)
        
        # Calculate metrics
        by_severity = {}
        by_component = {}
        top_findings = []
        
        for finding in findings:
            # Count by severity
            severity = finding.severity
            by_severity[severity] = by_severity.get(severity, 0) + 1
            
            # Count by component
            if finding.affected_components:
                for comp in finding.affected_components[:1]:  # First component
                    by_component[comp] = by_component.get(comp, 0) + 1
            
            # Top 5 findings by severity rank
            if len(top_findings) < 5:
                top_findings.append({
                    "id": finding.id,
                    "title": finding.title,
                    "severity": finding.severity,
                    "components": finding.affected_components,
                })
        
        summary = {
            "scan_id": scan_id,
            "status": scan.status,
            "created_at": scan.created_at.isoformat() if scan.created_at else None,
            "updated_at": scan.updated_at.isoformat() if scan.updated_at else None,
            "repository": scan.repository_source,
            "findings_count": len(findings),
            "findings_by_severity": by_severity,
            "top_services": sorted(
                by_component.items(),
                key=lambda x: x[1],
                reverse=True
            )[:10],
            "top_findings": top_findings,
        }
        
        logger.info(f"Retrieved summary for scan {scan_id}")
        return summary
        
    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"Error retrieving summary for scan {scan_id}: {e}")
        raise HTTPException(status_code=500, detail=f"Error retrieving summary: {str(e)}")


@router.post("/{scan_id}/regenerate")
async def regenerate_report(scan_id: str):
    """
    Regenerate cached report data for a scan.
    
    Useful after configuration changes or to refresh cached exports.
    
    Args:
        scan_id: Unique scan identifier
        
    Returns:
        Status confirmation
    """
    try:
        db = get_db_connection()
        graph_repo = GraphRepository(db)
        
        # Verify scan exists
        scan = graph_repo.get_scan(scan_id)
        if not scan:
            logger.warning(f"Scan {scan_id} not found for regeneration")
            raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")
        
        # Regenerate caches
        graph_repo.regenerate_report_cache(scan_id)
        logger.info(f"Regenerated report cache for scan {scan_id}")
        
        return {
            "status": "regenerated",
            "scan_id": scan_id,
            "timestamp": datetime.utcnow().isoformat(),
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"Error regenerating report for scan {scan_id}: {e}")
        raise HTTPException(status_code=500, detail=f"Error regenerating report: {str(e)}")
