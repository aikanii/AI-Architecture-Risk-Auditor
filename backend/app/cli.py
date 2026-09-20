"""Command-line interface for AI Architecture Risk Auditor."""
import click
import json
import sys
from pathlib import Path
from typing import Optional
import logging

from app.config import Settings, settings as default_settings
from app.pipeline import ScanPipeline
from app.graph.repository import GraphRepository
from app.reporting.exporters import ReportExporter
from app.models import Severity

# Configure logging
logging.basicConfig(
    level=default_settings.log_level,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

SEVERITY_ORDER = {
    "CRITICAL": 5,
    "HIGH": 4,
    "MEDIUM": 3,
    "LOW": 2,
    "INFO": 1,
}


@click.group()
@click.version_option("0.1.0")
def cli():
    """AI Architecture Risk Auditor - Static analysis for architectural risks."""
    pass


@cli.command()
@click.argument("path_or_url")
@click.option(
    "--config",
    type=click.Path(exists=True),
    help="Configuration file (YAML/JSON)",
)
@click.option(
    "--fail-on",
    type=click.Choice(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]),
    default="HIGH",
    help="Exit with non-zero code if finding of this severity or higher is found",
)
@click.option(
    "--skip-ai",
    is_flag=True,
    help="Skip LLM enrichment layer",
)
@click.option(
    "--output",
    type=click.Path(),
    help="Output directory or file for results",
)
def scan(
    path_or_url: str,
    config: Optional[str],
    fail_on: str,
    skip_ai: bool,
    output: Optional[str],
):
    """
    Scan a repository for architectural risks.
    
    PATH_OR_URL: Local path, Git URL, or archive file to scan
    """
    try:
        # Load config if provided
        pipeline_config = {}
        if config:
            with open(config) as f:
                if config.endswith(".json"):
                    pipeline_config = json.load(f)
                else:
                    import yaml
                    pipeline_config = yaml.safe_load(f)
        
        # Determine source type
        source_type = "local"
        if path_or_url.startswith("http://") or path_or_url.startswith("https://"):
            source_type = "git"
        elif path_or_url.endswith((".zip", ".tar.gz", ".tar")):
            source_type = "upload"
        
        repo_source = {
            "type": source_type,
        }
        
        if source_type == "local":
            repo_source["path"] = str(Path(path_or_url).resolve())
        elif source_type == "git":
            repo_source["url"] = path_or_url
            repo_source["branch"] = pipeline_config.get("branch", "main")
            repo_source["token"] = pipeline_config.get("git_token")
        elif source_type == "upload":
            repo_source["path"] = path_or_url
        
        click.echo(f"🔍 Starting architectural risk scan on {path_or_url}...")
        pipeline = ScanPipeline(default_settings)
        scan_id = pipeline.scan(repo_source=repo_source, skip_ai=skip_ai)
        click.echo(f"✅ Scan completed successfully. Scan ID: {scan_id}")
        
        # Retrieve findings
        graph_repo = GraphRepository()
        findings = graph_repo.get_findings_for_scan(scan_id, limit=1000)
        
        # Count by severity
        counts = {}
        for f in findings:
            sev = f.severity.value if hasattr(f.severity, 'value') else str(f.severity)
            counts[sev] = counts.get(sev, 0) + 1
            
        click.echo("\n📊 Findings Summary:")
        click.echo(f"  Total Findings: {len(findings)}")
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            if sev in counts:
                click.echo(f"  {sev}: {counts[sev]}")
        
        click.echo("\n🔍 Detected Risks:")
        for idx, f in enumerate(findings[:10]):
            sev = f.severity.value if hasattr(f.severity, 'value') else str(f.severity)
            click.echo(f"  [{sev}] {f.title}")
            if f.remediation_steps:
                click.echo(f"       Remediation: {f.remediation_steps[0]}")
        if len(findings) > 10:
            click.echo(f"  ... and {len(findings) - 10} more findings")
            
        # Export if output requested
        if output:
            scan_obj = graph_repo.get_scan(scan_id)
            exporter = ReportExporter(scan_obj, findings)
            out_path = Path(output)
            if out_path.suffix.lower() == ".sarif":
                data = exporter.export_sarif()
                out_path.write_text(json.dumps(data, indent=2))
            elif out_path.suffix.lower() == ".html":
                data = exporter.export_html()
                out_path.write_text(data)
            elif out_path.suffix.lower() == ".pdf":
                data = exporter.export_pdf()
                out_path.write_bytes(data)
            else:
                data = exporter.export_json()
                out_path.write_text(json.dumps(data, indent=2))
            click.echo(f"\n💾 Report exported to: {output}")

        # Check fail-on threshold
        fail_rank = SEVERITY_ORDER.get(fail_on.upper(), 4)
        has_violating = any(
            SEVERITY_ORDER.get(
                (f.severity.value if hasattr(f.severity, 'value') else str(f.severity)).upper(), 0
            ) >= fail_rank
            for f in findings
        )
        if has_violating:
            click.echo(f"\n❌ Failure threshold exceeded: found findings with severity >= {fail_on}", err=True)
            sys.exit(1)
        
    except Exception as e:
        click.echo(f"❌ Scan failed: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.argument("scan_id")
@click.option(
    "--format",
    type=click.Choice(["json", "sarif", "html", "pdf"]),
    default="json",
    help="Export format",
)
@click.option(
    "--output",
    type=click.Path(),
    required=True,
    help="Output file path",
)
def export(scan_id: str, format: str, output: str):
    """
    Export a scan report.
    
    SCAN_ID: ID of the scan to export
    """
    try:
        graph_repo = GraphRepository()
        scan_obj = graph_repo.get_scan(scan_id)
        if not scan_obj:
            click.echo(f"❌ Scan {scan_id} not found", err=True)
            sys.exit(1)
            
        findings = graph_repo.get_findings_for_scan(scan_id, limit=10000)
        exporter = ReportExporter(scan_obj, findings)
        out_path = Path(output)
        
        click.echo(f"📊 Exporting scan {scan_id} as {format}...")
        if format.lower() == "json":
            out_path.write_text(json.dumps(exporter.export_json(), indent=2))
        elif format.lower() == "sarif":
            out_path.write_text(json.dumps(exporter.export_sarif(), indent=2))
        elif format.lower() == "html":
            out_path.write_text(exporter.export_html())
        elif format.lower() == "pdf":
            out_path.write_bytes(exporter.export_pdf())
            
        click.echo(f"✅ Report exported to {output}")
    except Exception as e:
        click.echo(f"❌ Export failed: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.option(
    "--limit",
    type=int,
    default=10,
    help="Number of recent scans to list",
)
def list_scans(limit: int):
    """List recent scans."""
    try:
        graph_repo = GraphRepository()
        scans = graph_repo.list_scans(limit=limit)
        
        if not scans:
            click.echo("📋 No recent scans found.")
            return
            
        click.echo(f"📋 Recent Scans ({len(scans)}):")
        click.echo(f"{'SCAN ID':<38} {'STATUS':<12} {'CREATED AT':<20} {'REPOSITORY'}")
        click.echo("-" * 80)
        for s in scans:
            status = s.status.value if hasattr(s.status, 'value') else str(s.status)
            created = s.created_at.strftime("%Y-%m-%d %H:%M:%S") if s.created_at else "N/A"
            repo = s.repository_source.get("path") or s.repository_source.get("url") or "local"
            click.echo(f"{s.id:<38} {status:<12} {created:<20} {repo}")
    except Exception as e:
        click.echo(f"❌ Failed to list scans: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.argument("scan_id")
def status(scan_id: str):
    """Get the status of a scan."""
    try:
        graph_repo = GraphRepository()
        scan_obj = graph_repo.get_scan(scan_id)
        if not scan_obj:
            click.echo(f"❌ Scan {scan_id} not found", err=True)
            sys.exit(1)
            
        stats = graph_repo.get_graph_statistics(scan_id)
        status_val = scan_obj.status.value if hasattr(scan_obj.status, 'value') else str(scan_obj.status)
        click.echo(f"📍 Scan ID: {scan_obj.id}")
        click.echo(f"  Status: {status_val}")
        click.echo(f"  Created: {scan_obj.created_at}")
        click.echo(f"  Updated: {scan_obj.updated_at}")
        click.echo(f"  Services: {stats.get('service_count', 0)}")
        click.echo(f"  Endpoints: {stats.get('endpoint_count', 0)}")
        click.echo(f"  Findings: {stats.get('finding_count', 0)}")
    except Exception as e:
        click.echo(f"❌ Failed to get status: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.argument("scan_id")
def findings(scan_id: str):
    """Get findings for a scan."""
    try:
        graph_repo = GraphRepository()
        findings_list = graph_repo.get_findings_for_scan(scan_id, limit=1000)
        
        if not findings_list:
            click.echo(f"🔍 No findings found for scan {scan_id}.")
            return
            
        click.echo(f"🔍 Findings for scan {scan_id} ({len(findings_list)} total):")
        for idx, f in enumerate(findings_list):
            sev = f.severity.value if hasattr(f.severity, 'value') else str(f.severity)
            click.echo(f"\n{idx+1}. [{sev}] {f.title}")
            click.echo(f"   {f.description}")
            if f.affected_components:
                click.echo(f"   Affected: {', '.join(f.affected_components)}")
            if f.remediation_steps:
                click.echo(f"   Remediation: {f.remediation_steps[0]}")
    except Exception as e:
        click.echo(f"❌ Failed to get findings: {e}", err=True)
        sys.exit(1)


@cli.command()
def health():
    """Check health of the application and dependencies."""
    try:
        from app.main import health_check
        import asyncio
        result = asyncio.run(health_check())
        
        click.echo("🏥 Health Check:")
        click.echo(f"  Status: {result.status}")
        click.echo(f"  Version: {result.version}")
        click.echo(f"  Neo4j: {'✅ Connected' if result.neo4j_connected else 'ℹ️ In-Memory Graph Active'}")
        click.echo(f"  OpenAI: {'✅ Configured' if result.openai_available else 'ℹ️ Offline Mode (Deterministic only)'}")
    except Exception as e:
        click.echo(f"❌ Health check failed: {e}", err=True)
        sys.exit(1)


if __name__ == "__main__":
    cli()
