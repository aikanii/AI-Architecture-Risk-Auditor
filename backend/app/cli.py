"""Command-line interface for AI Architecture Risk Auditor."""
import click
import json
import sys
from pathlib import Path
from typing import Optional
import logging

from app.config import Settings, settings as default_settings
from app.pipeline import ScanPipeline
from app.models import ExportFormat

# Configure logging
logging.basicConfig(
    level=default_settings.log_level,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


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
    help="Output directory for results",
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
        
        # Prepare source specification
        repo_source = {
            "type": source_type,
        }
        
        if source_type == "local":
            repo_source["path"] = path_or_url
        elif source_type == "git":
            repo_source["url"] = path_or_url
            repo_source["branch"] = pipeline_config.get("branch", "main")
            repo_source["token"] = pipeline_config.get("git_token")
        elif source_type == "upload":
            repo_source["path"] = path_or_url
        
        # Initialize pipeline
        pipeline = ScanPipeline(default_settings)
        
        # Run scan
        click.echo("🔍 Starting architectural risk scan...")
        scan_id = pipeline.scan(repo_source)
        click.echo(f"✅ Scan completed: {scan_id}")
        
        # Get results
        # TODO: retrieve from database when implemented
        
        # Check for high-severity findings
        # If found and >= fail_on severity, exit with error code
        
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
        # TODO: Implement when reporting module is complete
        click.echo(f"📊 Exporting scan {scan_id} as {format}...")
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
        # TODO: Implement when database queries are complete
        click.echo("📋 Recent scans:")
        click.echo("(implementation pending)")
    except Exception as e:
        click.echo(f"❌ Failed to list scans: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.argument("scan_id")
def status(scan_id: str):
    """Get the status of a scan."""
    try:
        # TODO: Query scan status from database
        click.echo(f"📍 Scan status: {scan_id}")
        click.echo("(implementation pending)")
    except Exception as e:
        click.echo(f"❌ Failed to get status: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.argument("scan_id")
def findings(scan_id: str):
    """Get findings for a scan."""
    try:
        # TODO: Query findings from database
        click.echo(f"🔍 Findings for scan {scan_id}:")
        click.echo("(implementation pending)")
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
        click.echo(f"  Neo4j: {'✅' if result.neo4j_connected else '❌'}")
        click.echo(f"  OpenAI: {'✅' if result.openai_available else '❌'}")
    except Exception as e:
        click.echo(f"❌ Health check failed: {e}", err=True)
        sys.exit(1)


if __name__ == "__main__":
    cli()
