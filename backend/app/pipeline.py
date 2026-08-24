"""Core scanning pipeline orchestration."""
import logging
import uuid
from typing import List, Dict, Any, Optional
from pathlib import Path
from datetime import datetime

from app.config import Settings
from app.models import (
    Component, Finding, ScanMetadata, ScanStatus, RiskReport,
    Severity, FindingSource
)
from app.ingestion.ingester import RepositoryIngester, RepositoryInfo
from app.parser.orchestrator import MultiLanguageParser
from app.semgrep_runner.runner import SemgrepRunner, RulePackManager
from app.graph.repository import GraphRepository
from app.graph.db import get_db_connection
from app.risk_engine.deterministic import DeterministicRiskEngine
from app.risk_engine.llm_engine import LLMRiskEngine
from app.risk_engine.deduplicator import FindingDeduplicator

logger = logging.getLogger(__name__)


class ScanPipeline:
    """Orchestrates the complete scanning pipeline."""
    
    def __init__(self, settings: Settings):
        self.settings = settings
        self.ingester = RepositoryIngester()
        self.parser = MultiLanguageParser()
        self.semgrep_runner = SemgrepRunner(settings)
        self.graph_repo = GraphRepository(settings)
        self.deterministic_engine = DeterministicRiskEngine(settings)
        self.llm_engine = LLMRiskEngine(settings)
    
    def scan(self, repo_source: Dict[str, Any]) -> str:
        """
        Execute a complete scan.
        
        Args:
            repo_source: Repository source specification
            
        Returns:
            Scan ID
        """
        scan_id = str(uuid.uuid4())
        
        try:
            logger.info(f"Starting scan: {scan_id}")
            
            # Step 1: Ingest repository
            logger.info("Step 1: Ingesting repository")
            repo_info = self._ingest_repository(repo_source)
            
            # Step 2: Create scan node in graph
            self.graph_repo.create_scan_node(
                scan_id,
                repo_source.get("url", repo_source.get("path", "unknown"))
            )
            
            # Step 3: Parse codebase
            logger.info("Step 2: Parsing codebase")
            parsed_files = self.parser.parse_directory(repo_info.path)
            
            # Step 4: Extract components and build initial graph
            logger.info("Step 3: Building architecture graph")
            components = self._extract_components(parsed_files, repo_info)
            self._build_initial_graph(scan_id, components)
            
            # Step 5: Run Semgrep
            logger.info("Step 4: Running Semgrep analysis")
            semgrep_findings = self._run_semgrep(repo_info.path)
            
            # Step 6: Detect deterministic risks
            logger.info("Step 5: Detecting deterministic risks")
            deterministic_findings = self.deterministic_engine.detect_all_risks(scan_id)
            
            # Step 7: Deduplicate findings
            logger.info("Step 6: Deduplicating findings")
            all_findings = deterministic_findings  # + converted semgrep findings
            deduplicated = FindingDeduplicator.deduplicate(all_findings)
            
            # Step 8: Enrich with LLM if enabled
            if self.settings.openai.enable_ai_layer:
                logger.info("Step 7: Enriching findings with LLM")
                # TODO: Get subgraph context and call LLM
                pass
            
            # Step 9: Store findings
            logger.info("Step 8: Storing findings")
            for finding in deduplicated:
                self.graph_repo.create_finding(scan_id, finding)
            
            # Cleanup
            self.ingester.cleanup(repo_info)
            
            logger.info(f"Scan completed: {scan_id}")
            return scan_id
        
        except Exception as e:
            logger.error(f"Scan failed: {e}")
            raise
    
    def _ingest_repository(self, repo_source: Dict[str, Any]) -> RepositoryInfo:
        """Ingest repository from specified source."""
        source_type = repo_source.get("type", "local")
        
        if source_type == "local":
            path = repo_source.get("path")
            if not path:
                raise ValueError("Local source requires 'path'")
            return self.ingester.ingest_local(path)
        
        elif source_type == "git":
            url = repo_source.get("url")
            if not url:
                raise ValueError("Git source requires 'url'")
            branch = repo_source.get("branch", "main")
            token = repo_source.get("token")
            return self.ingester.ingest_git(url, branch, token)
        
        elif source_type == "upload":
            archive = repo_source.get("path")
            if not archive:
                raise ValueError("Upload source requires 'path'")
            return self.ingester.ingest_archive(archive)
        
        else:
            raise ValueError(f"Unknown source type: {source_type}")
    
    def _extract_components(
        self,
        parsed_files: Dict[str, Dict[str, Any]],
        repo_info: RepositoryInfo
    ) -> List[Component]:
        """Extract service components from parsed files."""
        components = []
        
        # Heuristics for service detection
        # Look for main entry points, package.json, pyproject.toml, etc.
        
        # For now, create a single service from the repo
        service_id = "main-service"
        component = Component(
            id=service_id,
            name=Path(repo_info.path).name or "service",
            language=repo_info.languages[0] if repo_info.languages else "unknown",
            repo_path=repo_info.path,
            owner_team=None,
            entry_points=[],
        )
        
        components.append(component)
        return components
    
    def _build_initial_graph(self, scan_id: str, components: List[Component]):
        """Build initial graph from extracted components."""
        for component in components:
            self.graph_repo.upsert_service(scan_id, component)
    
    def _run_semgrep(self, target_path: str) -> List[Dict[str, Any]]:
        """Run Semgrep and return findings."""
        result = self.semgrep_runner.run(target_path)
        return result.get("findings", [])
    
    def get_scan_status(self, scan_id: str) -> ScanMetadata:
        """Get the status of a scan."""
        # TODO: Query from database
        raise NotImplementedError()
    
    def get_scan_report(self, scan_id: str) -> RiskReport:
        """Get the complete risk report for a scan."""
        # TODO: Assemble report from database
        raise NotImplementedError()
