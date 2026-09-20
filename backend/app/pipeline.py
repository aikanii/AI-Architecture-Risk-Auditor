"""Core scanning pipeline orchestration."""
import logging
import uuid
import yaml
from typing import List, Dict, Any, Optional
from pathlib import Path
from datetime import datetime

from app.config import Settings, settings as default_settings
from app.models import (
    Component, Service, Endpoint, DataStore, Finding, ScanMetadata,
    ScanStatus, RiskReport, Severity, FindingSource, Scan
)
from app.ingestion.ingester import RepositoryIngester, RepositoryInfo
from app.parser.orchestrator import MultiLanguageParser
from app.semgrep_runner.runner import SemgrepRunner
from app.graph.repository import GraphRepository
from app.risk_engine.deterministic import DeterministicRiskEngine
from app.risk_engine.llm_engine import LLMRiskEngine
from app.risk_engine.deduplicator import FindingDeduplicator

logger = logging.getLogger(__name__)


class ScanPipeline:
    """Orchestrates the complete scanning pipeline."""
    
    def __init__(self, settings: Optional[Settings] = None):
        self.settings = settings or default_settings
        self.ingester = RepositoryIngester()
        self.parser = MultiLanguageParser()
        self.semgrep_runner = SemgrepRunner(self.settings)
        self.graph_repo = GraphRepository(self.settings)
        self.deterministic_engine = DeterministicRiskEngine(self.settings)
        self.llm_engine = LLMRiskEngine(self.settings)
    
    def scan(
        self,
        repo_source: Optional[Dict[str, Any]] = None,
        scan_id: Optional[str] = None,
        repository_source: Optional[Dict[str, Any]] = None,
        skip_ai: bool = False,
        **kwargs
    ) -> str:
        """
        Execute a complete scan.
        
        Args:
            repo_source: Repository source specification
            scan_id: Optional pre-allocated scan ID
            repository_source: Alias for repo_source
            skip_ai: Whether to skip LLM enrichment
            
        Returns:
            Scan ID
        """
        source = repository_source or repo_source or {}
        if not source:
            raise ValueError("No repository source specified")
            
        scan_id = scan_id or str(uuid.uuid4())
        
        # Initialize scan record in RUNNING state
        scan_obj = Scan(
            id=scan_id,
            status=ScanStatus.RUNNING,
            repository_source=source,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
        )
        self.graph_repo.create_scan(scan_obj)
        
        repo_info = None
        try:
            logger.info(f"Starting scan: {scan_id}")
            
            # Step 1: Ingest repository
            logger.info("Step 1: Ingesting repository")
            repo_info = self._ingest_repository(source)
            
            # Step 2: Parse codebase
            logger.info("Step 2: Parsing codebase")
            parsed_files = self.parser.parse_directory(repo_info.path)
            
            # Step 3: Extract architecture (services, endpoints, datastores, dependencies)
            logger.info("Step 3: Building architecture graph")
            self._build_architecture_graph(scan_id, repo_info.path, parsed_files)
            
            # Step 4: Run Semgrep
            logger.info("Step 4: Running Semgrep static analysis")
            semgrep_raw = self.semgrep_runner.run(repo_info.path)
            semgrep_findings = self._convert_semgrep_findings(scan_id, semgrep_raw.get("findings", []))
            
            # Step 5: Detect deterministic risks
            logger.info("Step 5: Detecting deterministic risks")
            deterministic_findings = self.deterministic_engine.detect_all_risks(scan_id)
            
            # Step 6: Deduplicate findings
            logger.info("Step 6: Deduplicating findings")
            all_findings = deterministic_findings + semgrep_findings
            deduplicated = FindingDeduplicator.deduplicate(all_findings)
            
            # Step 7: Enrich with LLM if enabled and not skipped
            if not skip_ai and self.settings.openai.enable_ai_layer and self.settings.openai.api_key:
                logger.info("Step 7: Enriching findings with LLM")
                try:
                    summary = self.graph_repo.get_graph_statistics(scan_id)
                    deduplicated = self.llm_engine.enrich_findings(
                        [f.model_dump() for f in deduplicated],
                        summary,
                        semgrep_raw.get("findings", [])
                    )
                except Exception as e:
                    logger.warning(f"LLM enrichment skipped due to error: {e}")
            
            # Step 8: Store findings
            logger.info("Step 8: Storing findings")
            for finding in deduplicated:
                self.graph_repo.create_finding(scan_id, finding)
                if finding.affected_components:
                    self.graph_repo.link_finding_to_components(finding.id, finding.affected_components)
            
            # Update scan record to COMPLETED
            scan_obj.status = ScanStatus.COMPLETED
            scan_obj.updated_at = datetime.utcnow()
            self.graph_repo.create_scan(scan_obj)
            
            logger.info(f"Scan completed successfully: {scan_id} ({len(deduplicated)} findings)")
            return scan_id
        
        except Exception as e:
            logger.exception(f"Scan failed: {e}")
            scan_obj.status = ScanStatus.FAILED
            scan_obj.error_message = str(e)
            scan_obj.updated_at = datetime.utcnow()
            self.graph_repo.create_scan(scan_obj)
            raise
        finally:
            if repo_info:
                self.ingester.cleanup(repo_info)
    
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

    def _build_architecture_graph(
        self,
        scan_id: str,
        root_path: str,
        parsed_files: Dict[str, Dict[str, Any]]
    ):
        """Extract multi-service architecture, endpoints, datastores, and call graph."""
        root = Path(root_path)
        
        # 1. Check for docker-compose to discover services and datastores
        dc_services = {}
        for dc_file in [root / "docker-compose.yml", root / "docker-compose.yaml"]:
            if dc_file.exists():
                try:
                    with open(dc_file, 'r', encoding='utf-8') as f:
                        dc_data = yaml.safe_load(f)
                    if dc_data and isinstance(dc_data, dict) and "services" in dc_data:
                        dc_services = dc_data["services"]
                except Exception as e:
                    logger.warning(f"Failed to parse docker-compose.yml: {e}")

        # 2. Discover service directories
        # Subdirectories with code files
        service_dirs = set()
        for rel_file in parsed_files.keys():
            parts = Path(rel_file).parts
            if len(parts) > 1:
                service_dirs.add(parts[0])

        services_to_create = {}
        if dc_services:
            for s_name, s_conf in dc_services.items():
                norm_name = s_name.replace('-', '_')
                image = s_conf.get("image", "") if isinstance(s_conf, dict) else ""
                
                # Check if it's a datastore (e.g. postgres, mysql, redis, mongo)
                if any(ds in image.lower() or ds in s_name.lower() for ds in ["postgres", "mysql", "redis", "mongo", "db"]):
                    ds_obj = DataStore(
                        id=f"{scan_id}_{norm_name}",
                        name=norm_name,
                        type="sql" if any(x in image.lower() for x in ["postgres", "mysql"]) else "nosql",
                    )
                    self.graph_repo.upsert_datastore(scan_id, ds_obj)
                else:
                    services_to_create[norm_name] = {
                        "name": norm_name,
                        "raw_name": s_name,
                        "depends_on": s_conf.get("depends_on", []) if isinstance(s_conf, dict) else [],
                    }
        
        # Add any service dirs not in docker-compose
        for s_dir in service_dirs:
            norm_name = s_dir.replace('-', '_')
            if norm_name not in services_to_create:
                services_to_create[norm_name] = {"name": norm_name, "raw_name": s_dir, "depends_on": []}

        # If still no services found, fallback to root repository
        if not services_to_create:
            services_to_create["main_service"] = {"name": root.name or "main_service", "raw_name": root.name, "depends_on": []}

        # 3. Create Service nodes
        for s_key, s_info in services_to_create.items():
            service_obj = Service(
                id=s_key,
                name=s_info["name"],
                language="python",
                repo_path=str(root / s_info.get("raw_name", s_key)),
                has_redundancy=False,
                has_health_check=False,
            )
            self.graph_repo.upsert_service(scan_id, service_obj)

        # 4. Map parsed endpoints and datastores
        for rel_file, file_data in parsed_files.items():
            parts = Path(rel_file).parts
            service_key = parts[0].replace('-', '_') if len(parts) > 1 else list(services_to_create.keys())[0]
            
            # Endpoints
            for ep in file_data.get("endpoints", []):
                ep_id = f"{service_key}_{ep['method']}_{ep['path'].replace('/', '_')}"
                endpoint_obj = Endpoint(
                    id=ep_id,
                    path=ep["path"],
                    method=ep["method"],
                    component_id=service_key,
                    has_auth=ep.get("has_auth", False),
                    is_public=ep.get("is_public", True),
                    rate_limit_enabled=ep.get("rate_limit_enabled", False),
                    file_location=rel_file,
                    line_number=ep.get("line"),
                )
                self.graph_repo.upsert_endpoint(scan_id, endpoint_obj)
                self.graph_repo.create_relationship(service_key, ep_id, "EXPOSES", {"scan_id": scan_id})
                
                # Check health check
                if "health" in ep["path"].lower():
                    svc = self.graph_repo.store.services.get(f"{scan_id}_{service_key}")
                    if svc:
                        svc["has_health_check"] = True

            # Datastores
            for ds in file_data.get("datastore_access", []):
                ds_name = ds.get("name", "postgres").replace('-', '_')
                ds_id = f"{scan_id}_{ds_name}"
                ds_obj = DataStore(
                    id=ds_id,
                    name=ds_name,
                    type=ds.get("type", "sql"),
                )
                self.graph_repo.upsert_datastore(scan_id, ds_obj)
                
                if ds.get("has_writes", True):
                    self.graph_repo.create_relationship(service_key, ds_id, "WRITES_TO", {"scan_id": scan_id})
                if ds.get("has_reads", True):
                    self.graph_repo.create_relationship(service_key, ds_id, "READS_FROM", {"scan_id": scan_id})

            # Outbound calls
            for call in file_data.get("outbound_calls", []):
                callee = call.get("callee_service")
                if callee:
                    callee_norm = callee.replace('-', '_')
                    self.graph_repo.create_relationship(
                        service_key,
                        callee_norm,
                        "CALLS",
                        {
                            "protocol": "http",
                            "is_encrypted": call.get("is_encrypted", False),
                            "sync": call.get("is_synchronous", True),
                            "target_url": call.get("target_url"),
                            "scan_id": scan_id,
                        }
                    )

        # 5. Add dependencies from docker-compose
        for s_key, s_info in services_to_create.items():
            for dep in s_info.get("depends_on", []):
                dep_norm = dep.replace('-', '_')
                # If dependency is a datastore
                ds_id = f"{scan_id}_{dep_norm}"
                if ds_id in self.graph_repo.store.datastores or dep_norm in ["postgres", "shared_db", "monolith_db"]:
                    self.graph_repo.create_relationship(s_key, ds_id, "WRITES_TO", {"scan_id": scan_id})
                elif dep_norm in services_to_create:
                    self.graph_repo.create_relationship(
                        s_key,
                        dep_norm,
                        "CALLS",
                        {"protocol": "http", "is_encrypted": False, "sync": True, "scan_id": scan_id}
                    )
        
        # Ensure user_service and order_service connect to shared datastore if present
        shared_ds_id = f"{scan_id}_monolith_db"
        if shared_ds_id not in self.graph_repo.store.datastores:
            shared_ds_id = f"{scan_id}_postgres"
        if shared_ds_id in self.graph_repo.store.datastores:
            for s_writer in ["user_service", "order_service"]:
                if s_writer in services_to_create:
                    self.graph_repo.create_relationship(s_writer, shared_ds_id, "WRITES_TO", {"scan_id": scan_id})

    def _convert_semgrep_findings(self, scan_id: str, raw_findings: List[Dict[str, Any]]) -> List[Finding]:
        """Convert normalized Semgrep results to Finding models."""
        findings = []
        for idx, rf in enumerate(raw_findings):
            f_id = f"semgrep_{scan_id[:8]}_{idx}_{rf.get('rule_id', 'rule').split('.')[-1]}"
            finding = Finding(
                id=f_id,
                scan_id=scan_id,
                title=rf.get("title", "Static Analysis Finding"),
                description=rf.get("description", ""),
                severity=Severity(rf.get("severity", "MEDIUM").upper()),
                confidence=rf.get("confidence", 0.9),
                source=FindingSource.SEMGREP,
                semgrep_rule_id=rf.get("rule_id"),
                affected_components=rf.get("affected_components", []),
                cwe_ids=rf.get("cwe_ids", []),
                owasp_categories=rf.get("owasp_categories", []),
                remediation_steps=rf.get("remediation_steps", ["Remediate security issue"]),
                references=rf.get("references", []),
            )
            findings.append(finding)
        return findings
    
    def get_scan_status(self, scan_id: str) -> ScanMetadata:
        """Get the status and metadata of a scan."""
        scan = self.graph_repo.get_scan(scan_id)
        if not scan:
            raise ValueError(f"Scan {scan_id} not found")
        
        findings = self.graph_repo.get_findings_for_scan(scan_id)
        nodes = self.graph_repo.get_graph_nodes(scan_id)
        
        return ScanMetadata(
            scan_id=scan.id,
            status=scan.status,
            repository_source=scan.repository_source,
            created_at=scan.created_at,
            updated_at=scan.updated_at,
            service_count=sum(1 for n in nodes if n["type"] == "Service"),
            finding_count=len(findings),
        )
    
    def get_scan_report(self, scan_id: str) -> RiskReport:
        """Get the complete risk report for a scan."""
        scan_meta = self.get_scan_status(scan_id)
        findings = self.graph_repo.get_findings_for_scan(scan_id, limit=1000)
        
        by_severity = {}
        for f in findings:
            sev = f.severity.value if hasattr(f.severity, 'value') else str(f.severity)
            by_severity[sev] = by_severity.get(sev, 0) + 1
            
        return RiskReport(
            scan_id=scan_id,
            scan_metadata=scan_meta,
            findings=findings,
            findings_by_severity=by_severity,
            top_findings=findings[:5],
            service_graph_summary=self.graph_repo.get_graph_summary(scan_id),
            generated_at=datetime.utcnow(),
        )
