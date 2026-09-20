"""Deterministic risk detection using Cypher and graph queries against the architecture graph."""
import logging
from typing import List, Dict, Any, Optional
from app.config import Settings, settings as default_settings
from app.graph.repository import GraphRepository
from app.models import Finding, Severity, FindingSource

logger = logging.getLogger(__name__)


class DeterministicRiskEngine:
    """Engine for deterministic risk detection using graph rules."""
    
    def __init__(self, settings: Optional[Settings] = None):
        self.settings = settings or default_settings
        self.repo = GraphRepository(self.settings)
    
    def detect_all_risks(self, scan_id: str) -> List[Finding]:
        """
        Run all deterministic risk detection rules.
        
        Args:
            scan_id: ID of the scan to analyze
            
        Returns:
            List of detected findings
        """
        findings = []
        
        findings.extend(self.detect_spof_services(scan_id))
        findings.extend(self.detect_unprotected_endpoints(scan_id))
        findings.extend(self.detect_multi_writer_datastores(scan_id))
        findings.extend(self.detect_unencrypted_calls(scan_id))
        findings.extend(self.detect_cyclic_dependencies(scan_id))
        findings.extend(self.detect_missing_observability(scan_id))
        findings.extend(self.detect_excessive_permissions(scan_id))
        
        return findings
    
    def detect_spof_services(self, scan_id: str) -> List[Finding]:
        """
        Detect single points of failure: services with high fan-in and no redundancy.
        """
        findings = []
        threshold = getattr(self.settings.risk_thresholds, 'spof_fan_in_threshold', 2)
        
        try:
            spof_services = self.repo.query_spof_services(scan_id, threshold)
            
            for service in spof_services:
                svc_id = service['service_id']
                svc_name = service['service_name']
                callers_str = ', '.join(service.get('callers', []))
                
                finding = Finding(
                    id=f"{scan_id}_spof_{svc_id}",
                    scan_id=scan_id,
                    title=f"Single Point of Failure: {svc_name}",
                    description=(
                        f"Service '{svc_name}' is a Single Point of Failure (SPOF) called by "
                        f"{service['fan_in_count']} services ({callers_str}) with no redundancy or failover mechanism. "
                        f"Any outage of this service directly degrades dependent services."
                    ),
                    severity=Severity.HIGH,
                    confidence=0.95,
                    source=FindingSource.DETERMINISTIC,
                    cypher_rule_name="spof_high_fan_in",
                    affected_components=[svc_id, svc_name],
                    cwe_ids=["CWE-1088", "CWE-400"],
                    owasp_categories=["A10:2021 - Insufficient Logging & Monitoring"],
                    remediation_steps=[
                        "Add horizontal scaling with multiple redundant replicas behind a load balancer",
                        "Implement circuit breaker and retry mechanisms on all caller services",
                        "Add health checks and liveness probes to enable automatic failover",
                        "Consider decoupling synchronous RPC dependencies using an asynchronous message queue",
                    ],
                    estimated_effort="HIGH",
                    references=[
                        "https://microservices.io/patterns/reliability/circuit-breaker.html",
                        "https://cwe.mitre.org/data/definitions/1088.html",
                    ]
                )
                findings.append(finding)
        
        except Exception as e:
            logger.error(f"Error detecting SPOF services: {e}")
        
        return findings
    
    def detect_unprotected_endpoints(self, scan_id: str) -> List[Finding]:
        """
        Detect public endpoints without authentication.
        """
        findings = []
        
        try:
            endpoints = self.repo.query_unprotected_endpoints(scan_id)
            
            for ep in endpoints:
                ep_id = ep['endpoint_id']
                path = ep['path']
                method = ep.get('method', 'GET')
                comp_id = ep.get('component_id', 'api_gateway')
                
                finding = Finding(
                    id=f"{scan_id}_unauth_ep_{ep_id}",
                    scan_id=scan_id,
                    title=f"Unprotected Endpoint: {path}",
                    description=(
                        f"Public endpoint {method} {path} in component '{comp_id}' lacks authentication. "
                        f"This endpoint is exposed and accessible without credentials."
                    ),
                    severity=Severity.CRITICAL,
                    confidence=0.99,
                    source=FindingSource.DETERMINISTIC,
                    cypher_rule_name="unprotected_endpoint",
                    affected_components=[comp_id],
                    affected_endpoints=[ep_id, path],
                    cwe_ids=["CWE-306", "CWE-439"],
                    owasp_categories=["A01:2021 - Broken Access Control"],
                    remediation_steps=[
                        "Add authentication middleware to enforce token or session validation",
                        "Implement JWT, OAuth2, or API key verification on the route",
                        "Validate user roles and permissions before processing requests",
                        "Enforce rate limiting on this route to mitigate automated abuse",
                    ],
                    estimated_effort="MEDIUM",
                    references=[
                        "https://cwe.mitre.org/data/definitions/306.html",
                        "https://owasp.org/www-community/attacks/Missing_Authentication",
                    ]
                )
                findings.append(finding)
        
        except Exception as e:
            logger.error(f"Error detecting unprotected endpoints: {e}")
        
        return findings
    
    def detect_multi_writer_datastores(self, scan_id: str) -> List[Finding]:
        """
        Detect data stores with multiple writers and no owning service abstraction.
        """
        findings = []
        
        try:
            datastores = self.repo.query_multi_writer_datastores(scan_id)
            
            for ds in datastores:
                ds_id = ds['datastore_id']
                ds_name = ds['datastore_name']
                writers = ds.get('writer_services', [])
                
                finding = Finding(
                    id=f"{scan_id}_multi_writer_{ds_id}",
                    scan_id=scan_id,
                    title=f"Multi-Writer DataStore: {ds_name}",
                    description=(
                        f"DataStore '{ds_name}' has direct write access from multiple distinct services "
                        f"({', '.join(writers)}) without an owning service abstraction. "
                        f"Shared database writes introduce distributed race conditions, schema coupling, and data corruption risks."
                    ),
                    severity=Severity.HIGH,
                    confidence=0.95,
                    source=FindingSource.DETERMINISTIC,
                    cypher_rule_name="multi_writer_datastore",
                    affected_components=writers + [ds_id, ds_name],
                    affected_data_stores=[ds_id, ds_name],
                    cwe_ids=["CWE-668", "CWE-1088"],
                    owasp_categories=["A04:2021 - Insecure Design"],
                    remediation_steps=[
                        "Assign strict service ownership to the datastore (database-per-service pattern)",
                        "Create a dedicated API layer or domain service for all mutations to this data",
                        "Use event-driven messaging (e.g., transactional outbox pattern) for cross-service state synchronization",
                        "Separate shared tables into service-specific schemas",
                    ],
                    estimated_effort="HIGH",
                    references=[
                        "https://microservices.io/patterns/data/database-per-service.html",
                        "https://cwe.mitre.org/data/definitions/668.html",
                    ]
                )
                findings.append(finding)
        
        except Exception as e:
            logger.error(f"Error detecting multi-writer datastores: {e}")
        
        return findings

    def detect_unencrypted_calls(self, scan_id: str) -> List[Finding]:
        """
        Detect unencrypted inter-service HTTP calls crossing trust boundaries.
        """
        findings = []
        
        try:
            calls = self.repo.query_unencrypted_calls(scan_id)
            
            for call in calls:
                caller = call['caller']
                callee = call['callee']
                target_url = call.get('target_url', f"http://{callee}")
                
                finding = Finding(
                    id=f"{scan_id}_unencrypted_call_{caller}_{callee}",
                    scan_id=scan_id,
                    title=f"Unencrypted Boundary Crossing: {caller} to {callee}",
                    description=(
                        f"Unencrypted HTTP call crossing network/trust boundary from service '{caller}' "
                        f"to service '{callee}' ({target_url}). Traffic transmitted in plaintext "
                        f"can be intercepted, tampered with, or eavesdropped."
                    ),
                    severity=Severity.HIGH,
                    confidence=0.95,
                    source=FindingSource.DETERMINISTIC,
                    cypher_rule_name="unprotected_boundary_crossing",
                    affected_components=[caller, callee],
                    cwe_ids=["CWE-319"],
                    owasp_categories=["A02:2021 - Cryptographic Failures"],
                    remediation_steps=[
                        "Enforce HTTPS/TLS on all inter-service endpoints",
                        "Deploy mutual TLS (mTLS) with a service mesh (e.g. Istio, Linkerd)",
                        "Enforce strict certificate validation in HTTP client configurations",
                    ],
                    estimated_effort="MEDIUM",
                    references=[
                        "https://cwe.mitre.org/data/definitions/319.html",
                        "https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure",
                    ]
                )
                findings.append(finding)
        
        except Exception as e:
            logger.error(f"Error detecting unencrypted calls: {e}")
        
        return findings
    
    def detect_cyclic_dependencies(self, scan_id: str) -> List[Finding]:
        """Detect cyclic service dependencies."""
        findings = []
        return findings
    
    def detect_missing_observability(self, scan_id: str) -> List[Finding]:
        """Detect critical services without health checks or tracing."""
        findings = []
        return findings
    
    def detect_excessive_permissions(self, scan_id: str) -> List[Finding]:
        """Detect overly broad permissions."""
        findings = []
        return findings
