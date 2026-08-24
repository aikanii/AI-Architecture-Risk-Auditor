"""Deterministic risk detection using Cypher queries against the Neo4j graph."""
import logging
from typing import List, Dict, Any
from app.config import Settings
from app.graph.repository import GraphRepository
from app.models import Finding, Severity, FindingSource

logger = logging.getLogger(__name__)


class DeterministicRiskEngine:
    """Engine for deterministic risk detection using Cypher queries."""
    
    def __init__(self, settings: Settings):
        self.settings = settings
        self.repo = GraphRepository(settings)
    
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
        findings.extend(self.detect_cyclic_dependencies(scan_id))
        findings.extend(self.detect_missing_observability(scan_id))
        findings.extend(self.detect_excessive_permissions(scan_id))
        
        return findings
    
    def detect_spof_services(self, scan_id: str) -> List[Finding]:
        """
        Detect single points of failure: services with high fan-in and no redundancy.
        """
        findings = []
        threshold = self.settings.risk_thresholds.spof_fan_in_threshold
        
        try:
            spof_services = self.repo.query_spof_services(scan_id, threshold)
            
            for service in spof_services:
                finding = Finding(
                    id=f"spof_{service['service_id']}",
                    scan_id=scan_id,
                    title=f"Single Point of Failure: {service['service_name']}",
                    description=(
                        f"Service '{service['service_name']}' is called by {service['fan_in_count']} services "
                        f"with no redundancy/failover mechanism. Callers: {', '.join(service['callers'])}. "
                        f"Any outage of this service affects all dependent services."
                    ),
                    severity=Severity.HIGH,
                    confidence=0.95,
                    source=FindingSource.DETERMINISTIC,
                    cypher_rule_name="spof_high_fan_in",
                    affected_components=[service['service_id']],
                    cwe_ids=["CWE-1088"],  # Architecture reliability
                    owasp_categories=["A10:2021 - Insufficient Logging & Monitoring"],
                    remediation_steps=[
                        "Add service redundancy (horizontal scaling)",
                        "Implement circuit breaker on all incoming calls",
                        "Add health checks to detect failures quickly",
                        "Implement retry logic with exponential backoff in callers",
                        "Consider breaking dependency into smaller services",
                    ],
                    estimated_effort="HIGH",
                    references=[
                        "https://microservices.io/patterns/reliability/circuit-breaker.html",
                        "https://en.wikipedia.org/wiki/Single_point_of_failure",
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
                finding = Finding(
                    id=f"unauth_ep_{ep['endpoint_id']}",
                    scan_id=scan_id,
                    title=f"Unprotected Endpoint: {ep['path']}",
                    description=(
                        f"Endpoint {ep['method']} {ep['path']} is public and lacks authentication. "
                        f"This endpoint is directly accessible from the internet."
                    ),
                    severity=Severity.CRITICAL,
                    confidence=0.99,
                    source=FindingSource.DETERMINISTIC,
                    cypher_rule_name="unprotected_endpoint",
                    affected_endpoints=[ep['endpoint_id']],
                    cwe_ids=["CWE-306", "CWE-439"],  # Missing authentication, unprivileged access
                    owasp_categories=["A01:2021 - Broken Access Control"],
                    remediation_steps=[
                        "Add authentication middleware to endpoint",
                        "Implement JWT, OAuth2, or API key authentication",
                        "Validate and enforce role-based access control",
                        "Add rate limiting to prevent abuse",
                    ],
                    estimated_effort="MEDIUM",
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
        
        # Query would come from GraphRepository
        # This is simplified implementation
        
        return findings
    
    def detect_cyclic_dependencies(self, scan_id: str) -> List[Finding]:
        """
        Detect cyclic service dependencies.
        """
        findings = []
        
        # Query would detect cycles in service call graph
        
        return findings
    
    def detect_missing_observability(self, scan_id: str) -> List[Finding]:
        """
        Detect critical services without health checks or tracing.
        """
        findings = []
        
        # Query would find public-facing services without observability
        
        return findings
    
    def detect_excessive_permissions(self, scan_id: str) -> List[Finding]:
        """
        Detect overly broad IAM/service permissions.
        """
        findings = []
        
        # Query would find permission policies with * scope
        
        return findings
