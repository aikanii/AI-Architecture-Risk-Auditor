"""Neo4j repository layer for graph operations."""
from typing import List, Dict, Any, Optional
from neo4j import Session
from app.models import Service, Endpoint, DataStore, Finding, Component
from app.graph.db import get_db_connection
from app.config import Settings
import logging

logger = logging.getLogger(__name__)


class GraphRepository:
    """Repository for all Neo4j operations."""
    
    def __init__(self, settings: Settings):
        self.settings = settings
        self.driver = get_db_connection(settings)
    
    def create_scan_node(self, scan_id: str, repository_url: str, **kwargs) -> Dict[str, Any]:
        """Create a Scan node."""
        with self.driver.session() as session:
            result = session.run(
                """
                MERGE (s:Scan {id: $scan_id})
                SET s.repository_url = $repo_url,
                    s.created_at = datetime(),
                    s.status = 'PENDING'
                RETURN s
                """,
                scan_id=scan_id,
                repo_url=repository_url,
            )
            record = result.single()
            return dict(record['s'].items()) if record else {}
    
    def upsert_service(self, scan_id: str, service: Component) -> Dict[str, Any]:
        """
        Upsert a Service node (idempotent).
        Uses MERGE to avoid duplicates.
        """
        with self.driver.session() as session:
            result = session.run(
                """
                MERGE (s:Service {id: $id})
                SET s.scan_id = $scan_id,
                    s.name = $name,
                    s.language = $language,
                    s.repo_path = $repo_path,
                    s.owner_team = $owner_team,
                    s.has_health_check = $has_health_check,
                    s.has_tracing = $has_tracing,
                    s.has_redundancy = $has_redundancy
                RETURN s
                """,
                id=service.id,
                scan_id=scan_id,
                name=service.name,
                language=service.language,
                repo_path=service.repo_path,
                owner_team=service.owner_team,
                has_health_check=service.has_health_check,
                has_tracing=service.has_tracing,
                has_redundancy=service.has_redundancy,
            )
            record = result.single()
            return dict(record['s'].items()) if record else {}
    
    def upsert_endpoint(self, scan_id: str, endpoint: Endpoint) -> Dict[str, Any]:
        """Upsert an Endpoint node."""
        with self.driver.session() as session:
            result = session.run(
                """
                MERGE (e:Endpoint {id: $id})
                SET e.scan_id = $scan_id,
                    e.path = $path,
                    e.method = $method,
                    e.component_id = $component_id,
                    e.has_auth = $has_auth,
                    e.is_public = $is_public,
                    e.auth_type = $auth_type,
                    e.rate_limit_enabled = $rate_limit_enabled,
                    e.rate_limit_rps = $rate_limit_rps,
                    e.file_location = $file_location,
                    e.line_number = $line_number
                RETURN e
                """,
                id=endpoint.id,
                scan_id=scan_id,
                path=endpoint.path,
                method=endpoint.method,
                component_id=endpoint.component_id,
                has_auth=endpoint.has_auth,
                is_public=endpoint.is_public,
                auth_type=endpoint.auth_type,
                rate_limit_enabled=endpoint.rate_limit_enabled,
                rate_limit_rps=endpoint.rate_limit_rps,
                file_location=endpoint.file_location,
                line_number=endpoint.line_number,
            )
            record = result.single()
            return dict(record['e'].items()) if record else {}
    
    def create_relationship(
        self,
        source_id: str,
        target_id: str,
        relationship_type: str,
        properties: Optional[Dict[str, Any]] = None
    ) -> bool:
        """
        Create a relationship between two nodes.
        
        Args:
            source_id: ID of source node
            target_id: ID of target node
            relationship_type: Type of relationship (e.g., CALLS, EXPOSES)
            properties: Additional relationship properties
            
        Returns:
            True if successful
        """
        props = properties or {}
        with self.driver.session() as session:
            # Find nodes by ID across any label
            result = session.run(
                """
                MATCH (s), (t)
                WHERE s.id = $source_id AND t.id = $target_id
                MERGE (s)-[r:""" + relationship_type + """]->(t)
                SET r += $properties
                RETURN r
                """,
                source_id=source_id,
                target_id=target_id,
                properties=props,
            )
            return result.single() is not None
    
    def create_finding(self, scan_id: str, finding: Finding) -> Dict[str, Any]:
        """Create a Finding node."""
        with self.driver.session() as session:
            result = session.run(
                """
                CREATE (f:Finding {
                    id: $id,
                    scan_id: $scan_id,
                    title: $title,
                    description: $description,
                    severity: $severity,
                    confidence: $confidence,
                    source: $source,
                    created_at: datetime()
                })
                RETURN f
                """,
                id=finding.id,
                scan_id=scan_id,
                title=finding.title,
                description=finding.description,
                severity=finding.severity.value,
                confidence=finding.confidence,
                source=finding.source.value,
            )
            record = result.single()
            return dict(record['f'].items()) if record else {}
    
    def link_finding_to_components(
        self,
        finding_id: str,
        component_ids: List[str]
    ) -> bool:
        """Link a Finding to affected components."""
        with self.driver.session() as session:
            for comp_id in component_ids:
                session.run(
                    """
                    MATCH (f:Finding {id: $finding_id})
                    MATCH (c {id: $component_id})
                    MERGE (c)-[:HAS_FINDING]->(f)
                    """,
                    finding_id=finding_id,
                    component_id=comp_id,
                )
        return True
    
    def query_spof_services(self, scan_id: str, threshold: int) -> List[Dict[str, Any]]:
        """Query services that are single points of failure."""
        with self.driver.session() as session:
            result = session.run(
                """
                MATCH (caller:Service)-[:CALLS {sync: true}]->(target:Service)
                WHERE target.scan_id = $scan_id AND NOT target.has_redundancy
                WITH target, COUNT(DISTINCT caller) as in_degree
                WHERE in_degree >= $threshold
                RETURN 
                    target.id as service_id,
                    target.name as service_name,
                    in_degree as fan_in_count,
                    COLLECT(DISTINCT caller.name) as callers
                """,
                scan_id=scan_id,
                threshold=threshold,
            )
            return [dict(record) for record in result]
    
    def query_unprotected_endpoints(self, scan_id: str) -> List[Dict[str, Any]]:
        """Query endpoints without proper authentication/encryption."""
        with self.driver.session() as session:
            result = session.run(
                """
                MATCH (e:Endpoint)
                WHERE e.scan_id = $scan_id 
                  AND e.is_public 
                  AND NOT e.has_auth
                RETURN 
                    e.id as endpoint_id,
                    e.path as path,
                    e.method as method,
                    "UNPROTECTED_ENDPOINT" as risk
                """,
                scan_id=scan_id,
            )
            return [dict(record) for record in result]
    
    def get_findings_for_scan(self, scan_id: str, limit: int = 100) -> List[Dict[str, Any]]:
        """Get all findings for a scan."""
        with self.driver.session() as session:
            result = session.run(
                """
                MATCH (f:Finding)
                WHERE f.scan_id = $scan_id
                RETURN f
                ORDER BY f.severity DESC
                LIMIT $limit
                """,
                scan_id=scan_id,
                limit=limit,
            )
            return [dict(record['f'].items()) for record in result]
    
    def get_graph_summary(self, scan_id: str) -> Dict[str, Any]:
        """Get summary statistics for a scan's graph."""
        with self.driver.session() as session:
            result = session.run(
                """
                MATCH (n)
                WHERE n.scan_id = $scan_id
                RETURN 
                    labels(n)[0] as node_type,
                    COUNT(n) as count
                """,
                scan_id=scan_id,
            )
            summary = {record['node_type']: record['count'] for record in result}
            return summary


# Module-level helper to get repository
def get_graph_repo(settings: Settings) -> GraphRepository:
    """Factory to get GraphRepository instance."""
    return GraphRepository(settings)
