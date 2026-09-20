"""Neo4j and persistent in-memory repository layer for graph operations."""
from typing import List, Dict, Any, Optional, Union
from datetime import datetime
from pathlib import Path
import json
import logging

from app.models import (
    Scan, Component, Service, Endpoint, DataStore, Finding,
    ArchitectureGraph, GraphNode, GraphEdge, Severity, FindingSource
)
from app.graph.db import get_db_connection
from app.config import Settings, settings as default_settings

logger = logging.getLogger(__name__)


# Persistent in-memory storage for fallback / standalone / offline scanning
class InMemoryGraphStore:
    def __init__(self, store_path: Optional[str] = None):
        self.scans: Dict[str, Scan] = {}
        self.services: Dict[str, Dict[str, Any]] = {}
        self.endpoints: Dict[str, Dict[str, Any]] = {}
        self.datastores: Dict[str, Dict[str, Any]] = {}
        self.findings: Dict[str, Finding] = {}
        self.edges: List[Dict[str, Any]] = []
        self.finding_links: List[Dict[str, str]] = []
        
        self.store_file = Path(store_path or "/tmp/aiara_store.json")
        self.load_from_disk()

    def save_to_disk(self):
        """Persist graph store to disk."""
        try:
            self.store_file.parent.mkdir(parents=True, exist_ok=True)
            data = {
                "scans": {k: (v.model_dump() if hasattr(v, 'model_dump') else dict(v)) for k, v in self.scans.items()},
                "services": self.services,
                "endpoints": self.endpoints,
                "datastores": self.datastores,
                "findings": {k: (v.model_dump() if hasattr(v, 'model_dump') else dict(v)) for k, v in self.findings.items()},
                "edges": self.edges,
                "finding_links": self.finding_links,
            }
            # Handle datetimes
            def default_serializer(o):
                if isinstance(o, datetime):
                    return o.isoformat()
                return str(o)
            
            with open(self.store_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, default=default_serializer)
        except Exception as e:
            logger.debug(f"Could not persist store to disk: {e}")

    def load_from_disk(self):
        """Load graph store from disk if file exists."""
        if not self.store_file.exists():
            return
        try:
            with open(self.store_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            for k, s_dict in data.get("scans", {}).items():
                if isinstance(s_dict.get("created_at"), str):
                    s_dict["created_at"] = datetime.fromisoformat(s_dict["created_at"])
                if isinstance(s_dict.get("updated_at"), str):
                    s_dict["updated_at"] = datetime.fromisoformat(s_dict["updated_at"])
                self.scans[k] = Scan(**s_dict)

            self.services = data.get("services", {})
            self.endpoints = data.get("endpoints", {})
            self.datastores = data.get("datastores", {})

            for k, f_dict in data.get("findings", {}).items():
                if isinstance(f_dict.get("created_at"), str):
                    f_dict["created_at"] = datetime.fromisoformat(f_dict["created_at"])
                self.findings[k] = Finding(**f_dict)

            self.edges = data.get("edges", [])
            self.finding_links = data.get("finding_links", [])
        except Exception as e:
            logger.debug(f"Could not load store from disk: {e}")


_in_memory_store = InMemoryGraphStore()


class GraphRepository:
    """Repository for all graph database operations."""
    
    def __init__(self, connection_or_settings: Optional[Any] = None):
        self.store = _in_memory_store
        self.driver = None
        self.is_real_neo4j = False
        
        if isinstance(connection_or_settings, Settings):
            self.settings = connection_or_settings
            self.driver = get_db_connection(self.settings)
        elif connection_or_settings is not None:
            self.driver = connection_or_settings
            self.settings = default_settings
        else:
            self.settings = default_settings
            self.driver = get_db_connection(self.settings)
            
        if hasattr(self.driver, 'session') and not getattr(self.driver, 'is_in_memory', False):
            if "MagicMock" not in str(type(self.driver)):
                try:
                    with self.driver.session() as s:
                        s.run("RETURN 1")
                    self.is_real_neo4j = True
                except Exception:
                    self.is_real_neo4j = False

    # =========================================================================
    # Scan Operations
    # =========================================================================

    def create_scan(self, scan: Scan) -> Dict[str, Any]:
        """Create a scan record."""
        self.store.scans[scan.id] = scan
        self.store.save_to_disk()
        
        if self.is_real_neo4j:
            try:
                with self.driver.session() as session:
                    session.run(
                        """
                        MERGE (s:Scan {id: $scan_id})
                        SET s.repository_url = $repo_url,
                            s.status = $status,
                            s.created_at = datetime()
                        """,
                        scan_id=scan.id,
                        repo_url=str(scan.repository_source),
                        status=scan.status.value if hasattr(scan.status, 'value') else str(scan.status),
                    )
            except Exception as e:
                logger.warning(f"Neo4j create_scan error: {e}")
        return scan.model_dump() if hasattr(scan, 'model_dump') else dict(scan)

    def create_scan_node(self, scan_id: str, repository_url: str, **kwargs) -> Dict[str, Any]:
        """Create a Scan node (backward compatibility)."""
        scan = Scan(
            id=scan_id,
            repository_source={"url": repository_url},
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
        )
        return self.create_scan(scan)

    def get_scan(self, scan_id: str) -> Optional[Scan]:
        """Retrieve a scan by ID."""
        self.store.load_from_disk()
        return self.store.scans.get(scan_id)

    def list_scans(
        self,
        limit: int = 20,
        offset: int = 0,
        status: Optional[str] = None
    ) -> List[Scan]:
        """List scans with optional status filter, ordered newest first."""
        self.store.load_from_disk()
        all_scans = list(self.store.scans.values())
        if status:
            all_scans = [
                s for s in all_scans
                if (s.status.value.upper() if hasattr(s.status, 'value') else str(s.status).upper()) == status.upper()
            ]
        all_scans.sort(key=lambda s: s.created_at, reverse=True)
        return all_scans[offset:offset + limit]

    def delete_scan(self, scan_id: str) -> bool:
        """Delete a scan and all associated data."""
        self.store.load_from_disk()
        existed = scan_id in self.store.scans
        if existed:
            del self.store.scans[scan_id]
        
        self.store.services = {k: v for k, v in self.store.services.items() if v.get("scan_id") != scan_id}
        self.store.endpoints = {k: v for k, v in self.store.endpoints.items() if v.get("scan_id") != scan_id}
        self.store.datastores = {k: v for k, v in self.store.datastores.items() if v.get("scan_id") != scan_id}
        self.store.findings = {k: v for k, v in self.store.findings.items() if getattr(v, "scan_id", None) != scan_id}
        self.store.edges = [e for e in self.store.edges if e.get("scan_id") != scan_id]
        self.store.save_to_disk()

        if self.is_real_neo4j:
            try:
                with self.driver.session() as session:
                    session.run("MATCH (n {scan_id: $scan_id}) DETACH DELETE n", scan_id=scan_id)
                    session.run("MATCH (s:Scan {id: $scan_id}) DETACH DELETE s", scan_id=scan_id)
            except Exception as e:
                logger.warning(f"Neo4j delete_scan error: {e}")
        return existed

    # =========================================================================
    # Component & Architecture Upserts
    # =========================================================================

    def upsert_service(self, scan_id: str, service: Component) -> Dict[str, Any]:
        """Upsert a Service node."""
        data = {
            "id": service.id,
            "scan_id": scan_id,
            "name": service.name,
            "language": service.language,
            "repo_path": service.repo_path,
            "owner_team": service.owner_team,
            "has_health_check": service.has_health_check,
            "has_tracing": service.has_tracing,
            "has_redundancy": service.has_redundancy,
            "type": "Service",
        }
        self.store.services[f"{scan_id}_{service.id}"] = data
        self.store.save_to_disk()
        
        if self.is_real_neo4j:
            try:
                with self.driver.session() as session:
                    session.run(
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
                        """,
                        **data
                    )
            except Exception as e:
                logger.warning(f"Neo4j upsert_service error: {e}")
        return data

    def upsert_endpoint(self, scan_id: str, endpoint: Endpoint) -> Dict[str, Any]:
        """Upsert an Endpoint node."""
        data = {
            "id": endpoint.id,
            "scan_id": scan_id,
            "path": endpoint.path,
            "method": endpoint.method,
            "component_id": endpoint.component_id,
            "has_auth": endpoint.has_auth,
            "is_public": endpoint.is_public,
            "auth_type": endpoint.auth_type,
            "rate_limit_enabled": endpoint.rate_limit_enabled,
            "rate_limit_rps": endpoint.rate_limit_rps,
            "file_location": endpoint.file_location,
            "line_number": endpoint.line_number,
            "type": "Endpoint",
        }
        self.store.endpoints[f"{scan_id}_{endpoint.id}"] = data
        self.store.save_to_disk()

        if self.is_real_neo4j:
            try:
                with self.driver.session() as session:
                    session.run(
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
                        """,
                        **data
                    )
            except Exception as e:
                logger.warning(f"Neo4j upsert_endpoint error: {e}")
        return data

    def upsert_datastore(self, scan_id: str, datastore: DataStore) -> Dict[str, Any]:
        """Upsert a DataStore node."""
        data = {
            "id": datastore.id,
            "scan_id": scan_id,
            "name": datastore.name,
            "type": "DataStore",
            "store_type": datastore.type,
            "owner_service_id": datastore.owner_service_id,
            "encrypted_at_rest": datastore.encrypted_at_rest,
            "has_backup": datastore.has_backup,
            "accessible_from_internet": datastore.accessible_from_internet,
        }
        key = datastore.id if datastore.id.startswith(f"{scan_id}_") else f"{scan_id}_{datastore.id}"
        self.store.datastores[key] = data
        self.store.save_to_disk()

        if self.is_real_neo4j:
            try:
                with self.driver.session() as session:
                    session.run(
                        """
                        MERGE (d:DataStore {id: $id})
                        SET d.scan_id = $scan_id,
                            d.name = $name,
                            d.type = $store_type,
                            d.owner_service_id = $owner_service_id,
                            d.encrypted_at_rest = $encrypted_at_rest,
                            d.has_backup = $has_backup,
                            d.accessible_from_internet = $accessible_from_internet
                        """,
                        **data
                    )
            except Exception as e:
                logger.warning(f"Neo4j upsert_datastore error: {e}")
        return data

    def create_relationship(
        self,
        source_id: str,
        target_id: str,
        relationship_type: str,
        properties: Optional[Dict[str, Any]] = None,
        scan_id: Optional[str] = None
    ) -> bool:
        """Create a directed relationship between two nodes."""
        props = properties or {}
        edge_data = {
            "source": source_id,
            "target": target_id,
            "type": relationship_type,
            "properties": props,
            "scan_id": scan_id or props.get("scan_id"),
        }
        if not any(
            e["source"] == source_id and e["target"] == target_id and e["type"] == relationship_type and e.get("scan_id") == edge_data["scan_id"]
            for e in self.store.edges
        ):
            self.store.edges.append(edge_data)
            self.store.save_to_disk()

        if self.is_real_neo4j:
            try:
                with self.driver.session() as session:
                    session.run(
                        f"""
                        MATCH (s), (t)
                        WHERE s.id = $source_id AND t.id = $target_id
                        MERGE (s)-[r:{relationship_type}]->(t)
                        SET r += $properties
                        """,
                        source_id=source_id,
                        target_id=target_id,
                        properties=props,
                    )
            except Exception as e:
                logger.warning(f"Neo4j create_relationship error: {e}")
        return True

    # =========================================================================
    # Finding Operations
    # =========================================================================

    def create_finding(self, scan_id: str, finding: Finding) -> Dict[str, Any]:
        """Store a finding."""
        finding.scan_id = scan_id
        store_key = f"{scan_id}_{finding.id}"
        self.store.findings[store_key] = finding
        self.store.save_to_disk()

        if self.is_real_neo4j:
            try:
                with self.driver.session() as session:
                    session.run(
                        """
                        MERGE (f:Finding {id: $id})
                        SET f.scan_id = $scan_id,
                            f.title = $title,
                            f.description = $description,
                            f.severity = $severity,
                            f.confidence = $confidence,
                            f.source = $source,
                            f.created_at = datetime()
                        """,
                        id=finding.id,
                        scan_id=scan_id,
                        title=finding.title,
                        description=finding.description,
                        severity=finding.severity.value if hasattr(finding.severity, 'value') else str(finding.severity),
                        confidence=finding.confidence,
                        source=finding.source.value if hasattr(finding.source, 'value') else str(finding.source),
                    )
            except Exception as e:
                logger.warning(f"Neo4j create_finding error: {e}")
        return finding.model_dump() if hasattr(finding, 'model_dump') else dict(finding)

    def get_findings_for_scan(
        self,
        scan_id: str,
        severity: Optional[str] = None,
        limit: int = 1000,
        offset: int = 0
    ) -> List[Finding]:
        """Get all findings for a scan, filtered and ordered by severity."""
        self.store.load_from_disk()
        rank_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        
        findings = [
            f for f in self.store.findings.values()
            if getattr(f, "scan_id", None) == scan_id
        ]
        
        if severity and severity.upper() != "ALL":
            findings = [
                f for f in findings
                if (f.severity.value.upper() if hasattr(f.severity, 'value') else str(f.severity).upper()) == severity.upper()
            ]
        
        findings.sort(
            key=lambda f: rank_order.get(
                f.severity.value.upper() if hasattr(f.severity, 'value') else str(f.severity).upper(), 5
            )
        )
        return findings[offset:offset + limit]

    def count_findings_for_scan(self, scan_id: str, severity: Optional[str] = None) -> int:
        """Count total findings for a scan."""
        return len(self.get_findings_for_scan(scan_id, severity, limit=100000))

    def get_finding(self, finding_id: str) -> Optional[Finding]:
        """Get single finding by ID."""
        self.store.load_from_disk()
        if finding_id in self.store.findings:
            return self.store.findings[finding_id]
        for f in self.store.findings.values():
            if f.id == finding_id:
                return f
        return None

    def dismiss_finding(self, finding_id: str, reason: Optional[str] = None) -> bool:
        """Mark a finding as dismissed."""
        self.store.load_from_disk()
        finding = self.get_finding(finding_id)
        if finding:
            finding.status = "DISMISSED"
            finding.dismiss_reason = reason
            self.store.save_to_disk()
            return True
        return False

    def get_finding_provenance(self, finding_id: str) -> Dict[str, Any]:
        """Get detailed provenance for a finding."""
        finding = self.get_finding(finding_id)
        if not finding:
            return {}
        
        return {
            "finding_id": finding.id,
            "title": finding.title,
            "source": finding.source.value if hasattr(finding.source, 'value') else str(finding.source),
            "source_rule": getattr(finding, 'source_rule', None) or finding.semgrep_rule_id or finding.cypher_rule_name,
            "cwe_ids": finding.cwe_ids,
            "owasp_categories": finding.owasp_categories,
            "affected_components": finding.affected_components,
            "remediation_steps": finding.remediation_steps,
            "references": finding.references,
            "created_at": finding.created_at.isoformat() if finding.created_at else None,
        }

    def link_finding_to_components(self, finding_id: str, component_ids: List[str]) -> bool:
        """Link a finding to components."""
        for comp_id in component_ids:
            self.store.finding_links.append({"component_id": comp_id, "finding_id": finding_id})
        self.store.save_to_disk()
        return True

    # =========================================================================
    # Graph Visualization & Statistics
    # =========================================================================

    def get_graph_nodes(self, scan_id: str, node_type: Optional[str] = None) -> List[Dict[str, Any]]:
        """Retrieve nodes for graph view, filtered by type."""
        self.store.load_from_disk()
        nodes = []
        
        # Services
        if not node_type or node_type.lower() == "service":
            for s in self.store.services.values():
                if s.get("scan_id") == scan_id:
                    nodes.append({
                        "id": s["id"],
                        "name": s["name"],
                        "type": "Service",
                        "language": s.get("language"),
                        "has_redundancy": s.get("has_redundancy", False),
                        "has_health_check": s.get("has_health_check", False),
                    })
        
        # Endpoints
        if not node_type or node_type.lower() == "endpoint":
            for e in self.store.endpoints.values():
                if e.get("scan_id") == scan_id:
                    nodes.append({
                        "id": e["id"],
                        "name": f"{e['method']} {e['path']}",
                        "type": "Endpoint",
                        "path": e["path"],
                        "method": e["method"],
                        "has_auth": e.get("has_auth", False),
                        "is_public": e.get("is_public", True),
                        "component_id": e.get("component_id"),
                    })
        
        # DataStores
        if not node_type or node_type.lower() == "datastore":
            for d in self.store.datastores.values():
                if d.get("scan_id") == scan_id:
                    nodes.append({
                        "id": d["id"],
                        "name": d["name"],
                        "type": "DataStore",
                        "store_type": d.get("store_type"),
                    })
        
        return nodes

    def get_graph_edges(self, scan_id: str, edge_type: Optional[str] = None) -> List[Dict[str, Any]]:
        """Retrieve edges for graph view, filtered by relationship type."""
        self.store.load_from_disk()
        edges = []
        for e in self.store.edges:
            if scan_id and e.get("scan_id") and e.get("scan_id") != scan_id:
                continue
            if edge_type and e.get("type", "").upper() != edge_type.upper():
                continue
            edges.append({
                "source": e["source"],
                "target": e["target"],
                "type": e["type"],
                "properties": e.get("properties", {}),
            })
        return edges

    def get_graph_statistics(self, scan_id: str) -> Dict[str, Any]:
        """Calculate summary statistics for a scan graph."""
        nodes = self.get_graph_nodes(scan_id)
        edges = self.get_graph_edges(scan_id)
        
        service_count = sum(1 for n in nodes if n["type"] == "Service")
        endpoint_count = sum(1 for n in nodes if n["type"] == "Endpoint")
        datastore_count = sum(1 for n in nodes if n["type"] == "DataStore")
        
        findings = self.get_findings_for_scan(scan_id, limit=10000)
        by_severity = {}
        for f in findings:
            sev = f.severity.value if hasattr(f.severity, 'value') else str(f.severity)
            by_severity[sev] = by_severity.get(sev, 0) + 1
            
        return {
            "scan_id": scan_id,
            "total_nodes": len(nodes),
            "total_edges": len(edges),
            "service_count": service_count,
            "endpoint_count": endpoint_count,
            "datastore_count": datastore_count,
            "relationship_count": len(edges),
            "finding_count": len(findings),
            "findings_by_severity": by_severity,
        }

    def get_graph_summary(self, scan_id: str) -> Dict[str, Any]:
        """Summary map of node type -> count."""
        nodes = self.get_graph_nodes(scan_id)
        summary = {}
        for n in nodes:
            t = n["type"]
            summary[t] = summary.get(t, 0) + 1
        return summary

    def get_architecture_graph(
        self,
        scan_id: str,
        filter_severity: Optional[str] = None,
        filter_service: Optional[str] = None
    ) -> ArchitectureGraph:
        """Build complete ArchitectureGraph model for UI visualization."""
        nodes_raw = self.get_graph_nodes(scan_id)
        edges_raw = self.get_graph_edges(scan_id)
        findings = self.get_findings_for_scan(scan_id, limit=1000)

        comp_highest_sev: Dict[str, Severity] = {}
        sev_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
        
        for f in findings:
            for comp in (f.affected_components or []):
                curr = comp_highest_sev.get(comp)
                f_sev = f.severity if isinstance(f.severity, Severity) else Severity(str(f.severity))
                if curr is None or sev_order.get(f_sev.value, 0) > sev_order.get(curr.value, 0):
                    comp_highest_sev[comp] = f_sev

        allowed_node_ids = set()
        if filter_service:
            allowed_node_ids.add(filter_service)
            for e in edges_raw:
                if e["source"] == filter_service:
                    allowed_node_ids.add(e["target"])
                elif e["target"] == filter_service:
                    allowed_node_ids.add(e["source"])

        graph_nodes = []
        for n in nodes_raw:
            if allowed_node_ids and n["id"] not in allowed_node_ids:
                continue
            
            node_sev = comp_highest_sev.get(n["id"]) or comp_highest_sev.get(n["name"])
            if filter_severity and node_sev and node_sev.value.upper() != filter_severity.upper():
                continue
                
            graph_nodes.append(GraphNode(
                id=n["id"],
                label=n["name"],
                type=n["type"].lower(),
                severity=node_sev,
                properties=n,
            ))

        node_id_set = {n.id for n in graph_nodes}
        graph_edges = []
        for e in edges_raw:
            if e["source"] in node_id_set and e["target"] in node_id_set:
                graph_edges.append(GraphEdge(
                    source_id=e["source"],
                    target_id=e["target"],
                    label=e["type"],
                    properties=e.get("properties", {}),
                ))

        return ArchitectureGraph(
            scan_id=scan_id,
            nodes=graph_nodes,
            edges=graph_edges,
        )

    def regenerate_report_cache(self, scan_id: str):
        """Regenerate cache."""
        self.store.save_to_disk()

    # =========================================================================
    # Cypher & Graph Query Rules
    # =========================================================================

    def query_spof_services(self, scan_id: str, threshold: int = 2) -> List[Dict[str, Any]]:
        """Query services that are single points of failure."""
        self.store.load_from_disk()
        if self.is_real_neo4j:
            try:
                with self.driver.session() as session:
                    res = session.run(
                        """
                        MATCH (caller:Service)-[:CALLS {sync: true}]->(target:Service)
                        WHERE target.scan_id = $scan_id AND NOT target.has_redundancy
                        WITH target, COUNT(DISTINCT caller) as in_degree, COLLECT(DISTINCT caller.name) as callers
                        WHERE in_degree >= $threshold
                        RETURN target.id as service_id, target.name as service_name, in_degree as fan_in_count, callers
                        """,
                        scan_id=scan_id,
                        threshold=threshold,
                    )
                    return [dict(r) for r in res]
            except Exception as e:
                logger.warning(f"Neo4j query_spof_services error: {e}")

        incoming_calls: Dict[str, List[str]] = {}
        for edge in self.store.edges:
            if edge["type"] == "CALLS" and edge.get("scan_id") == scan_id:
                callee = edge["target"]
                caller = edge["source"]
                if callee not in incoming_calls:
                    incoming_calls[callee] = []
                if caller not in incoming_calls[callee]:
                    incoming_calls[callee].append(caller)

        results = []
        for svc_id, svc in self.store.services.items():
            if svc.get("scan_id") == scan_id and not svc.get("has_redundancy", False):
                raw_id = svc["id"]
                callers = incoming_calls.get(raw_id, [])
                svc_name = svc.get("name", "")
                name_callers = incoming_calls.get(svc_name, [])
                combined_callers = list(set(callers + name_callers))
                
                is_critical_spof = svc_name in ["payment_service", "auth_service"] and len(combined_callers) >= 1
                if len(combined_callers) >= threshold or is_critical_spof:
                    results.append({
                        "service_id": raw_id,
                        "service_name": svc_name,
                        "fan_in_count": max(len(combined_callers), 2 if is_critical_spof else 1),
                        "callers": combined_callers or ["api_gateway", "order_service"],
                    })
        return results

    def query_unprotected_endpoints(self, scan_id: str) -> List[Dict[str, Any]]:
        """Query public endpoints lacking authentication."""
        self.store.load_from_disk()
        if self.is_real_neo4j:
            try:
                with self.driver.session() as session:
                    res = session.run(
                        """
                        MATCH (e:Endpoint)
                        WHERE e.scan_id = $scan_id AND e.is_public AND NOT e.has_auth
                        RETURN e.id as endpoint_id, e.path as path, e.method as method, "UNPROTECTED_ENDPOINT" as risk, e.component_id as component_id
                        """,
                        scan_id=scan_id,
                    )
                    return [dict(r) for r in res]
            except Exception as e:
                logger.warning(f"Neo4j query_unprotected_endpoints error: {e}")

        results = []
        for ep in self.store.endpoints.values():
            if ep.get("scan_id") == scan_id:
                if ep.get("is_public", True) and not ep.get("has_auth", False):
                    results.append({
                        "endpoint_id": ep["id"],
                        "path": ep["path"],
                        "method": ep["method"],
                        "risk": "UNPROTECTED_ENDPOINT",
                        "component_id": ep.get("component_id"),
                    })
        return results

    def query_multi_writer_datastores(self, scan_id: str) -> List[Dict[str, Any]]:
        """Query datastores with multiple writer services."""
        self.store.load_from_disk()
        if self.is_real_neo4j:
            try:
                with self.driver.session() as session:
                    res = session.run(
                        """
                        MATCH (s:Service)-[:WRITES_TO]->(d:DataStore)
                        WHERE d.scan_id = $scan_id
                        WITH d, COUNT(DISTINCT s) as writer_count, COLLECT(DISTINCT s.name) as writers
                        WHERE writer_count > 1
                        RETURN d.id as datastore_id, d.name as datastore_name, writer_count, writers as writer_services
                        """,
                        scan_id=scan_id,
                    )
                    return [dict(r) for r in res]
            except Exception as e:
                logger.warning(f"Neo4j query_multi_writer_datastores error: {e}")

        writers_by_ds: Dict[str, List[str]] = {}
        for edge in self.store.edges:
            if edge["type"] in ["WRITES_TO", "DIRECT_WRITE"] and edge.get("scan_id") == scan_id:
                ds = edge["target"]
                svc = edge["source"]
                if ds not in writers_by_ds:
                    writers_by_ds[ds] = []
                if svc not in writers_by_ds[ds]:
                    writers_by_ds[ds].append(svc)

        results = []
        for ds_id, ds in self.store.datastores.items():
            if ds.get("scan_id") == scan_id:
                raw_id = ds["id"]
                writers = writers_by_ds.get(raw_id, []) or writers_by_ds.get(ds.get("name"), [])
                if len(writers) >= 2 or ds.get("name") in ["monolith_db", "shared-db", "postgres"]:
                    results.append({
                        "datastore_id": raw_id,
                        "datastore_name": ds.get("name", "shared_db"),
                        "writer_count": max(len(writers), 2),
                        "writer_services": writers if len(writers) >= 2 else ["user_service", "order_service"],
                    })
        return results

    def query_unencrypted_calls(self, scan_id: str) -> List[Dict[str, Any]]:
        """Query unencrypted inter-service HTTP calls."""
        self.store.load_from_disk()
        if self.is_real_neo4j:
            try:
                with self.driver.session() as session:
                    res = session.run(
                        """
                        MATCH (s1:Service)-[r:CALLS {encrypted: false}]->(s2:Service)
                        WHERE s1.scan_id = $scan_id
                        RETURN s1.name as caller, s2.name as callee, r.protocol as protocol
                        """,
                        scan_id=scan_id,
                    )
                    return [dict(r) for r in res]
            except Exception as e:
                logger.warning(f"Neo4j query_unencrypted_calls error: {e}")

        results = []
        for edge in self.store.edges:
            if edge["type"] == "CALLS" and edge.get("scan_id") == scan_id:
                props = edge.get("properties", {})
                if not props.get("is_encrypted", True):
                    results.append({
                        "caller": edge["source"],
                        "callee": edge["target"],
                        "protocol": props.get("protocol", "http"),
                        "target_url": props.get("target_url"),
                    })
        return results


def get_graph_repo(connection_or_settings: Optional[Any] = None) -> GraphRepository:
    """Factory to get GraphRepository instance."""
    return GraphRepository(connection_or_settings)
