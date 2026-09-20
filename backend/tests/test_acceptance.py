"""Acceptance tests validating demo repo vulnerabilities are detected."""

import pytest
from pathlib import Path
from app.pipeline import ScanPipeline
from app.graph.db import get_db_connection
from app.graph.repository import GraphRepository


@pytest.fixture(scope="module")
def scan_result():
    """Run scan against demo repo and cache results."""
    demo_repo_path = Path(__file__).parent.parent.parent / "test-fixtures" / "demo-repo"
    
    pipeline = ScanPipeline()
    scan_id = pipeline.scan(
        scan_id="test-demo-scan",
        repository_source={"type": "local", "path": str(demo_repo_path)},
        skip_ai=False,
    )
    
    return {
        "scan_id": scan_id,
        "demo_repo_path": demo_repo_path,
    }


class TestDemoRepoVulnerabilities:
    """Tests that verify the demo repo vulnerabilities are detected."""
    
    @pytest.mark.acceptance
    def test_detects_unprotected_endpoint(self, scan_result):
        """Test detection of unprotected /health endpoint in api_gateway."""
        db = get_db_connection()
        graph_repo = GraphRepository(db)
        
        findings = graph_repo.get_findings_for_scan(scan_result["scan_id"])
        
        # Should find unprotected endpoint
        unprotected_findings = [
            f for f in findings
            if "unprotected" in f.title.lower() or "endpoint" in f.title.lower()
        ]
        
        assert len(unprotected_findings) > 0, "Should detect unprotected endpoint in api_gateway"
    
    @pytest.mark.acceptance
    def test_detects_hardcoded_secret(self, scan_result):
        """Test detection of hardcoded JWT_SECRET in auth_service."""
        db = get_db_connection()
        graph_repo = GraphRepository(db)
        
        findings = graph_repo.get_findings_for_scan(scan_result["scan_id"])
        
        # Should find hardcoded secret
        secret_findings = [
            f for f in findings
            if "secret" in f.title.lower() or "credential" in f.title.lower()
        ]
        
        assert len(secret_findings) > 0, "Should detect hardcoded secrets"
    
    @pytest.mark.acceptance
    def test_detects_spof_auth_service(self, scan_result):
        """Test detection of SPOF: Auth Service called by multiple services."""
        db = get_db_connection()
        graph_repo = GraphRepository(db)
        
        findings = graph_repo.get_findings_for_scan(scan_result["scan_id"])
        
        # Should find SPOF issues
        spof_findings = [
            f for f in findings
            if "spof" in f.title.lower() or "single point of failure" in f.description.lower()
        ]
        
        assert len(spof_findings) > 0, "Should detect SPOF in auth_service"
    
    @pytest.mark.acceptance
    def test_detects_multi_writer_datastore(self, scan_result):
        """Test detection of multi-writer shared database."""
        db = get_db_connection()
        graph_repo = GraphRepository(db)
        
        findings = graph_repo.get_findings_for_scan(scan_result["scan_id"])
        
        # Should find multi-writer datastore issues
        multi_writer_findings = [
            f for f in findings
            if "multi" in f.title.lower() and "writer" in f.title.lower()
        ]
        
        assert len(multi_writer_findings) > 0, "Should detect multi-writer datastore"
    
    @pytest.mark.acceptance
    def test_detects_unencrypted_calls(self, scan_result):
        """Test detection of unencrypted HTTP calls."""
        db = get_db_connection()
        graph_repo = GraphRepository(db)
        
        findings = graph_repo.get_findings_for_scan(scan_result["scan_id"])
        
        # Should find unencrypted boundary crossing
        unencrypted_findings = [
            f for f in findings
            if ("unencrypted" in f.title.lower() or "http" in f.title.lower())
            and ("boundary" in f.description.lower() or "cross" in f.description.lower())
        ]
        
        assert len(unencrypted_findings) > 0, "Should detect unencrypted boundary crossing"
    
    @pytest.mark.acceptance
    def test_severity_distribution(self, scan_result):
        """Test that findings have appropriate severity levels."""
        db = get_db_connection()
        graph_repo = GraphRepository(db)
        
        findings = graph_repo.get_findings_for_scan(scan_result["scan_id"])
        
        # Count by severity
        by_severity = {}
        for f in findings:
            by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
        
        # Should have at least some critical/high findings
        assert by_severity.get("CRITICAL", 0) + by_severity.get("HIGH", 0) > 0, \
            "Should detect at least some critical/high severity issues"
    
    @pytest.mark.acceptance
    def test_total_finding_count(self, scan_result):
        """Test that we detect expected number of vulnerabilities."""
        db = get_db_connection()
        graph_repo = GraphRepository(db)
        
        findings = graph_repo.get_findings_for_scan(scan_result["scan_id"])
        
        # Demo repo has 7 seeded vulnerabilities minimum
        # (may detect more with additional rules)
        assert len(findings) >= 5, \
            f"Should detect at least 5 vulnerabilities, found {len(findings)}"
    
    @pytest.mark.acceptance
    def test_findings_have_remediation(self, scan_result):
        """Test that all findings include remediation steps."""
        db = get_db_connection()
        graph_repo = GraphRepository(db)
        
        findings = graph_repo.get_findings_for_scan(scan_result["scan_id"])
        
        for finding in findings:
            assert finding.remediation_steps, \
                f"Finding '{finding.title}' should have remediation steps"
            assert len(finding.remediation_steps) > 0, \
                f"Finding '{finding.title}' should have at least one remediation step"
    
    @pytest.mark.acceptance
    def test_findings_have_cwe_refs(self, scan_result):
        """Test that findings reference CWE IDs."""
        db = get_db_connection()
        graph_repo = GraphRepository(db)
        
        findings = graph_repo.get_findings_for_scan(scan_result["scan_id"])
        
        # Most findings should have CWE references
        with_cwe = [f for f in findings if f.cwe_ids]
        assert len(with_cwe) >= len(findings) * 0.8, \
            f"At least 80% of findings should have CWE references"
    
    @pytest.mark.acceptance
    def test_idempotent_rescanning(self, scan_result):
        """Test that re-scanning produces identical results (idempotent)."""
        demo_repo_path = scan_result["demo_repo_path"]
        
        # Run second scan
        pipeline = ScanPipeline()
        scan_id_2 = pipeline.scan(
            scan_id="test-demo-scan-2",
            repository_source={"type": "local", "path": str(demo_repo_path)},
            skip_ai=False,
        )
        
        db = get_db_connection()
        graph_repo = GraphRepository(db)
        
        findings_1 = graph_repo.get_findings_for_scan(scan_result["scan_id"])
        findings_2 = graph_repo.get_findings_for_scan(scan_id_2)
        
        # Should have same number of findings
        assert len(findings_1) == len(findings_2), \
            f"Re-scan should produce identical results: {len(findings_1)} vs {len(findings_2)}"
        
        # Should have same severity distribution
        sev_1 = {f.severity: sum(1 for x in findings_1 if x.severity == f.severity) 
                for f in findings_1}
        sev_2 = {f.severity: sum(1 for x in findings_2 if x.severity == f.severity) 
                for f in findings_2}
        
        assert sev_1 == sev_2, "Severity distribution should be identical on re-scan"
    
    @pytest.mark.acceptance
    def test_ai_layer_optional(self, scan_result):
        """Test that scanning works without LLM layer."""
        demo_repo_path = scan_result["demo_repo_path"]
        
        # Scan with skip_ai=True
        pipeline = ScanPipeline()
        scan_id_no_ai = pipeline.scan(
            scan_id="test-demo-scan-no-ai",
            repository_source={"type": "local", "path": str(demo_repo_path)},
            skip_ai=True,
        )
        
        db = get_db_connection()
        graph_repo = GraphRepository(db)
        
        findings_with_ai = graph_repo.get_findings_for_scan(scan_result["scan_id"])
        findings_without_ai = graph_repo.get_findings_for_scan(scan_id_no_ai)
        
        # Without AI, should still find most findings (deterministic only)
        # Allow some difference but should be similar count
        assert len(findings_without_ai) >= len(findings_with_ai) * 0.7, \
            "Deterministic rules should find ~70%+ of findings without LLM layer"


class TestDemoRepoArchitecture:
    """Tests for demo repo architecture extraction."""
    
    @pytest.mark.acceptance
    def test_services_extracted(self, scan_result):
        """Test that all services are extracted from demo repo."""
        db = get_db_connection()
        graph_repo = GraphRepository(db)
        
        services = graph_repo.get_graph_nodes(
            scan_result["scan_id"],
            node_type="Service"
        )
        
        # Demo repo has 5 services
        assert len(services) >= 5, \
            f"Should extract 5+ services from demo repo, found {len(services)}"
        
        # Should include known services
        service_names = {s.get("name") for s in services}
        expected = {"api_gateway", "auth_service", "user_service", "order_service", "payment_service"}
        
        found = service_names & expected
        assert len(found) >= 4, \
            f"Should find at least 4 of {expected}, found {found}"
    
    @pytest.mark.acceptance
    def test_endpoints_extracted(self, scan_result):
        """Test that endpoints are extracted."""
        db = get_db_connection()
        graph_repo = GraphRepository(db)
        
        endpoints = graph_repo.get_graph_nodes(
            scan_result["scan_id"],
            node_type="Endpoint"
        )
        
        # Should extract multiple endpoints
        assert len(endpoints) >= 10, \
            f"Should extract 10+ endpoints from demo repo, found {len(endpoints)}"
    
    @pytest.mark.acceptance
    def test_datastore_extracted(self, scan_result):
        """Test that databases are extracted."""
        db = get_db_connection()
        graph_repo = GraphRepository(db)
        
        datastores = graph_repo.get_graph_nodes(
            scan_result["scan_id"],
            node_type="DataStore"
        )
        
        # Should find the shared PostgreSQL
        assert len(datastores) >= 1, \
            f"Should extract 1+ datastore from demo repo, found {len(datastores)}"
    
    @pytest.mark.acceptance
    def test_dependencies_extracted(self, scan_result):
        """Test that service dependencies are extracted."""
        db = get_db_connection()
        graph_repo = GraphRepository(db)
        
        edges = graph_repo.get_graph_edges(
            scan_result["scan_id"],
            edge_type="CALLS"
        )
        
        # Should find service call relationships
        assert len(edges) >= 5, \
            f"Should extract 5+ service calls from demo repo, found {len(edges)}"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-m", "acceptance"])
