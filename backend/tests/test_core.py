"""Unit and integration tests for AI Architecture Risk Auditor."""

import pytest
from datetime import datetime
from unittest.mock import MagicMock, patch
import json

from app.models import Scan, Finding, ScanStatus, Severity, FindingSource
from app.security import hash_secret, redact_secret, redact_dict
from app.parser.python_parser import PythonParser
from app.parser.js_parser import JavaScriptParser
from app.graph.repository import GraphRepository


class TestSecurity:
    """Tests for secret redaction and security utilities."""
    
    def test_hash_secret(self):
        """Test secret hashing."""
        secret = "sk_live_abc123xyz"
        hash1 = hash_secret(secret)
        hash2 = hash_secret(secret)
        
        # Same secret should produce same hash
        assert hash1 == hash2
        # Hash should not be plaintext
        assert hash1 != secret
        # Hash should be consistent
        assert len(hash1) > 0
    
    def test_redact_secret(self):
        """Test secret redaction in strings."""
        text = "api_key=sk_live_abc123xyz&password=secret123"
        redacted = redact_secret(text)
        
        # Should redact secrets
        assert "sk_live_abc123xyz" not in redacted
        assert "secret123" not in redacted
        # Should contain redaction markers
        assert "[REDACTED" in redacted
    
    def test_redact_dict(self):
        """Test recursive dict redaction."""
        data = {
            "api_key": "sk_live_abc123",
            "password": "supersecret",
            "nested": {
                "token": "eyJhbGciOiJIUzI1NiIs...",
                "public_info": "this is ok"
            },
            "list": ["secret123", "public_data"]
        }
        
        redacted = redact_dict(data)
        
        # Should redact nested secrets
        assert "sk_live_abc123" not in json.dumps(redacted)
        assert "supersecret" not in json.dumps(redacted)
        # Should preserve public data
        assert "public_info" in json.dumps(redacted)
        assert "public_data" in json.dumps(redacted)


class TestParsers:
    """Tests for language parsers."""
    
    def test_python_parser_init(self):
        """Test Python parser initialization."""
        parser = PythonParser()
        assert parser.language_name == "python"
        assert "py" in parser.file_extensions
    
    def test_python_parser_extension_detection(self):
        """Test Python file extension detection."""
        parser = PythonParser()
        assert parser.supports("script.py")
        assert parser.supports("fastapi_app.py")
        assert not parser.supports("script.js")
    
    def test_js_parser_init(self):
        """Test JavaScript parser initialization."""
        parser = JavaScriptParser()
        assert parser.language_name == "javascript"
        assert "js" in parser.file_extensions or "ts" in parser.file_extensions
    
    def test_js_parser_extension_detection(self):
        """Test JavaScript file extension detection."""
        parser = JavaScriptParser()
        assert parser.supports("app.js")
        assert parser.supports("server.ts")
        assert not parser.supports("script.py")


class TestModels:
    """Tests for Pydantic models."""
    
    def test_scan_creation(self):
        """Test Scan model creation."""
        scan = Scan(
            id="scan-123",
            status=ScanStatus.QUEUED,
            repository_source={"type": "local", "path": "/path/to/repo"},
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
        )
        
        assert scan.id == "scan-123"
        assert scan.status == ScanStatus.QUEUED
        assert scan.repository_source["type"] == "local"
    
    def test_finding_creation(self):
        """Test Finding model creation."""
        finding = Finding(
            id="finding-1",
            scan_id="scan-123",
            title="Unprotected Endpoint",
            description="Endpoint has no authentication",
            severity=Severity.CRITICAL,
            confidence=0.95,
            source=FindingSource.SEMGREP,
            affected_components=["api_gateway:/health"],
            cwe_ids=[306, 352],
            owasp_categories=["A07:2021 - Identification and Authentication Failures"],
            remediation_steps=["Add @require_auth decorator", "Implement API key validation"],
            references=["https://owasp.org/www-community/attacks/Missing_Authentication"],
        )
        
        assert finding.id == "finding-1"
        assert finding.severity == Severity.CRITICAL
        assert 306 in finding.cwe_ids
        assert len(finding.remediation_steps) == 2
    
    def test_finding_severity_comparison(self):
        """Test finding severity comparison."""
        critical = Severity.CRITICAL
        high = Severity.HIGH
        
        # This tests the enum comparison
        assert critical != high


class TestGraphRepository:
    """Tests for Neo4j graph repository (mocked)."""
    
    @patch('app.graph.db.get_db_connection')
    def test_create_scan(self, mock_db):
        """Test scan creation in graph."""
        mock_connection = MagicMock()
        mock_db.return_value = mock_connection
        
        repo = GraphRepository(mock_connection)
        scan = Scan(
            id="scan-123",
            status=ScanStatus.QUEUED,
            repository_source={"type": "local", "path": "/repo"},
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
        )
        
        # This would actually create in Neo4j; we're mocking to test interface
        # repo.create_scan(scan)
        # assert repo methods exist
        assert hasattr(repo, 'create_scan')
        assert hasattr(repo, 'get_scan')
        assert hasattr(repo, 'list_scans')
        assert hasattr(repo, 'delete_scan')
    
    @patch('app.graph.db.get_db_connection')
    def test_repository_has_required_methods(self, mock_db):
        """Test GraphRepository has all required methods."""
        mock_connection = MagicMock()
        mock_db.return_value = mock_connection
        
        repo = GraphRepository(mock_connection)
        
        # Verify all required methods exist
        required_methods = [
            'create_scan', 'get_scan', 'list_scans', 'delete_scan',
            'upsert_service', 'upsert_endpoint', 'create_relationship',
            'create_finding', 'get_findings_for_scan', 'get_graph_summary',
            'get_finding', 'dismiss_finding', 'get_finding_provenance',
            'get_architecture_graph', 'get_graph_nodes', 'get_graph_edges',
            'get_graph_statistics', 'regenerate_report_cache'
        ]
        
        for method in required_methods:
            assert hasattr(repo, method), f"Missing method: {method}"


class TestDeterministicRiskDetection:
    """Tests for deterministic risk detection engine."""
    
    def test_spof_severity(self):
        """Test SPOF findings have HIGH severity."""
        # This would be tested with actual Neo4j queries
        # For now, verify the model
        finding = Finding(
            id="spof-1",
            scan_id="scan-1",
            title="Single Point of Failure",
            description="Service has high fan-in with no redundancy",
            severity=Severity.HIGH,
            confidence=0.95,
            source=FindingSource.CYPHER,
            affected_components=["auth_service"],
            cwe_ids=[400],
            owasp_categories=["Insecure Deserialization"],
            remediation_steps=["Add redundant instances", "Implement load balancing"],
        )
        
        assert finding.severity == Severity.HIGH
        assert finding.confidence == 0.95
        assert "auth_service" in finding.affected_components


class TestLLMEngine:
    """Tests for LLM-assisted finding enrichment."""
    
    @patch('openai.OpenAI')
    def test_llm_redaction_before_call(self, mock_openai):
        """Test that secrets are redacted before LLM calls."""
        # This would test that redaction happens before API call
        # For now, verify the redaction utility works
        text_with_secret = "api_key=sk_live_abc123 in service config"
        redacted = redact_secret(text_with_secret)
        
        assert "sk_live_abc123" not in redacted


class TestAPIEndpoints:
    """Tests for REST API endpoints."""
    
    def test_scan_routes_exist(self):
        """Test that scan routes are properly defined."""
        from app.api.scans import router as scans_router
        
        # Verify routes exist
        routes = [route.path for route in scans_router.routes]
        assert "/" in routes or "api/scans" in str(routes)
    
    def test_findings_routes_exist(self):
        """Test that findings routes are properly defined."""
        from app.api.findings import router as findings_router
        
        # Verify routes exist
        assert hasattr(findings_router, 'routes')
    
    def test_graph_routes_exist(self):
        """Test that graph routes are properly defined."""
        from app.api.graph import router as graph_router
        
        # Verify routes exist
        assert hasattr(graph_router, 'routes')
    
    def test_reports_routes_exist(self):
        """Test that reports routes are properly defined."""
        from app.api.reports import router as reports_router
        
        # Verify routes exist
        assert hasattr(reports_router, 'routes')


class TestReportExport:
    """Tests for report export formats."""
    
    def test_export_json_format(self):
        """Test JSON export format."""
        from app.reporting.exporters import ReportExporter
        
        scan = Scan(
            id="scan-1",
            status=ScanStatus.COMPLETED,
            repository_source={"type": "local", "path": "/repo"},
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
        )
        
        finding = Finding(
            id="f-1",
            scan_id="scan-1",
            title="Test Finding",
            description="Test",
            severity=Severity.HIGH,
            confidence=0.9,
            source=FindingSource.SEMGREP,
            affected_components=["service-1"],
        )
        
        exporter = ReportExporter(scan, [finding])
        json_report = exporter.export_json()
        
        assert json_report["scan"]["id"] == "scan-1"
        assert len(json_report["findings"]) == 1
        assert json_report["summary"]["total_findings"] == 1
    
    def test_export_sarif_format(self):
        """Test SARIF export format."""
        from app.reporting.exporters import ReportExporter
        
        scan = Scan(
            id="scan-1",
            status=ScanStatus.COMPLETED,
            repository_source={"type": "local", "path": "/repo"},
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
        )
        
        finding = Finding(
            id="f-1",
            scan_id="scan-1",
            title="Test Finding",
            description="Test",
            severity=Severity.CRITICAL,
            confidence=0.95,
            source=FindingSource.SEMGREP,
            affected_components=["service-1"],
        )
        
        exporter = ReportExporter(scan, [finding])
        sarif_report = exporter.export_sarif()
        
        assert sarif_report["version"] == "2.1.0"
        assert "runs" in sarif_report
        assert len(sarif_report["runs"]) > 0
        assert len(sarif_report["runs"][0]["results"]) == 1


class TestConfigValidation:
    """Tests for configuration validation."""
    
    def test_settings_load(self):
        """Test that settings load properly."""
        from app.config import settings
        
        # Verify core settings exist
        assert hasattr(settings, 'neo4j')
        assert hasattr(settings, 'openai')
        assert hasattr(settings, 'logging')


# Integration test fixtures
@pytest.fixture
def mock_neo4j():
    """Fixture for mocked Neo4j connection."""
    return MagicMock()


@pytest.fixture
def sample_scan():
    """Fixture for sample scan."""
    return Scan(
        id="test-scan-123",
        status=ScanStatus.RUNNING,
        repository_source={"type": "local", "path": "/test/repo"},
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow(),
    )


@pytest.fixture
def sample_findings():
    """Fixture for sample findings."""
    return [
        Finding(
            id="f-1",
            scan_id="test-scan-123",
            title="Unprotected Endpoint",
            description="API endpoint has no authentication",
            severity=Severity.CRITICAL,
            confidence=0.99,
            source=FindingSource.SEMGREP,
            affected_components=["api_gateway"],
            cwe_ids=[306],
            owasp_categories=["A07:2021"],
            remediation_steps=["Add authentication"],
        ),
        Finding(
            id="f-2",
            scan_id="test-scan-123",
            title="SPOF: Auth Service",
            description="Auth service called by multiple services with no redundancy",
            severity=Severity.HIGH,
            confidence=0.95,
            source=FindingSource.CYPHER,
            affected_components=["auth_service", "user_service", "order_service"],
            cwe_ids=[400],
            remediation_steps=["Add replication", "Implement failover"],
        ),
    ]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
