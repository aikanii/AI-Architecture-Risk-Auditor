"""
Core data models and schemas for the AI Architecture Risk Auditor.
Pydantic models for API requests/responses and internal data structures.
"""
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from enum import Enum
from datetime import datetime


# ============================================================================
# Enums
# ============================================================================

class Severity(str, Enum):
    """Risk severity levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class FindingSource(str, Enum):
    """Source of a finding."""
    SEMGREP = "semgrep"
    DETERMINISTIC = "deterministic"
    LLM = "llm"
    HYBRID = "hybrid"


class ControlType(str, Enum):
    """Type of security control."""
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    ENCRYPTION = "encryption"
    RATE_LIMITING = "rate_limiting"
    INPUT_VALIDATION = "input_validation"
    CIRCUIT_BREAKER = "circuit_breaker"


class TrustBoundaryType(str, Enum):
    """Trust boundary classifications."""
    INTERNET = "internet"
    DMZ = "dmz"
    INTERNAL = "internal"
    DATA_TIER = "data_tier"


# ============================================================================
# Scanning & Ingestion
# ============================================================================

class RepositorySource(BaseModel):
    """Repository source specification."""
    type: str = Field(..., description="Type: 'local', 'git', 'upload'")
    path: Optional[str] = None
    url: Optional[str] = None
    branch: Optional[str] = "main"
    token: Optional[str] = None
    include_patterns: List[str] = ["**/*"]
    exclude_patterns: List[str] = [
        "node_modules/**",
        "vendor/**",
        "dist/**",
        "build/**",
        ".git/**",
        "**/*.test.*",
        "**/*.spec.*",
    ]


class ScanRequest(BaseModel):
    """Request to initiate a scan."""
    repository: RepositorySource
    config: Optional[Dict[str, Any]] = None
    skip_ai_layer: bool = False
    name: Optional[str] = None


class ScanStatus(str, Enum):
    """Scan execution status."""
    PENDING = "pending"
    INGESTING = "ingesting"
    PARSING = "parsing"
    ANALYZING = "analyzing"
    BUILDING_GRAPH = "building_graph"
    DETECTING_RISKS = "detecting_risks"
    COMPLETED = "completed"
    FAILED = "failed"


class ScanMetadata(BaseModel):
    """Metadata about a scan execution."""
    id: str
    status: ScanStatus
    repository_url: str
    scan_started_at: datetime
    scan_completed_at: Optional[datetime] = None
    language_stats: Dict[str, int] = {}
    file_count: int = 0
    service_count: int = 0
    finding_count: int = 0
    parsing_errors: int = 0
    error_message: Optional[str] = None


# ============================================================================
# Components & Architecture
# ============================================================================

class Component(BaseModel):
    """A software component (service, library, etc.)."""
    id: str
    name: str
    language: str
    repo_path: str
    owner_team: Optional[str] = None
    type: str = "service"  # service, library, function
    entry_points: List[str] = []
    has_health_check: bool = False
    has_tracing: bool = False
    has_redundancy: bool = False


class Endpoint(BaseModel):
    """An HTTP/RPC endpoint exposed by a component."""
    id: str
    path: str
    method: str  # GET, POST, etc.
    component_id: str
    has_auth: bool
    is_public: bool
    auth_type: Optional[str] = None  # JWT, API_KEY, OAUTH2, etc.
    rate_limit_enabled: bool = False
    rate_limit_rps: Optional[int] = None
    file_location: Optional[str] = None
    line_number: Optional[int] = None


class DataStore(BaseModel):
    """A data storage system."""
    id: str
    name: str
    type: str  # sql, nosql, cache, queue
    owner_service_id: Optional[str] = None
    encrypted_at_rest: bool = False
    has_backup: bool = False
    accessible_from_internet: bool = False


class ExternalDependency(BaseModel):
    """An external dependency (SaaS, library, API)."""
    id: str
    name: str
    type: str  # saas, api, library
    version: Optional[str] = None
    is_critical: bool = False


class ServiceCall(BaseModel):
    """A call/interaction between components."""
    id: str
    caller_id: str
    callee_id: str
    protocol: str  # http, rpc, grpc, queue, etc.
    is_synchronous: bool = True
    is_encrypted: bool = False
    has_retry_logic: bool = False
    has_circuit_breaker: bool = False
    crosses_boundary: bool = False
    boundary_type: Optional[str] = None
    file_location: Optional[str] = None


# ============================================================================
# Findings & Risk Detection
# ============================================================================

class Finding(BaseModel):
    """A detected risk finding."""
    id: str
    scan_id: str
    title: str
    description: str
    severity: Severity
    confidence: float = Field(ge=0, le=1)
    source: FindingSource
    cwe_ids: List[str] = []
    owasp_categories: List[str] = []
    
    # Affected components/resources
    affected_components: List[str] = []
    affected_endpoints: List[str] = []
    affected_data_stores: List[str] = []
    
    # Evidence and traceability
    semgrep_rule_id: Optional[str] = None
    cypher_rule_name: Optional[str] = None
    llm_call_id: Optional[str] = None
    file_locations: Dict[str, int] = {}  # file_path -> line_number
    
    # Remediation
    remediation_steps: List[str] = []
    estimated_effort: str = "MEDIUM"  # LOW, MEDIUM, HIGH, CRITICAL
    references: List[str] = []
    
    # Metadata
    is_duplicate: bool = False
    duplicate_of: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)


class RiskReport(BaseModel):
    """Aggregated risk report for a scan."""
    scan_id: str
    scan_metadata: ScanMetadata
    findings: List[Finding] = []
    
    # Summary
    findings_by_severity: Dict[Severity, int] = {}
    riskiest_services: List[str] = []
    top_findings: List[Finding] = []
    
    # Architecture snapshot
    service_graph_summary: Dict[str, Any] = {}
    
    # Generated at
    generated_at: datetime = Field(default_factory=datetime.utcnow)


# ============================================================================
# API Response Models
# ============================================================================

class HealthResponse(BaseModel):
    """Health check response."""
    status: str
    version: str
    neo4j_connected: bool
    openai_available: bool


class ScanResponse(BaseModel):
    """Response from scan initiation."""
    scan_id: str
    status: ScanStatus
    created_at: datetime


class FindingsResponse(BaseModel):
    """Response with findings list."""
    scan_id: str
    total_findings: int
    findings: List[Finding]
    filters_applied: Optional[Dict[str, Any]] = None


class ExportFormat(str, Enum):
    """Export format types."""
    JSON = "json"
    SARIF = "sarif"
    HTML = "html"
    PDF = "pdf"


# ============================================================================
# Graph Structures for Visualization
# ============================================================================

class GraphNode(BaseModel):
    """A node in the architecture graph."""
    id: str
    label: str
    type: str  # service, endpoint, datastore, etc.
    severity: Optional[Severity] = None
    properties: Dict[str, Any] = {}


class GraphEdge(BaseModel):
    """An edge in the architecture graph."""
    source_id: str
    target_id: str
    label: str
    properties: Dict[str, Any] = {}


class ArchitectureGraph(BaseModel):
    """Complete architecture graph."""
    scan_id: str
    nodes: List[GraphNode]
    edges: List[GraphEdge]
    generated_at: datetime = Field(default_factory=datetime.utcnow)
