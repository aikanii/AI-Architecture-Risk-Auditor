"""
Core data models and schemas for the AI Architecture Risk Auditor.
Pydantic models for API requests/responses and internal data structures.
"""
from pydantic import BaseModel, Field, model_validator
from typing import Optional, List, Dict, Any, Union
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

    @classmethod
    def _missing_(cls, value):
        if isinstance(value, str):
            for member in cls:
                if member.value.upper() == value.upper() or member.name.upper() == value.upper():
                    return member
        return None


class FindingSource(str, Enum):
    """Source of a finding."""
    SEMGREP = "semgrep"
    DETERMINISTIC = "deterministic"
    CYPHER = "deterministic"  # Alias for backward compatibility
    LLM = "llm"
    HYBRID = "hybrid"

    @classmethod
    def _missing_(cls, value):
        if isinstance(value, str):
            for member in cls:
                if member.value.lower() == value.lower() or member.name.lower() == value.lower():
                    return member
        return None


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
    repository: Union[RepositorySource, Dict[str, Any]]
    config: Optional[Dict[str, Any]] = None
    skip_ai_layer: bool = False
    skip_ai: bool = False
    name: Optional[str] = None


class ScanStatus(str, Enum):
    """Scan execution status."""
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    PENDING = "PENDING"
    INGESTING = "INGESTING"
    PARSING = "PARSING"
    ANALYZING = "ANALYZING"
    BUILDING_GRAPH = "BUILDING_GRAPH"
    DETECTING_RISKS = "DETECTING_RISKS"

    @classmethod
    def _missing_(cls, value):
        if isinstance(value, str):
            for member in cls:
                if member.value.upper() == value.upper() or member.name.upper() == value.upper():
                    return member
        return None


class Scan(BaseModel):
    """Scan instance model."""
    id: str
    status: ScanStatus = ScanStatus.QUEUED
    repository_source: Dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    error_message: Optional[str] = None


class ScanMetadata(BaseModel):
    """Metadata about a scan execution."""
    scan_id: Optional[str] = None
    id: Optional[str] = None
    status: ScanStatus = ScanStatus.QUEUED
    repository_url: Optional[str] = None
    repository_source: Optional[Dict[str, Any]] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: Optional[datetime] = None
    scan_started_at: Optional[datetime] = None
    scan_completed_at: Optional[datetime] = None
    language_stats: Dict[str, int] = Field(default_factory=dict)
    file_count: int = 0
    service_count: int = 0
    finding_count: int = 0
    parsing_errors: int = 0
    error_message: Optional[str] = None

    @model_validator(mode='after')
    def sync_id_and_scan_id(self):
        if not self.scan_id and self.id:
            self.scan_id = self.id
        elif not self.id and self.scan_id:
            self.id = self.scan_id
        if not self.scan_started_at and self.created_at:
            self.scan_started_at = self.created_at
        return self


# ============================================================================
# Components & Architecture
# ============================================================================

class Component(BaseModel):
    """A software component (service, library, etc.)."""
    id: str
    name: str
    language: str = "python"
    repo_path: str = ""
    owner_team: Optional[str] = None
    type: str = "service"  # service, library, function
    entry_points: List[str] = Field(default_factory=list)
    has_health_check: bool = False
    has_tracing: bool = False
    has_redundancy: bool = False


class Service(Component):
    """Service component alias for graph repository."""
    pass


class Endpoint(BaseModel):
    """An HTTP/RPC endpoint exposed by a component."""
    id: str
    path: str
    method: str = "GET"  # GET, POST, etc.
    component_id: str
    has_auth: bool = False
    is_public: bool = True
    auth_type: Optional[str] = None  # JWT, API_KEY, OAUTH2, etc.
    rate_limit_enabled: bool = False
    rate_limit_rps: Optional[int] = None
    file_location: Optional[str] = None
    line_number: Optional[int] = None


class DataStore(BaseModel):
    """A data storage system."""
    id: str
    name: str
    type: str = "sql"  # sql, nosql, cache, queue
    owner_service_id: Optional[str] = None
    encrypted_at_rest: bool = False
    has_backup: bool = False
    accessible_from_internet: bool = False


class ExternalDependency(BaseModel):
    """An external dependency (SaaS, library, API)."""
    id: str
    name: str
    type: str = "api"  # saas, api, library
    version: Optional[str] = None
    is_critical: bool = False


class ServiceCall(BaseModel):
    """A call/interaction between components."""
    id: str
    caller_id: str
    callee_id: str
    protocol: str = "http"  # http, rpc, grpc, queue, etc.
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
    cwe_ids: List[Any] = Field(default_factory=list)
    owasp_categories: List[str] = Field(default_factory=list)
    
    # Affected components/resources
    affected_components: List[str] = Field(default_factory=list)
    affected_endpoints: List[str] = Field(default_factory=list)
    affected_data_stores: List[str] = Field(default_factory=list)
    
    # Evidence and traceability
    semgrep_rule_id: Optional[str] = None
    cypher_rule_name: Optional[str] = None
    source_rule: Optional[str] = None
    llm_call_id: Optional[str] = None
    file_locations: Dict[str, Any] = Field(default_factory=dict)
    
    # Remediation
    remediation_steps: List[str] = Field(default_factory=list)
    estimated_effort: str = "MEDIUM"  # LOW, MEDIUM, HIGH, CRITICAL
    references: List[str] = Field(default_factory=list)
    
    # Metadata
    is_duplicate: bool = False
    duplicate_of: Optional[str] = None
    status: str = "OPEN"
    dismiss_reason: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)

    @model_validator(mode='after')
    def sync_source_rule(self):
        if not self.source_rule:
            self.source_rule = self.semgrep_rule_id or self.cypher_rule_name
        return self

    def __getitem__(self, item):
        return getattr(self, item)

    def get(self, item, default=None):
        return getattr(self, item, default)

    def __contains__(self, item):
        return hasattr(self, item)


class RiskReport(BaseModel):
    """Aggregated risk report for a scan."""
    scan_id: str
    scan_metadata: ScanMetadata
    findings: List[Finding] = Field(default_factory=list)
    
    # Summary
    findings_by_severity: Dict[str, int] = Field(default_factory=dict)
    riskiest_services: List[str] = Field(default_factory=list)
    top_findings: List[Finding] = Field(default_factory=list)
    
    # Architecture snapshot
    service_graph_summary: Dict[str, Any] = Field(default_factory=dict)
    
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
    findings: List[Finding]
    total: int = 0
    total_findings: Optional[int] = None
    limit: Optional[int] = None
    offset: Optional[int] = None
    filters_applied: Optional[Dict[str, Any]] = None

    @model_validator(mode='after')
    def sync_totals(self):
        if self.total_findings is None:
            self.total_findings = self.total if self.total > 0 else len(self.findings)
        if self.total == 0 and self.total_findings:
            self.total = self.total_findings
        return self


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
    properties: Dict[str, Any] = Field(default_factory=dict)


class GraphEdge(BaseModel):
    """An edge in the architecture graph."""
    source_id: str
    target_id: str
    label: str
    properties: Dict[str, Any] = Field(default_factory=dict)


class ArchitectureGraph(BaseModel):
    """Complete architecture graph."""
    scan_id: str
    nodes: List[GraphNode] = Field(default_factory=list)
    edges: List[GraphEdge] = Field(default_factory=list)
    generated_at: datetime = Field(default_factory=datetime.utcnow)
