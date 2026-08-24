"""Neo4j graph schema definition and migration scripts."""

# Neo4j schema as Cypher statements
SCHEMA_STATEMENTS = [
    # Create constraints for idempotency
    """
    CREATE CONSTRAINT scan_id_unique
    IF NOT EXISTS
    FOR (s:Scan) REQUIRE s.id IS UNIQUE
    """,
    
    """
    CREATE CONSTRAINT service_id_unique
    IF NOT EXISTS
    FOR (s:Service) REQUIRE s.id IS UNIQUE
    """,
    
    """
    CREATE CONSTRAINT endpoint_id_unique
    IF NOT EXISTS
    FOR (e:Endpoint) REQUIRE e.id IS UNIQUE
    """,
    
    """
    CREATE CONSTRAINT datastore_id_unique
    IF NOT EXISTS
    FOR (d:DataStore) REQUIRE d.id IS UNIQUE
    """,
    
    """
    CREATE CONSTRAINT finding_id_unique
    IF NOT EXISTS
    FOR (f:Finding) REQUIRE f.id IS UNIQUE
    """,
    
    # Create indexes for query performance
    """
    CREATE INDEX service_name
    IF NOT EXISTS
    FOR (s:Service) ON (s.name)
    """,
    
    """
    CREATE INDEX endpoint_path
    IF NOT EXISTS
    FOR (e:Endpoint) ON (e.path)
    """,
    
    """
    CREATE INDEX finding_severity
    IF NOT EXISTS
    FOR (f:Finding) ON (f.severity)
    """,
    
    """
    CREATE INDEX finding_scan_id
    IF NOT EXISTS
    FOR (f:Finding) ON (f.scan_id)
    """,
    
    """
    CREATE INDEX service_scan_id
    IF NOT EXISTS
    FOR (s:Service) ON (s.scan_id)
    """,
]


CYPHER_RISK_RULES = {
    # SPOF Detection: Service with high fan-in and no redundancy
    "spof_high_fan_in": """
    MATCH (caller:Service)-[:CALLS {sync: true}]->(target:Service)
    WHERE NOT target.has_redundancy
    WITH target, COUNT(DISTINCT caller) as in_degree
    WHERE in_degree >= $threshold
    RETURN 
        target.id as service_id,
        target.name as service_name,
        in_degree as fan_in_count,
        COLLECT(DISTINCT caller.name) as callers
    """,
    
    # Unprotected boundary crossing
    "unprotected_boundary_crossing": """
    MATCH (ep:Endpoint)-[:CALLS {encrypted: false}]->(ext)
    WHERE ep.is_public AND NOT EXISTS((ep)-[:PROTECTED_BY]->(:AuthControl))
    RETURN 
        ep.id as endpoint_id,
        ep.path as endpoint_path,
        "missing_auth_or_encryption" as risk_type
    """,
    
    # Multi-writer datastore
    "multi_writer_datastore": """
    MATCH (ds:DataStore)<-[:WRITES_TO]-(svc:Service)
    WITH ds, COUNT(DISTINCT svc) as writer_count, COLLECT(svc.name) as writers
    WHERE writer_count > 1 AND NOT EXISTS((ds)-[:OWNED_BY]->(:Service))
    RETURN 
        ds.id as datastore_id,
        ds.name as datastore_name,
        writer_count as writer_count,
        writers as writer_services
    """,
    
    # Cyclic dependencies
    "cyclic_dependency": """
    MATCH (s1:Service)-[:CALLS*2..]->(s1)
    WHERE s1.scan_id = $scan_id
    RETURN 
        s1.id as service_id,
        s1.name as service_name,
        "cyclic_dependency" as risk_type
    """,
    
    # Secrets exposed to internet
    "secrets_exposed": """
    MATCH (s:Service)-[:EXPOSES]->(ep:Endpoint)
    WHERE ep.is_public AND EXISTS((s)-[:HAS_FINDING]->(:Finding {source: "semgrep"}))
    RETURN 
        s.id as service_id,
        s.name as service_name,
        ep.path as endpoint_path
    """,
}


# Neo4j node and relationship structure documentation
SCHEMA_DOCUMENTATION = """
# Neo4j Graph Schema for AI Architecture Risk Auditor

## Node Labels

### Scan
- id (unique, string): UUID for the scan execution
- repository_url (string): URL of scanned repository
- started_at (datetime): When scan started
- completed_at (datetime): When scan completed
- status (enum): PENDING, PARSING, ANALYZING, COMPLETED, FAILED
- language_stats (json): Language breakdown
- file_count (int): Total files scanned

### Service
- id (unique, string): Service identifier (e.g., "api-service")
- scan_id (string): ID of parent scan
- name (string): Service name
- language (string): Primary language (python, js, java, go, etc.)
- repo_path (string): Path within repository
- owner_team (string, optional): Team owning the service
- has_health_check (bool): Whether health check endpoint exists
- has_tracing (bool): Whether service emits traces
- has_redundancy (bool): Whether service has failover/replica

### Endpoint
- id (unique, string): Endpoint identifier
- scan_id (string): ID of parent scan
- path (string): HTTP path (e.g., "/api/users")
- method (string): HTTP method (GET, POST, etc.)
- component_id (string): ID of Service exposing endpoint
- has_auth (bool): Whether endpoint checks authentication
- is_public (bool): Whether endpoint is internet-facing
- auth_type (string): Type of auth if present (JWT, API_KEY, OAUTH2)
- rate_limit_enabled (bool): Whether rate limiting is active
- rate_limit_rps (int): Requests per second limit if enabled
- file_location (string): Source file path
- line_number (int): Source line number

### DataStore
- id (unique, string): DataStore identifier
- scan_id (string): ID of parent scan
- name (string): Name of data store (e.g., "user_db")
- type (string): Type (sql, nosql, cache, queue)
- owner_service_id (string, optional): Service that owns this datastore
- encrypted_at_rest (bool): Whether encryption at rest enabled
- has_backup (bool): Whether backups exist
- accessible_from_internet (bool): Whether directly accessible from internet

### ExternalDependency
- id (unique, string): Dependency identifier
- name (string): Dependency name
- type (string): Type (saas, api, library)
- version (string, optional): Version number
- is_critical (bool): Whether mission-critical

### Finding
- id (unique, string): Finding identifier
- scan_id (string): ID of parent scan
- title (string): Finding title
- description (string): Detailed description
- severity (enum): CRITICAL, HIGH, MEDIUM, LOW, INFO
- confidence (float): Confidence score 0-1
- source (string): Where finding came from (semgrep, deterministic, llm)
- cwe_ids (array): Associated CWE IDs
- owasp_categories (array): OWASP categories
- semgrep_rule_id (string): Semgrep rule that triggered
- cypher_rule_name (string): Cypher rule that triggered
- llm_call_id (string): LLM reasoning session ID if from LLM
- created_at (datetime): When finding was created

### AuthControl / Encryption / RateLimit
Control nodes representing security/reliability controls applied to endpoints or calls.

### TrustBoundary
- id (unique, string): Boundary identifier
- name (string): Boundary name (internet, dmz, internal, data-tier)
- description (string): Boundary description

## Relationships

### Service Relationships
- (Service)-[:EXPOSES]->(Endpoint): Service exposes HTTP endpoint
- (Service)-[:CALLS {protocol, sync, encrypted, has_retry, has_circuit_breaker}]->(Service|ExternalDependency)
- (Service)-[:READS_FROM]->(DataStore)
- (Service)-[:WRITES_TO]->(DataStore)
- (Service)-[:DEPENDS_ON]->(ExternalDependency)
- (Service)-[:HAS_FINDING]->(Finding): Finding related to service
- (Service)-[:OWNED_BY]->(Team, optional)

### Endpoint Relationships
- (Endpoint)-[:CROSSES]->(TrustBoundary): Endpoint crosses boundary
- (Endpoint)-[:PROTECTED_BY]->(AuthControl): Has authentication control
- (Endpoint)-[:PROTECTED_BY]->(RateLimit): Has rate limiting control
- (Endpoint)-[:HAS_FINDING]->(Finding): Finding related to endpoint

### DataStore Relationships
- (DataStore)-[:PROTECTED_BY]->(Encryption): Has encryption control
- (DataStore)-[:OWNED_BY]->(Service): Service owns datastore
- (DataStore)-[:HAS_FINDING]->(Finding): Finding related to datastore

## Querying Patterns

### Find all services exposed to internet
MATCH (s:Service)-[:EXPOSES]->(e:Endpoint {is_public: true}) RETURN s, e

### Find all direct cross-boundary calls
MATCH (s1:Service)-[:CALLS]->(s2:Service)
WHERE s1.trust_boundary <> s2.trust_boundary
RETURN s1, s2

### Find data stores accessible from multiple services
MATCH (s:Service)-[:READS_FROM|WRITES_TO]->(d:DataStore)
WITH d, COUNT(DISTINCT s) as accessors
WHERE accessors > 1
RETURN d, accessors
"""
