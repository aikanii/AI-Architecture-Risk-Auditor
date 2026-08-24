# Neo4j Graph Schema Reference

## Node Labels

### Scan
Represents a single scan execution.

**Properties:**
- `id` (unique): UUID for the scan
- `repository_url`: URL or path of repository scanned
- `created_at`: Timestamp when scan started
- `completed_at`: Timestamp when scan completed
- `status`: PENDING, INGESTING, PARSING, ANALYZING, COMPLETED, FAILED
- `language_stats`: JSON map of language→file count
- `file_count`: Total files analyzed
- `service_count`: Number of services detected
- `finding_count`: Number of findings
- `parsing_errors`: Count of unparseable files
- `error_message`: If status=FAILED, error description

### Service
A deployed service/microservice/application.

**Properties:**
- `id` (unique): Service identifier (e.g., "payment-api")
- `scan_id`: ID of parent scan
- `name`: Human-readable name
- `language`: Primary language (python, javascript, java, go, etc.)
- `repo_path`: Path within repository
- `owner_team`: Team owning service (optional)
- `type`: service, library, function (default: service)
- `has_health_check`: Boolean
- `has_tracing`: Boolean  
- `has_redundancy`: Boolean (replicas/load balanced)

### Endpoint
An HTTP/RPC endpoint exposed by a service.

**Properties:**
- `id` (unique): Endpoint identifier
- `scan_id`: ID of parent scan
- `path`: HTTP path (e.g., "/api/users")
- `method`: HTTP method (GET, POST, PUT, DELETE, etc.)
- `component_id`: ID of Service exposing this endpoint
- `has_auth`: Boolean - whether endpoint checks authentication
- `is_public`: Boolean - whether accessible from internet
- `auth_type`: JWT, API_KEY, OAUTH2, BASIC, NONE (optional)
- `rate_limit_enabled`: Boolean
- `rate_limit_rps`: Requests per second limit (optional)
- `file_location`: Source file path
- `line_number`: Source line number

### DataStore
A data storage system (database, cache, queue).

**Properties:**
- `id` (unique): DataStore identifier
- `scan_id`: ID of parent scan
- `name`: Name (e.g., "user_database")
- `type`: sql, nosql, cache, queue, filesystem
- `owner_service_id`: ID of owning Service (optional)
- `encrypted_at_rest`: Boolean
- `has_backup`: Boolean
- `accessible_from_internet`: Boolean

### ExternalDependency
An external third-party service or library.

**Properties:**
- `id` (unique): Dependency identifier
- `scan_id`: ID of parent scan
- `name`: Name (e.g., "stripe-api")
- `type`: saas, api, library
- `version`: Version number (optional)
- `is_critical`: Boolean

### Finding
A detected risk or security issue.

**Properties:**
- `id` (unique): Finding identifier
- `scan_id`: ID of parent scan
- `title`: Finding title
- `description`: Detailed description
- `severity`: CRITICAL, HIGH, MEDIUM, LOW, INFO
- `confidence`: 0.0-1.0 confidence score
- `source`: semgrep, deterministic, llm, hybrid
- `cwe_ids`: Array of CWE identifiers
- `owasp_categories`: Array of OWASP categories
- `semgrep_rule_id`: ID of Semgrep rule (if from Semgrep)
- `cypher_rule_name`: Name of Cypher rule (if from deterministic)
- `llm_call_id`: ID of LLM API call (if from LLM)
- `is_duplicate`: Boolean - whether merged from multiple sources
- `duplicate_of`: ID of canonical finding (if duplicate)
- `created_at`: Timestamp
- `updated_at`: Timestamp
- `dismissed_at`: Timestamp if dismissed
- `dismissal_reason`: String if dismissed

### Control Nodes
Security/reliability controls applied to other nodes.

#### AuthControl
- `id` (unique)
- `type`: enum of auth mechanism (JWT, API_KEY, OAUTH2, BASIC, SAML, MUTUAL_TLS)
- `enforced_by`: Service/component name

#### Encryption
- `id` (unique)
- `protocol`: TLS, AES, etc.
- `key_length`: Bit length
- `certificate_pinning`: Boolean

#### RateLimit
- `id` (unique)
- `rps`: Requests per second
- `burst_size`: Max burst

### TrustBoundary
A security trust boundary.

**Properties:**
- `id` (unique): Boundary identifier
- `name`: internet, dmz, internal, data-tier, etc.
- `description`: Description
- `confidentiality_level`: PUBLIC, INTERNAL, CONFIDENTIAL, SECRET

## Relationship Types

### Service Relationships

```cypher
(Service)-[:EXPOSES]->(Endpoint)
  Properties: None (direct containment)
  Semantics: Service exposes/hosts this endpoint

(Service)-[:CALLS {
  protocol: string,
  sync: boolean,
  encrypted: boolean,
  has_retry: boolean,
  has_circuit_breaker: boolean,
  has_timeout: boolean,
  timeout_ms: integer
}]->(Service|ExternalDependency)
  Semantics: Service makes a call to another service
  
(Service)-[:READS_FROM]->(DataStore)
  Properties: table/collection names (optional)
  
(Service)-[:WRITES_TO]->(DataStore)
  Properties: table/collection names (optional)

(Service)-[:DEPENDS_ON]->(ExternalDependency)
  Properties: version constraint (optional)

(Service)-[:HAS_FINDING]->(Finding)
  Properties: None
  Semantics: Finding affects this service

(Service)-[:OWNER]->(Team)
  Properties: None
```

### Endpoint Relationships

```cypher
(Endpoint)-[:PART_OF]->(Service)
  (Inverse of EXPOSES)

(Endpoint)-[:CROSSES_BOUNDARY]->(TrustBoundary)
  Properties: boundary_type: string
  Semantics: Endpoint accessible from this boundary

(Endpoint)-[:PROTECTED_BY]->(AuthControl)
  Properties: None

(Endpoint)-[:PROTECTED_BY]->(RateLimit)
  Properties: None

(Endpoint)-[:CALLS {protocol, encrypted}]->(Service|ExternalDependency)
  Semantics: Endpoint handler makes calls

(Endpoint)-[:HAS_FINDING]->(Finding)
  Properties: None
```

### DataStore Relationships

```cypher
(DataStore)-[:PROTECTED_BY]->(Encryption)
  Properties: None

(DataStore)-[:PROTECTED_BY]->(AuthControl)
  Properties: None

(DataStore)-[:OWNED_BY]->(Service)
  Properties: None
  Semantics: Service owns/manages this datastore

(DataStore)-[:HAS_FINDING]->(Finding)
  Properties: None
```

## Useful Queries

### Find all public endpoints without authentication
```cypher
MATCH (e:Endpoint {is_public: true, has_auth: false})
RETURN e.path, e.method, e.component_id
```

### Find services acting as SPOFs
```cypher
MATCH (caller:Service)-[:CALLS {sync: true}]->(target:Service)
WHERE NOT target.has_redundancy
WITH target, COUNT(DISTINCT caller) as fan_in
WHERE fan_in >= 3
RETURN target.name, fan_in, COLLECT(caller.name) as callers
```

### Find cyclic service dependencies
```cypher
MATCH p=(s:Service)-[:CALLS*2..]->(s)
RETURN p
```

### Find multi-writer data stores
```cypher
MATCH (s:Service)-[:WRITES_TO]->(d:DataStore)
WITH d, COUNT(DISTINCT s) as writers, COLLECT(s.name) as services
WHERE writers > 1 AND NOT EXISTS((d)-[:OWNED_BY]->(:Service))
RETURN d.name, writers, services
```

### Find internet-accessible services with sensitive data access
```cypher
MATCH (s:Service)-[:EXPOSES]->(e:Endpoint {is_public: true})
MATCH (s)-[:READS_FROM|WRITES_TO]->(d:DataStore)
WHERE d.type IN ['sql', 'nosql']
MATCH (d)-[:HAS_FINDING]->(f:Finding {severity: 'HIGH'})
RETURN s.name, e.path, d.name, f.title
```

### Find findings by severity and scan
```cypher
MATCH (s:Scan {id: $scan_id})-[:HAS_FINDING]->(f:Finding)
WHERE f.severity IN ['CRITICAL', 'HIGH']
RETURN f.title, f.description, f.severity
ORDER BY f.severity DESC, f.confidence DESC
```

## Indexing Strategy

Indexes are created on high-cardinality properties for query performance:

- Unique constraints on all `id` properties
- Indexes on `scan_id` (for filtering findings by scan)
- Indexes on `severity` (for sorting findings)
- Indexes on `path` (for endpoint lookup)
- Indexes on `is_public` and `has_auth` (for risk queries)

See `app/graph/schema.py` for all index definitions.

## Maintenance

### Incremental Scans
On re-scan of same repo:
1. Old scan's nodes marked as `stale: true`
2. New scan creates fresh nodes with same IDs (MERGE)
3. Relationships updated to point to fresh nodes
4. Configurable retention (e.g., keep last 5 scans)

### Backup & Restore
```bash
# Backup
neo4j-admin database backup neo4j /path/to/backup

# Restore
neo4j-admin database restore /path/to/backup neo4j
```

## Performance Notes

- **SPOF queries** typically <100ms on 1000-node graphs
- **Cyclic dependency detection** O(services²) - use timeout if >1000 services
- **Finding retrieval** <50ms with proper indexing
- **Graph construction** 1000 nodes/sec with batch writes
