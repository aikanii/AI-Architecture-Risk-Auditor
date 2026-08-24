# AI Architecture Risk Auditor - Architecture Overview

## System Architecture

```
┌─────────────────┐
│   User Input    │
│  (CLI / Web)    │
└────────┬────────┘
         │
         ▼
┌──────────────────────┐
│  Request Handler     │
│  (FastAPI / Click)   │
└────────┬─────────────┘
         │
         ▼
┌───────────────────────────────────────────────────────────┐
│                   Scanning Pipeline                       │
├───────────────────────────────────────────────────────────┤
│                                                           │
│  1. Repository Ingestion                                │
│     └─ Local / Git Clone / Archive Extract              │
│                                                           │
│  2. Multi-Language Parsing (tree-sitter)                │
│     ├─ Python: FastAPI/Flask endpoints, imports        │
│     ├─ JavaScript: Express/NestJS endpoints            │
│     ├─ Java: Spring Boot endpoints                     │
│     └─ Go: stdlib HTTP server patterns                 │
│                                                           │
│  3. Static Analysis (Semgrep)                           │
│     └─ OWASP Top 10, Secrets, Insecure patterns       │
│                                                           │
│  4. Graph Construction (Neo4j)                          │
│     ├─ Service nodes with metadata                     │
│     ├─ Endpoint nodes with auth/encryption             │
│     ├─ DataStore nodes                                 │
│     └─ Relationship edges (CALLS, EXPOSES, etc.)       │
│                                                           │
│  5. Risk Detection (Deterministic)                      │
│     ├─ SPOF detection (high fan-in, no redundancy)     │
│     ├─ Unprotected endpoint detection                  │
│     ├─ Multi-writer datastore detection                │
│     ├─ Cyclic dependency detection                     │
│     └─ Missing observability detection                 │
│                                                           │
│  6. LLM Enrichment (Optional, OpenAI)                   │
│     ├─ Narrative generation                            │
│     ├─ Severity confirmation                           │
│     ├─ Remediation suggestion                          │
│     └─ Finding deduplication                           │
│                                                           │
└───────────────────────────────────────────────────────────┘
         │
         ▼
┌──────────────────────────────────────┐
│   Neo4j Graph Database               │
│   (Scan metadata, Graph, Findings)   │
└──────────────────────────────────────┘
         │
         ▼
┌──────────────────────────────────────┐
│  Reporting & Export                  │
│  ├─ REST API responses               │
│  ├─ JSON/SARIF/HTML/PDF export      │
│  └─ Web UI visualization             │
└──────────────────────────────────────┘
```

## Component Details

### Repository Ingestion (`app/ingestion/`)
- **Local paths**: Direct filesystem scan
- **Git repositories**: Clone with optional branch/token support
- **Archives**: Extract .zip, .tar, .tar.gz
- **Pattern matching**: Include/exclude file patterns (respects .gitignore style)

### Parsing Layer (`app/parser/`)
- **Multi-language support**: Python, JavaScript/TypeScript, Java, Go
- **Per-language extraction**:
  - HTTP endpoints (paths, methods, handlers)
  - Outbound calls (HTTP, database, queue)
  - Environment variable references
  - Authentication decorators/middleware
  - Import/dependency statements
- **Resilient**: Parse errors logged but don't crash entire scan
- **Caching**: Optional AST caching by file hash for incremental scans

### Static Analysis (`app/semgrep_runner/`)
- **Semgrep integration**: Subprocess invocation with JSON output
- **Default rule packs**: OWASP Top 10, CWE Top 25, Secrets, Security Audit
- **Custom rules**: Support for organization-specific Semgrep configs
- **Normalization**: Convert findings to common `Finding` schema

### Graph Database (`app/graph/`)
- **Neo4j driver**: Official Python driver with connection pooling
- **Schema**: Defined in `schema.py` with constraints and indexes
- **Repository pattern**: `GraphRepository` class encapsulates all writes
- **Idempotency**: MERGE-based upserts prevent duplicate nodes/edges on re-scan
- **Transactions**: All writes are transactional and atomic

### Risk Detection (`app/risk_engine/`)
- **Deterministic engine**: Cypher queries for structural patterns
  - SPOF: High fan-in + no redundancy
  - Unprotected endpoints: Public + no auth
  - Multi-writer datastores: Shared access without owner abstraction
  - Cyclic dependencies: Service call cycles
  - Missing observability: No health checks/tracing on critical paths
  
- **LLM engine**: OpenAI API for narrative generation
  - Structured outputs (JSON schema) for validated responses
  - Redaction of secrets before API calls
  - Caching of LLM responses to reduce API costs
  - Graceful degradation if API unavailable

- **Deduplicator**: Merge related findings from different sources
  - Groups by affected components
  - Elevates severity to highest in group
  - Combines remediation steps
  - Marks duplicates for tracking

### API Layer (`app/api/`)
- **REST endpoints**:
  - `/api/scans/`: POST (initiate), GET (list), GET/{id} (status)
  - `/api/findings/{scan_id}`: GET (filtered list)
  - `/api/graph/{scan_id}`: GET (full graph), GET/nodes, GET/edges
  - `/api/reports/{scan_id}`: GET (summary), POST/export, GET/export
  
- **OpenAPI/Swagger**: Auto-generated at `/api/docs`

## Data Flow

1. **User initiates scan** via CLI or Web UI
2. **Repository is ingested** to local temp directory
3. **Code is parsed** file-by-file, extracting architectural signals
4. **Graph nodes created** for services, endpoints, datastores
5. **Relationships created** (CALLS, EXPOSES, READS_FROM, etc.)
6. **Semgrep runs** on the codebase, producing security findings
7. **Deterministic rules execute** as Cypher queries against the graph
8. **Findings are deduplicated** and merged
9. **LLM enriches findings** (if enabled) with narratives and severity
10. **Report is generated** and stored in database
11. **Results exposed** via REST API and web UI

## Security Considerations

### Secret Redaction
- Secrets are never logged in plaintext
- Before LLM API calls, sensitive values are redacted
- Redaction patterns: `api_key=`, `password=`, `secret=`, AWS keys, OpenAI keys
- Hash-based comparison for detecting secret presence without storing plaintext

### Code Execution
- **Zero code execution**: All analysis is static only
- No remote execution, no network calls to target system
- Safe to scan untrusted/malicious code

### Data Privacy
- **On-premise option**: Run without OpenAI API
- **Data flow**: Only graph metadata + error messages sent to LLM
- **Secret handling**: Never send raw secret values to any external service
- **Audit trail**: Every finding traceable to its source (file:line, rule, LLM call ID)

## Configuration

See `.env.example` for all configurable options:
- Neo4j connection parameters
- OpenAI API key and model selection
- Scan timeouts and worker counts
- Risk threshold tuning (SPOF fan-in, boundary crossing)
- Security redaction settings

## Performance Characteristics

- **Parsing**: O(files) - parallelizable by file
- **Semgrep**: O(LOC) - fast, <5min for 500k LOC
- **Graph construction**: O(signals) - batched writes
- **Risk queries**: O(services) per rule - Cypher optimization handles
- **LLM calls**: Batched and cached to minimize API cost
- **Expected SLA**: <10 minutes for full pipeline on 500k LOC repo

## Testing Strategy

- **Unit tests**: Per-module extraction, rule logic, deduplication
- **Integration tests**: Full pipeline on demo vulnerable repo
- **Regression baseline**: Expected findings for demo repo
- **Acceptance criteria**: Detects all seeded vulnerabilities

## Future Extensions

- **Additional languages**: Add language-specific parsers (C#, Ruby, PHP)
- **Additional risk rules**: Extend deterministic Cypher queries
- **Historical tracking**: Store scan results over time for trend analysis
- **Custom rules marketplace**: Community-contributed risk rules
- **IDE integration**: VS Code extension for real-time linting
- **Policy enforcement**: Scan gate in CI/CD with SARIF annotation
