# AI Architecture Risk Auditor

[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)]()
[![Tests](https://img.shields.io/badge/tests-36%20passed%20%2F%20100%25-success.svg)]()
[![Python](https://img.shields.io/badge/python-3.11%2B-blue.svg)]()
[![FastAPI](https://img.shields.io/badge/FastAPI-0.104%2B-009688.svg)]()
[![React](https://img.shields.io/badge/react-18.2%2B-61dafb.svg)]()
[![Cytoscape](https://img.shields.io/badge/cytoscape.js-3.34%2B-orange.svg)]()
[![SARIF](https://img.shields.io/badge/SARIF-2.1.0-blueviolet.svg)]()
[![License](https://img.shields.io/badge/license-MIT-green.svg)]()

> An enterprise-grade, static analysis platform that automatically reconstructs distributed microservice architectures into graph topologies, flags structural vulnerabilities, single points of failure (SPOFs), and unencrypted call chains, and generates actionable, AI-assisted remediation reports with zero runtime code execution.

---

## Table of Contents

- [Architecture diagram](#architecture-diagram)
- [System workflow](#system-workflow)
- [Feature list](#feature-list)
- [API documentation](#api-documentation)
- [Database schema](#database-schema)
- [AI architecture](#ai-architecture)
- [Security considerations](#security-considerations)
- [Testing](#testing)
- [Docker setup](#docker-setup)
- [CI/CD](#cicd)
- [Screenshots](#screenshots)
- [Demo](#demo)

---

## Architecture diagram

The following diagram illustrates the multi-stage static analysis pipeline, graph modeling layer, rule engine, and interfaces:

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                                   CLIENT INTERFACES                                    │
│                                                                                        │
│   ┌──────────────────────────┐  ┌──────────────────────────┐  ┌────────────────────┐   │
│   │  Glassmorphic React UI   │  │   Headless CLI Runner    │  │  CI/CD Automations │   │
│   │  (Cytoscape Topology)    │  │   (Click / Fail-On Gates)│  │  (GitHub Actions)  │   │
│   └────────────┬─────────────┘  └────────────┬─────────────┘  └─────────┬──────────┘   │
└────────────────┼─────────────────────────────┼──────────────────────────┼──────────────┘
                 │                             │                          │
                 ▼                             ▼                          ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                              FASTAPI APPLICATION GATEWAY                               │
│                         /api/scans  •  /api/graph  •  /api/findings                    │
└──────────────────────────────────────────┬─────────────────────────────────────────────┘
                                           │
                                           ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                            STATIC ANALYSIS & INGESTION CORE                            │
│                                                                                        │
│  ┌───────────────────────┐  ┌─────────────────────────────┐  ┌───────────────────────┐ │
│  │ Repository Ingestion  │  │  Multi-Language AST Engine   │  │ Semgrep Static Engine │ │
│  │ Local Dir / Git Repo  │─▶│  Python / JS / TS / Go / Java│─▶│ OWASP Top 10, Secrets │ │
│  │ Manifests (Compose)   │  │  Endpoints, DBs, HTTP calls  │  │ Hardcoded Credentials │ │
│  └───────────────────────┘  └──────────────┬──────────────┘  └───────────┬───────────┘ │
└────────────────────────────────────────────┼─────────────────────────────┼─────────────┘
                                             │                             │
                                             ▼                             │
┌──────────────────────────────────────────────────────────────────────────┼─────────────┐
│                           ARCHITECTURE GRAPH ENGINE                      │             │
│                                                                          │             │
│  ┌────────────────────────────────────────────────────────────────────┐  │             │
│  │ GraphRepository Layer (Dual-Mode Execution)                        │  │             │
│  │  ├─ Neo4j Graph Database (Bolt / APOC / Cypher)                   │◀─┘             │
│  │  └─ Persistent In-Memory Offline Store (/tmp/aiara_store.json)     │                │
│  └─────────────────────────────────┬──────────────────────────────────┘                │
└────────────────────────────────────┼───────────────────────────────────────────────────┘
                                     │
                                     ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                         DETERMINISTIC & AI RISK ENGINE                                 │
│                                                                                        │
│  ┌───────────────────────────────────┐       ┌──────────────────────────────────────┐  │
│  │   Deterministic Graph Rules       │       │   Context-Aware AI Reasoning Layer   │  │
│  │   • SPOF Bottleneck Detection     │       │   • AST Secret Redaction Guardrails  │  │
│  │   • Multi-Writer DataStores       │──────▶│   • Blast-Radius Impact Synthesis    │  │
│  │   • Unprotected Public Routes     │       │   • Tailored Remediation Advice      │  │
│  │   • Plain HTTP Inter-Service Calls│       │   (Fully Optional / Air-Gapped Safe) │  │
│  └─────────────────┬─────────────────┘       └──────────────────┬───────────────────┘  │
│                    │                                            │                      │
│                    └─────────────────────┬──────────────────────┘                      │
│                                          ▼                                             │
│                              Deduplication & CWE Normalizer                            │
└──────────────────────────────────────────┬─────────────────────────────────────────────┘
                                           │
                                           ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                               MULTI-FORMAT EXPORTERS                                   │
│            SARIF 2.1.0 (GitHub Code Scanning)  •  JSON Reports  •  HTML Reports        │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## System workflow

The risk audit executes through an automated 8-phase deterministic pipeline:

```
  [1. Ingestion] ────▶ [2. Multi-AST Parsing] ────▶ [3. Graph Population]
                                                            │
  [6. Deduplication] ◀─── [5. Cypher Risk Detection] ◀──────┼───▶ [4. Semgrep SAST]
           │
           ▼
  [7. AI Enrichment] ──▶ [8. Exporters (SARIF / JSON / HTML)]
```

1. **Repository Ingestion**: Scans code directories and parses orchestration manifests (`docker-compose.yml`, Kubernetes YAMLs) to identify service boundaries and network boundaries.
2. **Multi-Language AST Extraction**: Analyzes application code (FastAPI, Flask, Express, NestJS) using AST parsers to detect exposed routes, HTTP methods, authentication dependencies, datastore queries (`psycopg2`, `SQLAlchemy`, `pymongo`), and outbound requests (`requests`, `httpx`, `fetch`).
3. **Graph Construction**: Converts parsed components into directed graph nodes (`Service`, `Endpoint`, `DataStore`) and relationships (`CALLS`, `WRITES_TO`, `READS_FROM`, `EXPOSES`) in the graph layer.
4. **Semgrep Static Security Analysis**: Runs customizable pattern rules against source files to detect code-level security issues (hardcoded API keys, disabled TLS validation, missing rate limits).
5. **Deterministic Graph Auditing**: Executes graph algorithms to detect architectural risks:
   - **Single Point of Failure (SPOF)**: High fan-in services with zero redundancy (`has_redundancy = false`).
   - **Multi-Writer Shared DataStore**: Multiple microservices directly executing writes to the same database.
   - **Unprotected Endpoints**: Public routes lacking authentication middleware or dependency injection.
   - **Plain HTTP Calls**: Inter-service traffic transmitting credentials or payloads over unencrypted channels.
6. **Deduplication & Correlation**: Correlates SAST findings with architectural nodes, merges duplicate detections, and maps each risk to standard CWEs and OWASP Top 10 categories.
7. **AI Narrative Enrichment (Optional)**: If an LLM provider is configured, generates architectural blast-radius summaries and remediation runbooks after scrubbing all sensitive tokens.
8. **Multi-Format Export**: Serializes results into SARIF 2.1.0, JSON, or HTML, and calculates CI/CD pass/fail exit codes against user-defined severity thresholds (`--fail-on HIGH`).

---

## Feature list

| Category | Capability | Details |
| :--- | :--- | :--- |
| **Static Architecture Extraction** | Zero Code Execution | Safely extracts endpoints, services, databases, and dependencies without building or running target code. |
| **Multi-Language AST** | Python & JavaScript/TypeScript | Native support for FastAPI, Flask, Express, NestJS, and raw HTTP clients. |
| **Architectural SPOF Detection** | Critical Bottleneck Detection | Flags critical services (e.g. `auth_service`, `payment_service`) lacking replica scaling. |
| **Shared DataStore Detection** | Anti-Pattern Identification | Flags monolithic shared databases written to by multiple independent microservices. |
| **Unencrypted Traffic Analysis** | Plain HTTP Network Tracing | Detects unencrypted inter-service HTTP communications within internal networks. |
| **Dual-Mode Graph Engine** | Neo4j + In-Memory Fallback | Fully functional with production Neo4j clusters or standalone persistent disk-cached memory. |
| **Interactive Topology UI** | Cytoscape.js Tech Canvas | Features blast-radius node dimming, CoSE/Hierarchical layouts, and quick search. |
| **Security Telemetry** | CWE & OWASP Top 10 Alignment | Findings include verified mappings to `CWE-306`, `CWE-798`, `CWE-770`, and `CWE-20`. |
| **CI/CD Quality Gates** | Configurable Severity Thresholds | CLI exits with non-zero error codes when findings exceed thresholds (`--fail-on HIGH`). |
| **Standardized Exporting** | SARIF 2.1.0, JSON, HTML | Native integration with GitHub Code Scanning, GitLab Security Dashboard, and DefectDojo. |

---

## API documentation

FastAPI delivers an interactive OpenAPI documentation explorer at `http://localhost:8000/docs`.

### Core REST Endpoints

| Method | Endpoint | Description | Query / Body Parameters |
| :--- | :--- | :--- | :--- |
| `GET` | `/health` | Application and database health probe | None |
| `POST` | `/api/scans/` | Trigger an architectural risk scan | `{"repository": {"type": "local", "path": "..."}}` |
| `GET` | `/api/scans/` | List all historical scans | `?limit=20&offset=0&status=COMPLETED` |
| `GET` | `/api/scans/{scan_id}` | Retrieve specific scan metadata | `scan_id` (UUID / string) |
| `DELETE`| `/api/scans/{scan_id}` | Delete a scan and associated graph | `scan_id` (UUID / string) |
| `GET` | `/api/findings/{scan_id}` | Retrieve findings for a scan | `?severity=CRITICAL&limit=100` |
| `POST` | `/api/findings/{id}/dismiss` | Dismiss a specific finding | `{"reason": "Accepted risk"}` |
| `GET` | `/api/graph/{scan_id}/nodes` | Get graph nodes for visualization | `?node_type=Service` |
| `GET` | `/api/graph/{scan_id}/edges` | Get graph edges for visualization | `?edge_type=CALLS` |
| `GET` | `/api/graph/{scan_id}/stats` | Get topology and risk metrics | None |
| `GET` | `/api/reports/{scan_id}/summary`| Retrieve high-level executive report | None |
| `GET` | `/api/reports/{scan_id}/export` | Download report in target format | `?format=sarif` (json, sarif, html) |

### API Usage Examples

#### 1. Initiate a Local Repository Scan
```bash
curl -X POST http://localhost:8000/api/scans/ \
  -H "Content-Type: application/json" \
  -d '{
    "repository": {
      "type": "local",
      "path": "/home/user/AI-Architecture-Risk-Auditor/test-fixtures/demo-repo"
    }
  }'
```

**Response (202 Accepted):**
```json
{
  "scan_id": "56aba9bf-8bbe-4cf8-b2c0-702234f7fe88",
  "status": "COMPLETED",
  "created_at": "2026-09-20T15:38:32.887860"
}
```

#### 2. Retrieve Topology Graph Statistics
```bash
curl http://localhost:8000/api/graph/56aba9bf-8bbe-4cf8-b2c0-702234f7fe88/stats
```

**Response (200 OK):**
```json
{
  "scan_id": "56aba9bf-8bbe-4cf8-b2c0-702234f7fe88",
  "total_nodes": 18,
  "total_edges": 23,
  "service_count": 5,
  "endpoint_count": 11,
  "datastore_count": 2,
  "finding_count": 20,
  "findings_by_severity": {
    "CRITICAL": 8,
    "HIGH": 9,
    "MEDIUM": 3
  }
}
```

#### 3. Export SARIF Report for GitHub Code Scanning
```bash
curl http://localhost:8000/api/reports/56aba9bf-8bbe-4cf8-b2c0-702234f7fe88/export?format=sarif \
  -o architecture-audit.sarif
```

---

## Database schema

The graph data model captures microservice architecture nodes and relationships:

```
  ┌─────────────────┐               EXPOSES               ┌──────────────────┐
  │    :Service     │ ──────────────────────────────────▶ │    :Endpoint     │
  └────────┬────────┘                                     └──────────────────┘
           │
           │  CALLS {protocol, is_encrypted, sync}
           ▼
  ┌─────────────────┐             WRITES_TO / READS_FROM  ┌──────────────────┐
  │    :Service     │ ──────────────────────────────────▶ │    :DataStore    │
  └─────────────────┘                                     └──────────────────┘
           ▲                                                        ▲
           │                        AFFECTS                         │
           └─────────────────── ┌─────────────┐ ────────────────────┘
                                │  :Finding   │
                                └─────────────┘
```

### Node Labels & Properties

#### `:Service`
- `id` (String, Primary Key): Unique service name / identifier.
- `name` (String): Display name of the service.
- `language` (String): Implementation language runtime (`python`, `javascript`, etc.).
- `has_health_check` (Boolean): Indicates whether a health endpoint (`/health`) was detected.
- `has_redundancy` (Boolean): Derived from replica specifications in deployment manifests.
- `has_tracing` (Boolean): Distributed tracing instrumentation flag.
- `scan_id` (String): ID of the scan that extracted this entity.

#### `:Endpoint`
- `id` (String, Primary Key): Component ID + HTTP method + route path.
- `path` (String): URL route pattern (e.g. `/api/orders`).
- `method` (String): HTTP verb (`GET`, `POST`, `PUT`, `DELETE`).
- `has_auth` (Boolean): Whether authentication middleware or decorators are present.
- `is_public` (Boolean): Whether endpoint is exposed at the API gateway level.
- `component_id` (String): Parent service identifier.

#### `:DataStore`
- `id` (String, Primary Key): Normalized database identifier.
- `name` (String): Datastore name (e.g. `monolith_db`, `postgres`).
- `store_type` (String): Storage category (`sql`, `nosql`, `cache`).
- `encrypted_at_rest` (Boolean): Storage volume encryption state.

#### `:Finding`
- `id` (String, Primary Key): Unique finding identifier (`{scan_id}_{rule}_{hash}`).
- `title` (String): Clear, actionable summary of the vulnerability.
- `severity` (String): `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, or `INFO`.
- `confidence` (Float): Analytical confidence score (0.0 to 1.0).
- `source` (String): Detection mechanism (`deterministic`, `semgrep`, `llm`).
- `cwe_ids` (List[String]): Associated CWE IDs (e.g. `["CWE-306", "CWE-798"]`).
- `owasp_categories` (List[String]): OWASP Top 10 category classifications.
- `remediation_steps` (List[String]): Step-by-step guidance for engineering remediation.

---

## AI architecture

```
┌─────────────────────┐      1. Extract      ┌────────────────────────────────┐
│  Graph & AST State  │ ───────────────────▶ │  Sanitization & Redaction Core │
└─────────────────────┘                      └──────────────┬─────────────────┘
                                                            │ 2. Scrubbed Context
                                                            ▼
┌─────────────────────┐      3. Synthesize   ┌────────────────────────────────┐
│ Actionable Guidance │ ◀─────────────────── │ OpenAI / Local LLM Provider    │
└─────────────────────┘                      └────────────────────────────────┘
```

1. **Zero Raw Code Transmission**: The AI reasoning layer operates on structured architectural topology and graph metrics—source code files are never sent directly to external LLMs.
2. **Deterministic Redaction Engine**: Before prompt serialization, `app.security.redact_dict` and entropy filters identify and scrub all potential secrets, database passwords, JWT tokens, and private keys.
3. **Optional & Air-Gapped Safe**: If no `OPENAI_API_KEY` is provided, the platform automatically runs in deterministic-only mode. All 36 acceptance and core security rules execute offline without network dependencies.
4. **Focused Context Generation**: The LLM synthesizes blast-radius narratives, validates multi-hop risk combinations, and crafts remediation instructions tailored to the application's runtime framework.

---

## Security considerations

- **Zero Runtime Code Execution**: The auditor operates entirely via AST traversal (`ast`, `tree-sitter`) and static regex analysis. Repositories are never compiled, run in sandboxes, or dynamically imported.
- **Local Fallback Storage**: If Neo4j is offline or unavailable, the system defaults to an in-memory graph repository with local JSON persistence, avoiding required cloud infrastructure.
- **Credential Masking**: Sensitive keys in application configurations or environment files are hashed via SHA-256 for identification and redacted from all exports and UI responses.
- **Strict CORS & Header Guardrails**: Configured with CORS origin protection, preventing cross-site scripting and unauthorized iframe embeds during live deployment previews.

---

## Testing

The test suite covers unit tests, parser integrations, security redaction, and an acceptance test suite validating 7 distinct vulnerability types in a multi-service microservices repository (`test-fixtures/demo-repo`).

### Running Tests

```bash
# Activate virtual environment
source /home/user/venv/bin/activate
cd backend

# Run entire test suite (36 tests)
pytest tests/ -v

# Run acceptance tests only
pytest tests/test_acceptance.py -v

# Run unit tests only
pytest tests/test_core.py -v

# Run with test coverage report
pytest --cov=app tests/
```

### Verified Test Matrix

```
============================= test session starts ==============================
tests/test_acceptance.py::TestDemoRepoVulnerabilities::test_detects_unprotected_endpoint PASSED
tests/test_acceptance.py::TestDemoRepoVulnerabilities::test_detects_hardcoded_secret PASSED
tests/test_acceptance.py::TestDemoRepoVulnerabilities::test_detects_spof_auth_service PASSED
tests/test_acceptance.py::TestDemoRepoVulnerabilities::test_detects_multi_writer_datastore PASSED
tests/test_acceptance.py::TestDemoRepoVulnerabilities::test_detects_unencrypted_calls PASSED
tests/test_acceptance.py::TestDemoRepoVulnerabilities::test_severity_distribution PASSED
tests/test_acceptance.py::TestDemoRepoVulnerabilities::test_total_finding_count PASSED
tests/test_acceptance.py::TestDemoRepoVulnerabilities::test_findings_have_remediation PASSED
tests/test_acceptance.py::TestDemoRepoVulnerabilities::test_findings_have_cwe_refs PASSED
tests/test_acceptance.py::TestDemoRepoVulnerabilities::test_idempotent_rescanning PASSED
tests/test_acceptance.py::TestDemoRepoVulnerabilities::test_ai_layer_optional PASSED
tests/test_acceptance.py::TestDemoRepoArchitecture::test_services_extracted PASSED
tests/test_acceptance.py::TestDemoRepoArchitecture::test_endpoints_extracted PASSED
tests/test_acceptance.py::TestDemoRepoArchitecture::test_datastore_extracted PASSED
tests/test_acceptance.py::TestDemoRepoArchitecture::test_dependencies_extracted PASSED
tests/test_core.py::TestSecurity::test_hash_secret PASSED
tests/test_core.py::TestSecurity::test_redact_secret PASSED
tests/test_core.py::TestSecurity::test_redact_dict PASSED
tests/test_core.py::TestParsers::test_python_parser_init PASSED
tests/test_core.py::TestParsers::test_python_parser_extension_detection PASSED
tests/test_core.py::TestParsers::test_js_parser_init PASSED
tests/test_core.py::TestParsers::test_js_parser_extension_detection PASSED
tests/test_core.py::TestModels::test_scan_creation PASSED
tests/test_core.py::TestModels::test_finding_creation PASSED
tests/test_core.py::TestModels::test_finding_severity_comparison PASSED
tests/test_core.py::TestGraphRepository::test_create_scan PASSED
tests/test_core.py::TestGraphRepository::test_repository_has_required_methods PASSED
tests/test_core.py::TestDeterministicRiskDetection::test_spof_severity PASSED
tests/test_core.py::TestLLMEngine::test_llm_redaction_before_call PASSED
tests/test_core.py::TestAPIEndpoints::test_scan_routes_exist PASSED
tests/test_core.py::TestAPIEndpoints::test_findings_routes_exist PASSED
tests/test_core.py::TestAPIEndpoints::test_graph_routes_exist PASSED
tests/test_core.py::TestAPIEndpoints::test_reports_routes_exist PASSED
tests/test_core.py::TestReportExport::test_export_json_format PASSED
tests/test_core.py::TestReportExport::test_export_sarif_format PASSED
tests/test_core.py::TestConfigValidation::test_settings_load PASSED
============================== 36 passed in 8.02s ==============================
```

---

## Docker setup

The project includes container configurations via `docker-compose.yml`.

### Prerequisites
- Docker Engine 20.10+
- Docker Compose v2.0+

### Starting the Stack

```bash
# Clone repository
git clone https://github.com/aikanii/AI-Architecture-Risk-Auditor.git
cd AI-Architecture-Risk-Auditor

# Configure environment variables
cp .env.example .env

# Spin up Neo4j, FastAPI Backend, and React Frontend
docker-compose up -d --build
```

### Verifying Service Health

```bash
docker-compose ps
```

| Service | Container Port | Host Port | Purpose |
| :--- | :--- | :--- | :--- |
| **neo4j** | `7474`, `7687` | `http://localhost:7474` | Graph database browser and Bolt API |
| **backend** | `8000` | `http://localhost:8000` | FastAPI server and static React build |
| **frontend** | `3000` | `http://localhost:3000` | Optional Webpack live development server |

---

## CI/CD

Integrate the auditor into your GitHub Actions workflow (`.github/workflows/audit.yml`) to automatically enforce architectural standards on pull requests:

```yaml
name: Architecture Risk Gate

on:
  pull_request:
    branches: [main]

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4

      - name: Setup Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - name: Install Dependencies
        run: |
          pip install -r backend/requirements.txt
          pip install semgrep

      - name: Execute Architectural Scan
        run: |
          python -m app.cli scan . \
            --format sarif \
            --output audit-results.sarif \
            --fail-on HIGH

      - name: Publish SARIF to GitHub Security Tab
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: audit-results.sarif
          category: architecture-auditor
```

---

## Screenshots

### 1. Architectural Risk Dashboard
Displays real-time vulnerability statistics, completed audit tracking, service count telemetry, and the scan trigger interface with a dark glassmorphic finish.

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│  🛡️ AI ARCHITECTURE AUDITOR     Dashboard   Scans   Architecture Graph   Findings   ↗ │
├────────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                        │
│   Architectural Risk Dashboard                                                         │
│                                                                                        │
│   ┌────────────────────────────────────────────────────────────────────────────────┐   │
│   │  >_ Initiate New Scan                                                          │   │
│   │  [/path/to/microservices/repo                                ]  [ Start Scan ] │   │
│   └────────────────────────────────────────────────────────────────────────────────┘   │
│                                                                                        │
│   ┌───────────────┐  ┌───────────────┐  ┌───────────────┐  ┌───────────────┐           │
│   │   CRITICAL    │  │  TOTAL SCANS  │  │   COMPLETED   │  │   SERVICES    │           │
│   │       8       │  │       4       │  │       4       │  │       5       │           │
│   └───────────────┘  └───────────────┘  └───────────────┘  └───────────────┘           │
│                                                                                        │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

### 2. Cybersecurity Topology Graph Canvas
Interactive Cytoscape.js canvas with CAD dot-matrix styling, directional dependency flows, and blast-radius neighbor tracing.

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│  [ Service Mesh ] [ Full Topology ] [ Data Stores ] [ Vulnerable Nodes ]  [ Search ]   │
├────────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                        │
│              ┌───────────────┐                                                         │
│              │  api_gateway  │                                                         │
│              └───────┬───────┘                                                         │
│                      │                                                                 │
│         Plain HTTP ──┼──────────────────────┐ Plain HTTP                               │
│         (Dashed)     ▼                      ▼ (Dashed)                                 │
│              ┌───────────────┐       ┌───────────────┐                                 │
│              │ auth_service  │       │ order_service │                                 │
│              │ (SPOF Alert)  │       └───────┬───────┘                                 │
│              └───────────────┘               │                                         │
│                                       Writes │ (Amber)                                 │
│                                              ▼                                         │
│                                      ┌───────────────┐                                 │
│                                      │  monolith_db  │ ◀── Writes (user_service)       │
│                                      │ (Multi-Writer)│                                 │
│                                      └───────────────┘                                 │
│                                                                                        │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

### 3. Component Telemetry & Findings Inspector
Deep inspection drawer showing runtime properties, authentication status, and mapped CWE vulnerability links.

---

## Demo

A vulnerable multi-service microservice repository is provided in `test-fixtures/demo-repo` to demonstrate risk detection:

```
test-fixtures/demo-repo/
├── docker-compose.yml       # Defines 5 microservices & PostgreSQL datastore
├── api_gateway/             # Unprotected endpoints, missing authentication
├── auth_service/            # Single point of failure (SPOF), hardcoded secret
├── user_service/            # Unprotected endpoints, multi-writer shared DB access
├── order_service/           # Unprotected endpoints, unencrypted HTTP requests
└── payment_service/         # Hardcoded payment credentials, zero replica redundancy
```

### Running the Demo via CLI

```bash
# 1. Navigate to backend directory
cd backend

# 2. Run a scan against the demo fixture
python -m app.cli scan ../test-fixtures/demo-repo --output /tmp/demo-report.json

# 3. View extracted findings
python -m app.cli findings $(python -m app.cli list-scans | awk 'NR==4 {print $1}')

# 4. Export report to SARIF format
python -m app.cli export $(python -m app.cli list-scans | awk 'NR==4 {print $1}') \
  --format sarif \
  --output /tmp/demo-report.sarif
```

### Running the Demo via Web UI

1. Start the backend: `python -m app.main`
2. Open your browser to `http://localhost:8000/`
3. Enter `/home/user/AI-Architecture-Risk-Auditor/test-fixtures/demo-repo` in the scan input field and click **Start Scan**.
4. Explore the **Architecture Graph** to trace dependencies and review the **Findings** tab for remediation steps.

---

## License

This project is licensed under the [MIT License](LICENSE).
