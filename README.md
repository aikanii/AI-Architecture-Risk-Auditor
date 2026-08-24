# AI Architecture Risk Auditor

A production-quality static analysis platform that scans software repositories to reconstruct service architecture as a graph and uses AI-assisted reasoning to flag security/reliability risks, single points of failure, and risky architectural decisions.

## Features

- **Multi-language parsing** via tree-sitter for AST extraction
- **Pattern-based static analysis** via Semgrep for OWASP/security rules
- **Service dependency graph** via Neo4j for structural risk analysis
- **AI reasoning layer** via OpenAI API for narrative generation and context understanding
- **Interactive web UI** with graph visualization and findings dashboard
- **CLI and REST API** for headless/CI/CD integration
- **Multiple export formats**: JSON, SARIF (for GitHub code scanning), HTML/PDF reports
- **Zero code execution** — entirely static analysis

## Quick Start

### Prerequisites

- Docker & Docker Compose (for Neo4j, optional for local dev)
- Python 3.11+
- Node.js 18+ (for frontend)
- OpenAI API key (optional, for AI layer)
- Semgrep (install via `pip install semgrep`)

### Setup

```bash
# Clone and install backend
cd backend
python -m venv venv
source venv/bin/activate  # or `venv\Scripts\activate` on Windows
pip install -r requirements.txt

# Set environment variables
cp .env.example .env
# Edit .env with your OpenAI API key and Neo4j credentials

# Start Neo4j (optional, via Docker)
docker-compose up -d

# Run migrations
python -m scripts.setup_neo4j

# Start backend
uvicorn app.main:app --reload

# In another terminal, set up frontend
cd frontend
npm install
npm start
```

Visit http://localhost:3000 for the web UI, or http://localhost:8000/api/docs for the REST API.

### CLI Usage

```bash
# Scan a local repository
python -m app.cli scan /path/to/repo --config config.yaml

# Scan with fail threshold (for CI/CD)
python -m app.cli scan /path/to/repo --fail-on HIGH

# Export report
python -m app.cli export <scan-id> --format sarif --output report.sarif
```

## Architecture

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for detailed architecture, schema, and design decisions.

## Project Structure

```
.
├── backend/                      # Python FastAPI application
│   ├── app/
│   │   ├── main.py              # FastAPI app initialization
│   │   ├── cli.py               # CLI entry point
│   │   ├── config.py            # Configuration management
│   │   ├── ingestion/           # Repo scanning & cloning
│   │   ├── parser/              # tree-sitter integration
│   │   ├── semgrep_runner/      # Semgrep wrapper
│   │   ├── graph/               # Neo4j schema & repository
│   │   ├── risk_engine/         # Risk rules (Cypher + LLM)
│   │   ├── reporting/           # Report generation & export
│   │   ├── api/                 # REST endpoints
│   │   └── models/              # Pydantic schemas
│   ├── tests/                   # Unit & integration tests
│   └── requirements.txt
├── frontend/                    # React application
│   ├── public/
│   ├── src/
│   │   ├── components/          # React components
│   │   ├── pages/               # Page components
│   │   ├── services/            # API client
│   │   ├── utils/               # Utilities (graph rendering, etc.)
│   │   └── App.tsx
│   └── package.json
├── rules/                       # Semgrep rule packs & Cypher queries
│   ├── semgrep/
│   │   ├── owasp-top10.yaml
│   │   ├── secrets.yaml
│   │   └── ...
│   └── cypher/
│       ├── spof.cypher
│       ├── boundary_crossing.cypher
│       └── ...
├── test-fixtures/              # Demo vulnerable repo
│   └── demo-repo/              # Multi-service example
├── docs/
│   ├── ARCHITECTURE.md
│   ├── SCHEMA.md
│   ├── ADDING_LANGUAGE.md
│   ├── ADDING_RISK_RULE.md
│   ├── DATA_PRIVACY.md
│   └── DEPLOYMENT.md
├── docker-compose.yml          # Neo4j + app stack
└── .env.example
```

## Documentation

- [Architecture Overview](docs/ARCHITECTURE.md)
- [Neo4j Graph Schema](docs/SCHEMA.md)
- [Adding a New Language](docs/ADDING_LANGUAGE.md)
- [Adding a Risk Rule](docs/ADDING_RISK_RULE.md)
- [Data Privacy & LLM Redaction](docs/DATA_PRIVACY.md)
- [Deployment Guide](docs/DEPLOYMENT.md)

## Acceptance Criteria Status

- ✓ CLI detects seeded vulnerabilities in demo repo
- ✓ Re-scans produce identical findings (idempotent)
- ✓ AI layer optional; deterministic report available offline
- ✓ SARIF export validates against schema
- ✓ Secret redaction verified by test suite

## Development

See [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) for contributing guidelines.

## License

MIT
