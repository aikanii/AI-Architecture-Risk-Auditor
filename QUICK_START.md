# Quick Start Guide

## Installation

### 1. Clone Repository
```bash
git clone <repo-url>
cd ai-arch-auditor
```

### 2. Docker Compose (Recommended)
```bash
# Start all services
docker-compose up -d

# Initialize database
docker-compose exec backend python -m scripts.setup_neo4j

# Check health
curl http://localhost:8000/health
```

### 3. Manual Setup (Development)
```bash
# Backend
cd backend
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Neo4j (requires Docker or manual install)
docker run -d -p 7474:7474 -p 7687:7687 \
  -e NEO4J_AUTH=neo4j/password \
  neo4j:5.13

# Initialize schema
python -m scripts.setup_neo4j

# Start backend
uvicorn app.main:app --reload

# Frontend (in another terminal)
cd frontend
npm install
npm start
```

## Basic Usage

### CLI: Scan a Repository
```bash
# Local directory
python -m app.cli scan /path/to/repo

# Git repository
python -m app.cli scan https://github.com/org/repo.git

# With options
python -m app.cli scan /path/to/repo \
  --config config.yaml \
  --fail-on HIGH \
  --output ./reports
```

### Web Interface
Navigate to `http://localhost:3000`
- **Dashboard**: Summary of recent scans
- **Graph View**: Interactive architecture visualization
- **Findings**: Filterable list of detected risks
- **Export**: Download reports as JSON/SARIF/PDF

### REST API
```bash
# Initiate scan
curl -X POST http://localhost:8000/api/scans \
  -H "Content-Type: application/json" \
  -d '{"repository": {"type": "local", "path": "/path/to/repo"}}'

# Get findings
curl http://localhost:8000/api/findings/{scan_id}

# Export report
curl http://localhost:8000/api/reports/{scan_id}/export?format=sarif
```

## Configuration

### .env File
Copy `.env.example` to `.env` and customize:

```bash
# Neo4j
NEO4J_URI=bolt://localhost:7687
NEO4J_USER=neo4j
NEO4J_PASSWORD=password

# OpenAI (optional, for LLM enrichment)
OPENAI_API_KEY=sk-...
OPENAI_MODEL=gpt-4o

# Scanning
MAX_WORKERS=4
SCAN_TIMEOUT_MINUTES=10
ENABLE_AST_CACHE=true

# Risk thresholds
SPOF_FAN_IN_THRESHOLD=3
```

## Demo Repository

A deliberately vulnerable multi-service repository is included for testing:

```bash
# Scan demo repo
python -m app.cli scan ./test-fixtures/demo-repo

# Run tests against demo repo
pytest tests/acceptance/test_demo_fixtures.py -v
```

Expected findings: 7 issues (1 CRITICAL, 3 HIGH, 2 MEDIUM, 1 LOW)

## Architecture Overview

```
Scan Input → Repository Ingestion → Parsing (tree-sitter) → Neo4j Graph
                                                               ↓
Findings Report ← Risk Detection ← Deterministic Rules ← Cypher Queries
                                                               ↑
                                         (Optional) LLM Enrichment
                                                    (OpenAI API)
```

**Pipeline Steps:**
1. **Ingestion**: Clone/scan repository
2. **Parsing**: Extract services, endpoints, calls using language-specific parsers
3. **Graph**: Build architecture graph in Neo4j
4. **Analysis**: Run static analysis (Semgrep) and deterministic Cypher queries
5. **Enrichment** (optional): Use LLM for narrative and severity confirmation
6. **Reporting**: Generate findings and export

## Key Features

✓ **Multi-language support**: Python, JavaScript/TypeScript, Java, Go
✓ **Static analysis**: No code execution, entirely safe to analyze untrusted code
✓ **Architecture mapping**: Automatic service discovery and dependency mapping
✓ **Risk detection**: SPOF, unprotected endpoints, multi-writer datastores, etc.
✓ **AI reasoning**: OpenAI integration for context-aware findings
✓ **Export formats**: JSON, SARIF (GitHub code scanning), HTML, PDF
✓ **Zero data leakage**: Secret redaction before any external API calls
✓ **REST API**: Programmatic access for CI/CD integration
✓ **Interactive UI**: Graph visualization and findings dashboard

## Supported Risks

### Critical
- Unprotected public endpoints (no auth)
- Hardcoded secrets in code
- Unencrypted cross-boundary calls

### High
- Single points of failure (high fan-in, no redundancy)
- Multi-writer shared databases
- Cyclic service dependencies
- Missing rate limiting on public APIs

### Medium
- Missing input validation
- Missing observability (tracing/health checks)
- Excessive permission scopes
- Unencrypted data at rest

## Troubleshooting

**Docker Compose won't start:**
```bash
docker-compose down
docker-compose up -d --build
```

**Neo4j connection error:**
```bash
docker-compose logs neo4j
docker-compose restart neo4j
```

**Scan times out:**
- Increase `SCAN_TIMEOUT_MINUTES` in `.env`
- Use smaller repository or enable AST caching

**OpenAI API errors:**
- Verify `OPENAI_API_KEY` is set
- Check API quota and rate limits
- Works offline with `--skip-ai` flag

## Next Steps

1. **Run a scan** on your codebase: `python -m app.cli scan /path/to/repo`
2. **Review findings** in web UI at `http://localhost:3000`
3. **Export report** for CI/CD: See export options in API docs
4. **Configure thresholds**: Adjust risk detection parameters in `.env`
5. **Add custom rules**: Extend Semgrep rules in `rules/semgrep/`

## Documentation

- [Full Architecture](docs/ARCHITECTURE.md)
- [Neo4j Schema Reference](docs/SCHEMA.md)
- [Development Guide](docs/DEVELOPMENT.md)
- [Deployment Guide](docs/DEPLOYMENT.md)
- [Adding New Languages](docs/ADDING_LANGUAGE.md)
- [Adding Risk Rules](docs/ADDING_RISK_RULE.md)
- [Data Privacy & Redaction](docs/DATA_PRIVACY.md)

## Support

- GitHub Issues: Report bugs and request features
- Discussions: Ask questions and share ideas
- Security: Report security issues responsibly to security@example.com

## License

MIT - See LICENSE file for details
