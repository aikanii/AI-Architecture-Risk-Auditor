# DEVELOPMENT.md - Development Guide

## Getting Started

### Prerequisites
- Python 3.11+
- Node.js 18+
- Docker & Docker Compose
- Neo4j (via Docker)
- Git
- OpenAI API key (optional for testing)

### Initial Setup

```bash
# Clone repository
git clone <repo-url>
cd ai-arch-auditor

# Create Python virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install backend dependencies
cd backend
pip install -r requirements.txt
pip install -e .  # Install in editable mode

# Install frontend dependencies
cd ../frontend
npm install
```

### Start Development Environment

```bash
# Terminal 1: Start Neo4j
docker-compose up neo4j

# Terminal 2: Initialize database
cd backend
python -m scripts.setup_neo4j

# Terminal 3: Start backend
cd backend
uvicorn app.main:app --reload

# Terminal 4: Start frontend
cd frontend
npm start
```

Visit:
- Backend API: http://localhost:8000
- API Docs: http://localhost:8000/docs
- Frontend: http://localhost:3000

## Project Structure

```
backend/
  ├── app/
  │   ├── api/             # REST API routes
  │   ├── config.py        # Configuration management
  │   ├── ingestion/       # Repository ingestion
  │   ├── models.py        # Pydantic schemas
  │   ├── parser/          # Language-specific parsers
  │   ├── graph/           # Neo4j integration
  │   ├── risk_engine/     # Risk detection
  │   ├── semgrep_runner/  # Semgrep integration
  │   ├── security.py      # Secret redaction
  │   ├── cli.py           # CLI commands
  │   ├── main.py          # FastAPI app
  │   └── pipeline.py      # Scan orchestration
  ├── scripts/
  │   └── setup_neo4j.py   # Database initialization
  ├── tests/               # Unit & integration tests
  └── requirements.txt

frontend/
  ├── src/
  │   ├── components/      # React components
  │   ├── pages/          # Page components
  │   ├── services/       # API client
  │   ├── utils/          # Utilities (graph rendering, etc)
  │   └── App.tsx
  └── package.json

rules/
  ├── semgrep/            # Semgrep YAML rules
  └── cypher/             # Cypher risk queries

test-fixtures/
  └── demo-repo/          # Deliberately vulnerable repo
```

## Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=app

# Run specific test
pytest tests/test_parser.py::test_python_endpoint_extraction

# Run integration tests
pytest tests/integration/ -v

# Run demo repo fixture tests
pytest tests/acceptance/test_demo_fixtures.py -v
```

## Adding a New Language

1. **Create language-specific parser**:
   ```python
   # backend/app/parser/java_parser.py
   from app.parser.base import LanguageParser
   
   class JavaParser(LanguageParser):
       language_name = "java"
       file_extensions = [".java"]
       
       def extract_endpoints(self, tree, content):
           # Implement Spring Boot endpoint extraction
           ...
   ```

2. **Register parser in factory**:
   ```python
   # backend/app/parser/orchestrator.py
   elif language == "java":
       parser = JavaParser()
   ```

3. **Add to supported languages**:
   ```python
   # backend/app/config.py
   supported_languages: list = [..., "java"]
   ```

4. **Add tests**:
   ```python
   # tests/test_java_parser.py
   def test_spring_boot_endpoint_extraction():
       parser = JavaParser()
       # Test Spring @GetMapping, @PostMapping, etc.
   ```

## Adding a New Risk Rule

### Deterministic (Cypher)

1. **Add Cypher query to schema**:
   ```python
   # backend/app/graph/schema.py
   CYPHER_RISK_RULES = {
       "new_rule_name": """
       MATCH (service:Service)-[:CALLS]->(external:ExternalDependency)
       WHERE external.is_critical AND NOT service.has_redundancy
       RETURN service.id as service_id, external.name
       """
   }
   ```

2. **Implement detection method**:
   ```python
   # backend/app/risk_engine/deterministic.py
   def detect_critical_dependency_spof(self, scan_id: str):
       results = self.repo.run_cypher_query(...)
       return [Finding(...) for each result]
   ```

3. **Add to detection pipeline**:
   ```python
   def detect_all_risks(self, scan_id: str):
       findings.extend(self.detect_critical_dependency_spof(scan_id))
   ```

### LLM-Assisted (OpenAI)

LLM rules are generated dynamically based on subgraph context. The LLM receives:
- Matched deterministic findings
- Related code snippets
- Architecture graph subgraph
- Semgrep findings

It synthesizes these into narratives and confirms/adjusts severity.

## Code Quality

### Linting
```bash
cd backend
flake8 app/
black app/
mypy app/
```

### Type Hints
- Add type hints to all function signatures
- Use Pydantic models for API contracts
- Use `Optional[T]` for nullable fields

### Docstrings
- Module-level docstrings for all modules
- Google-style docstrings for all public functions
- Example:
  ```python
  def extract_endpoints(self, tree: Any, content: str) -> List[Dict[str, Any]]:
      """
      Extract HTTP endpoints from AST.
      
      Args:
          tree: Parsed AST tree
          content: Original file content
          
      Returns:
          List of endpoint definitions with path, method, auth status
      """
  ```

## Debugging

### Enable Debug Logging
```bash
export LOG_LEVEL=DEBUG
python -m app.cli scan /path/to/repo
```

### Debug Backend in VSCode
```json
// .vscode/launch.json
{
  "version": "0.2.0",
  "configurations": [
    {
      "name": "Python: FastAPI",
      "type": "python",
      "request": "launch",
      "module": "uvicorn",
      "args": ["app.main:app", "--reload"],
      "cwd": "${workspaceFolder}/backend",
      "env": {"PYTHONPATH": "${workspaceFolder}/backend"}
    }
  ]
}
```

### Neo4j Browser
Access Neo4j admin console at http://localhost:7474
- Username: neo4j
- Password: password (from docker-compose.yml)

Query to inspect graph:
```cypher
MATCH (n) RETURN n LIMIT 25
```

## CI/CD Integration

### GitHub Actions Example
```yaml
name: Test & Scan

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    services:
      neo4j:
        image: neo4j:5.13
        env:
          NEO4J_AUTH: neo4j/password
        options: >-
          --health-cmd "curl -f http://localhost:7474 || exit 1"
          --health-interval 10s
          --health-timeout 5s
    
    steps:
      - uses: actions/checkout@v3
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      - name: Install dependencies
        run: |
          cd backend
          pip install -r requirements.txt
      - name: Run tests
        run: |
          cd backend
          pytest tests/ --cov
      - name: Scan codebase
        run: |
          cd backend
          python -m app.cli scan ../ --fail-on CRITICAL
```

## Common Issues

### Neo4j Connection Refused
- Ensure Neo4j container is running: `docker ps | grep neo4j`
- Check connection string in `.env`
- Try: `docker-compose restart neo4j`

### Parser errors
- Check language detection: `ParserFactory.detect_language(file_path)`
- Ensure tree-sitter grammar is installed
- Check file encoding

### Semgrep not found
- Install: `pip install semgrep`
- Check PATH: `which semgrep`

## Contributing

1. Create feature branch: `git checkout -b feature/description`
2. Make changes with tests
3. Run linting: `black app/` && `flake8 app/`
4. Commit: `git commit -m "Description"`
5. Push and create PR

## Release Process

1. Update version in `backend/app/config.py`
2. Update CHANGELOG.md
3. Run full test suite
4. Tag release: `git tag v0.2.0`
5. Push tags: `git push --tags`
6. Build Docker image: `docker build -t ai-arch-audit:0.2.0 .`
7. Push image: `docker push ai-arch-audit:0.2.0`
