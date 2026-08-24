# First-Time Setup Guide

## Prerequisites Check

Before starting, ensure you have:

```bash
# Check Python
python --version  # Should be 3.11+
which python

# Check Node.js (for frontend)
node --version   # Should be 18+
npm --version

# Check Docker
docker --version
docker-compose --version

# Check Git
git --version
```

If any are missing, install them:
- **Python**: https://www.python.org/downloads/
- **Node.js**: https://nodejs.org/
- **Docker**: https://docs.docker.com/get-docker/
- **Git**: https://git-scm.com/

## Quick Setup (5 minutes)

### Option 1: Docker Compose (Recommended)

```bash
# Navigate to project directory
cd ai-arch-auditor

# Copy environment template
cp .env.example .env

# Start all services (Neo4j, Backend, Frontend)
docker-compose up -d

# Wait for services to be ready (check logs)
docker-compose logs -f backend

# When you see "Application startup complete", initialize the database
docker-compose exec backend python -m scripts.setup_neo4j

# Verify everything is working
curl http://localhost:8000/health
# Should return: {"status":"healthy","version":"0.1.0","neo4j_connected":true,"openai_available":false}

# Open in browser
# Backend API: http://localhost:8000
# API Docs: http://localhost:8000/docs
# Frontend: http://localhost:3000
# Neo4j Browser: http://localhost:7474 (neo4j/password)
```

### Option 2: Manual Setup (Development)

#### Terminal 1: Start Neo4j
```bash
docker run -d \
  --name neo4j-local \
  -p 7474:7474 \
  -p 7687:7687 \
  -e NEO4J_AUTH=neo4j/password \
  neo4j:5.13
```

#### Terminal 2: Backend
```bash
cd backend

# Create virtual environment
python -m venv venv

# Activate venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Copy environment
cp ../.env.example ../.env

# Initialize database schema
python -m scripts.setup_neo4j

# Start development server
uvicorn app.main:app --reload
```

#### Terminal 3: Frontend (if developing UI)
```bash
cd frontend

npm install

npm start  # Starts on port 3000
```

## Test Installation

### Run Health Check
```bash
# Check all services
curl http://localhost:8000/health

# Expected output:
# {
#   "status": "healthy",
#   "version": "0.1.0",
#   "neo4j_connected": true,
#   "openai_available": false
# }
```

### Scan Demo Repository
```bash
# Navigate to backend directory
cd backend

# Scan the demo vulnerable repo
python -m app.cli scan ../test-fixtures/demo-repo

# Should complete and show:
# ✅ Scan completed: <scan-id>
```

### Query Results
```bash
# Get findings for the scan
curl "http://localhost:8000/api/findings/<scan-id>"

# Should return findings from the demo repo
```

## Configuration

### Essential Settings (.env)

```bash
# Neo4j Connection (default: local Docker)
NEO4J_URI=bolt://localhost:7687
NEO4J_USER=neo4j
NEO4J_PASSWORD=password

# OpenAI (optional, for LLM enrichment)
OPENAI_API_KEY=sk-...  # Get from https://platform.openai.com/api-keys
OPENAI_MODEL=gpt-4o    # or gpt-4-turbo, gpt-3.5-turbo

# Logging
LOG_LEVEL=INFO  # Set to DEBUG for verbose logs

# Scanning
MAX_WORKERS=4
SCAN_TIMEOUT_MINUTES=10
ENABLE_AST_CACHE=true

# Risk Thresholds
SPOF_FAN_IN_THRESHOLD=3
```

## Common Issues & Solutions

### Issue: "Connection refused" (Neo4j)
```bash
# Check if Neo4j is running
docker ps | grep neo4j

# If not running, start it
docker-compose up -d neo4j

# Check logs
docker-compose logs neo4j

# Restart
docker-compose restart neo4j
```

### Issue: "ModuleNotFoundError: No module named 'app'"
```bash
# Make sure you're in the backend directory
cd backend

# And using the correct Python
which python
python -m pip install -e .
```

### Issue: "Port already in use"
```bash
# Check what's using port 8000, 3000, 7474, 5432
lsof -i :8000
lsof -i :3000
lsof -i :7474

# Kill the process (or change port in docker-compose.yml)
kill -9 <PID>
```

### Issue: "OpenAI API key not working"
```bash
# Check your API key is set correctly
echo $OPENAI_API_KEY

# If empty, set it
export OPENAI_API_KEY=sk-...

# Test API key validity
python -c "from openai import OpenAI; c = OpenAI(); print('Valid!')"

# To disable LLM temporarily
export OPENAI_API_KEY=  # Empty string disables
python -m app.cli scan /path/to/repo --skip-ai
```

## Next Steps

1. **Read Documentation**
   - Start: `QUICK_START.md`
   - Deep dive: `docs/ARCHITECTURE.md`
   - Setup: `docs/DEVELOPMENT.md`

2. **Try Your First Scan**
   ```bash
   python -m app.cli scan /path/to/your/repo
   ```

3. **Review Results**
   - CLI output
   - Web UI: http://localhost:3000
   - API: http://localhost:8000/docs

4. **Configure for Your Needs**
   - Edit `.env` for risk thresholds
   - Add custom Semgrep rules in `rules/semgrep/`
   - Adjust risk detection in `backend/app/risk_engine/`

5. **Integrate with CI/CD** (future)
   - SARIF export for GitHub Actions
   - Webhook notifications
   - Policy gating

## Development Workflow

### Making Changes

```bash
# Backend
cd backend
vim app/main.py  # Make changes
# Changes auto-reload with --reload flag

# Frontend
cd frontend
vim src/App.tsx  # Make changes
# Changes auto-reload with npm start
```

### Running Tests
```bash
cd backend
pytest
pytest -v  # Verbose
pytest --cov  # With coverage
```

### Committing Changes
```bash
git add .
git commit -m "Description of changes"
git push
```

## Getting Help

1. **Check Logs**
   ```bash
   docker-compose logs -f backend
   docker-compose logs -f neo4j
   ```

2. **Read Documentation**
   - Troubleshooting in `docs/DEPLOYMENT.md`
   - Architecture in `docs/ARCHITECTURE.md`

3. **Test with Demo Repo**
   ```bash
   python -m app.cli scan ./test-fixtures/demo-repo -v
   ```

4. **Check API Documentation**
   - Interactive: http://localhost:8000/docs
   - Schema: http://localhost:8000/openapi.json

5. **Enable Debug Logging**
   ```bash
   export LOG_LEVEL=DEBUG
   python -m app.cli scan /path/to/repo
   ```

## Performance Tips

- **Enable AST caching**: `ENABLE_AST_CACHE=true` for faster re-scans
- **Adjust workers**: `MAX_WORKERS=8` for more parallel parsing
- **Increase timeouts**: `SCAN_TIMEOUT_MINUTES=20` for large repos
- **Batch LLM calls**: Combine findings before LLM enrichment

## Next Read

After setup completes, read in this order:
1. `QUICK_START.md` - Quick reference
2. `docs/ARCHITECTURE.md` - System design
3. `docs/SCHEMA.md` - Database schema
4. `docs/DEVELOPMENT.md` - Development guide
5. `docs/DEPLOYMENT.md` - Production deployment

## You're Ready!

Your AI Architecture Risk Auditor is now set up and ready to scan codebases for architectural risks. 

Start with:
```bash
python -m app.cli scan /path/to/repository
```

Good luck! 🚀
