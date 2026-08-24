# Deployment Guide

## Local Development

See `docs/DEVELOPMENT.md`

## Docker Compose (All-in-One)

The easiest way to get up and running:

```bash
# Build and start all services
docker-compose up -d

# Initialize Neo4j schema
docker-compose exec backend python -m scripts.setup_neo4j

# View logs
docker-compose logs -f backend

# Scan a local repository
docker-compose exec backend python -m app.cli scan /workspace --output /workspace/reports
```

Access:
- API: http://localhost:8000
- API Docs: http://localhost:8000/docs
- Web UI: http://localhost:3000
- Neo4j: http://localhost:7474

## Kubernetes Deployment

### Prerequisites
- Kubernetes cluster 1.20+
- Helm 3+
- Docker registry access

### Install

```bash
# Add Helm chart repo (if published)
helm repo add ai-arch-audit https://charts.example.com
helm repo update

# Install with default values
helm install ai-arch-audit ai-arch-audit/ai-arch-audit

# Install with custom values
helm install ai-arch-audit ai-arch-audit/ai-arch-audit \
  -f values.yaml \
  --set neo4j.password=prod-password \
  --set openai.apiKey=$OPENAI_KEY
```

### Example values.yaml
```yaml
replicaCount: 2

image:
  repository: myregistry.azurecr.io/ai-arch-audit
  tag: "0.1.0"

neo4j:
  enabled: true
  auth: "neo4j/prod-password"
  storage: 50Gi

openai:
  apiKey: <your-key>
  model: gpt-4o

resources:
  requests:
    memory: "512Mi"
    cpu: "500m"
  limits:
    memory: "2Gi"
    cpu: "1000m"

ingress:
  enabled: true
  host: "audit.example.com"
```

## AWS ECS

### Build Docker image
```bash
docker build -t ai-arch-audit:latest .
docker tag ai-arch-audit:latest <account>.dkr.ecr.<region>.amazonaws.com/ai-arch-audit:latest
docker push <account>.dkr.ecr.<region>.amazonaws.com/ai-arch-audit:latest
```

### Deploy
```bash
aws ecs register-task-definition --cli-input-json file://task-definition.json
aws ecs update-service --cluster prod --service ai-audit --force-new-deployment
```

## Self-Hosted (Single Machine)

### System Requirements
- Ubuntu 20.04+
- 8GB RAM, 50GB disk
- Docker installed

### Setup

```bash
# Clone repository
git clone <repo-url>
cd ai-arch-auditor

# Copy and edit environment
cp .env.example .env
nano .env  # Set OPENAI_API_KEY, etc.

# Start services
docker-compose up -d

# Initialize database
docker-compose exec backend python -m scripts.setup_neo4j

# Add systemd service for auto-start
sudo cp docker-compose.service /etc/systemd/system/ai-arch-audit.service
sudo systemctl daemon-reload
sudo systemctl enable ai-arch-audit
sudo systemctl start ai-arch-audit
```

## Production Checklist

- [ ] Neo4j with persistent storage (not container-local)
- [ ] Database backups scheduled (daily)
- [ ] HTTPS/TLS enabled on ingress
- [ ] Authentication configured for API (e.g., OAuth2)
- [ ] Rate limiting on API endpoints
- [ ] Log aggregation (ELK, CloudWatch, etc.)
- [ ] Monitoring and alerting (Prometheus, DataDog, etc.)
- [ ] Security scanning on images (Trivy, etc.)
- [ ] Network policies (no public access to Neo4j)
- [ ] Secrets management (AWS Secrets, HashiCorp Vault)
- [ ] RBAC configured
- [ ] Audit logging enabled
- [ ] Disaster recovery plan

## Backup & Recovery

### Neo4j Backup
```bash
# Using Docker
docker-compose exec neo4j neo4j-admin database backup --to-path=/backups neo4j

# Restore
docker-compose exec neo4j neo4j-admin database restore /backups/neo4j-<date>
```

### Full System Backup
```bash
# Backup all data
docker-compose exec neo4j tar czf /backups/neo4j-$(date +%Y%m%d).tar.gz /data
docker cp $(docker-compose ps -q backend):/app/reports ./backups/reports-$(date +%Y%m%d)
```

## Scaling

### Horizontal Scaling (Multiple Backends)
- Use load balancer (nginx, HAProxy) in front
- Scale Neo4j via clustering (Enterprise license)
- Use Redis for scan job queue (future enhancement)

### Performance Tuning
- Increase Neo4j heap: `NEO4J_dbms_memory_heap_max__size: 4G`
- Increase worker threads: `MAX_WORKERS: 8`
- Enable parsing cache: `ENABLE_AST_CACHE: true`
- Adjust Semgrep timeout: `SEMGREP_TIMEOUT: 600`

## Troubleshooting

### High Memory Usage
- Check Neo4j logs: `docker-compose logs neo4j`
- Reduce query timeout or pagination limits
- Monitor with `SHOW TRANSACTIONS`

### Scan Timeout
- Increase `SCAN_TIMEOUT_MINUTES` in .env
- Break large repos into smaller scans
- Enable parsing cache

### Database Connection Issues
- Verify connection string
- Check network connectivity
- Ensure Neo4j is running: `docker ps`
- Review logs: `docker-compose logs neo4j`

## Monitoring

### Health Check
```bash
curl http://localhost:8000/health
```

### Metrics
- Scan duration by repository
- Finding count and severity distribution
- API response times
- Neo4j query performance

### Logging
All logs are JSON formatted and sent to stdout:
```bash
docker-compose logs -f backend | jq .
```

## Support

For issues and questions:
- GitHub Issues: <repo>/issues
- Documentation: See `docs/` directory
- Email: support@example.com
