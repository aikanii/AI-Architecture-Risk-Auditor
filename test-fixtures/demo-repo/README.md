# Demo Vulnerable Repository

This is a deliberately vulnerable multi-service demo repository for testing the AI Architecture Risk Auditor.

## Architecture

```
┌─────────────────┐
│   Web Client    │
│   (Frontend)    │
└────────┬────────┘
         │ HTTP (no TLS)
         ▼
┌─────────────────┐                ┌──────────────┐
│  API Gateway    │────────────────│  Auth Service│
│  (no rate limit)│   sync HTTP    │ (hardcoded   │
│  (unauth ep)    │                │  secrets)    │
└────────┬────────┘                └──────────────┘
         │
    ┌────┴───────┬──────────────┐
    │            │              │
    ▼            ▼              ▼
┌────────────┐ ┌──────────┐ ┌──────────┐
│ User Svc   │ │Order Svc │ │Payment   │
│ (direct DB)│ │          │ │Svc (SPOF)│
└────┬───────┘ └────┬─────┘ └────┬─────┘
     │              │            │
     └──────┬───────┴────────────┘
            │
            ▼
        ┌───────────────┐
        │  Shared DB    │
        │  (multi-write)│
        │  (no encrypt) │
        └───────────────┘
```

## Seeded Vulnerabilities

### 1. Unprotected Endpoint (CRITICAL)
**File**: `api_gateway/routes.py`
**Issue**: GET /health endpoint with no authentication
**Finding**: Public endpoint without auth control
**Remediation**: Add auth middleware

### 2. Hardcoded Secret (CRITICAL)
**File**: `auth_service/config.py`
**Issue**: Hardcoded JWT secret
**Finding**: Secret in source code, potential exposure
**Remediation**: Move to environment variable

### 3. Single Point of Failure (HIGH)
**File**: Architecture
**Issue**: Payment service is called by both Order and User services, no redundancy
**Finding**: SPOF - high fan-in with no failover
**Remediation**: Add circuit breaker, horizontal scaling

### 4. Multi-Writer DataStore (HIGH)
**File**: Database schema
**Issue**: User service and Order service both write to shared database
**Finding**: Multiple services with direct write access to shared DB
**Remediation**: Add abstraction layer, service-owned schemas

### 5. Unencrypted Cross-Boundary Call (HIGH)
**File**: `api_gateway/handler.py`
**Issue**: HTTP (not HTTPS) call from API Gateway to Auth Service
**Finding**: Synchronous call across trust boundary without encryption
**Remediation**: Use HTTPS/TLS, implement async with circuit breaker

### 6. Missing Input Validation (MEDIUM)
**File**: `user_service/routes.py`
**Issue**: User ID taken directly from query param without validation
**Finding**: Unvalidated input could lead to injection
**Remediation**: Add input validation, use parameterized queries

### 7. Missing Rate Limiting (MEDIUM)
**File**: `api_gateway/main.py`
**Issue**: No rate limiting on endpoints
**Finding**: API exposed to abuse/DoS
**Remediation**: Add rate limiting middleware

## Expected Scan Results

Running the auditor on this repo should detect:
- [ ] 1 CRITICAL: Unprotected endpoint
- [ ] 1 CRITICAL: Hardcoded secret
- [ ] 1 HIGH: SPOF (Payment service)
- [ ] 1 HIGH: Multi-writer datastore
- [ ] 1 HIGH: Unencrypted boundary crossing
- [ ] 1 MEDIUM: Missing input validation
- [ ] 1 MEDIUM: Missing rate limiting

**Total**: 7 findings

## Usage for Testing

```bash
# Scan this demo repo
python -m app.cli scan ./test-fixtures/demo-repo

# Compare against expected baseline
pytest tests/test_demo_repo_fixtures.py

# Should exit 0 if all expected findings detected
pytest tests/acceptance/test_demo_fixtures.py -v
```

## Quick Start with Docker

```bash
docker run -v $(pwd):/workspace \
  ai-arch-audit scan /workspace/test-fixtures/demo-repo \
  --fail-on HIGH
```
