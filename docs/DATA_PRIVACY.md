# Data Privacy & Secret Redaction

## Overview

The AI Architecture Risk Auditor never leaks secrets or sensitive data. This document describes the redaction and privacy controls built into every layer of the system.

## Secret Redaction Strategy

### 1. Detection
Secrets are detected at three points:
- **Parser level**: Looks for common patterns (api_key=, password=, JWT tokens)
- **Semgrep**: Static rules detect hardcoded credentials
- **Pre-LLM**: Before any external API call

### 2. Redaction Patterns
The system recognizes and redacts:
- API keys: `sk-...`, `pk_...`, `AKIA...`
- Secrets: Variables named `secret`, `password`, `api_key`, etc.
- JWTs: Patterns like `eyJ...`
- Database credentials: `postgres://user:PASSWORD@host`
- AWS/GCP/Azure credentials
- Private keys
- Auth tokens

### 3. Redaction Levels

#### Logs
All logging is JSON-formatted and redacted:
```python
logger.info("Connecting to database", extra=redact_dict({
    "url": "postgres://user:secret@host"
}))
# Output: {"url": "postgres://user:[REDACTED]@host"}
```

#### Database Storage
Findings store only:
- Severity level
- Finding title
- Remediation steps
- File path (no content)
- Line number

NOT stored:
- Raw secret values
- Sensitive data samples
- Full file contents

#### API Responses
Findings returned via REST API never contain:
- Secret values
- Sensitive code snippets
- Personally identifiable information

#### LLM API Calls
Before sending to OpenAI:
1. All secret values redacted → `[REDACTED_KEY]`
2. Sensitive file paths removed
3. Only graph metadata and risk signals sent
4. Example sent to LLM:
```json
{
  "finding": {
    "title": "Hardcoded secret detected",
    "file": "config.py",
    "line": 42,
    "severity": "CRITICAL"
  },
  "risk_type": "secrets_in_code"
}
```

NOT sent:
- `secret_value: "sk_live_abc123"`
- Raw password strings
- Private key contents

## Hash-Based Comparison

When comparing secrets to detect duplicates:
1. Secret is salted: `secret + SECRETS_HASH_SALT`
2. Hashed: `SHA256(salted_secret)`
3. Only hash stored, not original value
4. Comparison done on hashes

```python
# Never stored
secret = "sk_live_abc123"

# Stored in database
secret_hash = hash_secret(secret)  # SHA256 hash with salt
```

## Audit Trail

Every finding is traceable to its evidence sources:
- **Semgrep rule ID**: Which rule detected it
- **Cypher query name**: Which architectural pattern
- **LLM call ID**: Which reasoning session (if LLM was used)
- **File location**: Exact file:line where issue was found

This audit trail allows security teams to verify findings without leaking sensitive data.

## On-Premises Deployment

For maximum privacy:
1. **Run Neo4j on your infrastructure** (not cloud)
2. **Skip LLM layer**: Set `ENABLE_AI_LAYER=false`
3. **Store reports locally**: No external upload
4. **Network isolation**: Block outbound connections except for necessary APIs

```bash
# CLI mode with AI layer disabled
python -m app.cli scan /path/to/repo --skip-ai

# Results in deterministic findings only
# No external API calls made
```

## Compliance

### GDPR Compliance
- No PII collected or retained
- Secrets redacted before storage
- Easy data deletion: `DELETE FROM scan WHERE ...`
- Audit logs available for compliance

### HIPAA Compliance
- All data encrypted at rest (when configured)
- All data encrypted in transit (TLS)
- No cloud storage by default
- On-premises deployment supported

### SOC 2 Compliance
- Comprehensive audit logging
- Access controls via RBAC
- Incident response procedures
- Regular security testing

## Security Best Practices

### For Administrators

1. **Protect .env file**: Contains OpenAI API key
   ```bash
   chmod 600 .env
   ```

2. **Use separate API keys**: Different keys for different environments
   ```bash
   # Production key
   OPENAI_API_KEY=sk-prod-...
   
   # Development key
   OPENAI_API_KEY=sk-dev-...
   ```

3. **Enable TLS for Neo4j**: Production deployments
   ```yaml
   NEO4J_URI=bolt+s://neo4j:7687  # Secure connection
   ```

4. **Audit logs**: Monitor all scan activity
   ```bash
   docker-compose logs backend | grep "risk_engine"
   ```

### For Users

1. **Don't share raw reports**: Export only after reviewing for PII
2. **Redact before sharing**: Use PDF export with annotations
3. **SARIF for CI/CD**: GitHub annotations auto-redact
4. **API authentication**: Always use API keys/tokens, never URLs

## Testing Redaction

A test suite verifies redaction works:

```bash
# Run redaction tests
pytest tests/test_security.py::test_secret_redaction -v

# Tests cover:
# - API key redaction
# - Password redaction
# - Private key redaction
# - Database credential redaction
# - Hash-based comparison
```

## Troubleshooting

### Secrets appearing in logs
1. Check log level: `LOG_LEVEL=INFO` (not DEBUG)
2. Verify `REDACT_SECRETS_IN_LOGS=true`
3. Check for custom logger bypasses

### Secrets in database
1. Never store raw secrets (use hash)
2. Check `REDACT_SECRETS_IN_REPORTS=true`
3. Verify finding schema doesn't include `secret_value`

### LLM sees secrets
1. Always test with `--skip-ai` first
2. Redact before LLM call: `redact_dict()` applied
3. Monitor LLM API calls in logs

## Future Enhancements

- [ ] GPG encryption for database
- [ ] Hardware security module (HSM) integration
- [ ] Masking for PII in comments
- [ ] Differential privacy for statistical reports
- [ ] Tokenization for sensitive values

## References

- [OWASP: Secrets Management](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)
- [CWE-798: Use of Hard-Coded Credentials](https://cwe.mitre.org/data/definitions/798.html)
- [GDPR Compliance](https://gdpr-info.eu/)
- [HIPAA Privacy Rule](https://www.hhs.gov/hipaa/for-professionals/privacy/index.html)
