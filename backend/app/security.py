"""Security utilities for secret redaction and hashing."""
import hashlib
import re
from typing import Dict, Any, Optional
from app.config import settings


# Common secret patterns to redact
SECRET_PATTERNS = [
    r'(api[_-]?key|apikey)["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_\-\.]+)',
    r'(password|pwd)["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_\-\.]+)',
    r'(secret|token)["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_\-\.]+)',
    r'(aws_secret_access_key|aws_access_key_id)["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_\-\.]+)',
    r'(private[_-]?key)["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_\-\.]+)',
]


def redact_secret(value: str) -> str:
    """
    Redact sensitive values in a string.
    
    Args:
        value: String that may contain secrets
        
    Returns:
        String with secrets replaced with [REDACTED]
    """
    if not settings.security.redact_secrets_in_logs:
        return value
    
    redacted = value
    for pattern in SECRET_PATTERNS:
        redacted = re.sub(pattern, r'\1=[REDACTED]', redacted, flags=re.IGNORECASE)
    
    # Redact common secret formats
    redacted = re.sub(r'sk[-_][a-zA-Z0-9_\-]+', '[REDACTED_KEY]', redacted)  # OpenAI / Stripe keys
    redacted = re.sub(r'AKIA[0-9A-Z]{16}', '[REDACTED_AWS]', redacted)  # AWS keys
    redacted = re.sub(r'eyJ[a-zA-Z0-9_\-]+\.eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+', '[REDACTED_JWT]', redacted)

    # Redact standalone secret values (e.g., secret123, supersecret, my_secret_token)
    # Check if the entire string or tokens contain secret/password indicators without being public info
    def replace_secret_token(match):
        token = match.group(0)
        lower = token.lower()
        if "public" in lower:
            return token
        return "[REDACTED]"

    redacted = re.sub(r'\b(?:super)?(?:secret|password|token)[0-9a-zA-Z_\-]*\b', replace_secret_token, redacted, flags=re.IGNORECASE)
    
    return redacted


def hash_secret(secret: str) -> str:
    """
    Hash a secret value for comparison without storing plaintext.
    
    Args:
        secret: The secret to hash
        
    Returns:
        SHA256 hash of the secret with salt
    """
    salted = f"{secret}{settings.security.secrets_hash_salt}".encode()
    return hashlib.sha256(salted).hexdigest()


def redact_dict(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Recursively redact secrets in a dictionary.
    
    Args:
        data: Dictionary that may contain secrets
        
    Returns:
        Dictionary with secrets redacted
    """
    if not settings.security.redact_secrets_in_logs:
        return data
    
    redacted = {}
    for key, value in data.items():
        # Check if key itself indicates a sensitive value
        if any(secret_key in key.lower() for secret_key in ['secret', 'password', 'key', 'token', 'credential']):
            redacted[key] = '[REDACTED]'
        elif isinstance(value, dict):
            redacted[key] = redact_dict(value)
        elif isinstance(value, list):
            redacted[key] = [
                redact_dict(v) if isinstance(v, dict)
                else redact_secret(str(v)) if isinstance(v, str)
                else v
                for v in value
            ]
        elif isinstance(value, str):
            redacted[key] = redact_secret(value)
        else:
            redacted[key] = value
    
    return redacted
