"""
Auth Service - Handles authentication
VULNERABILITIES:
1. Hardcoded JWT secret in source code
2. SPOF: Called by multiple services with no redundancy
"""
from fastapi import FastAPI, Depends, HTTPException, Header
import jwt
from typing import Optional

app = FastAPI()

# VULNERABILITY: Hardcoded secret in source code!
JWT_SECRET = "super_secret_jwt_key_12345"  # NEVER DO THIS


def verify_token(authorization: Optional[str] = Header(None)):
    """Verify JWT token"""
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing token")
    
    try:
        scheme, token = authorization.split()
        if scheme.lower() != "bearer":
            raise HTTPException(status_code=401, detail="Invalid scheme")
        
        # VULNERABILITY: Secret is hardcoded
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        return payload
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")


@app.post("/token")
async def create_token(user_id: int):
    """Create JWT token"""
    # VULNERABILITY: Secret is hardcoded
    token = jwt.encode(
        {"user_id": user_id},
        JWT_SECRET,
        algorithm="HS256"
    )
    return {"access_token": token}


@app.get("/validate")
async def validate_token(payload: dict = Depends(verify_token)):
    """Validate token - VULNERABILITY: This is a SPOF"""
    return {"valid": True, "user_id": payload.get("user_id")}
