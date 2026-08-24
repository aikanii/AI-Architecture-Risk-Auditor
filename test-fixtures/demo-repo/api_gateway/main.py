"""
API Gateway - Entry point for all services
VULNERABILITIES:
1. Unprotected /health endpoint (no auth)
2. No rate limiting
3. Unencrypted HTTP calls to auth service
"""
from fastapi import FastAPI, Query
from fastapi.responses import JSONResponse
import httpx

app = FastAPI()

AUTH_SERVICE_URL = "http://auth-service:8001"  # Unencrypted!


@app.get("/health")
async def health():
    """VULNERABILITY: No authentication on public endpoint"""
    return {"status": "healthy"}


@app.get("/api/users")
async def get_user(user_id: int = Query(...)):
    """
    VULNERABILITY: No input validation on user_id
    VULNERABILITY: No rate limiting
    """
    # Validate token with auth service
    async with httpx.AsyncClient() as client:
        # VULNERABILITY: HTTP (not HTTPS) call across boundary
        auth_response = await client.get(
            f"{AUTH_SERVICE_URL}/validate",
            headers={"Authorization": "Bearer token"}
        )
    
    if auth_response.status_code != 200:
        return {"error": "Unauthorized"}, 401
    
    # Call user service
    async with httpx.AsyncClient() as client:
        user_response = await client.get(
            f"http://user-service:8002/users/{user_id}"
        )
    
    return user_response.json()


@app.get("/api/orders")
async def get_orders():
    """VULNERABILITY: No rate limiting"""
    async with httpx.AsyncClient() as client:
        orders = await client.get("http://order-service:8003/orders")
    return orders.json()
