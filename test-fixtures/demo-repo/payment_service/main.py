"""
Payment Service - Processes payments
VULNERABILITY:
1. SPOF: Called by both Order and User services, no redundancy
"""
from fastapi import FastAPI
import httpx

app = FastAPI()

STRIPE_API_KEY = "sk_live_abc123"  # In real system, from env var


@app.post("/payments")
async def process_payment(order_id: int, amount: float):
    """
    VULNERABILITY: This is a Single Point of Failure
    Both Order Service and User Service call this
    If this service is down, both dependent services fail
    No redundancy/failover mechanism
    """
    # Call Stripe API (simplified)
    async with httpx.AsyncClient() as client:
        stripe_response = await client.post(
            "https://api.stripe.com/v1/charges",
            auth=("Bearer", STRIPE_API_KEY),
            data={"amount": int(amount * 100), "currency": "usd"}
        )
    
    if stripe_response.status_code != 200:
        return {"error": "Payment processing failed"}, 500
    
    return {"status": "success", "order_id": order_id}
