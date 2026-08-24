"""
Order Service - Manages orders
VULNERABILITIES:
1. Direct database write access (shared DB with User Service)
2. Synchronous calls to Payment Service (SPOF without circuit breaker)
"""
from fastapi import FastAPI, Query
import httpx
import databases

app = FastAPI()

DATABASE_URL = "postgresql://user:password@shared-db:5432/monolith_db"
database = databases.Database(DATABASE_URL)

PAYMENT_SERVICE_URL = "http://payment-service:8004"


@app.on_event("startup")
async def startup():
    await database.connect()


@app.on_event("shutdown")
async def shutdown():
    await database.disconnect()


@app.get("/orders")
async def list_orders():
    """List all orders"""
    query = "SELECT * FROM orders"
    return await database.fetch(query)


@app.post("/orders")
async def create_order(user_id: int = Query(...), amount: float = Query(...)):
    """
    VULNERABILITY: Synchronous call to Payment Service
    This is a SPOF - if payment service is down, order creation fails
    No circuit breaker, timeout, or retry logic
    """
    # VULNERABILITY: Direct write to shared database
    query = """
    INSERT INTO orders (user_id, amount, status)
    VALUES (:user_id, :amount, 'pending')
    RETURNING id, user_id, amount, status
    """
    order = await database.fetch_one(
        query,
        values={"user_id": user_id, "amount": amount}
    )
    
    # VULNERABILITY: Synchronous HTTP call to Payment Service (SPOF)
    # No timeout, no retry, no circuit breaker
    async with httpx.AsyncClient() as client:
        payment_response = await client.post(
            f"{PAYMENT_SERVICE_URL}/payments",
            json={"order_id": order["id"], "amount": amount},
            timeout=None  # VULNERABILITY: No timeout!
        )
    
    if payment_response.status_code != 200:
        # Order created but payment failed - inconsistent state
        return {"error": "Payment failed"}, 500
    
    # Update order status
    update_query = """
    UPDATE orders
    SET status = 'paid'
    WHERE id = :order_id
    """
    await database.execute(
        update_query,
        values={"order_id": order["id"]}
    )
    
    return order
