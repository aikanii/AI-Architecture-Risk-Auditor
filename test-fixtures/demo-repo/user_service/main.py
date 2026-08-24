"""
User Service - Manages user data
VULNERABILITIES:
1. Direct database write access (shared DB with Order Service)
2. No input validation
"""
from fastapi import FastAPI, Query
import databases

app = FastAPI()

DATABASE_URL = "postgresql://user:password@shared-db:5432/monolith_db"
database = databases.Database(DATABASE_URL)


@app.on_event("startup")
async def startup():
    await database.connect()


@app.on_event("shutdown")
async def shutdown():
    await database.disconnect()


@app.get("/users/{user_id}")
async def get_user(user_id: int):
    """
    VULNERABILITY: No input validation on user_id
    This could be vulnerable to injection if using string concatenation
    """
    # Using parameterized query is safe, but missing validation
    query = "SELECT * FROM users WHERE id = :user_id"
    return await database.fetch_one(query, values={"user_id": user_id})


@app.post("/users")
async def create_user(email: str = Query(...), name: str = Query(...)):
    """
    VULNERABILITY: Direct write to shared database
    No service-owned schema abstraction
    Order Service also writes to this same table
    """
    # VULNERABILITY: No validation on email format or length
    query = """
    INSERT INTO users (email, name) 
    VALUES (:email, :name)
    RETURNING id, email, name
    """
    return await database.fetch_one(
        query,
        values={"email": email, "name": name}
    )


@app.put("/users/{user_id}")
async def update_user(user_id: int, name: str = Query(...)):
    """
    VULNERABILITY: Direct write to shared database
    """
    query = """
    UPDATE users 
    SET name = :name 
    WHERE id = :user_id
    RETURNING id, email, name
    """
    return await database.fetch_one(
        query,
        values={"user_id": user_id, "name": name}
    )
