"""
Main FastAPI application for the AI Architecture Risk Auditor.
Entry point for the web server and API.
"""
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
import logging
from app.config import settings
from app.models import HealthResponse
from app import api

# Configure logging
logging.basicConfig(
    level=settings.log_level,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


# ============================================================================
# Lifespan Events
# ============================================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup and shutdown events."""
    # Startup
    logger.info("Starting AI Architecture Risk Auditor")
    
    # Initialize database
    try:
        from app.graph.db import get_db_connection
        driver = get_db_connection(settings)
        logger.info("Connected to Neo4j")
    except Exception as e:
        logger.error(f"Failed to connect to Neo4j: {e}")
    
    yield
    
    # Shutdown
    logger.info("Shutting down AI Architecture Risk Auditor")
    try:
        if driver:
            driver.close()
    except Exception as e:
        logger.error(f"Error closing database connection: {e}")


# ============================================================================
# FastAPI App Initialization
# ============================================================================

app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="Static analysis platform for architectural risk detection",
    lifespan=lifespan,
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Restrict in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================================
# Health Check
# ============================================================================

@app.get("/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint."""
    from app.graph.db import check_neo4j_connection
    
    neo4j_connected = await check_neo4j_connection(settings)
    openai_available = settings.openai.api_key is not None and settings.openai.enable_ai_layer
    
    return HealthResponse(
        status="healthy" if neo4j_connected else "degraded",
        version=settings.app_version,
        neo4j_connected=neo4j_connected,
        openai_available=openai_available,
    )


# ============================================================================
# API Routes
# ============================================================================

# Include API route modules
app.include_router(api.scans.router, prefix="/api/scans", tags=["scans"])
app.include_router(api.findings.router, prefix="/api/findings", tags=["findings"])
app.include_router(api.graph.router, prefix="/api/graph", tags=["graph"])
app.include_router(api.reports.router, prefix="/api/reports", tags=["reports"])


# ============================================================================
# Error Handlers
# ============================================================================

@app.exception_handler(ValueError)
async def value_error_handler(request, exc):
    return HTTPException(status_code=400, detail=str(exc))


# ============================================================================
# Root Endpoint
# ============================================================================

@app.get("/")
async def root():
    """Root endpoint returning API information."""
    return {
        "name": settings.app_name,
        "version": settings.app_version,
        "api_docs": "/docs",
        "status": "running",
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
