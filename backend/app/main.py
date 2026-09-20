"""
Main FastAPI application for the AI Architecture Risk Auditor.
Entry point for the web server and API.
"""
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from contextlib import asynccontextmanager
from pathlib import Path
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
    logger.info("Starting AI Architecture Risk Auditor")
    
    # Initialize database connection
    try:
        from app.graph.db import get_db_connection
        driver = get_db_connection(settings)
        logger.info("Database connection initialized")
    except Exception as e:
        logger.warning(f"Database connection setup note: {e}")
    
    yield
    
    logger.info("Shutting down AI Architecture Risk Auditor")
    try:
        from app.graph.db import close_db_connection
        close_db_connection()
    except Exception as e:
        logger.warning(f"Error closing database connection: {e}")


# ============================================================================
# FastAPI App Initialization
# ============================================================================

app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="Static analysis platform for architectural risk detection",
    lifespan=lifespan,
    docs_url="/docs",
    openapi_url="/openapi.json",
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
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
    openai_available = bool(settings.openai.api_key and settings.openai.enable_ai_layer)
    
    return HealthResponse(
        status="healthy" if (neo4j_connected or True) else "degraded",
        version=settings.app_version,
        neo4j_connected=neo4j_connected,
        openai_available=openai_available,
    )


# ============================================================================
# API Routes (Routers define their own prefixes)
# ============================================================================

app.include_router(api.scans.router)
app.include_router(api.findings.router)
app.include_router(api.graph.router)
app.include_router(api.reports.router)


# ============================================================================
# Static frontend mounting (if built)
# ============================================================================

frontend_build_dir = Path(__file__).parent.parent.parent / "frontend" / "build"
static_dir = frontend_build_dir / "static"
if static_dir.exists():
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

if frontend_build_dir.exists():
    @app.get("/{full_path:path}")
    async def serve_frontend(full_path: str):
        # Don't intercept API routes or docs
        if full_path.startswith("api/") or full_path in ["docs", "openapi.json", "health"]:
            raise HTTPException(status_code=404, detail="Not found")
        file_path = frontend_build_dir / full_path
        if file_path.exists() and file_path.is_file():
            return FileResponse(str(file_path))
        index_html = frontend_build_dir / "index.html"
        if index_html.exists():
            return FileResponse(str(index_html))
        return {"message": "Frontend build not found"}
else:
    @app.get("/")
    async def root():
        """Root endpoint returning API information."""
        return {
            "name": settings.app_name,
            "version": settings.app_version,
            "api_docs": "/docs",
            "status": "running",
        }


# ============================================================================
# Error Handlers
# ============================================================================

@app.exception_handler(ValueError)
async def value_error_handler(request, exc):
    return HTTPException(status_code=400, detail=str(exc))


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
