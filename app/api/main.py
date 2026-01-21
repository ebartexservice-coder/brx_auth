"""
FastAPI Application Main Entry Point
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import logging

from app.api.v1.endpoints.auth import router as auth_router
from app.api.dependencies import startup_event, shutdown_event
from app.core.config import get_settings

# Get settings
settings = get_settings()

# Configure logging
logging.basicConfig(
    level=settings.log_level,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)

logger = logging.getLogger(__name__)

# Create FastAPI app
app = FastAPI(
    title=settings.app_name,
    description="Enterprise authentication microservice",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    debug=settings.debug
)

# CORS configuration using centralized settings
allowed_origins = settings.get_allowed_origins()
if allowed_origins:
    logger.info(f"CORS enabled for origins: {allowed_origins}")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=allowed_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
else:
    logger.warning("No CORS origins configured. CORS middleware not added.")

# Include routers
app.include_router(auth_router, prefix="/api/v1")

# Startup and shutdown events
@app.on_event("startup")
async def startup():
    """Application startup"""
    logger.info("Starting Auth Service...")
    await startup_event()
    logger.info("Auth Service started successfully")


@app.on_event("shutdown")
async def shutdown():
    """Application shutdown"""
    logger.info("Shutting down Auth Service...")
    await shutdown_event()
    logger.info("Auth Service shut down")


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "service": "auth-service",
        "version": "1.0.0"
    }


@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "message": "Auth Service API",
        "version": "1.0.0",
        "docs": "/docs"
    }
