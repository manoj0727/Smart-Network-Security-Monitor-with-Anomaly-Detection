from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
import structlog

logger = structlog.get_logger()

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting Smart Network Security Monitor API...")
    yield
    logger.info("Shutting down Smart Network Security Monitor API...")

def create_app():
    app = FastAPI(
        title="Smart Network Security Monitor",
        description="Enterprise-grade network security monitoring with ML-based anomaly detection",
        version="1.0.0",
        lifespan=lifespan
    )
    
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    
    @app.get("/")
    async def root():
        return {
            "name": "Smart Network Security Monitor",
            "status": "running",
            "version": "1.0.0",
            "endpoints": {
                "docs": "/docs",
                "health": "/health",
                "api": "/api"
            }
        }
    
    @app.get("/health")
    async def health_check():
        return {"status": "healthy", "timestamp": datetime.now().isoformat()}
    
    @app.get("/api/status")
    async def get_status():
        return {
            "capture_status": "ready",
            "threats_detected": 0,
            "packets_analyzed": 0,
            "anomalies_detected": 0
        }
    
    return app

from datetime import datetime