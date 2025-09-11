from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
from datetime import datetime
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
    
    # Add global variables for simulation
    import random
    import asyncio
    
    # Simulated data storage
    app.state.packets_analyzed = 0
    app.state.threats_detected = 0
    app.state.anomalies_detected = 0
    app.state.simulation_active = False
    
    @app.get("/api/status")
    async def get_status():
        return {
            "capture_status": "active" if app.state.simulation_active else "ready",
            "threats_detected": app.state.threats_detected,
            "packets_analyzed": app.state.packets_analyzed,
            "anomalies_detected": app.state.anomalies_detected
        }
    
    @app.post("/api/simulate/start")
    async def start_simulation():
        """Start threat simulation"""
        app.state.simulation_active = True
        
        # Simulate packet analysis
        app.state.packets_analyzed += random.randint(100, 500)
        
        # Randomly generate threats
        if random.random() > 0.7:  # 30% chance of threat
            app.state.threats_detected += 1
            threat_type = random.choice([
                "Port Scan Detected",
                "SQL Injection Attempt",
                "DDoS Attack Pattern",
                "Suspicious DNS Query",
                "Malware Communication"
            ])
            return {
                "status": "threat_detected",
                "threat": threat_type,
                "severity": random.choice(["low", "medium", "high", "critical"]),
                "source_ip": f"192.168.{random.randint(1,255)}.{random.randint(1,255)}",
                "packets_analyzed": app.state.packets_analyzed,
                "threats_total": app.state.threats_detected
            }
        
        # Randomly generate anomalies
        if random.random() > 0.8:  # 20% chance of anomaly
            app.state.anomalies_detected += 1
            return {
                "status": "anomaly_detected",
                "anomaly": "Unusual traffic pattern",
                "packets_analyzed": app.state.packets_analyzed,
                "anomalies_total": app.state.anomalies_detected
            }
        
        return {
            "status": "normal",
            "packets_analyzed": app.state.packets_analyzed,
            "message": "Traffic appears normal"
        }
    
    @app.post("/api/simulate/stop")
    async def stop_simulation():
        """Stop threat simulation"""
        app.state.simulation_active = False
        return {"status": "simulation_stopped"}
    
    @app.post("/api/simulate/reset")
    async def reset_simulation():
        """Reset all counters"""
        app.state.packets_analyzed = 0
        app.state.threats_detected = 0
        app.state.anomalies_detected = 0
        app.state.simulation_active = False
        return {"status": "counters_reset"}
    
    return app