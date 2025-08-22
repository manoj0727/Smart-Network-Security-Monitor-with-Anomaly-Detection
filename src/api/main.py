from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect, BackgroundTasks, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
import asyncio
import json
import io
import csv

from contextlib import asynccontextmanager
import structlog

from ..core.packet_analyzer import PacketAnalyzer, PacketInfo
from ..core.protocol_parser import ProtocolParser
from ..security.threat_detector import ThreatDetector, ThreatEvent
from ..ml.anomaly_detector import AnomalyDetector, AnomalyScore
from .models import (
    CaptureRequest, ThreatResponse, StatisticsResponse,
    AnomalyResponse, TrainingRequest, AlertConfig
)
from .websocket_manager import WebSocketManager

logger = structlog.get_logger()

websocket_manager = WebSocketManager()
packet_analyzer = None
threat_detector = None
anomaly_detector = None
protocol_parser = None
capture_task = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global packet_analyzer, threat_detector, anomaly_detector, protocol_parser
    
    logger.info("Initializing network security monitor...")
    packet_analyzer = PacketAnalyzer(packet_callback=process_packet)
    threat_detector = ThreatDetector(sensitivity="medium")
    anomaly_detector = AnomalyDetector()
    protocol_parser = ProtocolParser()
    
    yield
    
    logger.info("Shutting down network security monitor...")
    if capture_task:
        capture_task.cancel()


app = FastAPI(
    title="Smart Network Security Monitor API",
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


class CaptureStatus(BaseModel):
    is_running: bool
    packets_captured: int
    threats_detected: int
    start_time: Optional[datetime]
    filter: Optional[str]


packet_buffer = []
threat_events = []
anomaly_scores = []


def process_packet(packet_info: PacketInfo):
    global packet_buffer, threat_events, anomaly_scores
    
    packet_dict = packet_info.to_dict()
    packet_buffer.append(packet_dict)
    
    if len(packet_buffer) > 10000:
        packet_buffer.pop(0)
    
    threat_event = threat_detector.analyze_packet(packet_dict)
    if threat_event:
        threat_events.append(threat_event)
        asyncio.create_task(
            websocket_manager.broadcast_threat(threat_event.to_dict())
        )
    
    if len(packet_buffer) % 100 == 0:
        anomaly_score = anomaly_detector.detect(packet_buffer[-100:])
        anomaly_scores.append(anomaly_score)
        
        if anomaly_score.is_anomaly:
            asyncio.create_task(
                websocket_manager.broadcast_anomaly(anomaly_score.to_dict())
            )
    
    asyncio.create_task(
        websocket_manager.broadcast_packet(packet_dict)
    )


@app.get("/", tags=["Root"])
async def root():
    return {
        "name": "Smart Network Security Monitor",
        "version": "1.0.0",
        "status": "operational",
        "endpoints": {
            "capture": "/api/capture",
            "threats": "/api/threats",
            "anomalies": "/api/anomalies",
            "statistics": "/api/statistics",
            "websocket": "/ws"
        }
    }


@app.post("/api/capture/start", tags=["Capture"])
async def start_capture(request: CaptureRequest, background_tasks: BackgroundTasks):
    global capture_task
    
    if capture_task and not capture_task.done():
        raise HTTPException(status_code=400, detail="Capture already in progress")
    
    async def run_capture():
        try:
            await packet_analyzer.start_async_capture(
                filter_expr=request.filter or "",
                count=request.packet_count or 0
            )
        except Exception as e:
            logger.error(f"Capture error: {e}")
    
    capture_task = asyncio.create_task(run_capture())
    
    return {
        "status": "started",
        "filter": request.filter,
        "interface": request.interface
    }


@app.post("/api/capture/stop", tags=["Capture"])
async def stop_capture():
    global capture_task
    
    if capture_task:
        capture_task.cancel()
        capture_task = None
        return {"status": "stopped"}
    
    return {"status": "not_running"}


@app.get("/api/capture/status", response_model=CaptureStatus, tags=["Capture"])
async def get_capture_status():
    is_running = capture_task and not capture_task.done()
    
    return CaptureStatus(
        is_running=is_running,
        packets_captured=packet_analyzer.packet_count if packet_analyzer else 0,
        threats_detected=len(threat_events),
        start_time=datetime.fromtimestamp(packet_analyzer.start_time) if packet_analyzer else None,
        filter=None
    )


@app.get("/api/threats", tags=["Threats"])
async def get_threats(
    limit: int = 100,
    level: Optional[str] = None,
    threat_type: Optional[str] = None
):
    filtered_threats = threat_events
    
    if level:
        filtered_threats = [t for t in filtered_threats if t.level.name == level.upper()]
    
    if threat_type:
        filtered_threats = [t for t in filtered_threats if t.threat_type.value == threat_type]
    
    return {
        "total": len(filtered_threats),
        "threats": [t.to_dict() for t in filtered_threats[-limit:]]
    }


@app.get("/api/threats/statistics", tags=["Threats"])
async def get_threat_statistics():
    if not threat_detector:
        return {"error": "Threat detector not initialized"}
    
    return threat_detector.get_threat_statistics()


@app.get("/api/anomalies", tags=["Anomalies"])
async def get_anomalies(limit: int = 100, anomalies_only: bool = False):
    filtered_scores = anomaly_scores
    
    if anomalies_only:
        filtered_scores = [s for s in filtered_scores if s.is_anomaly]
    
    return {
        "total": len(filtered_scores),
        "anomalies": [s.to_dict() for s in filtered_scores[-limit:]]
    }


@app.post("/api/anomalies/train", tags=["Anomalies"])
async def train_anomaly_detector(request: TrainingRequest):
    if not anomaly_detector:
        raise HTTPException(status_code=500, detail="Anomaly detector not initialized")
    
    try:
        anomaly_detector.train(packet_buffer, request.labels)
        return {"status": "training_completed", "samples": len(packet_buffer)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/statistics", tags=["Statistics"])
async def get_statistics():
    if not packet_analyzer:
        return {"error": "Packet analyzer not initialized"}
    
    stats = packet_analyzer.get_statistics()
    flow_stats = packet_analyzer.get_flow_statistics()
    
    return {
        "packet_statistics": stats,
        "flow_statistics": flow_stats[:10],
        "buffer_size": len(packet_buffer),
        "threats_detected": len(threat_events),
        "anomalies_detected": sum(1 for s in anomaly_scores if s.is_anomaly)
    }


@app.get("/api/packets", tags=["Packets"])
async def get_packets(
    limit: int = 100,
    protocol: Optional[str] = None,
    src_ip: Optional[str] = None,
    dst_ip: Optional[str] = None
):
    filtered_packets = packet_buffer
    
    if protocol:
        filtered_packets = [p for p in filtered_packets if p.get('protocol') == protocol]
    
    if src_ip:
        filtered_packets = [p for p in filtered_packets if p.get('src_ip') == src_ip]
    
    if dst_ip:
        filtered_packets = [p for p in filtered_packets if p.get('dst_ip') == dst_ip]
    
    return {
        "total": len(filtered_packets),
        "packets": filtered_packets[-limit:]
    }


@app.get("/api/protocols", tags=["Protocols"])
async def analyze_protocol(payload: str):
    if not protocol_parser:
        raise HTTPException(status_code=500, detail="Protocol parser not initialized")
    
    try:
        result = protocol_parser.parse_packet(payload.encode())
        return result
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/api/export/threats", tags=["Export"])
async def export_threats(format: str = "json"):
    if format == "json":
        content = json.dumps([t.to_dict() for t in threat_events], indent=2)
        return StreamingResponse(
            io.BytesIO(content.encode()),
            media_type="application/json",
            headers={"Content-Disposition": "attachment; filename=threats.json"}
        )
    elif format == "csv":
        output = io.StringIO()
        if threat_events:
            writer = csv.DictWriter(output, fieldnames=threat_events[0].to_dict().keys())
            writer.writeheader()
            for threat in threat_events:
                writer.writerow(threat.to_dict())
        
        return StreamingResponse(
            io.BytesIO(output.getvalue().encode()),
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=threats.csv"}
        )
    else:
        raise HTTPException(status_code=400, detail="Unsupported format")


@app.get("/api/export/ioc", tags=["Export"])
async def export_indicators_of_compromise():
    if not threat_detector:
        raise HTTPException(status_code=500, detail="Threat detector not initialized")
    
    ioc = threat_detector.export_ioc()
    return JSONResponse(content=ioc)


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket_manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            
            message = json.loads(data)
            if message.get("type") == "subscribe":
                channels = message.get("channels", ["packets"])
                await websocket_manager.subscribe(websocket, channels)
                await websocket.send_json({
                    "type": "subscribed",
                    "channels": channels
                })
            elif message.get("type") == "ping":
                await websocket.send_json({"type": "pong"})
                
    except WebSocketDisconnect:
        websocket_manager.disconnect(websocket)
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
        websocket_manager.disconnect(websocket)


@app.get("/api/health", tags=["Health"])
async def health_check():
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "components": {
            "packet_analyzer": packet_analyzer is not None,
            "threat_detector": threat_detector is not None,
            "anomaly_detector": anomaly_detector is not None,
            "websocket_connections": len(websocket_manager.active_connections)
        }
    }


@app.post("/api/alerts/config", tags=["Alerts"])
async def configure_alerts(config: AlertConfig):
    return {
        "status": "configured",
        "email": config.email_enabled,
        "webhook": config.webhook_enabled,
        "threshold": config.threat_level_threshold
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)