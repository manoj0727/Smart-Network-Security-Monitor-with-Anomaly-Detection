from typing import List, Dict, Set
from fastapi import WebSocket
import json
import asyncio
from datetime import datetime
import structlog

logger = structlog.get_logger()


class WebSocketManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []
        self.subscriptions: Dict[WebSocket, Set[str]] = {}
        self.connection_info: Dict[WebSocket, Dict] = {}
        
    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        self.subscriptions[websocket] = {"packets"}
        self.connection_info[websocket] = {
            "connected_at": datetime.now(),
            "messages_sent": 0,
            "messages_received": 0
        }
        logger.info(f"WebSocket connected. Total connections: {len(self.active_connections)}")
        
    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
        if websocket in self.subscriptions:
            del self.subscriptions[websocket]
        if websocket in self.connection_info:
            del self.connection_info[websocket]
        logger.info(f"WebSocket disconnected. Total connections: {len(self.active_connections)}")
    
    async def subscribe(self, websocket: WebSocket, channels: List[str]):
        valid_channels = {"packets", "threats", "anomalies", "statistics", "alerts"}
        channels_to_add = set(channels) & valid_channels
        self.subscriptions[websocket] = channels_to_add
        logger.debug(f"WebSocket subscribed to channels: {channels_to_add}")
    
    async def send_personal_message(self, message: str, websocket: WebSocket):
        try:
            await websocket.send_text(message)
            if websocket in self.connection_info:
                self.connection_info[websocket]["messages_sent"] += 1
        except Exception as e:
            logger.error(f"Error sending personal message: {e}")
            self.disconnect(websocket)
    
    async def broadcast(self, message: str, channel: str = "packets"):
        disconnected = []
        for websocket in self.active_connections:
            if channel in self.subscriptions.get(websocket, set()):
                try:
                    await websocket.send_text(message)
                    if websocket in self.connection_info:
                        self.connection_info[websocket]["messages_sent"] += 1
                except Exception as e:
                    logger.error(f"Error broadcasting to websocket: {e}")
                    disconnected.append(websocket)
        
        for websocket in disconnected:
            self.disconnect(websocket)
    
    async def broadcast_packet(self, packet_data: Dict):
        message = json.dumps({
            "type": "packet",
            "timestamp": datetime.now().isoformat(),
            "data": packet_data
        })
        await self.broadcast(message, "packets")
    
    async def broadcast_threat(self, threat_data: Dict):
        message = json.dumps({
            "type": "threat",
            "timestamp": datetime.now().isoformat(),
            "data": threat_data
        })
        await self.broadcast(message, "threats")
        
        if threat_data.get("level") in ["HIGH", "CRITICAL"]:
            alert_message = json.dumps({
                "type": "alert",
                "severity": threat_data.get("level"),
                "message": threat_data.get("description"),
                "timestamp": datetime.now().isoformat(),
                "data": threat_data
            })
            await self.broadcast(alert_message, "alerts")
    
    async def broadcast_anomaly(self, anomaly_data: Dict):
        message = json.dumps({
            "type": "anomaly",
            "timestamp": datetime.now().isoformat(),
            "data": anomaly_data
        })
        await self.broadcast(message, "anomalies")
        
        if anomaly_data.get("confidence", 0) > 0.8:
            alert_message = json.dumps({
                "type": "alert",
                "severity": "MEDIUM",
                "message": f"Anomaly detected: {anomaly_data.get('explanation')}",
                "timestamp": datetime.now().isoformat(),
                "data": anomaly_data
            })
            await self.broadcast(alert_message, "alerts")
    
    async def broadcast_statistics(self, stats_data: Dict):
        message = json.dumps({
            "type": "statistics",
            "timestamp": datetime.now().isoformat(),
            "data": stats_data
        })
        await self.broadcast(message, "statistics")
    
    def get_connection_stats(self) -> Dict:
        return {
            "total_connections": len(self.active_connections),
            "subscriptions": {
                channel: sum(1 for subs in self.subscriptions.values() if channel in subs)
                for channel in ["packets", "threats", "anomalies", "statistics", "alerts"]
            },
            "connections": [
                {
                    "connected_at": info["connected_at"].isoformat(),
                    "messages_sent": info["messages_sent"],
                    "messages_received": info["messages_received"],
                    "subscribed_channels": list(self.subscriptions.get(ws, set()))
                }
                for ws, info in self.connection_info.items()
            ]
        }