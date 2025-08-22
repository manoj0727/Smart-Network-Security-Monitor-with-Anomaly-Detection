from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional
from datetime import datetime
from enum import Enum


class CaptureRequest(BaseModel):
    interface: Optional[str] = Field(None, description="Network interface to capture on")
    filter: Optional[str] = Field(None, description="BPF filter expression")
    packet_count: Optional[int] = Field(0, description="Number of packets to capture (0 for unlimited)")
    timeout: Optional[int] = Field(None, description="Capture timeout in seconds")


class ThreatLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ThreatResponse(BaseModel):
    timestamp: datetime
    threat_type: str
    level: ThreatLevel
    source_ip: str
    destination_ip: Optional[str]
    port: Optional[int]
    protocol: Optional[str]
    description: str
    evidence: Dict[str, Any]
    signature_id: Optional[str]
    false_positive_probability: float
    recommended_action: str


class AnomalyResponse(BaseModel):
    timestamp: datetime
    score: float
    is_anomaly: bool
    confidence: float
    feature_contributions: Dict[str, float]
    anomaly_type: str
    explanation: str


class StatisticsResponse(BaseModel):
    total_packets: int
    packets_per_second: float
    uptime_seconds: float
    protocol_distribution: Dict[str, int]
    active_flows: int
    buffer_size: int
    threats_detected: int
    anomalies_detected: int


class TrainingRequest(BaseModel):
    labels: Optional[List[int]] = Field(None, description="Labels for supervised training")
    use_current_buffer: bool = Field(True, description="Use current packet buffer for training")


class AlertConfig(BaseModel):
    email_enabled: bool = Field(False, description="Enable email alerts")
    email_recipients: List[str] = Field(default_factory=list, description="Email recipients")
    webhook_enabled: bool = Field(False, description="Enable webhook alerts")
    webhook_url: Optional[str] = Field(None, description="Webhook URL")
    threat_level_threshold: ThreatLevel = Field(ThreatLevel.MEDIUM, description="Minimum threat level for alerts")
    anomaly_confidence_threshold: float = Field(0.7, description="Minimum confidence for anomaly alerts")


class FlowStatistics(BaseModel):
    flow_id: str
    duration: float
    packet_count: int
    bytes: int
    avg_packet_size: float
    is_active: bool


class ProtocolAnalysis(BaseModel):
    protocol: str
    details: Dict[str, Any]
    confidence: float


class NetworkInterface(BaseModel):
    name: str
    description: str
    addresses: List[str]
    is_up: bool
    is_wireless: bool


class FilterTemplate(BaseModel):
    name: str
    description: str
    filter: str
    category: str


class ExportRequest(BaseModel):
    format: str = Field("json", description="Export format (json, csv, pcap)")
    start_time: Optional[datetime] = Field(None, description="Start time for export")
    end_time: Optional[datetime] = Field(None, description="End time for export")
    include_threats: bool = Field(True, description="Include threat events")
    include_anomalies: bool = Field(True, description="Include anomaly scores")
    include_packets: bool = Field(False, description="Include raw packets")