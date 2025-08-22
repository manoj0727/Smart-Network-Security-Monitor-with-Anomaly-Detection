import asyncio
import threading
from typing import Dict, List, Any, Optional, Callable
from datetime import datetime, timedelta
import json
from pathlib import Path
from collections import deque

import structlog
import schedule

from .packet_analyzer import PacketAnalyzer, PacketInfo
from .protocol_parser import ProtocolParser
from ..security.threat_detector import ThreatDetector, ThreatEvent
from ..ml.anomaly_detector import AnomalyDetector, AnomalyScore
from ..security.incident_response import IncidentResponder

logger = structlog.get_logger()


class NetworkMonitor:
    def __init__(self, config_path: Optional[str] = None):
        self.config = self._load_config(config_path)
        
        self.packet_analyzer = PacketAnalyzer(
            interface=self.config.get('interface'),
            packet_callback=self._process_packet
        )
        
        self.threat_detector = ThreatDetector(
            sensitivity=self.config.get('threat_sensitivity', 'medium')
        )
        
        self.anomaly_detector = AnomalyDetector(
            model_path=self.config.get('model_path')
        )
        
        self.protocol_parser = ProtocolParser()
        self.incident_responder = IncidentResponder()
        
        self.packet_buffer = deque(maxlen=10000)
        self.threat_history = deque(maxlen=1000)
        self.anomaly_history = deque(maxlen=1000)
        
        self.statistics = {
            'start_time': None,
            'packets_processed': 0,
            'threats_detected': 0,
            'anomalies_detected': 0,
            'incidents_responded': 0
        }
        
        self.callbacks = {
            'packet': [],
            'threat': [],
            'anomaly': [],
            'incident': []
        }
        
        self.is_running = False
        self.capture_thread = None
        self.analysis_task = None
        
        self._setup_scheduled_tasks()
    
    def _load_config(self, config_path: Optional[str]) -> Dict:
        if config_path and Path(config_path).exists():
            with open(config_path, 'r') as f:
                return json.load(f)
        
        return {
            'interface': None,
            'capture_filter': '',
            'threat_sensitivity': 'medium',
            'anomaly_threshold': 0.7,
            'model_path': 'models/anomaly_detector.pkl',
            'auto_response': True,
            'log_level': 'INFO'
        }
    
    def _setup_scheduled_tasks(self):
        schedule.every(5).minutes.do(self._update_statistics)
        schedule.every(30).minutes.do(self._retrain_models)
        schedule.every(1).hour.do(self._generate_report)
        schedule.every(24).hours.do(self._cleanup_old_data)
    
    def register_callback(self, event_type: str, callback: Callable):
        if event_type in self.callbacks:
            self.callbacks[event_type].append(callback)
            logger.info(f"Registered callback for {event_type} events")
    
    def start(self, capture_filter: Optional[str] = None):
        if self.is_running:
            logger.warning("Monitor already running")
            return
        
        self.is_running = True
        self.statistics['start_time'] = datetime.now()
        
        filter_expr = capture_filter or self.config.get('capture_filter', '')
        
        self.capture_thread = threading.Thread(
            target=self._run_capture,
            args=(filter_expr,),
            daemon=True
        )
        self.capture_thread.start()
        
        asyncio.create_task(self._run_analysis_loop())
        
        threading.Thread(target=self._run_scheduler, daemon=True).start()
        
        logger.info("Network monitor started", filter=filter_expr)
    
    def stop(self):
        if not self.is_running:
            logger.warning("Monitor not running")
            return
        
        self.is_running = False
        
        if self.analysis_task:
            self.analysis_task.cancel()
        
        self._generate_final_report()
        
        logger.info("Network monitor stopped")
    
    def _run_capture(self, filter_expr: str):
        try:
            self.packet_analyzer.start_capture(filter_expr)
        except Exception as e:
            logger.error(f"Capture error: {e}")
            self.is_running = False
    
    async def _run_analysis_loop(self):
        while self.is_running:
            try:
                await self._analyze_traffic_patterns()
                await asyncio.sleep(10)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Analysis loop error: {e}")
    
    def _run_scheduler(self):
        while self.is_running:
            schedule.run_pending()
            threading.Event().wait(1)
    
    def _process_packet(self, packet_info: PacketInfo):
        self.statistics['packets_processed'] += 1
        
        packet_dict = packet_info.to_dict()
        self.packet_buffer.append(packet_dict)
        
        for callback in self.callbacks['packet']:
            try:
                callback(packet_dict)
            except Exception as e:
                logger.error(f"Packet callback error: {e}")
        
        threat_event = self.threat_detector.analyze_packet(packet_dict)
        if threat_event:
            self._handle_threat(threat_event)
        
        if len(self.packet_buffer) % 100 == 0:
            self._check_anomaly()
    
    def _handle_threat(self, threat_event: ThreatEvent):
        self.statistics['threats_detected'] += 1
        self.threat_history.append(threat_event)
        
        logger.warning(
            "Threat detected",
            type=threat_event.threat_type.value,
            level=threat_event.level.value,
            source=threat_event.source_ip
        )
        
        for callback in self.callbacks['threat']:
            try:
                callback(threat_event.to_dict())
            except Exception as e:
                logger.error(f"Threat callback error: {e}")
        
        if self.config.get('auto_response') and threat_event.level.value >= 3:
            response = self.incident_responder.respond_to_threat(threat_event)
            self._handle_incident_response(response)
    
    def _check_anomaly(self):
        recent_packets = list(self.packet_buffer)[-100:]
        anomaly_score = self.anomaly_detector.detect(recent_packets)
        
        if anomaly_score.is_anomaly:
            self.statistics['anomalies_detected'] += 1
            self.anomaly_history.append(anomaly_score)
            
            logger.warning(
                "Anomaly detected",
                type=anomaly_score.anomaly_type,
                confidence=anomaly_score.confidence,
                explanation=anomaly_score.explanation
            )
            
            for callback in self.callbacks['anomaly']:
                try:
                    callback(anomaly_score.to_dict())
                except Exception as e:
                    logger.error(f"Anomaly callback error: {e}")
            
            if self.config.get('auto_response') and anomaly_score.confidence > 0.8:
                response = self.incident_responder.respond_to_anomaly(anomaly_score)
                self._handle_incident_response(response)
    
    def _handle_incident_response(self, response: Dict[str, Any]):
        if not response:
            return
        
        self.statistics['incidents_responded'] += 1
        
        logger.info(
            "Incident response executed",
            action=response.get('action'),
            success=response.get('success')
        )
        
        for callback in self.callbacks['incident']:
            try:
                callback(response)
            except Exception as e:
                logger.error(f"Incident callback error: {e}")
    
    async def _analyze_traffic_patterns(self):
        if len(self.packet_buffer) < 100:
            return
        
        recent_packets = list(self.packet_buffer)[-1000:]
        
        flow_stats = self.packet_analyzer.get_flow_statistics()
        active_flows = [f for f in flow_stats if f['is_active']]
        
        if len(active_flows) > 100:
            logger.warning(f"High number of active flows: {len(active_flows)}")
        
        port_scanners = self.packet_analyzer.detect_port_scan()
        if port_scanners:
            logger.warning(f"Port scan detected from: {port_scanners}")
        
        protocol_dist = self.packet_analyzer.protocol_stats
        total_packets = sum(protocol_dist.values())
        if total_packets > 0:
            for protocol, count in protocol_dist.items():
                ratio = count / total_packets
                if protocol == 'ICMP' and ratio > 0.3:
                    logger.warning(f"High ICMP traffic ratio: {ratio:.2%}")
    
    def _update_statistics(self):
        stats = self.get_statistics()
        logger.info("Statistics update", **stats)
    
    def _retrain_models(self):
        if len(self.packet_buffer) < 1000:
            return
        
        logger.info("Retraining anomaly detection model...")
        
        normal_traffic = [p for p in self.packet_buffer if not self._is_malicious(p)]
        if len(normal_traffic) > 500:
            self.anomaly_detector.update_baseline(list(normal_traffic))
    
    def _is_malicious(self, packet: Dict[str, Any]) -> bool:
        for threat in self.threat_history:
            if (threat.source_ip == packet.get('src_ip') and 
                abs((threat.timestamp - datetime.fromtimestamp(packet.get('timestamp', 0))).total_seconds()) < 60):
                return True
        return False
    
    def _generate_report(self):
        report = {
            'timestamp': datetime.now().isoformat(),
            'statistics': self.get_statistics(),
            'top_threats': self._get_top_threats(),
            'top_anomalies': self._get_top_anomalies(),
            'recommendations': self._generate_recommendations()
        }
        
        report_path = Path('reports') / f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        report_path.parent.mkdir(exist_ok=True)
        
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2)
        
        logger.info(f"Report generated: {report_path}")
    
    def _generate_final_report(self):
        report = {
            'session_summary': {
                'start_time': self.statistics['start_time'].isoformat() if self.statistics['start_time'] else None,
                'end_time': datetime.now().isoformat(),
                'total_packets': self.statistics['packets_processed'],
                'threats_detected': self.statistics['threats_detected'],
                'anomalies_detected': self.statistics['anomalies_detected'],
                'incidents_responded': self.statistics['incidents_responded']
            },
            'threat_summary': self._get_threat_summary(),
            'anomaly_summary': self._get_anomaly_summary(),
            'ioc': self.threat_detector.export_ioc()
        }
        
        report_path = Path('reports') / f"final_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        report_path.parent.mkdir(exist_ok=True)
        
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2)
        
        logger.info(f"Final report generated: {report_path}")
    
    def _get_top_threats(self, limit: int = 5) -> List[Dict]:
        threat_counts = {}
        for threat in self.threat_history:
            key = threat.threat_type.value
            threat_counts[key] = threat_counts.get(key, 0) + 1
        
        sorted_threats = sorted(threat_counts.items(), key=lambda x: x[1], reverse=True)
        return [{'type': k, 'count': v} for k, v in sorted_threats[:limit]]
    
    def _get_top_anomalies(self, limit: int = 5) -> List[Dict]:
        anomaly_types = {}
        for anomaly in self.anomaly_history:
            key = anomaly.anomaly_type
            anomaly_types[key] = anomaly_types.get(key, 0) + 1
        
        sorted_anomalies = sorted(anomaly_types.items(), key=lambda x: x[1], reverse=True)
        return [{'type': k, 'count': v} for k, v in sorted_anomalies[:limit]]
    
    def _get_threat_summary(self) -> Dict:
        if not self.threat_history:
            return {}
        
        return {
            'total': len(self.threat_history),
            'by_level': self._count_by_level(self.threat_history),
            'by_type': self._count_by_type(self.threat_history),
            'top_sources': self._get_top_sources(self.threat_history)
        }
    
    def _get_anomaly_summary(self) -> Dict:
        if not self.anomaly_history:
            return {}
        
        confidences = [a.confidence for a in self.anomaly_history]
        return {
            'total': len(self.anomaly_history),
            'avg_confidence': sum(confidences) / len(confidences),
            'by_type': self._count_anomaly_types(self.anomaly_history)
        }
    
    def _count_by_level(self, threats: List[ThreatEvent]) -> Dict:
        levels = {}
        for threat in threats:
            level = threat.level.name
            levels[level] = levels.get(level, 0) + 1
        return levels
    
    def _count_by_type(self, threats: List[ThreatEvent]) -> Dict:
        types = {}
        for threat in threats:
            threat_type = threat.threat_type.value
            types[threat_type] = types.get(threat_type, 0) + 1
        return types
    
    def _get_top_sources(self, threats: List[ThreatEvent], limit: int = 5) -> List[str]:
        sources = {}
        for threat in threats:
            src = threat.source_ip
            sources[src] = sources.get(src, 0) + 1
        
        sorted_sources = sorted(sources.items(), key=lambda x: x[1], reverse=True)
        return [src for src, _ in sorted_sources[:limit]]
    
    def _count_anomaly_types(self, anomalies: List[AnomalyScore]) -> Dict:
        types = {}
        for anomaly in anomalies:
            types[anomaly.anomaly_type] = types.get(anomaly.anomaly_type, 0) + 1
        return types
    
    def _generate_recommendations(self) -> List[str]:
        recommendations = []
        
        if self.statistics['threats_detected'] > 100:
            recommendations.append("High threat activity detected. Consider implementing stricter firewall rules.")
        
        if self.statistics['anomalies_detected'] > 50:
            recommendations.append("Frequent anomalies detected. Review network baseline and update detection thresholds.")
        
        port_scanners = self.packet_analyzer.detect_port_scan()
        if port_scanners:
            recommendations.append(f"Block IP addresses involved in port scanning: {', '.join(port_scanners)}")
        
        threat_stats = self.threat_detector.get_threat_statistics()
        if threat_stats.get('blacklisted_ips', 0) > 10:
            recommendations.append("Update firewall blacklist with newly detected malicious IPs.")
        
        return recommendations
    
    def _cleanup_old_data(self):
        max_buffer_size = 10000
        if len(self.packet_buffer) > max_buffer_size:
            removed = len(self.packet_buffer) - max_buffer_size
            for _ in range(removed):
                self.packet_buffer.popleft()
            logger.info(f"Cleaned up {removed} old packets from buffer")
    
    def get_statistics(self) -> Dict[str, Any]:
        uptime = None
        if self.statistics['start_time']:
            uptime = (datetime.now() - self.statistics['start_time']).total_seconds()
        
        return {
            'uptime_seconds': uptime,
            'packets_processed': self.statistics['packets_processed'],
            'threats_detected': self.statistics['threats_detected'],
            'anomalies_detected': self.statistics['anomalies_detected'],
            'incidents_responded': self.statistics['incidents_responded'],
            'packets_per_second': self.statistics['packets_processed'] / uptime if uptime else 0,
            'threat_rate': self.statistics['threats_detected'] / (uptime / 3600) if uptime else 0,
            'anomaly_rate': self.statistics['anomalies_detected'] / (uptime / 3600) if uptime else 0
        }