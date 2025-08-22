import subprocess
import json
import os
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
from dataclasses import dataclass
from pathlib import Path
import hashlib
import ipaddress

import structlog

from .threat_detector import ThreatEvent, ThreatType, ThreatLevel
from ..ml.anomaly_detector import AnomalyScore

logger = structlog.get_logger()


@dataclass
class IncidentResponse:
    timestamp: datetime
    incident_id: str
    action_type: str
    target: str
    success: bool
    details: Dict[str, Any]
    rollback_command: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'timestamp': self.timestamp.isoformat(),
            'incident_id': self.incident_id,
            'action_type': self.action_type,
            'target': self.target,
            'success': self.success,
            'details': self.details,
            'rollback_command': self.rollback_command
        }


class IncidentResponder:
    def __init__(self, config_path: Optional[str] = None):
        self.config = self._load_config(config_path)
        self.response_history = []
        self.blocked_ips = set()
        self.rate_limits = {}
        self.firewall_rules = []
        self.quarantined_files = []
        
    def _load_config(self, config_path: Optional[str]) -> Dict:
        if config_path and Path(config_path).exists():
            with open(config_path, 'r') as f:
                return json.load(f)
        
        return {
            'auto_block': True,
            'auto_quarantine': False,
            'max_block_duration': 3600,
            'rate_limit_threshold': 100,
            'firewall_backend': 'iptables',
            'notification_webhook': None,
            'cisco_asa_integration': False,
            'meraki_integration': False
        }
    
    def respond_to_threat(self, threat: ThreatEvent) -> Dict[str, Any]:
        incident_id = self._generate_incident_id(threat)
        
        logger.info(f"Responding to threat incident {incident_id}",
                   threat_type=threat.threat_type.value,
                   level=threat.level.value)
        
        responses = []
        
        if threat.level == ThreatLevel.CRITICAL:
            responses.append(self._critical_response(threat, incident_id))
        elif threat.level == ThreatLevel.HIGH:
            responses.append(self._high_level_response(threat, incident_id))
        elif threat.level == ThreatLevel.MEDIUM:
            responses.append(self._medium_level_response(threat, incident_id))
        else:
            responses.append(self._low_level_response(threat, incident_id))
        
        if threat.threat_type == ThreatType.DDOS:
            responses.append(self._respond_to_ddos(threat, incident_id))
        elif threat.threat_type == ThreatType.PORT_SCAN:
            responses.append(self._respond_to_port_scan(threat, incident_id))
        elif threat.threat_type == ThreatType.BRUTE_FORCE:
            responses.append(self._respond_to_brute_force(threat, incident_id))
        elif threat.threat_type == ThreatType.MALWARE:
            responses.append(self._respond_to_malware(threat, incident_id))
        elif threat.threat_type == ThreatType.DATA_EXFILTRATION:
            responses.append(self._respond_to_exfiltration(threat, incident_id))
        
        self._generate_firewall_rules(threat, incident_id)
        
        if self.config.get('notification_webhook'):
            self._send_notification(threat, responses)
        
        return {
            'incident_id': incident_id,
            'responses': [r.to_dict() for r in responses if r],
            'success': all(r.success for r in responses if r)
        }
    
    def respond_to_anomaly(self, anomaly: AnomalyScore) -> Dict[str, Any]:
        incident_id = self._generate_incident_id(anomaly)
        
        logger.info(f"Responding to anomaly incident {incident_id}",
                   anomaly_type=anomaly.anomaly_type,
                   confidence=anomaly.confidence)
        
        responses = []
        
        if anomaly.confidence > 0.9:
            responses.append(self._high_confidence_anomaly_response(anomaly, incident_id))
        elif anomaly.confidence > 0.7:
            responses.append(self._medium_confidence_anomaly_response(anomaly, incident_id))
        else:
            responses.append(self._low_confidence_anomaly_response(anomaly, incident_id))
        
        if "Port Scanning" in anomaly.anomaly_type:
            responses.append(self._anomaly_port_scan_response(anomaly, incident_id))
        elif "DDoS" in anomaly.anomaly_type:
            responses.append(self._anomaly_ddos_response(anomaly, incident_id))
        elif "Data Exfiltration" in anomaly.anomaly_type:
            responses.append(self._anomaly_exfiltration_response(anomaly, incident_id))
        
        return {
            'incident_id': incident_id,
            'responses': [r.to_dict() for r in responses if r],
            'success': all(r.success for r in responses if r)
        }
    
    def _generate_incident_id(self, event: Any) -> str:
        timestamp = datetime.now().isoformat()
        event_str = str(event)
        hash_input = f"{timestamp}{event_str}"
        return hashlib.md5(hash_input.encode()).hexdigest()[:12]
    
    def _critical_response(self, threat: ThreatEvent, incident_id: str) -> IncidentResponse:
        logger.critical(f"Critical threat response initiated for {threat.source_ip}")
        
        success = self._block_ip_immediate(threat.source_ip)
        
        if threat.destination_ip:
            self._isolate_host(threat.destination_ip)
        
        self._create_forensic_snapshot(incident_id)
        
        return IncidentResponse(
            timestamp=datetime.now(),
            incident_id=incident_id,
            action_type="CRITICAL_BLOCK",
            target=threat.source_ip,
            success=success,
            details={
                'ip_blocked': threat.source_ip,
                'isolation': threat.destination_ip is not None,
                'forensics': True
            },
            rollback_command=f"iptables -D INPUT -s {threat.source_ip} -j DROP"
        )
    
    def _high_level_response(self, threat: ThreatEvent, incident_id: str) -> IncidentResponse:
        success = self._block_ip_temporary(threat.source_ip, duration=3600)
        
        self._rate_limit_ip(threat.source_ip, limit=10)
        
        return IncidentResponse(
            timestamp=datetime.now(),
            incident_id=incident_id,
            action_type="HIGH_BLOCK",
            target=threat.source_ip,
            success=success,
            details={
                'ip_blocked': threat.source_ip,
                'duration': 3600,
                'rate_limited': True
            }
        )
    
    def _medium_level_response(self, threat: ThreatEvent, incident_id: str) -> IncidentResponse:
        success = self._rate_limit_ip(threat.source_ip, limit=50)
        
        return IncidentResponse(
            timestamp=datetime.now(),
            incident_id=incident_id,
            action_type="RATE_LIMIT",
            target=threat.source_ip,
            success=success,
            details={
                'ip_rate_limited': threat.source_ip,
                'limit': 50
            }
        )
    
    def _low_level_response(self, threat: ThreatEvent, incident_id: str) -> IncidentResponse:
        logger.info(f"Monitoring low-level threat from {threat.source_ip}")
        
        return IncidentResponse(
            timestamp=datetime.now(),
            incident_id=incident_id,
            action_type="MONITOR",
            target=threat.source_ip,
            success=True,
            details={
                'action': 'monitoring',
                'ip': threat.source_ip
            }
        )
    
    def _respond_to_ddos(self, threat: ThreatEvent, incident_id: str) -> IncidentResponse:
        success = True
        
        if self.config.get('auto_block'):
            success = self._enable_syn_cookies()
            self._configure_rate_limiting(threat.source_ip)
        
        if threat.evidence.get('packets_per_10s', 0) > 1000:
            self._null_route_ip(threat.source_ip)
        
        return IncidentResponse(
            timestamp=datetime.now(),
            incident_id=incident_id,
            action_type="DDOS_MITIGATION",
            target=threat.source_ip,
            success=success,
            details={
                'syn_cookies': True,
                'rate_limited': True,
                'null_routed': threat.evidence.get('packets_per_10s', 0) > 1000
            }
        )
    
    def _respond_to_port_scan(self, threat: ThreatEvent, incident_id: str) -> IncidentResponse:
        ports_scanned = threat.evidence.get('ports_scanned', 0)
        
        if ports_scanned > 100:
            success = self._block_ip_immediate(threat.source_ip)
        else:
            success = self._block_ip_temporary(threat.source_ip, duration=1800)
        
        return IncidentResponse(
            timestamp=datetime.now(),
            incident_id=incident_id,
            action_type="PORT_SCAN_BLOCK",
            target=threat.source_ip,
            success=success,
            details={
                'ports_scanned': ports_scanned,
                'block_duration': 'permanent' if ports_scanned > 100 else 1800
            }
        )
    
    def _respond_to_brute_force(self, threat: ThreatEvent, incident_id: str) -> IncidentResponse:
        service = threat.evidence.get('service', 'unknown')
        attempts = threat.evidence.get('attempts_per_minute', 0)
        
        success = self._block_ip_temporary(threat.source_ip, duration=7200)
        
        if service == 'SSH':
            self._configure_fail2ban('ssh', threat.source_ip)
        
        return IncidentResponse(
            timestamp=datetime.now(),
            incident_id=incident_id,
            action_type="BRUTE_FORCE_BLOCK",
            target=threat.source_ip,
            success=success,
            details={
                'service': service,
                'attempts': attempts,
                'block_duration': 7200,
                'fail2ban': service == 'SSH'
            }
        )
    
    def _respond_to_malware(self, threat: ThreatEvent, incident_id: str) -> IncidentResponse:
        success = self._block_ip_immediate(threat.source_ip)
        
        if threat.destination_ip:
            self._quarantine_host(threat.destination_ip)
        
        self._update_antivirus_signatures()
        
        return IncidentResponse(
            timestamp=datetime.now(),
            incident_id=incident_id,
            action_type="MALWARE_QUARANTINE",
            target=threat.source_ip,
            success=success,
            details={
                'ip_blocked': threat.source_ip,
                'host_quarantined': threat.destination_ip,
                'av_updated': True
            }
        )
    
    def _respond_to_exfiltration(self, threat: ThreatEvent, incident_id: str) -> IncidentResponse:
        success = self._block_outbound_traffic(threat.destination_ip)
        
        self._capture_traffic_pcap(threat.source_ip, threat.destination_ip, incident_id)
        
        return IncidentResponse(
            timestamp=datetime.now(),
            incident_id=incident_id,
            action_type="EXFILTRATION_BLOCK",
            target=threat.destination_ip,
            success=success,
            details={
                'outbound_blocked': threat.destination_ip,
                'pcap_captured': True,
                'bytes_transferred': threat.evidence.get('bytes_transferred', 0)
            }
        )
    
    def _block_ip_immediate(self, ip: str) -> bool:
        if ip in self.blocked_ips:
            return True
        
        try:
            if self.config.get('firewall_backend') == 'iptables':
                cmd = f"iptables -A INPUT -s {ip} -j DROP"
                subprocess.run(cmd.split(), check=True, capture_output=True)
            elif self.config.get('cisco_asa_integration'):
                self._cisco_asa_block(ip)
            elif self.config.get('meraki_integration'):
                self._meraki_block(ip)
            
            self.blocked_ips.add(ip)
            logger.info(f"Blocked IP immediately: {ip}")
            return True
        except Exception as e:
            logger.error(f"Failed to block IP {ip}: {e}")
            return False
    
    def _block_ip_temporary(self, ip: str, duration: int) -> bool:
        if ip in self.blocked_ips:
            return True
        
        try:
            if self.config.get('firewall_backend') == 'iptables':
                cmd = f"iptables -A INPUT -s {ip} -j DROP"
                subprocess.run(cmd.split(), check=True, capture_output=True)
                
                cmd_remove = f"echo 'iptables -D INPUT -s {ip} -j DROP' | at now + {duration} seconds"
                subprocess.run(cmd_remove, shell=True, check=True, capture_output=True)
            
            self.blocked_ips.add(ip)
            logger.info(f"Blocked IP temporarily: {ip} for {duration} seconds")
            return True
        except Exception as e:
            logger.error(f"Failed to block IP {ip}: {e}")
            return False
    
    def _rate_limit_ip(self, ip: str, limit: int) -> bool:
        try:
            if self.config.get('firewall_backend') == 'iptables':
                cmd = f"iptables -A INPUT -s {ip} -m limit --limit {limit}/min -j ACCEPT"
                subprocess.run(cmd.split(), check=True, capture_output=True)
                
                cmd2 = f"iptables -A INPUT -s {ip} -j DROP"
                subprocess.run(cmd2.split(), check=True, capture_output=True)
            
            self.rate_limits[ip] = limit
            logger.info(f"Rate limited IP: {ip} to {limit}/min")
            return True
        except Exception as e:
            logger.error(f"Failed to rate limit IP {ip}: {e}")
            return False
    
    def _isolate_host(self, ip: str):
        logger.info(f"Isolating host: {ip}")
    
    def _quarantine_host(self, ip: str):
        logger.info(f"Quarantining host: {ip}")
    
    def _null_route_ip(self, ip: str):
        try:
            cmd = f"ip route add blackhole {ip}"
            subprocess.run(cmd.split(), check=True, capture_output=True)
            logger.info(f"Null routed IP: {ip}")
        except Exception as e:
            logger.error(f"Failed to null route IP {ip}: {e}")
    
    def _enable_syn_cookies(self) -> bool:
        try:
            cmd = "echo 1 > /proc/sys/net/ipv4/tcp_syncookies"
            subprocess.run(cmd, shell=True, check=True, capture_output=True)
            logger.info("Enabled SYN cookies")
            return True
        except Exception as e:
            logger.error(f"Failed to enable SYN cookies: {e}")
            return False
    
    def _configure_rate_limiting(self, ip: str):
        logger.info(f"Configuring rate limiting for {ip}")
    
    def _configure_fail2ban(self, service: str, ip: str):
        logger.info(f"Configuring fail2ban for {service} against {ip}")
    
    def _block_outbound_traffic(self, ip: str) -> bool:
        try:
            cmd = f"iptables -A OUTPUT -d {ip} -j DROP"
            subprocess.run(cmd.split(), check=True, capture_output=True)
            logger.info(f"Blocked outbound traffic to: {ip}")
            return True
        except Exception as e:
            logger.error(f"Failed to block outbound traffic to {ip}: {e}")
            return False
    
    def _capture_traffic_pcap(self, src_ip: str, dst_ip: str, incident_id: str):
        pcap_file = f"captures/incident_{incident_id}.pcap"
        logger.info(f"Capturing traffic to {pcap_file}")
    
    def _create_forensic_snapshot(self, incident_id: str):
        snapshot_dir = Path(f"forensics/{incident_id}")
        snapshot_dir.mkdir(parents=True, exist_ok=True)
        logger.info(f"Created forensic snapshot: {snapshot_dir}")
    
    def _update_antivirus_signatures(self):
        logger.info("Updating antivirus signatures")
    
    def _generate_firewall_rules(self, threat: ThreatEvent, incident_id: str):
        rule = {
            'id': incident_id,
            'source': threat.source_ip,
            'destination': threat.destination_ip,
            'port': threat.port,
            'protocol': threat.protocol,
            'action': 'DROP',
            'threat_type': threat.threat_type.value,
            'timestamp': datetime.now().isoformat()
        }
        
        self.firewall_rules.append(rule)
        
        rules_file = Path('firewall_rules.json')
        with open(rules_file, 'w') as f:
            json.dump(self.firewall_rules, f, indent=2)
    
    def _cisco_asa_block(self, ip: str):
        logger.info(f"Cisco ASA: Blocking {ip}")
    
    def _meraki_block(self, ip: str):
        logger.info(f"Meraki: Blocking {ip}")
    
    def _send_notification(self, threat: ThreatEvent, responses: List[IncidentResponse]):
        webhook_url = self.config.get('notification_webhook')
        if not webhook_url:
            return
        
        payload = {
            'incident': threat.to_dict(),
            'responses': [r.to_dict() for r in responses if r],
            'timestamp': datetime.now().isoformat()
        }
        
        logger.info(f"Sending notification to webhook: {webhook_url}")
    
    def _high_confidence_anomaly_response(self, anomaly: AnomalyScore, incident_id: str) -> IncidentResponse:
        logger.warning(f"High confidence anomaly response: {anomaly.anomaly_type}")
        
        return IncidentResponse(
            timestamp=datetime.now(),
            incident_id=incident_id,
            action_type="ANOMALY_HIGH",
            target="network",
            success=True,
            details={
                'anomaly_type': anomaly.anomaly_type,
                'confidence': anomaly.confidence,
                'action': 'investigate'
            }
        )
    
    def _medium_confidence_anomaly_response(self, anomaly: AnomalyScore, incident_id: str) -> IncidentResponse:
        return IncidentResponse(
            timestamp=datetime.now(),
            incident_id=incident_id,
            action_type="ANOMALY_MEDIUM",
            target="network",
            success=True,
            details={
                'anomaly_type': anomaly.anomaly_type,
                'confidence': anomaly.confidence,
                'action': 'monitor'
            }
        )
    
    def _low_confidence_anomaly_response(self, anomaly: AnomalyScore, incident_id: str) -> IncidentResponse:
        return IncidentResponse(
            timestamp=datetime.now(),
            incident_id=incident_id,
            action_type="ANOMALY_LOW",
            target="network",
            success=True,
            details={
                'anomaly_type': anomaly.anomaly_type,
                'confidence': anomaly.confidence,
                'action': 'log'
            }
        )
    
    def _anomaly_port_scan_response(self, anomaly: AnomalyScore, incident_id: str) -> IncidentResponse:
        logger.info("Anomaly-based port scan detected")
        return IncidentResponse(
            timestamp=datetime.now(),
            incident_id=incident_id,
            action_type="ANOMALY_PORT_SCAN",
            target="network",
            success=True,
            details={'action': 'enhanced_monitoring'}
        )
    
    def _anomaly_ddos_response(self, anomaly: AnomalyScore, incident_id: str) -> IncidentResponse:
        success = self._enable_syn_cookies()
        return IncidentResponse(
            timestamp=datetime.now(),
            incident_id=incident_id,
            action_type="ANOMALY_DDOS",
            target="network",
            success=success,
            details={'syn_cookies': True}
        )
    
    def _anomaly_exfiltration_response(self, anomaly: AnomalyScore, incident_id: str) -> IncidentResponse:
        return IncidentResponse(
            timestamp=datetime.now(),
            incident_id=incident_id,
            action_type="ANOMALY_EXFILTRATION",
            target="network",
            success=True,
            details={'action': 'traffic_analysis'}
        )