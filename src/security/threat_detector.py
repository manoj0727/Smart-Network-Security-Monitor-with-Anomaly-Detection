import re
import ipaddress
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from collections import defaultdict, deque
import hashlib
import json

import structlog
from enum import Enum

logger = structlog.get_logger()


class ThreatLevel(Enum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class ThreatType(Enum):
    PORT_SCAN = "Port Scan"
    DDOS = "DDoS Attack"
    BRUTE_FORCE = "Brute Force"
    SQL_INJECTION = "SQL Injection"
    XSS = "Cross-Site Scripting"
    MALWARE = "Malware Traffic"
    DATA_EXFILTRATION = "Data Exfiltration"
    PRIVILEGE_ESCALATION = "Privilege Escalation"
    COMMAND_INJECTION = "Command Injection"
    DNS_TUNNELING = "DNS Tunneling"
    ARP_SPOOFING = "ARP Spoofing"
    MAN_IN_THE_MIDDLE = "Man-in-the-Middle"
    ZERO_DAY = "Zero-Day Exploit"
    BOTNET = "Botnet Activity"
    CRYPTOMINING = "Cryptocurrency Mining"


@dataclass
class ThreatSignature:
    id: str
    name: str
    type: ThreatType
    pattern: str
    level: ThreatLevel
    description: str
    protocol: Optional[str] = None
    port: Optional[int] = None
    direction: str = "any"
    action: str = "alert"
    references: List[str] = field(default_factory=list)


@dataclass
class ThreatEvent:
    timestamp: datetime
    threat_type: ThreatType
    level: ThreatLevel
    source_ip: str
    destination_ip: Optional[str]
    port: Optional[int]
    protocol: Optional[str]
    description: str
    evidence: Dict[str, Any]
    signature_id: Optional[str] = None
    false_positive_probability: float = 0.0
    recommended_action: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'timestamp': self.timestamp.isoformat(),
            'threat_type': self.threat_type.value,
            'level': self.level.value,
            'source_ip': self.source_ip,
            'destination_ip': self.destination_ip,
            'port': self.port,
            'protocol': self.protocol,
            'description': self.description,
            'evidence': self.evidence,
            'signature_id': self.signature_id,
            'false_positive_probability': self.false_positive_probability,
            'recommended_action': self.recommended_action
        }


class ThreatDetector:
    def __init__(self, sensitivity: str = "medium"):
        self.sensitivity = sensitivity
        self.signatures = self._load_signatures()
        self.threat_history = deque(maxlen=10000)
        self.ip_reputation = {}
        self.connection_tracker = defaultdict(lambda: {'count': 0, 'last_seen': None})
        self.port_scan_tracker = defaultdict(set)
        self.ddos_tracker = defaultdict(lambda: {'count': 0, 'window_start': datetime.now()})
        self.brute_force_tracker = defaultdict(list)
        self.dns_query_tracker = defaultdict(list)
        self.blacklisted_ips = set()
        self.whitelisted_ips = set()
        self._load_threat_intelligence()
        
    def _load_signatures(self) -> List[ThreatSignature]:
        signatures = [
            ThreatSignature(
                id="SIG001",
                name="SQL Injection Attempt",
                type=ThreatType.SQL_INJECTION,
                pattern=r"(\bSELECT\b.*\bFROM\b|\bUNION\b.*\bSELECT\b|\bDROP\b.*\bTABLE\b|'.*OR.*'.*=|1=1|\'|\"|;|--)",
                level=ThreatLevel.HIGH,
                description="Detected potential SQL injection attempt",
                protocol="HTTP"
            ),
            ThreatSignature(
                id="SIG002",
                name="XSS Attack Pattern",
                type=ThreatType.XSS,
                pattern=r"(<script.*?>.*?</script>|javascript:|onerror=|onload=|alert\(|document\.cookie)",
                level=ThreatLevel.MEDIUM,
                description="Detected potential cross-site scripting attack",
                protocol="HTTP"
            ),
            ThreatSignature(
                id="SIG003",
                name="Command Injection",
                type=ThreatType.COMMAND_INJECTION,
                pattern=r"(;|\||&&|\$\(|\`|>|<|\{|\}|\[|\]|\\n|%0a|%0d)",
                level=ThreatLevel.HIGH,
                description="Detected potential command injection attempt"
            ),
            ThreatSignature(
                id="SIG004",
                name="Directory Traversal",
                type=ThreatType.PRIVILEGE_ESCALATION,
                pattern=r"(\.\./|\.\.\\|%2e%2e%2f|%252e%252e%252f)",
                level=ThreatLevel.MEDIUM,
                description="Detected directory traversal attempt"
            ),
            ThreatSignature(
                id="SIG005",
                name="Suspicious PowerShell",
                type=ThreatType.MALWARE,
                pattern=r"(powershell|cmd\.exe|/c\s+|IEX|Invoke-Expression|downloadstring)",
                level=ThreatLevel.HIGH,
                description="Detected suspicious PowerShell activity"
            ),
            ThreatSignature(
                id="SIG006",
                name="Cryptominer Detection",
                type=ThreatType.CRYPTOMINING,
                pattern=r"(coinhive|cryptonight|monero|xmrig|minergate)",
                level=ThreatLevel.MEDIUM,
                description="Detected potential cryptocurrency mining activity"
            ),
            ThreatSignature(
                id="SIG007",
                name="DNS Tunneling Pattern",
                type=ThreatType.DNS_TUNNELING,
                pattern=r"([a-zA-Z0-9]{50,}\.)",
                level=ThreatLevel.HIGH,
                description="Unusually long DNS query detected",
                protocol="DNS"
            ),
            ThreatSignature(
                id="SIG008",
                name="Suspicious User Agent",
                type=ThreatType.BOTNET,
                pattern=r"(bot|crawler|scanner|nikto|nmap|masscan|sqlmap|metasploit)",
                level=ThreatLevel.MEDIUM,
                description="Detected suspicious user agent"
            ),
        ]
        
        return signatures
    
    def _load_threat_intelligence(self):
        known_malicious_ips = [
            "192.168.1.100",
            "10.0.0.50",
        ]
        
        self.blacklisted_ips.update(known_malicious_ips)
        
        trusted_ips = [
            "8.8.8.8",
            "1.1.1.1",
            "127.0.0.1",
        ]
        
        self.whitelisted_ips.update(trusted_ips)
    
    def analyze_packet(self, packet_info: Dict[str, Any]) -> Optional[ThreatEvent]:
        threats = []
        
        if self._is_whitelisted(packet_info.get('src_ip')):
            return None
        
        if self._is_blacklisted(packet_info.get('src_ip')):
            threats.append(self._create_threat_event(
                ThreatType.MALWARE,
                ThreatLevel.CRITICAL,
                packet_info,
                "Traffic from known malicious IP",
                {'blacklisted_ip': packet_info.get('src_ip')}
            ))
        
        port_scan_threat = self._detect_port_scan(packet_info)
        if port_scan_threat:
            threats.append(port_scan_threat)
        
        ddos_threat = self._detect_ddos(packet_info)
        if ddos_threat:
            threats.append(ddos_threat)
        
        brute_force_threat = self._detect_brute_force(packet_info)
        if brute_force_threat:
            threats.append(brute_force_threat)
        
        payload = packet_info.get('payload_preview', '')
        if payload:
            signature_threats = self._check_signatures(payload, packet_info)
            threats.extend(signature_threats)
        
        dns_threat = self._detect_dns_tunneling(packet_info)
        if dns_threat:
            threats.append(dns_threat)
        
        exfiltration_threat = self._detect_data_exfiltration(packet_info)
        if exfiltration_threat:
            threats.append(exfiltration_threat)
        
        if threats:
            most_severe = max(threats, key=lambda t: t.level.value)
            self.threat_history.append(most_severe)
            self._update_ip_reputation(packet_info.get('src_ip'), most_severe)
            return most_severe
        
        return None
    
    def _detect_port_scan(self, packet_info: Dict[str, Any]) -> Optional[ThreatEvent]:
        src_ip = packet_info.get('src_ip')
        dst_port = packet_info.get('dst_port')
        flags = packet_info.get('flags', {})
        
        if not src_ip or not dst_port:
            return None
        
        if flags.get('syn') and not flags.get('ack'):
            self.port_scan_tracker[src_ip].add(dst_port)
            
            threshold = self._get_threshold('port_scan')
            if len(self.port_scan_tracker[src_ip]) > threshold:
                return self._create_threat_event(
                    ThreatType.PORT_SCAN,
                    ThreatLevel.MEDIUM,
                    packet_info,
                    f"Port scan detected from {src_ip}",
                    {
                        'ports_scanned': len(self.port_scan_tracker[src_ip]),
                        'scan_type': 'SYN scan'
                    }
                )
        
        return None
    
    def _detect_ddos(self, packet_info: Dict[str, Any]) -> Optional[ThreatEvent]:
        src_ip = packet_info.get('src_ip')
        timestamp = datetime.fromtimestamp(packet_info.get('timestamp', 0))
        
        if not src_ip:
            return None
        
        tracker = self.ddos_tracker[src_ip]
        
        if timestamp - tracker['window_start'] > timedelta(seconds=10):
            tracker['count'] = 0
            tracker['window_start'] = timestamp
        
        tracker['count'] += 1
        
        threshold = self._get_threshold('ddos')
        if tracker['count'] > threshold:
            level = ThreatLevel.CRITICAL if tracker['count'] > threshold * 2 else ThreatLevel.HIGH
            return self._create_threat_event(
                ThreatType.DDOS,
                level,
                packet_info,
                f"Potential DDoS attack from {src_ip}",
                {
                    'packets_per_10s': tracker['count'],
                    'attack_type': self._classify_ddos_type(packet_info)
                }
            )
        
        return None
    
    def _detect_brute_force(self, packet_info: Dict[str, Any]) -> Optional[ThreatEvent]:
        src_ip = packet_info.get('src_ip')
        dst_port = packet_info.get('dst_port')
        timestamp = packet_info.get('timestamp', 0)
        
        auth_ports = {22: 'SSH', 21: 'FTP', 23: 'Telnet', 3389: 'RDP', 445: 'SMB'}
        
        if dst_port not in auth_ports:
            return None
        
        self.brute_force_tracker[src_ip].append(timestamp)
        
        self.brute_force_tracker[src_ip] = [
            t for t in self.brute_force_tracker[src_ip] 
            if timestamp - t < 60
        ]
        
        threshold = self._get_threshold('brute_force')
        if len(self.brute_force_tracker[src_ip]) > threshold:
            return self._create_threat_event(
                ThreatType.BRUTE_FORCE,
                ThreatLevel.HIGH,
                packet_info,
                f"Brute force attack detected on {auth_ports[dst_port]}",
                {
                    'service': auth_ports[dst_port],
                    'attempts_per_minute': len(self.brute_force_tracker[src_ip])
                }
            )
        
        return None
    
    def _check_signatures(self, payload: str, packet_info: Dict[str, Any]) -> List[ThreatEvent]:
        threats = []
        
        for signature in self.signatures:
            if signature.protocol and signature.protocol != packet_info.get('protocol'):
                continue
            
            if re.search(signature.pattern, payload, re.IGNORECASE):
                threat = self._create_threat_event(
                    signature.type,
                    signature.level,
                    packet_info,
                    signature.description,
                    {
                        'signature_id': signature.id,
                        'matched_pattern': signature.pattern[:50]
                    }
                )
                threat.signature_id = signature.id
                threats.append(threat)
        
        return threats
    
    def _detect_dns_tunneling(self, packet_info: Dict[str, Any]) -> Optional[ThreatEvent]:
        if packet_info.get('protocol') != 'DNS':
            return None
        
        dns_query = packet_info.get('dns_query', '')
        if not dns_query:
            return None
        
        src_ip = packet_info.get('src_ip')
        self.dns_query_tracker[src_ip].append(dns_query)
        
        if len(dns_query) > 50:
            return self._create_threat_event(
                ThreatType.DNS_TUNNELING,
                ThreatLevel.HIGH,
                packet_info,
                "Suspicious DNS query detected - possible tunneling",
                {
                    'query_length': len(dns_query),
                    'query': dns_query[:100]
                }
            )
        
        query_parts = dns_query.split('.')
        if any(len(part) > 30 for part in query_parts):
            return self._create_threat_event(
                ThreatType.DNS_TUNNELING,
                ThreatLevel.MEDIUM,
                packet_info,
                "Unusual DNS subdomain length detected",
                {
                    'suspicious_domain': dns_query
                }
            )
        
        return None
    
    def _detect_data_exfiltration(self, packet_info: Dict[str, Any]) -> Optional[ThreatEvent]:
        size = packet_info.get('size', 0)
        dst_port = packet_info.get('dst_port')
        protocol = packet_info.get('protocol')
        
        if size > 1000000:
            suspicious_ports = [443, 53, 123, 69]
            if dst_port in suspicious_ports:
                return self._create_threat_event(
                    ThreatType.DATA_EXFILTRATION,
                    ThreatLevel.HIGH,
                    packet_info,
                    f"Large data transfer on unusual port {dst_port}",
                    {
                        'bytes_transferred': size,
                        'protocol': protocol,
                        'port': dst_port
                    }
                )
        
        src_ip = packet_info.get('src_ip')
        tracker = self.connection_tracker[src_ip]
        tracker['count'] += size
        
        if tracker['count'] > 10000000:
            return self._create_threat_event(
                ThreatType.DATA_EXFILTRATION,
                ThreatLevel.MEDIUM,
                packet_info,
                f"Significant data transfer from {src_ip}",
                {
                    'total_bytes': tracker['count']
                }
            )
        
        return None
    
    def _classify_ddos_type(self, packet_info: Dict[str, Any]) -> str:
        protocol = packet_info.get('protocol')
        flags = packet_info.get('flags', {})
        
        if protocol == 'ICMP':
            return 'ICMP Flood'
        elif protocol == 'UDP':
            return 'UDP Flood'
        elif protocol == 'TCP':
            if flags.get('syn') and not flags.get('ack'):
                return 'SYN Flood'
            elif flags.get('ack'):
                return 'ACK Flood'
            else:
                return 'TCP Flood'
        elif protocol == 'DNS':
            return 'DNS Amplification'
        else:
            return 'Unknown DDoS Type'
    
    def _create_threat_event(self, threat_type: ThreatType, level: ThreatLevel,
                            packet_info: Dict[str, Any], description: str,
                            evidence: Dict[str, Any]) -> ThreatEvent:
        
        recommended_action = self._get_recommended_action(threat_type, level)
        
        return ThreatEvent(
            timestamp=datetime.fromtimestamp(packet_info.get('timestamp', 0)),
            threat_type=threat_type,
            level=level,
            source_ip=packet_info.get('src_ip'),
            destination_ip=packet_info.get('dst_ip'),
            port=packet_info.get('dst_port'),
            protocol=packet_info.get('protocol'),
            description=description,
            evidence=evidence,
            false_positive_probability=self._calculate_false_positive_probability(threat_type, evidence),
            recommended_action=recommended_action
        )
    
    def _get_recommended_action(self, threat_type: ThreatType, level: ThreatLevel) -> str:
        actions = {
            ThreatType.PORT_SCAN: "Block source IP temporarily and monitor for further activity",
            ThreatType.DDOS: "Activate DDoS mitigation, rate limit source IP, consider null routing",
            ThreatType.BRUTE_FORCE: "Block source IP, enforce account lockout policies",
            ThreatType.SQL_INJECTION: "Block request, review application firewall rules",
            ThreatType.XSS: "Sanitize input, update WAF rules",
            ThreatType.MALWARE: "Isolate affected system, run full antivirus scan",
            ThreatType.DATA_EXFILTRATION: "Block outbound connection, investigate source",
            ThreatType.DNS_TUNNELING: "Block DNS queries to suspicious domains",
            ThreatType.ARP_SPOOFING: "Enable ARP inspection, implement static ARP entries",
            ThreatType.BOTNET: "Isolate infected host, block C&C communication"
        }
        
        base_action = actions.get(threat_type, "Investigate and monitor")
        
        if level == ThreatLevel.CRITICAL:
            return f"IMMEDIATE ACTION REQUIRED: {base_action}"
        elif level == ThreatLevel.HIGH:
            return f"URGENT: {base_action}"
        else:
            return base_action
    
    def _calculate_false_positive_probability(self, threat_type: ThreatType, 
                                             evidence: Dict[str, Any]) -> float:
        base_rates = {
            ThreatType.PORT_SCAN: 0.2,
            ThreatType.DDOS: 0.1,
            ThreatType.BRUTE_FORCE: 0.15,
            ThreatType.SQL_INJECTION: 0.25,
            ThreatType.XSS: 0.3,
            ThreatType.DNS_TUNNELING: 0.35,
            ThreatType.DATA_EXFILTRATION: 0.4
        }
        
        probability = base_rates.get(threat_type, 0.5)
        
        if 'signature_id' in evidence:
            probability *= 0.5
        
        if self.sensitivity == "low":
            probability *= 1.5
        elif self.sensitivity == "high":
            probability *= 0.7
        
        return min(probability, 1.0)
    
    def _get_threshold(self, threat_type: str) -> int:
        thresholds = {
            'low': {'port_scan': 20, 'ddos': 200, 'brute_force': 10},
            'medium': {'port_scan': 10, 'ddos': 100, 'brute_force': 5},
            'high': {'port_scan': 5, 'ddos': 50, 'brute_force': 3}
        }
        
        return thresholds[self.sensitivity].get(threat_type, 10)
    
    def _is_whitelisted(self, ip: str) -> bool:
        if not ip:
            return False
        
        if ip in self.whitelisted_ips:
            return True
        
        try:
            ip_obj = ipaddress.ip_address(ip)
            if ip_obj.is_private or ip_obj.is_loopback:
                return True
        except ValueError:
            pass
        
        return False
    
    def _is_blacklisted(self, ip: str) -> bool:
        return ip in self.blacklisted_ips if ip else False
    
    def _update_ip_reputation(self, ip: str, threat: ThreatEvent):
        if not ip:
            return
        
        if ip not in self.ip_reputation:
            self.ip_reputation[ip] = {
                'score': 0,
                'threats': [],
                'first_seen': datetime.now(),
                'last_seen': datetime.now()
            }
        
        reputation = self.ip_reputation[ip]
        reputation['score'] += threat.level.value
        reputation['threats'].append(threat.threat_type.value)
        reputation['last_seen'] = datetime.now()
        
        if reputation['score'] > 10:
            self.blacklisted_ips.add(ip)
            logger.warning(f"IP {ip} added to blacklist due to high threat score")
    
    def get_threat_statistics(self) -> Dict[str, Any]:
        threat_counts = defaultdict(int)
        level_counts = defaultdict(int)
        
        for threat in self.threat_history:
            threat_counts[threat.threat_type.value] += 1
            level_counts[threat.level.name] += 1
        
        return {
            'total_threats': len(self.threat_history),
            'threat_types': dict(threat_counts),
            'threat_levels': dict(level_counts),
            'blacklisted_ips': len(self.blacklisted_ips),
            'monitored_ips': len(self.ip_reputation),
            'active_port_scans': len(self.port_scan_tracker),
            'recent_threats': [t.to_dict() for t in list(self.threat_history)[-10:]]
        }
    
    def export_ioc(self) -> Dict[str, List[str]]:
        return {
            'malicious_ips': list(self.blacklisted_ips),
            'suspicious_ips': [ip for ip, rep in self.ip_reputation.items() 
                              if rep['score'] > 5],
            'threat_signatures': [sig.id for sig in self.signatures]
        }