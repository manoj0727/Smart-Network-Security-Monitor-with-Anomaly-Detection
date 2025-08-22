import pytest
from datetime import datetime, timedelta
from unittest.mock import Mock, patch

from src.security.threat_detector import (
    ThreatDetector, ThreatEvent, ThreatType, 
    ThreatLevel, ThreatSignature
)


class TestThreatDetector:
    def setup_method(self):
        self.detector = ThreatDetector(sensitivity="medium")
    
    def test_initialization(self):
        assert self.detector.sensitivity == "medium"
        assert len(self.detector.signatures) > 0
        assert len(self.detector.blacklisted_ips) > 0
        assert len(self.detector.whitelisted_ips) > 0
    
    def test_sql_injection_detection(self):
        packet_info = {
            'timestamp': datetime.now().timestamp(),
            'src_ip': '192.168.1.100',
            'dst_ip': '192.168.1.1',
            'dst_port': 80,
            'protocol': 'HTTP',
            'payload_preview': "SELECT * FROM users WHERE id='1' OR '1'='1'"
        }
        
        threat = self.detector.analyze_packet(packet_info)
        
        assert threat is not None
        assert threat.threat_type == ThreatType.SQL_INJECTION
        assert threat.level in [ThreatLevel.MEDIUM, ThreatLevel.HIGH]
    
    def test_xss_detection(self):
        packet_info = {
            'timestamp': datetime.now().timestamp(),
            'src_ip': '10.0.0.50',
            'dst_ip': '10.0.0.1',
            'dst_port': 443,
            'protocol': 'HTTPS',
            'payload_preview': '<script>alert("XSS")</script>'
        }
        
        threat = self.detector.analyze_packet(packet_info)
        
        assert threat is not None
        assert threat.threat_type == ThreatType.XSS
    
    def test_port_scan_detection(self):
        src_ip = '192.168.1.50'
        
        for port in range(1, 20):
            packet_info = {
                'timestamp': datetime.now().timestamp(),
                'src_ip': src_ip,
                'dst_ip': '192.168.1.1',
                'dst_port': port,
                'protocol': 'TCP',
                'flags': {'syn': True, 'ack': False}
            }
            threat = self.detector.analyze_packet(packet_info)
        
        assert threat is not None
        assert threat.threat_type == ThreatType.PORT_SCAN
        assert threat.source_ip == src_ip
    
    def test_ddos_detection(self):
        src_ip = '10.10.10.10'
        timestamp = datetime.now().timestamp()
        
        for i in range(150):
            packet_info = {
                'timestamp': timestamp,
                'src_ip': src_ip,
                'dst_ip': '192.168.1.1',
                'dst_port': 80,
                'protocol': 'TCP',
                'size': 1500
            }
            threat = self.detector.analyze_packet(packet_info)
        
        assert threat is not None
        assert threat.threat_type == ThreatType.DDOS
        assert threat.level in [ThreatLevel.HIGH, ThreatLevel.CRITICAL]
    
    def test_brute_force_detection(self):
        src_ip = '192.168.1.200'
        timestamp = datetime.now().timestamp()
        
        for i in range(10):
            packet_info = {
                'timestamp': timestamp + i,
                'src_ip': src_ip,
                'dst_ip': '192.168.1.1',
                'dst_port': 22,
                'protocol': 'TCP'
            }
            threat = self.detector.analyze_packet(packet_info)
        
        assert threat is not None
        assert threat.threat_type == ThreatType.BRUTE_FORCE
        assert 'SSH' in threat.evidence.get('service', '')
    
    def test_dns_tunneling_detection(self):
        long_domain = 'a' * 60 + '.example.com'
        packet_info = {
            'timestamp': datetime.now().timestamp(),
            'src_ip': '192.168.1.100',
            'dst_ip': '8.8.8.8',
            'dst_port': 53,
            'protocol': 'DNS',
            'dns_query': long_domain
        }
        
        threat = self.detector.analyze_packet(packet_info)
        
        assert threat is not None
        assert threat.threat_type == ThreatType.DNS_TUNNELING
    
    def test_data_exfiltration_detection(self):
        packet_info = {
            'timestamp': datetime.now().timestamp(),
            'src_ip': '192.168.1.100',
            'dst_ip': '1.2.3.4',
            'dst_port': 443,
            'protocol': 'HTTPS',
            'size': 2000000
        }
        
        threat = self.detector.analyze_packet(packet_info)
        
        assert threat is not None
        assert threat.threat_type == ThreatType.DATA_EXFILTRATION
    
    def test_whitelisted_ip_bypass(self):
        packet_info = {
            'timestamp': datetime.now().timestamp(),
            'src_ip': '127.0.0.1',
            'dst_ip': '192.168.1.1',
            'dst_port': 80,
            'protocol': 'HTTP',
            'payload_preview': "SELECT * FROM users"
        }
        
        threat = self.detector.analyze_packet(packet_info)
        
        assert threat is None
    
    def test_blacklisted_ip_detection(self):
        packet_info = {
            'timestamp': datetime.now().timestamp(),
            'src_ip': '192.168.1.100',
            'dst_ip': '192.168.1.1',
            'dst_port': 80,
            'protocol': 'HTTP'
        }
        
        threat = self.detector.analyze_packet(packet_info)
        
        assert threat is not None
        assert threat.threat_type == ThreatType.MALWARE
        assert threat.level == ThreatLevel.CRITICAL
    
    def test_threat_statistics(self):
        for i in range(5):
            packet_info = {
                'timestamp': datetime.now().timestamp(),
                'src_ip': f'10.0.0.{i}',
                'dst_ip': '192.168.1.1',
                'dst_port': 80 + i,
                'protocol': 'TCP',
                'flags': {'syn': True, 'ack': False}
            }
            self.detector.analyze_packet(packet_info)
        
        stats = self.detector.get_threat_statistics()
        
        assert 'total_threats' in stats
        assert 'threat_types' in stats
        assert 'threat_levels' in stats
        assert stats['total_threats'] > 0
    
    def test_ip_reputation_update(self):
        malicious_ip = '10.20.30.40'
        
        for i in range(5):
            threat = ThreatEvent(
                timestamp=datetime.now(),
                threat_type=ThreatType.PORT_SCAN,
                level=ThreatLevel.HIGH,
                source_ip=malicious_ip,
                destination_ip='192.168.1.1',
                port=None,
                protocol='TCP',
                description='Test threat',
                evidence={}
            )
            self.detector._update_ip_reputation(malicious_ip, threat)
        
        assert malicious_ip in self.detector.ip_reputation
        assert self.detector.ip_reputation[malicious_ip]['score'] > 10
        assert malicious_ip in self.detector.blacklisted_ips
    
    def test_sensitivity_thresholds(self):
        low_detector = ThreatDetector(sensitivity="low")
        high_detector = ThreatDetector(sensitivity="high")
        
        low_threshold = low_detector._get_threshold('port_scan')
        high_threshold = high_detector._get_threshold('port_scan')
        
        assert low_threshold > high_threshold
    
    def test_export_ioc(self):
        self.detector.blacklisted_ips.add('1.2.3.4')
        self.detector.blacklisted_ips.add('5.6.7.8')
        
        ioc = self.detector.export_ioc()
        
        assert 'malicious_ips' in ioc
        assert '1.2.3.4' in ioc['malicious_ips']
        assert '5.6.7.8' in ioc['malicious_ips']


if __name__ == "__main__":
    pytest.main([__file__, "-v"])