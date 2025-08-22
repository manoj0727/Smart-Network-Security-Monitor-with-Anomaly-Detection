import pytest
import time
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime

from src.core.packet_analyzer import PacketAnalyzer, PacketInfo


class TestPacketInfo:
    def test_packet_info_creation(self):
        packet_info = PacketInfo(
            timestamp=time.time(),
            src_ip="192.168.1.1",
            dst_ip="192.168.1.2",
            src_port=8080,
            dst_port=443,
            protocol="TCP",
            size=1500
        )
        
        assert packet_info.src_ip == "192.168.1.1"
        assert packet_info.dst_ip == "192.168.1.2"
        assert packet_info.src_port == 8080
        assert packet_info.dst_port == 443
        assert packet_info.protocol == "TCP"
        assert packet_info.size == 1500
    
    def test_packet_info_to_dict(self):
        timestamp = time.time()
        packet_info = PacketInfo(
            timestamp=timestamp,
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            src_port=80,
            dst_port=8080,
            protocol="HTTP",
            size=512,
            http_method="GET",
            http_host="example.com"
        )
        
        data = packet_info.to_dict()
        
        assert data['timestamp'] == timestamp
        assert data['src_ip'] == "10.0.0.1"
        assert data['protocol'] == "HTTP"
        assert data['http_method'] == "GET"
        assert data['http_host'] == "example.com"


class TestPacketAnalyzer:
    def setup_method(self):
        self.analyzer = PacketAnalyzer()
    
    def test_initialization(self):
        assert self.analyzer.packet_count == 0
        assert self.analyzer.interface is None
        assert self.analyzer.enable_deep_inspection is True
        assert len(self.analyzer.protocol_stats) > 0
    
    def test_statistics_calculation(self):
        stats = self.analyzer.get_statistics()
        
        assert 'total_packets' in stats
        assert 'packets_per_second' in stats
        assert 'protocol_distribution' in stats
        assert 'active_flows' in stats
        assert stats['total_packets'] == 0
    
    @patch('src.core.packet_analyzer.sniff')
    def test_start_capture(self, mock_sniff):
        self.analyzer.start_capture(filter_expr="tcp", count=10)
        
        mock_sniff.assert_called_once()
        call_args = mock_sniff.call_args
        assert call_args.kwargs['filter'] == "tcp"
        assert call_args.kwargs['count'] == 10
    
    def test_flow_tracking(self):
        packet_info = PacketInfo(
            timestamp=time.time(),
            src_ip="192.168.1.1",
            dst_ip="192.168.1.2",
            src_port=12345,
            dst_port=80,
            protocol="TCP",
            size=100,
            tcp_flags="SYN"
        )
        
        self.analyzer._track_flow(packet_info)
        
        assert len(self.analyzer.flow_table) == 1
        flow_key = list(self.analyzer.flow_table.keys())[0]
        assert "192.168.1.1" in flow_key
        assert "192.168.1.2" in flow_key
    
    def test_port_scan_detection(self):
        base_time = time.time()
        
        for port in range(100, 120):
            packet_info = PacketInfo(
                timestamp=base_time,
                src_ip="192.168.1.100",
                dst_ip="192.168.1.1",
                src_port=54321,
                dst_port=port,
                protocol="TCP",
                size=60,
                flags={'syn': True, 'ack': False}
            )
            self.analyzer.packet_buffer.append(packet_info)
        
        scanners = self.analyzer.detect_port_scan(threshold=10)
        
        assert len(scanners) == 1
        assert "192.168.1.100" in scanners
    
    def test_protocol_statistics_update(self):
        packet_info = PacketInfo(
            timestamp=time.time(),
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            src_port=None,
            dst_port=None,
            protocol="ICMP",
            size=64
        )
        
        initial_count = self.analyzer.protocol_stats['ICMP']
        self.analyzer._update_statistics(packet_info)
        
        assert self.analyzer.protocol_stats['ICMP'] == initial_count + 1
    
    def test_flow_statistics(self):
        for i in range(5):
            packet_info = PacketInfo(
                timestamp=time.time(),
                src_ip="192.168.1.1",
                dst_ip="192.168.1.2",
                src_port=8080,
                dst_port=443,
                protocol="TCP",
                size=1000 * (i + 1)
            )
            self.analyzer._track_flow(packet_info)
        
        flow_stats = self.analyzer.get_flow_statistics()
        
        assert len(flow_stats) == 1
        assert flow_stats[0]['packet_count'] == 5
        assert flow_stats[0]['bytes'] == 15000
    
    def test_packet_buffer_limit(self):
        self.analyzer.max_buffer_size = 10
        
        for i in range(15):
            packet_info = PacketInfo(
                timestamp=time.time(),
                src_ip=f"192.168.1.{i}",
                dst_ip="192.168.1.100",
                src_port=None,
                dst_port=None,
                protocol="ICMP",
                size=64
            )
            self.analyzer._process_packet(Mock())
        
        assert len(self.analyzer.packet_buffer) <= 10


if __name__ == "__main__":
    pytest.main([__file__, "-v"])