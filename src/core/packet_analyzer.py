import asyncio
import time
from typing import Dict, Any, Optional, List, Callable
from dataclasses import dataclass, field
from datetime import datetime
import struct
import socket

from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, ARP, Raw, Ether
from scapy.layers.http import HTTPRequest, HTTPResponse
from scapy.layers.inet import traceroute
import structlog

logger = structlog.get_logger()


@dataclass
class PacketInfo:
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: Optional[int]
    dst_port: Optional[int]
    protocol: str
    size: int
    flags: Dict[str, bool] = field(default_factory=dict)
    payload_preview: Optional[str] = None
    dns_query: Optional[str] = None
    http_method: Optional[str] = None
    http_host: Optional[str] = None
    http_path: Optional[str] = None
    tcp_flags: Optional[str] = None
    ttl: Optional[int] = None
    window_size: Optional[int] = None
    checksum: Optional[int] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'timestamp': self.timestamp,
            'src_ip': self.src_ip,
            'dst_ip': self.dst_ip,
            'src_port': self.src_port,
            'dst_port': self.dst_port,
            'protocol': self.protocol,
            'size': self.size,
            'flags': self.flags,
            'payload_preview': self.payload_preview,
            'dns_query': self.dns_query,
            'http_method': self.http_method,
            'http_host': self.http_host,
            'http_path': self.http_path,
            'tcp_flags': self.tcp_flags,
            'ttl': self.ttl,
            'window_size': self.window_size
        }


class PacketAnalyzer:
    def __init__(self, interface: Optional[str] = None, 
                 packet_callback: Optional[Callable] = None,
                 enable_deep_inspection: bool = True):
        self.interface = interface
        self.packet_callback = packet_callback
        self.enable_deep_inspection = enable_deep_inspection
        self.packet_count = 0
        self.start_time = time.time()
        self.protocol_stats = {
            'TCP': 0, 'UDP': 0, 'ICMP': 0, 'DNS': 0, 
            'HTTP': 0, 'HTTPS': 0, 'ARP': 0, 'Other': 0
        }
        self.flow_table = {}
        self.packet_buffer = []
        self.max_buffer_size = 10000
        
    def start_capture(self, filter_expr: str = "", count: int = 0):
        logger.info("Starting packet capture", interface=self.interface, filter=filter_expr)
        try:
            sniff(
                iface=self.interface,
                filter=filter_expr,
                prn=self._process_packet,
                count=count,
                store=False
            )
        except Exception as e:
            logger.error("Packet capture error", error=str(e))
            raise
    
    async def start_async_capture(self, filter_expr: str = "", count: int = 0):
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(
            None, 
            self.start_capture,
            filter_expr,
            count
        )
    
    def _process_packet(self, packet):
        self.packet_count += 1
        packet_info = self._extract_packet_info(packet)
        
        if packet_info:
            self._update_statistics(packet_info)
            self._track_flow(packet_info)
            
            if len(self.packet_buffer) >= self.max_buffer_size:
                self.packet_buffer.pop(0)
            self.packet_buffer.append(packet_info)
            
            if self.packet_callback:
                self.packet_callback(packet_info)
                
            if self.packet_count % 100 == 0:
                logger.debug(f"Processed {self.packet_count} packets")
    
    def _extract_packet_info(self, packet) -> Optional[PacketInfo]:
        try:
            timestamp = time.time()
            
            if not packet.haslayer(IP):
                if packet.haslayer(ARP):
                    return self._process_arp_packet(packet, timestamp)
                return None
            
            ip_layer = packet[IP]
            
            packet_info = PacketInfo(
                timestamp=timestamp,
                src_ip=ip_layer.src,
                dst_ip=ip_layer.dst,
                src_port=None,
                dst_port=None,
                protocol="Unknown",
                size=len(packet),
                ttl=ip_layer.ttl,
                checksum=ip_layer.chksum
            )
            
            if packet.haslayer(TCP):
                self._extract_tcp_info(packet, packet_info)
            elif packet.haslayer(UDP):
                self._extract_udp_info(packet, packet_info)
            elif packet.haslayer(ICMP):
                self._extract_icmp_info(packet, packet_info)
            
            if self.enable_deep_inspection:
                self._deep_packet_inspection(packet, packet_info)
            
            return packet_info
            
        except Exception as e:
            logger.warning("Failed to extract packet info", error=str(e))
            return None
    
    def _extract_tcp_info(self, packet, packet_info: PacketInfo):
        tcp_layer = packet[TCP]
        packet_info.protocol = "TCP"
        packet_info.src_port = tcp_layer.sport
        packet_info.dst_port = tcp_layer.dport
        packet_info.window_size = tcp_layer.window
        
        flags = []
        if tcp_layer.flags & 0x01: flags.append("FIN")
        if tcp_layer.flags & 0x02: flags.append("SYN")
        if tcp_layer.flags & 0x04: flags.append("RST")
        if tcp_layer.flags & 0x08: flags.append("PSH")
        if tcp_layer.flags & 0x10: flags.append("ACK")
        if tcp_layer.flags & 0x20: flags.append("URG")
        packet_info.tcp_flags = "|".join(flags)
        
        packet_info.flags = {
            'syn': bool(tcp_layer.flags & 0x02),
            'ack': bool(tcp_layer.flags & 0x10),
            'fin': bool(tcp_layer.flags & 0x01),
            'rst': bool(tcp_layer.flags & 0x04),
            'psh': bool(tcp_layer.flags & 0x08)
        }
        
        if tcp_layer.dport == 443 or tcp_layer.sport == 443:
            packet_info.protocol = "HTTPS"
        elif tcp_layer.dport == 80 or tcp_layer.sport == 80:
            if packet.haslayer(HTTPRequest):
                self._extract_http_request(packet, packet_info)
    
    def _extract_udp_info(self, packet, packet_info: PacketInfo):
        udp_layer = packet[UDP]
        packet_info.protocol = "UDP"
        packet_info.src_port = udp_layer.sport
        packet_info.dst_port = udp_layer.dport
        
        if udp_layer.dport == 53 or udp_layer.sport == 53:
            if packet.haslayer(DNS):
                self._extract_dns_info(packet, packet_info)
    
    def _extract_icmp_info(self, packet, packet_info: PacketInfo):
        icmp_layer = packet[ICMP]
        packet_info.protocol = "ICMP"
        packet_info.flags = {
            'type': icmp_layer.type,
            'code': icmp_layer.code
        }
    
    def _extract_dns_info(self, packet, packet_info: PacketInfo):
        dns_layer = packet[DNS]
        packet_info.protocol = "DNS"
        
        if dns_layer.qr == 0 and dns_layer.qd:
            packet_info.dns_query = dns_layer.qd.qname.decode('utf-8')
    
    def _extract_http_request(self, packet, packet_info: PacketInfo):
        http_layer = packet[HTTPRequest]
        packet_info.protocol = "HTTP"
        packet_info.http_method = http_layer.Method.decode('utf-8')
        packet_info.http_host = http_layer.Host.decode('utf-8') if http_layer.Host else None
        packet_info.http_path = http_layer.Path.decode('utf-8') if http_layer.Path else None
    
    def _process_arp_packet(self, packet, timestamp: float) -> PacketInfo:
        arp_layer = packet[ARP]
        return PacketInfo(
            timestamp=timestamp,
            src_ip=arp_layer.psrc,
            dst_ip=arp_layer.pdst,
            src_port=None,
            dst_port=None,
            protocol="ARP",
            size=len(packet),
            flags={'op': arp_layer.op}
        )
    
    def _deep_packet_inspection(self, packet, packet_info: PacketInfo):
        if packet.haslayer(Raw):
            payload = packet[Raw].load
            if len(payload) > 0:
                try:
                    payload_str = payload[:100].decode('utf-8', errors='ignore')
                    packet_info.payload_preview = payload_str
                    
                    if b'SSH' in payload[:10]:
                        packet_info.protocol = "SSH"
                    elif b'GET' in payload[:10] or b'POST' in payload[:10]:
                        packet_info.protocol = "HTTP"
                    elif b'\x16\x03' in payload[:2]:
                        packet_info.protocol = "TLS/SSL"
                        
                except Exception:
                    packet_info.payload_preview = payload[:100].hex()
    
    def _update_statistics(self, packet_info: PacketInfo):
        protocol = packet_info.protocol
        if protocol in self.protocol_stats:
            self.protocol_stats[protocol] += 1
        else:
            self.protocol_stats['Other'] += 1
    
    def _track_flow(self, packet_info: PacketInfo):
        if packet_info.src_port and packet_info.dst_port:
            flow_key = self._get_flow_key(packet_info)
            
            if flow_key not in self.flow_table:
                self.flow_table[flow_key] = {
                    'start_time': packet_info.timestamp,
                    'last_seen': packet_info.timestamp,
                    'packet_count': 0,
                    'bytes': 0,
                    'flags_seen': set()
                }
            
            flow = self.flow_table[flow_key]
            flow['last_seen'] = packet_info.timestamp
            flow['packet_count'] += 1
            flow['bytes'] += packet_info.size
            
            if packet_info.tcp_flags:
                flow['flags_seen'].add(packet_info.tcp_flags)
    
    def _get_flow_key(self, packet_info: PacketInfo) -> str:
        src = f"{packet_info.src_ip}:{packet_info.src_port}"
        dst = f"{packet_info.dst_ip}:{packet_info.dst_port}"
        
        if src < dst:
            return f"{src}-{dst}-{packet_info.protocol}"
        else:
            return f"{dst}-{src}-{packet_info.protocol}"
    
    def get_statistics(self) -> Dict[str, Any]:
        uptime = time.time() - self.start_time
        return {
            'total_packets': self.packet_count,
            'packets_per_second': self.packet_count / uptime if uptime > 0 else 0,
            'uptime_seconds': uptime,
            'protocol_distribution': self.protocol_stats,
            'active_flows': len(self.flow_table),
            'buffer_size': len(self.packet_buffer)
        }
    
    def get_flow_statistics(self) -> List[Dict[str, Any]]:
        current_time = time.time()
        flow_stats = []
        
        for flow_key, flow_data in self.flow_table.items():
            duration = flow_data['last_seen'] - flow_data['start_time']
            flow_stats.append({
                'flow_id': flow_key,
                'duration': duration,
                'packet_count': flow_data['packet_count'],
                'bytes': flow_data['bytes'],
                'avg_packet_size': flow_data['bytes'] / flow_data['packet_count'] if flow_data['packet_count'] > 0 else 0,
                'is_active': (current_time - flow_data['last_seen']) < 60
            })
        
        return sorted(flow_stats, key=lambda x: x['bytes'], reverse=True)
    
    def detect_port_scan(self, threshold: int = 10, time_window: int = 60) -> List[str]:
        current_time = time.time()
        suspicious_ips = {}
        
        for packet_info in self.packet_buffer:
            if current_time - packet_info.timestamp > time_window:
                continue
                
            if packet_info.flags.get('syn') and not packet_info.flags.get('ack'):
                if packet_info.src_ip not in suspicious_ips:
                    suspicious_ips[packet_info.src_ip] = set()
                suspicious_ips[packet_info.src_ip].add(packet_info.dst_port)
        
        port_scanners = []
        for ip, ports in suspicious_ips.items():
            if len(ports) >= threshold:
                port_scanners.append(ip)
                logger.warning(f"Potential port scan detected from {ip}", 
                             ports_scanned=len(ports))
        
        return port_scanners
    
    def export_pcap(self, filename: str, packets: Optional[List] = None):
        from scapy.utils import wrpcap
        if packets is None:
            packets = self.packet_buffer
        wrpcap(filename, packets)
        logger.info(f"Exported {len(packets)} packets to {filename}")