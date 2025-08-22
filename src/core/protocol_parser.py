import struct
import socket
from typing import Dict, Any, Optional, Tuple, List
from enum import Enum
import ipaddress
import hashlib
from dataclasses import dataclass

import structlog

logger = structlog.get_logger()


class ProtocolType(Enum):
    TCP = "TCP"
    UDP = "UDP"
    ICMP = "ICMP"
    HTTP = "HTTP"
    HTTPS = "HTTPS"
    DNS = "DNS"
    SSH = "SSH"
    FTP = "FTP"
    SMTP = "SMTP"
    POP3 = "POP3"
    IMAP = "IMAP"
    TELNET = "TELNET"
    RDP = "RDP"
    VPN = "VPN"
    DHCP = "DHCP"
    NTP = "NTP"
    SNMP = "SNMP"
    SIP = "SIP"
    RTP = "RTP"
    BGP = "BGP"
    OSPF = "OSPF"
    UNKNOWN = "UNKNOWN"


@dataclass
class ProtocolSignature:
    name: str
    port: Optional[int]
    pattern: bytes
    offset: int = 0
    

class ProtocolParser:
    def __init__(self):
        self.signatures = self._initialize_signatures()
        self.port_mapping = self._initialize_port_mapping()
        
    def _initialize_signatures(self) -> List[ProtocolSignature]:
        return [
            ProtocolSignature("SSH", 22, b"SSH-", 0),
            ProtocolSignature("HTTP", 80, b"GET ", 0),
            ProtocolSignature("HTTP", 80, b"POST ", 0),
            ProtocolSignature("HTTP", 80, b"HEAD ", 0),
            ProtocolSignature("HTTP", 80, b"PUT ", 0),
            ProtocolSignature("HTTP", 80, b"DELETE ", 0),
            ProtocolSignature("FTP", 21, b"220 ", 0),
            ProtocolSignature("FTP", 21, b"USER ", 0),
            ProtocolSignature("SMTP", 25, b"HELO ", 0),
            ProtocolSignature("SMTP", 25, b"EHLO ", 0),
            ProtocolSignature("POP3", 110, b"+OK", 0),
            ProtocolSignature("IMAP", 143, b"* OK", 0),
            ProtocolSignature("TLS", 443, b"\x16\x03", 0),
            ProtocolSignature("RDP", 3389, b"\x03\x00", 0),
            ProtocolSignature("VNC", 5900, b"RFB ", 0),
            ProtocolSignature("MySQL", 3306, b"\x00\x00\x00\x0a", 0),
            ProtocolSignature("PostgreSQL", 5432, b"\x00\x00\x00\x08", 0),
            ProtocolSignature("MongoDB", 27017, b"\x00\x00\x00\x00", 0),
        ]
    
    def _initialize_port_mapping(self) -> Dict[int, str]:
        return {
            20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "TELNET",
            25: "SMTP", 53: "DNS", 67: "DHCP", 68: "DHCP",
            80: "HTTP", 110: "POP3", 123: "NTP", 143: "IMAP",
            161: "SNMP", 162: "SNMP", 179: "BGP", 194: "IRC",
            443: "HTTPS", 445: "SMB", 465: "SMTPS", 514: "SYSLOG",
            587: "SMTP", 636: "LDAPS", 989: "FTPS", 990: "FTPS",
            993: "IMAPS", 995: "POP3S", 1194: "OpenVPN", 1433: "MSSQL",
            1521: "Oracle", 1723: "PPTP", 2049: "NFS", 3306: "MySQL",
            3389: "RDP", 5060: "SIP", 5061: "SIPS", 5432: "PostgreSQL",
            5900: "VNC", 6379: "Redis", 8080: "HTTP-Proxy", 8443: "HTTPS-Alt",
            8888: "HTTP-Alt", 9200: "Elasticsearch", 11211: "Memcached",
            27017: "MongoDB", 50000: "SAP"
        }
    
    def parse_packet(self, packet_data: bytes, src_port: int = None, 
                     dst_port: int = None) -> Dict[str, Any]:
        result = {
            'protocol': ProtocolType.UNKNOWN.value,
            'details': {},
            'confidence': 0.0
        }
        
        protocol = self._identify_protocol(packet_data, src_port, dst_port)
        result['protocol'] = protocol.value
        
        if protocol == ProtocolType.HTTP:
            result['details'] = self._parse_http(packet_data)
            result['confidence'] = 1.0
        elif protocol == ProtocolType.DNS:
            result['details'] = self._parse_dns(packet_data)
            result['confidence'] = 0.9
        elif protocol == ProtocolType.SSH:
            result['details'] = self._parse_ssh(packet_data)
            result['confidence'] = 1.0
        elif protocol == ProtocolType.HTTPS:
            result['details'] = self._parse_tls(packet_data)
            result['confidence'] = 0.95
        else:
            result['confidence'] = self._calculate_confidence(packet_data, protocol)
        
        return result
    
    def _identify_protocol(self, packet_data: bytes, 
                          src_port: Optional[int], 
                          dst_port: Optional[int]) -> ProtocolType:
        
        for signature in self.signatures:
            if len(packet_data) > signature.offset + len(signature.pattern):
                if packet_data[signature.offset:].startswith(signature.pattern):
                    return ProtocolType[signature.name.upper()]
        
        if src_port:
            protocol = self.port_mapping.get(src_port)
            if protocol:
                return ProtocolType[protocol.replace("-", "_").upper()]
        
        if dst_port:
            protocol = self.port_mapping.get(dst_port)
            if protocol:
                return ProtocolType[protocol.replace("-", "_").upper()]
        
        return ProtocolType.UNKNOWN
    
    def _parse_http(self, data: bytes) -> Dict[str, Any]:
        try:
            lines = data.split(b'\r\n')
            if not lines:
                return {}
            
            request_line = lines[0].decode('utf-8', errors='ignore')
            parts = request_line.split(' ')
            
            headers = {}
            for line in lines[1:]:
                if b':' in line:
                    key, value = line.split(b':', 1)
                    headers[key.decode('utf-8', errors='ignore').strip()] = \
                        value.decode('utf-8', errors='ignore').strip()
            
            return {
                'method': parts[0] if len(parts) > 0 else None,
                'path': parts[1] if len(parts) > 1 else None,
                'version': parts[2] if len(parts) > 2 else None,
                'headers': headers,
                'host': headers.get('Host'),
                'user_agent': headers.get('User-Agent'),
                'content_type': headers.get('Content-Type'),
                'content_length': headers.get('Content-Length')
            }
        except Exception as e:
            logger.debug(f"HTTP parsing error: {e}")
            return {}
    
    def _parse_dns(self, data: bytes) -> Dict[str, Any]:
        try:
            if len(data) < 12:
                return {}
            
            header = struct.unpack('!HHHHHH', data[:12])
            
            return {
                'transaction_id': header[0],
                'flags': header[1],
                'questions': header[2],
                'answers': header[3],
                'authority': header[4],
                'additional': header[5],
                'query_type': 'query' if (header[1] & 0x8000) == 0 else 'response',
                'opcode': (header[1] >> 11) & 0xF,
                'recursion_desired': bool(header[1] & 0x100),
                'recursion_available': bool(header[1] & 0x80),
                'response_code': header[1] & 0xF
            }
        except Exception as e:
            logger.debug(f"DNS parsing error: {e}")
            return {}
    
    def _parse_ssh(self, data: bytes) -> Dict[str, Any]:
        try:
            if data.startswith(b'SSH-'):
                version_line = data.split(b'\r\n')[0]
                parts = version_line.split(b'-')
                return {
                    'protocol_version': parts[1].decode('utf-8') if len(parts) > 1 else None,
                    'software_version': parts[2].decode('utf-8') if len(parts) > 2 else None,
                    'comments': b'-'.join(parts[3:]).decode('utf-8') if len(parts) > 3 else None
                }
            return {}
        except Exception as e:
            logger.debug(f"SSH parsing error: {e}")
            return {}
    
    def _parse_tls(self, data: bytes) -> Dict[str, Any]:
        try:
            if len(data) < 5:
                return {}
            
            if data[0] == 0x16:
                return {
                    'content_type': 'Handshake',
                    'version': f"{data[1]}.{data[2]}",
                    'length': struct.unpack('!H', data[3:5])[0],
                    'handshake_type': self._get_handshake_type(data[5] if len(data) > 5 else 0)
                }
            
            content_types = {
                0x14: 'ChangeCipherSpec',
                0x15: 'Alert',
                0x16: 'Handshake',
                0x17: 'ApplicationData',
                0x18: 'Heartbeat'
            }
            
            return {
                'content_type': content_types.get(data[0], 'Unknown'),
                'version': f"{data[1]}.{data[2]}" if len(data) > 2 else None
            }
        except Exception as e:
            logger.debug(f"TLS parsing error: {e}")
            return {}
    
    def _get_handshake_type(self, type_byte: int) -> str:
        handshake_types = {
            0: 'HelloRequest',
            1: 'ClientHello',
            2: 'ServerHello',
            11: 'Certificate',
            12: 'ServerKeyExchange',
            13: 'CertificateRequest',
            14: 'ServerHelloDone',
            15: 'CertificateVerify',
            16: 'ClientKeyExchange',
            20: 'Finished'
        }
        return handshake_types.get(type_byte, 'Unknown')
    
    def _calculate_confidence(self, data: bytes, protocol: ProtocolType) -> float:
        if protocol == ProtocolType.UNKNOWN:
            return 0.0
        
        confidence = 0.5
        
        if protocol in [ProtocolType.HTTP, ProtocolType.SSH, ProtocolType.FTP]:
            if all(32 <= b < 127 or b in [9, 10, 13] for b in data[:100]):
                confidence += 0.3
        
        if len(data) > 0:
            entropy = self._calculate_entropy(data[:100])
            if protocol in [ProtocolType.HTTPS, ProtocolType.SSH] and entropy > 6:
                confidence += 0.2
            elif protocol in [ProtocolType.HTTP, ProtocolType.SMTP] and entropy < 5:
                confidence += 0.2
        
        return min(confidence, 1.0)
    
    def _calculate_entropy(self, data: bytes) -> float:
        import math
        if not data:
            return 0
        
        frequency = {}
        for byte in data:
            frequency[byte] = frequency.get(byte, 0) + 1
        
        entropy = 0
        for count in frequency.values():
            probability = count / len(data)
            if probability > 0:
                entropy -= probability * math.log2(probability)
        
        return entropy
    
    def detect_tunneling(self, data: bytes, expected_protocol: ProtocolType) -> bool:
        actual_protocol = self._identify_protocol(data, None, None)
        
        if expected_protocol == ProtocolType.HTTPS and actual_protocol != ProtocolType.HTTPS:
            entropy = self._calculate_entropy(data[:100])
            if entropy < 5:
                logger.warning("Possible protocol tunneling detected",
                             expected=expected_protocol.value,
                             actual=actual_protocol.value)
                return True
        
        return False
    
    def extract_application_data(self, protocol: ProtocolType, 
                                data: bytes) -> Optional[Dict[str, Any]]:
        extractors = {
            ProtocolType.HTTP: self._extract_http_data,
            ProtocolType.DNS: self._extract_dns_query,
            ProtocolType.SMTP: self._extract_smtp_data,
            ProtocolType.FTP: self._extract_ftp_data
        }
        
        extractor = extractors.get(protocol)
        if extractor:
            return extractor(data)
        return None
    
    def _extract_http_data(self, data: bytes) -> Dict[str, Any]:
        parsed = self._parse_http(data)
        if not parsed:
            return {}
        
        return {
            'url': f"{parsed.get('host', '')}{parsed.get('path', '')}",
            'method': parsed.get('method'),
            'user_agent': parsed.get('user_agent'),
            'cookies': self._extract_cookies(parsed.get('headers', {}))
        }
    
    def _extract_cookies(self, headers: Dict[str, str]) -> List[str]:
        cookie_header = headers.get('Cookie', '')
        if not cookie_header:
            return []
        
        cookies = []
        for cookie in cookie_header.split(';'):
            cookie = cookie.strip()
            if '=' in cookie:
                name = cookie.split('=')[0]
                cookies.append(name)
        return cookies
    
    def _extract_dns_query(self, data: bytes) -> Dict[str, Any]:
        parsed = self._parse_dns(data)
        if not parsed or parsed.get('query_type') != 'query':
            return {}
        
        try:
            query_start = 12
            query_name = []
            
            while query_start < len(data):
                length = data[query_start]
                if length == 0:
                    break
                query_start += 1
                query_name.append(data[query_start:query_start + length].decode('utf-8'))
                query_start += length
            
            return {
                'domain': '.'.join(query_name),
                'type': 'A'
            }
        except Exception:
            return {}
    
    def _extract_smtp_data(self, data: bytes) -> Dict[str, Any]:
        try:
            lines = data.split(b'\r\n')
            commands = []
            
            for line in lines:
                if line.startswith((b'HELO', b'EHLO', b'MAIL', b'RCPT', b'DATA')):
                    commands.append(line.decode('utf-8', errors='ignore'))
            
            return {'commands': commands}
        except Exception:
            return {}
    
    def _extract_ftp_data(self, data: bytes) -> Dict[str, Any]:
        try:
            lines = data.split(b'\r\n')
            commands = []
            
            for line in lines:
                if line.startswith((b'USER', b'PASS', b'LIST', b'RETR', b'STOR')):
                    cmd = line.decode('utf-8', errors='ignore')
                    if cmd.startswith('PASS'):
                        cmd = 'PASS ****'
                    commands.append(cmd)
            
            return {'commands': commands}
        except Exception:
            return {}