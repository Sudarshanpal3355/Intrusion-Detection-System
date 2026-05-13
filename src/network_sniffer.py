"""
Real-time Network Traffic Packet Capture and Feature Extraction
Captures actual network packets and extracts features for anomaly detection
"""

import socket
import struct
import textwrap
import logging
from collections import defaultdict, deque
from datetime import datetime
import numpy as np
import pandas as pd

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class PacketParser:
    """Parse network packets into extractable features"""
    
    IPV4_PROTOCOL_MAP = {
        6: "TCP",
        17: "UDP",
        1: "ICMP",
        2: "IGMP",
        41: "IPv6",
    }
    
    TCP_FLAGS = {
        0x01: "FIN",
        0x02: "SYN",
        0x04: "RST",
        0x08: "PSH",
        0x10: "ACK",
        0x20: "URG",
    }

    def __init__(self):
        self.packet_count = 0
        self.flow_cache = defaultdict(dict)
        self.packet_history = deque(maxlen=10000)  # Last 10k packets

    def parse_ipv4(self, data):
        """Extract IPv4 header information"""
        try:
            version_header_length = data[0]
            header_length = (version_header_length & 15) * 4
            ttl = data[8]
            proto = data[9]
            src_addr = self.format_ipv4_addr(data[12:16])
            dst_addr = self.format_ipv4_addr(data[16:20])
            return {
                "src_ip": src_addr,
                "dst_ip": dst_addr,
                "protocol": self.IPV4_PROTOCOL_MAP.get(proto, proto),
                "ttl": ttl,
                "header_length": header_length,
                "packet_length": len(data),
            }, data[header_length:]
        except Exception as e:
            logger.error(f"IPv4 parsing error: {e}")
            return None, None

    def parse_tcp(self, src_ip, dst_ip, data):
        """Extract TCP segment information"""
        try:
            if len(data) < 20:
                return None
                
            src_port = struct.unpack("!H", data[0:2])[0]
            dst_port = struct.unpack("!H", data[2:4])[0]
            sequence = struct.unpack("!I", data[4:8])[0]
            acknowledgment = struct.unpack("!I", data[8:12])[0]
            offset_reserved_flags = struct.unpack("!B", data[12:13])[0]
            flag_urg = offset_reserved_flags & 32
            flag_ack = offset_reserved_flags & 16
            flag_psh = offset_reserved_flags & 8
            flag_rst = offset_reserved_flags & 4
            flag_syn = offset_reserved_flags & 2
            flag_fin = offset_reserved_flags & 1
            window = struct.unpack("!H", data[14:16])[0]
            checksum = struct.unpack("!H", data[16:18])[0]
            
            return {
                "src_port": src_port,
                "dst_port": dst_port,
                "sequence": sequence,
                "acknowledgment": acknowledgment,
                "flags": {
                    "URG": bool(flag_urg),
                    "ACK": bool(flag_ack),
                    "PSH": bool(flag_psh),
                    "RST": bool(flag_rst),
                    "SYN": bool(flag_syn),
                    "FIN": bool(flag_fin),
                },
                "window_size": window,
                "checksum": checksum,
                "protocol": "TCP",
            }
        except Exception as e:
            logger.error(f"TCP parsing error: {e}")
            return None

    def parse_udp(self, src_ip, dst_ip, data):
        """Extract UDP datagram information"""
        try:
            if len(data) < 8:
                return None
                
            src_port = struct.unpack("!H", data[0:2])[0]
            dst_port = struct.unpack("!H", data[2:4])[0]
            length = struct.unpack("!H", data[4:6])[0]
            checksum = struct.unpack("!H", data[6:8])[0]
            
            return {
                "src_port": src_port,
                "dst_port": dst_port,
                "length": length,
                "checksum": checksum,
                "protocol": "UDP",
            }
        except Exception as e:
            logger.error(f"UDP parsing error: {e}")
            return None

    def parse_icmp(self, src_ip, dst_ip, data):
        """Extract ICMP message information"""
        try:
            if len(data) < 4:
                return None
                
            icmp_type = data[0]
            code = data[1]
            checksum = struct.unpack("!H", data[2:4])[0]
            
            return {
                "type": icmp_type,
                "code": code,
                "checksum": checksum,
                "protocol": "ICMP",
            }
        except Exception as e:
            logger.error(f"ICMP parsing error: {e}")
            return None

    @staticmethod
    def format_ipv4_addr(bytes_addr):
        """Convert bytes to dotted decimal IPv4 address"""
        bytes_iter = iter(bytes_addr)
        return ".".join(map(str, bytes_iter))

    def extract_flow_features(self, packet_data):
        """Extract flow-level features for ML model"""
        flow_id = f"{packet_data.get('src_ip')}:{packet_data.get('src_port', 'N/A')}-" \
                  f"{packet_data.get('dst_ip')}:{packet_data.get('dst_port', 'N/A')}"
        
        if flow_id not in self.flow_cache:
            self.flow_cache[flow_id] = {
                "packet_count": 0,
                "byte_count": 0,
                "first_seen": datetime.now(),
                "last_seen": datetime.now(),
                "src_ports": [],
                "dst_ports": [],
            }
        
        flow = self.flow_cache[flow_id]
        flow["packet_count"] += 1
        flow["byte_count"] += packet_data.get("packet_length", 0)
        flow["last_seen"] = datetime.now()
        
        if packet_data.get("src_port"):
            flow["src_ports"].append(packet_data["src_port"])
        if packet_data.get("dst_port"):
            flow["dst_ports"].append(packet_data["dst_port"])
        
        return flow_id, flow

    def get_flow_statistics(self):
        """Get aggregated flow statistics for anomaly detection"""
        stats = []
        for flow_id, flow_data in self.flow_cache.items():
            duration = (flow_data["last_seen"] - flow_data["first_seen"]).total_seconds()
            stats.append({
                "flow_id": flow_id,
                "pkt_count": flow_data["packet_count"],
                "bytes": flow_data["byte_count"],
                "duration": max(duration, 1),  # Avoid division by zero
                "rate": flow_data["packet_count"] / max(duration, 1),
                "unique_src_ports": len(set(flow_data["src_ports"])),
                "unique_dst_ports": len(set(flow_data["dst_ports"])),
            })
        return pd.DataFrame(stats) if stats else pd.DataFrame()


class NetworkSniffer:
    """Capture and process network traffic"""
    
    def __init__(self, packet_limit=1000):
        self.packet_limit = packet_limit
        self.packets_captured = 0
        self.parser = PacketParser()

    def sniff(self, interface=None, packet_callback=None):
        """
        Start sniffing on network interface
        
        Args:
            interface: Network interface name (None for all)
            packet_callback: Function to call for each packet
        """
        try:
            # Create raw socket
            if hasattr(socket, 'AF_PACKET'):
                # Linux
                conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
            else:
                # Windows/macOS - requires admin privileges
                logger.warning("Raw socket requires admin privileges on Windows/macOS")
                return self.simulate_traffic(packet_callback)
            
            logger.info(f"Starting network sniffer... (limit: {self.packet_limit} packets)")
            
            while self.packets_captured < self.packet_limit:
                raw_buffer, _ = conn.recvfrom(65535)
                self.packets_captured += 1
                
                ipv4_info, data = self.parser.parse_ipv4(raw_buffer[14:])
                
                if ipv4_info is None:
                    continue
                
                protocol = ipv4_info["protocol"]
                
                if protocol == "TCP":
                    tcp_info = self.parser.parse_tcp(
                        ipv4_info["src_ip"],
                        ipv4_info["dst_ip"],
                        data
                    )
                    if tcp_info:
                        packet_info = {**ipv4_info, **tcp_info}
                elif protocol == "UDP":
                    udp_info = self.parser.parse_udp(
                        ipv4_info["src_ip"],
                        ipv4_info["dst_ip"],
                        data
                    )
                    if udp_info:
                        packet_info = {**ipv4_info, **udp_info}
                elif protocol == "ICMP":
                    icmp_info = self.parser.parse_icmp(
                        ipv4_info["src_ip"],
                        ipv4_info["dst_ip"],
                        data
                    )
                    if icmp_info:
                        packet_info = {**ipv4_info, **icmp_info}
                else:
                    packet_info = ipv4_info
                
                packet_info["timestamp"] = datetime.now()
                
                if packet_callback:
                    packet_callback(packet_info)
                
                if self.packets_captured % 100 == 0:
                    logger.info(f"Captured {self.packets_captured} packets")
            
            conn.close()
        except Exception as e:
            logger.error(f"Sniffing error: {e}")
            logger.info("Falling back to traffic simulation...")
            self.simulate_traffic(packet_callback)

    def simulate_traffic(self, packet_callback=None):
        """Simulate network traffic for testing (when raw socket unavailable)"""
        import random
        
        normal_dport_ranges = [80, 443, 22, 21, 25, 53, 123, 3306, 5432, 8080]
        suspicious_dport_ranges = [4444, 5555, 6666, 7777, 8888, 9999]
        internal_ips = [f"192.168.1.{i}" for i in range(1, 255)]
        external_ips = [f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}" for _ in range(50)]
        
        logger.info("Simulating network traffic for demonstration...")
        
        for i in range(self.packet_limit):
            is_anomaly = random.random() < 0.15  # 15% anomalies
            
            if is_anomaly:
                # Anomalous pattern
                packet_info = {
                    "src_ip": random.choice(external_ips),
                    "dst_ip": random.choice(internal_ips),
                    "src_port": random.randint(40000, 65535),
                    "dst_port": random.choice(suspicious_dport_ranges),
                    "protocol": random.choice(["TCP", "UDP"]),
                    "packet_length": random.randint(1000, 65535),
                    "ttl": random.randint(1, 64),
                    "timestamp": datetime.now(),
                    "flags": {
                        "SYN": random.random() < 0.5,
                        "ACK": random.random() < 0.5,
                        "RST": random.random() < 0.3,
                        "FIN": random.random() < 0.2,
                    } if random.random() < 0.5 else None,
                }
            else:
                # Normal pattern
                packet_info = {
                    "src_ip": random.choice(internal_ips),
                    "dst_ip": random.choice(external_ips),
                    "src_port": random.randint(40000, 65535),
                    "dst_port": random.choice(normal_dport_ranges),
                    "protocol": "TCP" if random.random() < 0.7 else "UDP",
                    "packet_length": random.randint(64, 1500),
                    "ttl": random.randint(60, 64),
                    "timestamp": datetime.now(),
                    "flags": {
                        "SYN": random.random() < 0.2,
                        "ACK": random.random() < 0.8,
                        "RST": random.random() < 0.05,
                        "FIN": random.random() < 0.1,
                    } if random.random() < 0.7 else None,
                }
            
            if packet_callback:
                packet_callback(packet_info)

    def get_statistics(self):
        """Get network statistics from captured packets"""
        return self.parser.get_flow_statistics()


if __name__ == "__main__":
    sniffer = NetworkSniffer(packet_limit=100)
    
    def process_packet(pkt):
        print(f"[{pkt['timestamp']}] {pkt['src_ip']}:{pkt.get('src_port', 'N/A')} → "
              f"{pkt['dst_ip']}:{pkt.get('dst_port', 'N/A')} ({pkt['protocol']})")
    
    sniffer.sniff(packet_callback=process_packet)
    print("\n📊 Flow Statistics:")
    print(sniffer.get_statistics())
