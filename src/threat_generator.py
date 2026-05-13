"""
Realistic Threat Data Generator
Generates synthetic network attack scenarios based on real-world attack patterns
"""

import random
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from typing import Dict, List
import csv


class ThreatScenarioGenerator:
    """Generate realistic cyber attack scenarios"""
    
    ATTACK_TYPES = {
        "port_scan": {
            "description": "Port scanning attack",
            "characteristics": {
                "high_dst_port_variation": True,
                "rapid_connections": True,
                "low_payload": True,
                "various_protocols": True,
            }
        },
        "ddos": {
            "description": "Distributed Denial of Service",
            "characteristics": {
                "multiple_src_ips": True,
                "same_dst": True,
                "high_packet_rate": True,
                "large_payloads": True,
            }
        },
        "bruteforce": {
            "description": "Credential bruteforce attack",
            "characteristics": {
                "repeated_failed_attempts": True,
                "same_port": True,
                "slow_pattern": False,
                "specific_ports": [22, 3389, 23],
            }
        },
        "malware_command": {
            "description": "Malware command & control (C2)",
            "characteristics": {
                "periodic_beaconing": True,
                "unusual_ports": True,
                "encrypted_payload": True,
                "external_communication": True,
            }
        },
        "data_exfiltration": {
            "description": "Data exfiltration attack",
            "characteristics": {
                "large_data_transfer": True,
                "unusual_protocols": True,
                "external_destinations": True,
                "off_hours": True,
            }
        },
        "sql_injection": {
            "description": "SQL injection attempt",
            "characteristics": {
                "web_ports": [80, 443, 8080],
                "specific_packets": True,
                "http_protocol": True,
                "payloads": ["union select", "drop table", "--", "/*", "*/"],
            }
        },
        "privilege_escalation": {
            "description": "Privilege escalation exploit",
            "characteristics": {
                "system_ports": [135, 139, 445, 3389],
                "multiple_protocols": True,
                "abnormal_sequences": True,
            }
        },
        "botnet": {
            "description": "Botnet activity",
            "characteristics": {
                "periodic_checkins": True,
                "known_c2_ports": [4444, 5555, 6666, 8888],
                "multiple_outbound": True,
                "low_and_slow": False,
            }
        }
    }
    
    INTERNAL_IP_RANGES = {
        "10.0.0.0/8": list(range(10, 11)),
        "172.16.0.0/12": list(range(172, 173)),
        "192.168.0.0/16": list(range(192, 193)),
    }
    
    SUSPICIOUS_EXTERNAL_IPS = [
        "203.0.113.45", "198.51.100.12", "192.0.2.55",  # RFC examples
        "185.220.101.0", "45.142.182.0",  # Known malicious ranges
    ]
    
    def __init__(self, random_seed=42):
        random.seed(random_seed)
        np.random.seed(random_seed)

    def generate_normal_traffic(self, num_packets: int = 100) -> List[Dict]:
        """Generate normal, benign network traffic"""
        packets = []
        
        for _ in range(num_packets):
            src_ip = f"192.168.1.{random.randint(1, 254)}"
            dst_ip = f"{random.choice(['8.8.8.8', '1.1.1.1', '208.67.222.222'])}"
            
            packet = {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": random.randint(40000, 65535),
                "dst_port": random.choice([80, 443, 53, 123, 25, 22]),
                "protocol": random.choice(["TCP", "UDP"]),
                "packet_length": random.randint(64, 1500),
                "pkt_count": random.randint(1, 100),
                "bytes": random.randint(100, 50000),
                "duration": random.randint(1, 300),
                "rate": random.uniform(0.1, 100),
                "label": "BENIGN"
            }
            packets.append(packet)
        
        return packets

    def generate_port_scan_attack(self, num_packets: int = 50, scan_target: str = None) -> List[Dict]:
        """Generate port scanning attack pattern"""
        if scan_target is None:
            scan_target = f"192.168.1.{random.randint(1, 254)}"
        
        packets = []
        attacker_ip = random.choice(self.SUSPICIOUS_EXTERNAL_IPS)
        
        for dst_port in range(1, num_packets + 1):
            packet = {
                "src_ip": attacker_ip,
                "dst_ip": scan_target,
                "src_port": random.randint(40000, 65535),
                "dst_port": dst_port,  # Sequential port scanning
                "protocol": random.choice(["TCP", "UDP"]),
                "packet_length": random.randint(40, 120),  # Small packets
                "pkt_count": 1,
                "bytes": random.randint(40, 120),
                "duration": 1,
                "rate": random.uniform(10, 1000),  # Fast rate
                "label": "Port_Scan"
            }
            packets.append(packet)
        
        return packets

    def generate_ddos_attack(self, num_packets: int = 200, target_ip: str = None) -> List[Dict]:
        """Generate DDoS attack with multiple source IPs"""
        if target_ip is None:
            target_ip = f"192.168.1.{random.randint(1, 254)}"
        
        packets = []
        attacker_ips = [f"203.0.113.{random.randint(1, 254)}" for _ in range(10)]
        
        for _ in range(num_packets):
            packet = {
                "src_ip": random.choice(attacker_ips),
                "dst_ip": target_ip,
                "src_port": random.randint(1024, 65535),
                "dst_port": random.choice([80, 443]),  # Web services
                "protocol": "TCP",
                "packet_length": random.randint(500, 1500),  # Larger packets
                "pkt_count": random.randint(100, 1000),
                "bytes": random.randint(50000, 500000),  # High volume
                "duration": random.randint(1, 10),
                "rate": random.uniform(1000, 10000),  # Very high rate
                "label": "DDoS"
            }
            packets.append(packet)
        
        return packets

    def generate_botnet_traffic(self, num_packets: int = 100, c2_server: str = None) -> List[Dict]:
        """Generate botnet command & control traffic"""
        if c2_server is None:
            c2_server = random.choice(self.SUSPICIOUS_EXTERNAL_IPS)
        
        packets = []
        infected_ips = [f"192.168.1.{random.randint(50, 150)}" for _ in range(5)]
        
        for _ in range(num_packets):
            packet = {
                "src_ip": random.choice(infected_ips),
                "dst_ip": c2_server,
                "src_port": random.randint(40000, 65535),
                "dst_port": random.choice([4444, 5555, 6666, 8888, 9999]),  # Botnet ports
                "protocol": random.choice(["TCP", "UDP"]),
                "packet_length": random.randint(100, 500),  # Small packets
                "pkt_count": random.randint(10, 50),
                "bytes": random.randint(1000, 25000),
                "duration": random.randint(60, 3600),  # Long duration
                "rate": random.uniform(0.1, 1),  # Slow regular pattern
                "label": "Botnet"
            }
            packets.append(packet)
        
        return packets

    def generate_brute_force_attack(self, num_packets: int = 100, target_ip: str = None) -> List[Dict]:
        """Generate SSH/RDP brute force attack"""
        if target_ip is None:
            target_ip = f"192.168.1.{random.randint(1, 254)}"
        
        packets = []
        attacker_ip = random.choice(self.SUSPICIOUS_EXTERNAL_IPS)
        brute_port = random.choice([22, 3389, 23])  # SSH, RDP, Telnet
        
        for attempt in range(num_packets):
            packet = {
                "src_ip": attacker_ip,
                "dst_ip": target_ip,
                "src_port": random.randint(40000, 65535),
                "dst_port": brute_port,
                "protocol": "TCP",
                "packet_length": random.randint(100, 256),
                "pkt_count": attempt + 1,  # Increasing connection attempts
                "bytes": random.randint(100, 25600),
                "duration": random.randint(1, 60),
                "rate": random.uniform(0.5, 10),  # Moderate rate
                "label": "Brute_Force"
            }
            packets.append(packet)
        
        return packets

    def generate_data_exfiltration(self, num_packets: int = 100, victim_ip: str = None) -> List[Dict]:
        """Generate data exfiltration attack"""
        if victim_ip is None:
            victim_ip = f"192.168.1.{random.randint(50, 200)}"
        
        packets = []
        exfil_ips = [
            "203.0.113.100", "198.51.100.50", "192.0.2.200"
        ]
        
        for _ in range(num_packets):
            packet = {
                "src_ip": victim_ip,
                "dst_ip": random.choice(exfil_ips),
                "src_port": random.randint(40000, 65535),
                "dst_port": random.choice([80, 443, 8080, 873]),  # Various protocols
                "protocol": random.choice(["TCP", "UDP"]),
                "packet_length": random.randint(1400, 1500),  # Large packets (near MTU)
                "pkt_count": random.randint(50, 500),
                "bytes": random.randint(1000000, 10000000),  # Huge data transfer
                "duration": random.randint(300, 3600),  # Long duration
                "rate": random.uniform(100, 10000),  # High sustained rate
                "label": "Data_Exfiltration"
            }
            packets.append(packet)
        
        return packets

    def generate_privilege_escalation(self, num_packets: int = 100, target_ip: str = None) -> List[Dict]:
        """Generate privilege escalation attempts"""
        if target_ip is None:
            target_ip = f"192.168.1.{random.randint(1, 254)}"
        
        packets = []
        attacker_ip = f"192.168.1.{random.randint(1, 254)}"
        
        # Exploit ports
        exploit_ports = [135, 139, 445, 3389, 5985, 5986]
        
        for _ in range(num_packets):
            packet = {
                "src_ip": attacker_ip,
                "dst_ip": target_ip,
                "src_port": random.randint(40000, 65535),
                "dst_port": random.choice(exploit_ports),
                "protocol": "TCP",
                "packet_length": random.randint(100, 512),
                "pkt_count": random.randint(1, 20),
                "bytes": random.randint(100, 10240),
                "duration": random.randint(1, 30),
                "rate": random.uniform(1, 100),
                "label": "Privilege_Escalation"
            }
            packets.append(packet)
        
        return packets

    def generate_mixed_dataset(self, total_samples: int = 10000) -> pd.DataFrame:
        """Generate balanced dataset with mixed attack types"""
        all_packets = []
        
        # 70% normal traffic
        normal_count = int(total_samples * 0.70)
        all_packets.extend(self.generate_normal_traffic(normal_count))
        
        # 30% various attacks (roughly equal distribution)
        attack_count = total_samples - normal_count
        per_attack = attack_count // 7
        
        all_packets.extend(self.generate_port_scan_attack(per_attack))
        all_packets.extend(self.generate_ddos_attack(per_attack))
        all_packets.extend(self.generate_botnet_traffic(per_attack))
        all_packets.extend(self.generate_brute_force_attack(per_attack))
        all_packets.extend(self.generate_data_exfiltration(per_attack))
        all_packets.extend(self.generate_privilege_escalation(per_attack))
        
        # Remaining samples for variety
        remaining = attack_count - (per_attack * 6)
        all_packets.extend(self.generate_ddos_attack(remaining))
        
        df = pd.DataFrame(all_packets)
        df['timestamp'] = [datetime.now() - timedelta(seconds=i) for i in range(len(df))]
        
        # Shuffle
        df = df.sample(frac=1).reset_index(drop=True)
        
        return df

    def save_to_csv(self, df: pd.DataFrame, filepath: str):
        """Save generated dataset to CSV"""
        df.to_csv(filepath, index=False)
        print(f"✅ Dataset saved: {filepath}")
        print(f"📊 Total samples: {len(df)}")
        print(f"🏷️  Label distribution:\n{df['label'].value_counts()}")


class RealWorldScenarioSimulator:
    """Simulate realistic network scenarios with time-based attacks"""
    
    def __init__(self):
        self.generator = ThreatScenarioGenerator()

    def simulate_night_attack(self, hours: int = 8):
        """Simulate coordinated attack during night hours"""
        packets = []
        base_time = datetime.now().replace(hour=2, minute=0, second=0)  # 2 AM
        
        # Phase 1: Reconnaissance (port scanning)
        for i in range(50):
            pkt = self.generator.generate_port_scan_attack(10)[0]
            pkt['timestamp'] = base_time + timedelta(seconds=i*10)
            packets.append(pkt)
        
        # Phase 2: Exploitation (privilege escalation)
        for i in range(30):
            pkt = self.generator.generate_privilege_escalation(5)[0]
            pkt['timestamp'] = base_time + timedelta(minutes=10, seconds=i*20)
            packets.append(pkt)
        
        # Phase 3: Data exfiltration
        for i in range(20):
            pkt = self.generator.generate_data_exfiltration(10)[0]
            pkt['timestamp'] = base_time + timedelta(minutes=30, seconds=i*30)
            packets.append(pkt)
        
        return pd.DataFrame(packets)

    def simulate_ddos_campaign(self, duration_minutes: int = 60):
        """Simulate realistic DDoS attack campaign"""
        packets = self.generator.generate_ddos_attack(num_packets=1000)
        base_time = datetime.now()
        df = pd.DataFrame(packets)
        df['timestamp'] = [base_time + timedelta(seconds=random.randint(0, duration_minutes*60)) 
                          for _ in range(len(df))]
        return df


if __name__ == "__main__":
    # Generate realistic threat dataset
    generator = ThreatScenarioGenerator(random_seed=42)
    
    print("🔒 Generating realistic threat scenarios...\n")
    
    # Generate mixed dataset
    print("1️⃣  Generating mixed attack dataset...")
    mixed_df = generator.generate_mixed_dataset(total_samples=5000)
    generator.save_to_csv(mixed_df, "data/realistic_threats.csv")
    
    # Generate specific attack scenarios
    print("\n2️⃣  Generating port scan attack...")
    port_scan_df = pd.DataFrame(generator.generate_port_scan_attack(num_packets=100))
    print(f"Generated {len(port_scan_df)} port scan packets")
    
    print("\n3️⃣  Generating DDoS attack...")
    ddos_df = pd.DataFrame(generator.generate_ddos_attack(num_packets=200))
    print(f"Generated {len(ddos_df)} DDoS packets")
    
    print("\n4️⃣  Generating botnet traffic...")
    botnet_df = pd.DataFrame(generator.generate_botnet_traffic(num_packets=150))
    print(f"Generated {len(botnet_df)} botnet packets")
    
    # Composite scenario
    print("\n5️⃣  Simulating night attack campaign...")
    simulator = RealWorldScenarioSimulator()
    night_attack_df = simulator.simulate_night_attack()
    print(f"Generated {len(night_attack_df)} packets for night attack scenario")
