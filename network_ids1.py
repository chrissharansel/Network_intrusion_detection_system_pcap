"""
Standalone Network Intrusion Detection System
Real-time packet capture and analysis
Run independently from other IDS systems
"""

import threading
import time
from datetime import datetime, timedelta
from collections import defaultdict, deque
from typing import Dict, List
import subprocess
import re
import json
import os
import logging
from logging.handlers import RotatingFileHandler

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("❌ Scapy not installed. Install with: pip install scapy")
    exit(1)

import numpy as np
from sklearn.ensemble import IsolationForest


class NetworkIDS:
    """
    Standalone Network Intrusion Detection System
    """
    
    def __init__(self, interface: str = None, alert_file: str = "network_alerts.json"):
        """
        Initialize Network IDS
        
        Args:
            interface: Network interface to monitor (auto-detect if None)
            alert_file: File to save alerts (JSON format)
        """
        self.interface = interface or self._get_default_interface()
        self.alert_file = alert_file
        
        self.running = False
        self.capture_thread = None
        self.analysis_thread = None
        # =========================
        # Logging Setup
        # =========================
        self.logger = logging.getLogger("NetworkIDS")
        self.logger.setLevel(logging.INFO)

        # Prevent duplicate handlers
        if not self.logger.handlers:
            handler = RotatingFileHandler(
                "network_ids.log",
                maxBytes=5 * 1024 * 1024,  # 5 MB
                backupCount=5
            )

            formatter = logging.Formatter(
                "%(asctime)s | %(levelname)s | %(message)s"
            )

            handler.setFormatter(formatter)
            self.logger.addHandler(handler)

        self.logger.info("Network IDS Initialized")
        
        # Connection tracking per IP
        self.connections = defaultdict(lambda: {
            'packet_count': 0,
            'syn_count': 0,
            'ack_count': 0,
            'fin_count': 0,
            'rst_count': 0,
            'udp_count': 0,
            'icmp_count': 0,
            'tcp_count': 0,
            'bytes_sent': 0,
            'ports_accessed': set(),
            'first_seen': datetime.now(),
            'last_seen': datetime.now(),
            'packet_timestamps': deque(maxlen=200),
            'packet_sizes': deque(maxlen=200),
            'protocols': defaultdict(int)
        })
        
        # Detection thresholds
        self.thresholds = {
            # DDoS Detection
            'ddos_pps': 1000,              # Packets per second
            'ddos_connections': 100,        # Connections per second
            
            # Flood Detection
            'syn_flood_ratio': 3.0,         # SYN:ACK ratio
            'udp_flood_pps': 500,           # UDP packets per second
            'icmp_flood_pps': 10,          # ICMP packets per second
            
            # Scan Detection
            'port_scan_ports': 15,          # Unique ports in timeframe
            'port_scan_time': 10,           # Seconds
            
            # Brute Force
            'brute_force_attempts': 30,     # Connection attempts per minute
            'brute_force_ports': {22, 21, 3389, 23, 3306, 5432},
            
            # Anomaly Detection
            'anomaly_packet_size': 1500,    # Bytes
            'anomaly_connection_rate': 50   # Connections per second
        }
        
        # Statistics
        self.stats = {
            'total_packets': 0,
            'total_bytes': 0,
            'tcp_packets': 0,
            'udp_packets': 0,
            'icmp_packets': 0,
            'arp_packets': 0,
            'other_packets': 0,
            'unique_ips': 0,
            'alerts_generated': 0,
            'start_time': datetime.now()
        }
        
        # Alert storage
        self.alerts = deque(maxlen=1000)
        self.alert_counts = defaultdict(int)
        
        # ML Anomaly Detector
        self.anomaly_detector = IsolationForest(
            contamination=0.1,
            random_state=42,
            n_estimators=100
        )
        self.ml_trained = False
        self.training_buffer = deque(maxlen=500)
        # ML control + cooldown
        self.ml_enabled = True
        self.anomaly_cooldown = {}
        
        print(f"""
╔══════════════════════════════════════════════════════════╗
║          Network Intrusion Detection System              ║
╠══════════════════════════════════════════════════════════╣
║  Interface: {self.interface:44s} ║
║  Alert File: {alert_file:43s} ║
╚══════════════════════════════════════════════════════════╝
        """)
    
    def _get_default_interface(self) -> str:
        """
        Auto-detect the correct active network interface.
        Prioritizes real private IP addresses (192.168.x.x / 10.x.x.x / 172.16-31.x.x)
        """
        from scapy.all import get_if_list, get_if_addr

        interfaces = get_if_list()

        best_interface = None

        for iface in interfaces:
            try:
                ip = get_if_addr(iface)

                if not ip:
                    continue

                # Skip unusable addresses
                if ip.startswith("127.") or ip == "0.0.0.0":
                    continue

                # Skip Windows APIPA fallback addresses
                if ip.startswith("169.254."):
                    continue

                # Prefer real private LAN IP ranges
                if (
                    ip.startswith("192.168.")
                    or ip.startswith("10.")
                    or ip.startswith("172.")
                ):
                    print(f"✓ Auto-selected active interface: {iface} ({ip})")
                    return iface

                # Otherwise keep as fallback
                best_interface = iface

            except Exception:
                continue

        if best_interface:
            print(f"⚠ Using fallback interface: {best_interface}")
            return best_interface

        raise RuntimeError("No suitable active network interface found")
    
    def start(self):
        """Start the Network IDS"""
        if not SCAPY_AVAILABLE:
            print("❌ Cannot start: Scapy not installed")
            return False
        
        if self.running:
            print("⚠ Already running")
            return True
        
        print("\n🚀 Starting Network IDS...")
        self.logger.info("IDS Started")
        self.running = True
        
        # Start packet capture thread
        self.capture_thread = threading.Thread(target=self._packet_capture)
        self.capture_thread.start()
        
        # Start analysis thread
        self.analysis_thread = threading.Thread(target=self._analysis_loop)
        self.analysis_thread.start()
        
        print(f"✓ Monitoring interface: {self.interface}")
        print(f"✓ Saving alerts to: {self.alert_file}")
        print("✓ Press Ctrl+C to stop\n")
        
        return True
    
    def stop(self):
        """Stop the Network IDS"""
        print("\n🛑 Stopping Network IDS...")
        self.running = False
        self.logger.info("IDS Stopped")
        if self.capture_thread:
            self.capture_thread.join(timeout=3)
        
        if self.analysis_thread:
            self.analysis_thread.join(timeout=3)
        
        self._print_final_statistics()
        print("✓ Network IDS stopped")
    
    def _packet_capture(self):
        """Capture network packets"""
        try:
            print(f"📡 Starting packet capture on {self.interface}...")
            sniff(
                iface=self.interface,
                prn=self._process_packet,
                store=False,
                stop_filter=lambda x: not self.running
            )
        except PermissionError:
            print("\n❌ Permission denied!")
            print("   Run with: sudo python3 network_ids.py")
            print("   OR grant capability: sudo setcap cap_net_raw+ep $(which python3)")
            self.running = False
        except Exception as e:
            print(f"❌ Capture error: {e}")
            self.running = False
    
    def _process_packet(self, packet):
        """Process individual packet"""
        try:
            self.stats['total_packets'] += 1
            
            # Process by protocol
            if IP in packet:
                self._process_ip_packet(packet)
            elif ARP in packet:
                self.stats['arp_packets'] += 1
            else:
                self.stats['other_packets'] += 1
            
            # Update unique IPs count
            self.stats['unique_ips'] = len(self.connections)
            
            # Print periodic stats
            if self.stats['total_packets'] % 1000 == 0:
                self._print_realtime_stats()
                
        except Exception as e:
            pass  # Silently ignore malformed packets
    
    def _process_ip_packet(self, packet):
        """Process IP layer packet"""
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        
        # Update connection info
        conn = self.connections[src_ip]
        conn['packet_count'] += 1
        conn['last_seen'] = datetime.now()
        conn['packet_timestamps'].append(time.time())
        
        packet_size = len(packet)
        conn['bytes_sent'] += packet_size
        conn['packet_sizes'].append(packet_size)
        self.stats['total_bytes'] += packet_size
        
        # Process TCP
        if TCP in packet:
            self._process_tcp(packet, src_ip)
            self.stats['tcp_packets'] += 1
            conn['tcp_count'] += 1
            conn['protocols']['TCP'] += 1
        
        # Process UDP
        elif UDP in packet:
            conn['udp_count'] += 1
            conn['protocols']['UDP'] += 1
            self.stats['udp_packets'] += 1
        
        # Process ICMP
        elif ICMP in packet:
            conn['icmp_count'] += 1
            conn['protocols']['ICMP'] += 1
            self.stats['icmp_packets'] += 1
    
    def _process_tcp(self, packet, src_ip):
        """Process TCP packet"""
        tcp_layer = packet[TCP]
        conn = self.connections[src_ip]
        
        # Track destination port
        conn['ports_accessed'].add(tcp_layer.dport)
        
        # Analyze TCP flags
        flags = tcp_layer.flags
        
        if flags & 0x02:  # SYN
            conn['syn_count'] += 1
        if flags & 0x10:  # ACK
            conn['ack_count'] += 1
        if flags & 0x01:  # FIN
            conn['fin_count'] += 1
        if flags & 0x04:  # RST
            conn['rst_count'] += 1
    
    def _analysis_loop(self):
        """Continuously analyze traffic for attacks"""
        print("🔍 Analysis engine started\n")
        
        while self.running:
            try:
                # Run all detection algorithms
                self._detect_ddos()
                self._detect_syn_flood()
                self._detect_udp_flood()
                self._detect_icmp_flood()
                self._detect_port_scans()
                self._detect_brute_force()
                self._detect_anomalies()
                
                # Cleanup old connections
                self._cleanup_stale_connections()
                
                # Train ML model periodically
                self._train_anomaly_detector()
                
                time.sleep(2)  # Analyze every 2 seconds
                
            except Exception as e:
                print(f"Analysis error: {e}")
    
    def _detect_ddos(self):
        """Detect DDoS/DoS attacks"""
        current_time = time.time()
        
        for ip, conn in list(self.connections.items()):
            # Calculate packets per second (last 5 seconds)
            recent_time = current_time - 5
            recent_packets = [t for t in conn['packet_timestamps'] if t > recent_time]
            
            if len(recent_packets) > 50:  # Minimum threshold
                pps = len(recent_packets) / 5
                
                if pps > self.thresholds['ddos_pps']:
                    self._create_alert(
                        attack_type='DDoS / DoS Attack',
                        src_ip=ip,
                        severity='Critical',
                        confidence=0.95,
                        details={
                            'packets_per_second': f"{pps:.1f}",
                            'total_packets': conn['packet_count'],
                            'total_bytes': f"{conn['bytes_sent']:,}",
                            'description': 'Abnormally high packet rate detected'
                        }
                    )
    
    def _detect_syn_flood(self):
        """Detect SYN flood attacks"""
        for ip, conn in list(self.connections.items()):
            if conn['syn_count'] > 50 and conn['ack_count'] > 0:
                ratio = conn['syn_count'] / max(conn['ack_count'], 1)
                
                if ratio > self.thresholds['syn_flood_ratio']:
                    self._create_alert(
                        attack_type='SYN Flood Attack',
                        src_ip=ip,
                        severity='Critical',
                        confidence=0.96,
                        details={
                            'syn_packets': conn['syn_count'],
                            'ack_packets': conn['ack_count'],
                            'syn_ack_ratio': f"{ratio:.2f}",
                            'description': 'Half-open TCP connections indicate SYN flood'
                        }
                    )
                    
                    # Reset counters
                    conn['syn_count'] = 0
                    conn['ack_count'] = 0
    
    def _detect_udp_flood(self):
        """Detect UDP flood attacks"""
        current_time = time.time()
        
        for ip, conn in list(self.connections.items()):
            if conn['udp_count'] > 100:
                # Calculate UDP packets per second
                recent_time = current_time - 5
                recent_udp = conn['udp_count']  # Simplified
                
                if recent_udp > self.thresholds['udp_flood_pps']:
                    self._create_alert(
                        attack_type='UDP Flood Attack',
                        src_ip=ip,
                        severity='High',
                        confidence=0.92,
                        details={
                            'udp_packets': conn['udp_count'],
                            'description': 'Excessive UDP traffic detected',
                            'target': 'Network bandwidth saturation'
                        }
                    )
                    
                    conn['udp_count'] = 0
    
    def _detect_icmp_flood(self):
        """Detect ICMP flood (Ping flood)"""
        for ip, conn in list(self.connections.items()):
            if conn['icmp_count'] > self.thresholds['icmp_flood_pps']:
                self._create_alert(
                    attack_type='ICMP Flood (Ping Flood)',
                    src_ip=ip,
                    severity='Medium',
                    confidence=0.90,
                    details={
                        'icmp_packets': conn['icmp_count'],
                        'description': 'Excessive ICMP echo requests',
                        'attack_variant': 'Ping flood / Smurf attack'
                    }
                )
                
                conn['icmp_count'] = 0
    
    def _detect_port_scans(self):
        """Detect port scanning activity"""
        current_time = datetime.now()
        
        for ip, conn in list(self.connections.items()):
            time_diff = (current_time - conn['first_seen']).total_seconds()
            
            if time_diff < self.thresholds['port_scan_time']:
                ports_scanned = len(conn['ports_accessed'])
                
                if ports_scanned >= self.thresholds['port_scan_ports']:
                    self._create_alert(
                        attack_type='Port Scan Detected',
                        src_ip=ip,
                        severity='High',
                        confidence=0.93,
                        details={
                            'ports_scanned': ports_scanned,
                            'sample_ports': list(conn['ports_accessed'])[:15],
                            'scan_duration': f"{time_diff:.1f}s",
                            'scan_type': 'Sequential/Random port probe',
                            'description': f'Scanned {ports_scanned} ports in {time_diff:.1f} seconds'
                        }
                    )
                    
                    # Reset
                    conn['ports_accessed'].clear()
                    conn['first_seen'] = datetime.now()
    
    def _detect_brute_force(self):
        """Detect brute force attacks on services"""
        current_time = time.time()
        
        for ip, conn in list(self.connections.items()):
            # Check if accessing sensitive ports
            sensitive_accessed = conn['ports_accessed'].intersection(
                self.thresholds['brute_force_ports']
            )
            
            if sensitive_accessed:
                # Count recent connection attempts (last 60 seconds)
                recent_time = current_time - 60
                recent_attempts = [t for t in conn['packet_timestamps'] if t > recent_time]
                
                if len(recent_attempts) > self.thresholds['brute_force_attempts']:
                    self._create_alert(
                        attack_type='Brute Force Attack',
                        src_ip=ip,
                        severity='High',
                        confidence=0.88,
                        details={
                            'connection_attempts': len(recent_attempts),
                            'target_ports': list(sensitive_accessed),
                            'time_window': '60 seconds',
                            'services': self._identify_services(sensitive_accessed),
                            'description': 'Repeated authentication attempts detected'
                        }
                    )
    
    def _detect_anomalies(self):
        """Improved ML-based anomaly detection"""

        if not self.ml_enabled:
            return

        features_list = []
        ip_list = []

        current_time = time.time()

        for ip, conn in list(self.connections.items()):

            if conn['packet_count'] < 100:
                continue

            duration = max((current_time - conn['packet_timestamps'][0]), 1)
            pps = conn['packet_count'] / duration
            byte_rate = conn['bytes_sent'] / duration

            avg_packet_size = np.mean(conn['packet_sizes']) if conn['packet_sizes'] else 0
            std_packet_size = np.std(conn['packet_sizes']) if len(conn['packet_sizes']) > 1 else 0

            syn_ratio = conn['syn_count'] / max(conn['packet_count'], 1)
            unique_ports = len(conn['ports_accessed'])

            tcp_udp_ratio = conn['tcp_count'] / max(conn['udp_count'], 1)

            features = [
                pps,
                byte_rate,
                avg_packet_size,
                std_packet_size,
                syn_ratio,
                unique_ports,
                tcp_udp_ratio
            ]

            features_list.append(features)
            ip_list.append(ip)
            self.training_buffer.append(features)

        if self.ml_trained and features_list:

            scores = self.anomaly_detector.decision_function(features_list)
            predictions = self.anomaly_detector.predict(features_list)

            for i, pred in enumerate(predictions):
                if pred == -1:

                    ip = ip_list[i]
                    anomaly_score = float(scores[i])

                    now = time.time()
                    last_alert = self.anomaly_cooldown.get(ip, 0)

                    if now - last_alert < 60:
                        continue

                    self.anomaly_cooldown[ip] = now

                    self._create_alert(
                        attack_type='Network Anomaly Detected',
                        src_ip=ip,
                        severity='Medium',
                        confidence=abs(anomaly_score),
                        details={
                            'anomaly_score': anomaly_score,
                            'pps': round(features_list[i][0], 2),
                            'byte_rate': round(features_list[i][1], 2),
                            'unique_ports': unique_ports,
                            'description': 'ML detected abnormal traffic behavior'
                        }
                    )
    
    def _train_anomaly_detector(self):
        """Train ML anomaly detector"""
        if not self.ml_trained and len(self.training_buffer) >= 100:
            try:
                self.anomaly_detector.fit(list(self.training_buffer))
                self.ml_trained = True
                print("🤖 ML Anomaly Detector trained on baseline traffic")
            except Exception as e:
                print(f"⚠ ML training failed: {e}")
    
    def _cleanup_stale_connections(self):
        """Remove old connection data"""
        cutoff = datetime.now() - timedelta(minutes=5)
        to_remove = [
            ip for ip, conn in self.connections.items()
            if conn['last_seen'] < cutoff
        ]
        
        for ip in to_remove:
            del self.connections[ip]
    
    def _create_alert(self, attack_type: str, src_ip: str, severity: str,
                    confidence: float, details: Dict):
        """Create and log alert"""

        # ✅ Ensure anomaly_score always exists
        if 'anomaly_score' not in details:
            details['anomaly_score'] = 0.0

        alert = {
            'timestamp': datetime.now().isoformat(),
            'attack_type': attack_type,
            'src_ip': src_ip,
            'severity': severity,
            'confidence': confidence,
            'details': self._make_json_serializable(details)
        }

        safe_alert = self._make_json_serializable(alert)
        self.alerts.append(safe_alert)
        self.alert_counts[attack_type] += 1
        self.stats['alerts_generated'] += 1

        # Print to console
        self._print_alert(alert)

        # Save to file
        self._save_alert(alert)
    
    def _print_alert(self, alert: Dict):
        """Print alert to console"""
        severity_colors = {
            'Critical': '\033[91m',  # Red
            'High': '\033[93m',      # Yellow
            'Medium': '\033[94m',    # Blue
            'Low': '\033[92m'        # Green
        }
        reset = '\033[0m'
        
        color = severity_colors.get(alert['severity'], '')
        
        print(f"\n{color}{'='*60}")
        print(f"🚨 ALERT: {alert['attack_type']}")
        print(f"{'='*60}{reset}")
        print(f"Timestamp:   {alert['timestamp']}")
        print(f"Source IP:   {alert['src_ip']}")
        print(f"Severity:    {alert['severity']}")
        print(f"Confidence:  {alert['confidence']*100:.1f}%")
        print(f"Details:")
        for key, value in alert['details'].items():
            print(f"  - {key}: {value}")
        print(f"{color}{'='*60}{reset}\n")
    
    def _save_alert(self, alert: Dict):
        """Save alert to JSON file"""
        try:
            # Load existing alerts
            if os.path.exists(self.alert_file):
                with open(self.alert_file, 'r') as f:
                    alerts = json.load(f)
            else:
                alerts = []
            
            # Append new alert
            alerts.append(alert)
            
            # Keep last 1000 alerts
            alerts = alerts[-1000:]
            
            # Save
            with open(self.alert_file, 'w') as f:
                json.dump(alerts, f, indent=2, default=str)
                
        except Exception as e:
            print(f"⚠ Error saving alert: {e}")
    
    def _make_json_serializable(self, obj):
        """Make any object JSON safe"""
        import numpy as np
        
        if isinstance(obj, dict):
            return {str(k): self._make_json_serializable(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self._make_json_serializable(v) for v in obj]
        elif isinstance(obj, set):
            return list(obj)
        elif isinstance(obj, datetime):
            return obj.isoformat()
        elif isinstance(obj, (np.integer, np.floating)):
            return float(obj)
        elif isinstance(obj, (np.ndarray,)):
            return obj.tolist()
        else:
            return obj


            
    def _print_realtime_stats(self):
        """Print real-time statistics"""
        uptime = (datetime.now() - self.stats['start_time']).total_seconds()
        pps = self.stats['total_packets'] / max(uptime, 1)
        
        print(f"\r📊 Packets: {self.stats['total_packets']:,} | "
              f"Rate: {pps:.1f} pps | "
              f"IPs: {self.stats['unique_ips']} | "
              f"Alerts: {self.stats['alerts_generated']}", end='', flush=True)
    
    def _print_final_statistics(self):
        """Print final statistics on shutdown"""
        uptime = (datetime.now() - self.stats['start_time']).total_seconds()
        
        print(f"""
╔══════════════════════════════════════════════════════════╗
║                  Final Statistics                        ║
╠══════════════════════════════════════════════════════════╣
║  Runtime:        {uptime/60:.1f} minutes                           
║  Total Packets:  {self.stats['total_packets']:,}
║  Total Bytes:    {self.stats['total_bytes']:,}
║  TCP Packets:    {self.stats['tcp_packets']:,}
║  UDP Packets:    {self.stats['udp_packets']:,}
║  ICMP Packets:   {self.stats['icmp_packets']:,}
║  Unique IPs:     {self.stats['unique_ips']}
║  Alerts:         {self.stats['alerts_generated']}
╠══════════════════════════════════════════════════════════╣
║                  Alert Breakdown                          ║
╠══════════════════════════════════════════════════════════╣""")
        
        for attack_type, count in sorted(self.alert_counts.items(), 
                                        key=lambda x: x[1], reverse=True):
            print(f"║  {attack_type:40s} {count:6d}       ║")
        
        print(f"╚══════════════════════════════════════════════════════════╝")
    
    def _identify_services(self, ports: set) -> str:
        """Identify services by port numbers"""
        service_map = {
            22: 'SSH', 21: 'FTP', 23: 'Telnet', 25: 'SMTP',
            80: 'HTTP', 443: 'HTTPS', 3306: 'MySQL', 5432: 'PostgreSQL',
            3389: 'RDP', 1433: 'MSSQL', 27017: 'MongoDB'
        }
        
        services = [service_map.get(port, f'Port {port}') for port in ports]
        return ', '.join(services)


def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Standalone Network IDS')
    parser.add_argument('-i', '--interface', help='Network interface (auto-detect if not specified)')
    parser.add_argument('-o', '--output', default='network_alerts.json', 
                       help='Alert output file (default: network_alerts.json)')
    
    args = parser.parse_args()
    
    # Create IDS instance
    ids = NetworkIDS(interface=args.interface, alert_file=args.output)
    
    # Start monitoring
    if ids.start():
        try:
            # Keep running until Ctrl+C
            while ids.running:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n\n⚠ Interrupted by user")
        finally:
            ids.stop()
    else:
        print("❌ Failed to start Network IDS")


if __name__ == '__main__':
    main()