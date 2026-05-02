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

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("❌ Scapy not installed. Install with: pip install scapy")
    exit(1)

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler


# ─────────────────────────────────────────────────────────────
# Known benign cloud / CDN ranges — ML won't alert on these
# ─────────────────────────────────────────────────────────────
WHITELIST_PREFIXES = (
    "192.168.", "10.", "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
    "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
    # Azure
    "20.", "40.", "52.", "104.", "13.107.", "23.99.",
    # Google / GCP
    "142.250.", "172.217.", "216.58.", "34.120.", "35.",
    # AWS CloudFront
    "13.", "54.", "18.", "3.",
    # GitHub
    "140.82.", "185.199.", "192.30.",
    # Cloudflare
    "1.1.", "1.0.", "104.16.", "104.17.", "104.18.", "104.19.",
)

# Minimum anomaly score (negative = more anomalous) to trigger alert
ANOMALY_SCORE_THRESHOLD = -0.15

# Minimum packets from an IP before ML will even consider it
ML_MIN_PACKETS = 150

# How long (seconds) before the same IP can fire another ML alert
ML_COOLDOWN_SECONDS = 180


class NetworkIDS:
    """
    Standalone Network Intrusion Detection System
    """

    def __init__(self, interface: str = None, alert_file: str = "network_alerts.json"):
        self.interface = interface or self._get_default_interface()
        self.alert_file = alert_file

        self.running = False
        self.capture_thread = None
        self.analysis_thread = None

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
            'ddos_pps': 1000,
            'ddos_connections': 100,
            'syn_flood_ratio': 3.0,
            'udp_flood_pps': 500,
            'icmp_flood_pps': 100,
            'port_scan_ports': 15,
            'port_scan_time': 10,
            'brute_force_attempts': 30,
            'brute_force_ports': {22, 21, 3389, 23, 3306, 5432},
            'anomaly_packet_size': 1500,
            'anomaly_connection_rate': 50
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

        # ── ML components ──────────────────────────────────────────
        self.anomaly_detector = IsolationForest(
            contamination=0.05,   # Expect only ~5 % true anomalies
            random_state=42,
            n_estimators=200,     # More trees → more stable scores
            max_samples='auto'
        )
        self.scaler = StandardScaler()          # Normalise features
        self.ml_trained = False
        self.ml_enabled = True

        # Separate buffers: baseline (first N samples) vs ongoing
        self.training_buffer = deque(maxlen=1000)
        self.baseline_locked = False            # True after first fit

        # Per-IP ML cooldown  {ip: last_alert_timestamp}
        self.anomaly_cooldown: Dict[str, float] = {}

        # Track per-IP feature history to smooth out spikes
        # {ip: deque of recent feature vectors}
        self.ip_feature_history: Dict[str, deque] = defaultdict(lambda: deque(maxlen=5))

        print(f"""
╔══════════════════════════════════════════════════════════╗
║          Network Intrusion Detection System              ║
╠══════════════════════════════════════════════════════════╣
║  Interface: {self.interface:44s} ║
║  Alert File: {self.alert_file:43s} ║
║  ML Score Threshold : {ANOMALY_SCORE_THRESHOLD:<37.2f} ║
║  ML Cooldown        : {ML_COOLDOWN_SECONDS:<37d} ║
╚══════════════════════════════════════════════════════════╝
        """)

    # ──────────────────────────────────────────────────────────────
    # Interface detection
    # ──────────────────────────────────────────────────────────────
    def _get_default_interface(self) -> str:
        from scapy.all import get_if_list, get_if_addr

        for iface in get_if_list():
            try:
                ip = get_if_addr(iface)
                if not ip or ip.startswith("127.") or ip == "0.0.0.0" or ip.startswith("169.254."):
                    continue
                if ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172."):
                    print(f"✓ Auto-selected active interface: {iface} ({ip})")
                    return iface
            except Exception:
                continue

        raise RuntimeError("No suitable active network interface found")

    # ──────────────────────────────────────────────────────────────
    # Start / Stop
    # ──────────────────────────────────────────────────────────────
    def start(self):
        if not SCAPY_AVAILABLE:
            print("❌ Cannot start: Scapy not installed")
            return False
        if self.running:
            return True

        print("\n🚀 Starting Network IDS...")
        self.running = True

        self.capture_thread = threading.Thread(target=self._packet_capture, daemon=True)
        self.capture_thread.start()

        self.analysis_thread = threading.Thread(target=self._analysis_loop, daemon=True)
        self.analysis_thread.start()

        print(f"✓ Monitoring interface : {self.interface}")
        print(f"✓ Saving alerts to     : {self.alert_file}")
        print("✓ Press Ctrl+C to stop\n")
        return True

    def stop(self):
        print("\n🛑 Stopping Network IDS...")
        self.running = False
        if self.capture_thread:
            self.capture_thread.join(timeout=3)
        if self.analysis_thread:
            self.analysis_thread.join(timeout=3)
        self._print_final_statistics()
        print("✓ Network IDS stopped")

    # ──────────────────────────────────────────────────────────────
    # Packet capture
    # ──────────────────────────────────────────────────────────────
    def _packet_capture(self):
        try:
            print(f"📡 Starting packet capture on {self.interface}...")
            sniff(
                iface=self.interface,
                prn=self._process_packet,
                store=False,
                stop_filter=lambda x: not self.running
            )
        except PermissionError:
            print("\n❌ Permission denied! Run with: sudo python3 network_ids.py")
            self.running = False
        except Exception as e:
            print(f"❌ Capture error: {e}")
            self.running = False

    def _process_packet(self, packet):
        try:
            self.stats['total_packets'] += 1
            if IP in packet:
                self._process_ip_packet(packet)
            elif ARP in packet:
                self.stats['arp_packets'] += 1
            else:
                self.stats['other_packets'] += 1

            self.stats['unique_ips'] = len(self.connections)

            if self.stats['total_packets'] % 1000 == 0:
                self._print_realtime_stats()
        except Exception:
            pass

    def _process_ip_packet(self, packet):
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        conn = self.connections[src_ip]
        conn['packet_count'] += 1
        conn['last_seen'] = datetime.now()
        conn['packet_timestamps'].append(time.time())

        packet_size = len(packet)
        conn['bytes_sent'] += packet_size
        conn['packet_sizes'].append(packet_size)
        self.stats['total_bytes'] += packet_size

        if TCP in packet:
            self._process_tcp(packet, src_ip)
            self.stats['tcp_packets'] += 1
            conn['tcp_count'] += 1
            conn['protocols']['TCP'] += 1
        elif UDP in packet:
            conn['udp_count'] += 1
            conn['protocols']['UDP'] += 1
            self.stats['udp_packets'] += 1
        elif ICMP in packet:
            conn['icmp_count'] += 1
            conn['protocols']['ICMP'] += 1
            self.stats['icmp_packets'] += 1

    def _process_tcp(self, packet, src_ip):
        tcp_layer = packet[TCP]
        conn = self.connections[src_ip]
        conn['ports_accessed'].add(tcp_layer.dport)
        flags = tcp_layer.flags
        if flags & 0x02: conn['syn_count'] += 1
        if flags & 0x10: conn['ack_count'] += 1
        if flags & 0x01: conn['fin_count'] += 1
        if flags & 0x04: conn['rst_count'] += 1

    # ──────────────────────────────────────────────────────────────
    # Analysis loop
    # ──────────────────────────────────────────────────────────────
    def _analysis_loop(self):
        print("🔍 Analysis engine started\n")
        while self.running:
            try:
                self._detect_ddos()
                self._detect_syn_flood()
                self._detect_udp_flood()
                self._detect_icmp_flood()
                self._detect_port_scans()
                self._detect_brute_force()
                self._detect_anomalies()
                self._cleanup_stale_connections()
                self._train_anomaly_detector()
                time.sleep(2)
            except Exception as e:
                print(f"Analysis error: {e}")

    # ──────────────────────────────────────────────────────────────
    # Rule-based detectors (unchanged)
    # ──────────────────────────────────────────────────────────────
    def _detect_ddos(self):
        current_time = time.time()
        for ip, conn in list(self.connections.items()):
            recent = [t for t in conn['packet_timestamps'] if t > current_time - 5]
            if len(recent) > 50:
                pps = len(recent) / 5
                if pps > self.thresholds['ddos_pps']:
                    self._create_alert(
                        attack_type='DDoS / DoS Attack', src_ip=ip,
                        severity='Critical', confidence=0.95,
                        details={
                            'packets_per_second': f"{pps:.1f}",
                            'total_packets': conn['packet_count'],
                            'description': 'Abnormally high packet rate detected'
                        })

    def _detect_syn_flood(self):
        for ip, conn in list(self.connections.items()):
            if conn['syn_count'] > 50 and conn['ack_count'] > 0:
                ratio = conn['syn_count'] / max(conn['ack_count'], 1)
                if ratio > self.thresholds['syn_flood_ratio']:
                    self._create_alert(
                        attack_type='SYN Flood Attack', src_ip=ip,
                        severity='Critical', confidence=0.96,
                        details={
                            'syn_packets': conn['syn_count'],
                            'ack_packets': conn['ack_count'],
                            'syn_ack_ratio': f"{ratio:.2f}",
                            'description': 'Half-open TCP connections indicate SYN flood'
                        })
                    conn['syn_count'] = 0
                    conn['ack_count'] = 0

    def _detect_udp_flood(self):
        for ip, conn in list(self.connections.items()):
            if conn['udp_count'] > self.thresholds['udp_flood_pps']:
                self._create_alert(
                    attack_type='UDP Flood Attack', src_ip=ip,
                    severity='High', confidence=0.92,
                    details={
                        'udp_packets': conn['udp_count'],
                        'description': 'Excessive UDP traffic detected'
                    })
                conn['udp_count'] = 0

    def _detect_icmp_flood(self):
        for ip, conn in list(self.connections.items()):
            if conn['icmp_count'] > self.thresholds['icmp_flood_pps']:
                self._create_alert(
                    attack_type='ICMP Flood (Ping Flood)', src_ip=ip,
                    severity='Medium', confidence=0.90,
                    details={
                        'icmp_packets': conn['icmp_count'],
                        'description': 'Excessive ICMP echo requests'
                    })
                conn['icmp_count'] = 0

    def _detect_port_scans(self):
        current_time = datetime.now()
        for ip, conn in list(self.connections.items()):
            time_diff = (current_time - conn['first_seen']).total_seconds()
            if time_diff < self.thresholds['port_scan_time']:
                ports_scanned = len(conn['ports_accessed'])
                if ports_scanned >= self.thresholds['port_scan_ports']:
                    self._create_alert(
                        attack_type='Port Scan Detected', src_ip=ip,
                        severity='High', confidence=0.93,
                        details={
                            'ports_scanned': ports_scanned,
                            'sample_ports': list(conn['ports_accessed'])[:15],
                            'scan_duration': f"{time_diff:.1f}s",
                            'description': f'Scanned {ports_scanned} ports in {time_diff:.1f} seconds'
                        })
                    conn['ports_accessed'].clear()
                    conn['first_seen'] = datetime.now()

    def _detect_brute_force(self):
        current_time = time.time()
        for ip, conn in list(self.connections.items()):
            sensitive = conn['ports_accessed'].intersection(self.thresholds['brute_force_ports'])
            if sensitive:
                recent = [t for t in conn['packet_timestamps'] if t > current_time - 60]
                if len(recent) > self.thresholds['brute_force_attempts']:
                    self._create_alert(
                        attack_type='Brute Force Attack', src_ip=ip,
                        severity='High', confidence=0.88,
                        details={
                            'connection_attempts': len(recent),
                            'target_ports': list(sensitive),
                            'services': self._identify_services(sensitive),
                            'description': 'Repeated authentication attempts detected'
                        })

    # ──────────────────────────────────────────────────────────────
    # ✨ IMPROVED ML anomaly detection
    # ──────────────────────────────────────────────────────────────
    def _build_features(self, ip: str, conn: dict, current_time: float):
        """
        Extract a 9-dimensional normalised feature vector for one IP.
        Returns None if there isn't enough data yet.
        """
        if conn['packet_count'] < ML_MIN_PACKETS:
            return None

        timestamps = list(conn['packet_timestamps'])
        if not timestamps:
            return None

        duration = max(current_time - timestamps[0], 1.0)
        pps           = conn['packet_count'] / duration
        byte_rate     = conn['bytes_sent']   / duration
        avg_pkt_size  = float(np.mean(conn['packet_sizes'])) if conn['packet_sizes'] else 0.0
        std_pkt_size  = float(np.std(conn['packet_sizes']))  if len(conn['packet_sizes']) > 1 else 0.0
        syn_ratio     = conn['syn_count']  / max(conn['packet_count'], 1)
        rst_ratio     = conn['rst_count']  / max(conn['packet_count'], 1)
        unique_ports  = len(conn['ports_accessed'])
        tcp_udp_ratio = conn['tcp_count']  / max(conn['udp_count'], 1)
        icmp_ratio    = conn['icmp_count'] / max(conn['packet_count'], 1)

        return [pps, byte_rate, avg_pkt_size, std_pkt_size,
                syn_ratio, rst_ratio, unique_ports, tcp_udp_ratio, icmp_ratio]

    def _is_whitelisted(self, ip: str) -> bool:
        """Return True if IP belongs to a known benign range."""
        return any(ip.startswith(prefix) for prefix in WHITELIST_PREFIXES)

    def _severity_from_score(self, score: float) -> str:
        """Map isolation-forest score to human severity."""
        if score < -0.35:
            return 'High'
        if score < -0.25:
            return 'Medium'
        return 'Low'

    def _detect_anomalies(self):
        """
        Smarter ML anomaly detection:
          • Skips whitelisted cloud / LAN IPs
          • Requires minimum packet count before evaluating
          • Averages feature vectors over a short history (noise smoothing)
          • Only alerts when anomaly score is below a strict threshold
          • Enforces a per-IP cooldown window
          • Maps score magnitude to Low / Medium / High severity
        """
        if not self.ml_enabled or not self.ml_trained:
            return

        current_time = time.time()
        features_list: List[List[float]] = []
        ip_list: List[str] = []

        for ip, conn in list(self.connections.items()):
            # ── Skip whitelisted ranges ────────────────────────────
            if self._is_whitelisted(ip):
                continue

            # ── Build feature vector ───────────────────────────────
            fv = self._build_features(ip, conn, current_time)
            if fv is None:
                continue

            # ── Smooth using history (reduces one-off spikes) ──────
            self.ip_feature_history[ip].append(fv)
            if len(self.ip_feature_history[ip]) < 2:
                continue                        # Need at least 2 samples
            smoothed = list(np.mean(list(self.ip_feature_history[ip]), axis=0))

            features_list.append(smoothed)
            ip_list.append(ip)

            # Feed into training buffer (use raw, not smoothed)
            self.training_buffer.append(fv)

        if not features_list:
            return

        try:
            # Scale features (use the already-fitted scaler)
            X = self.scaler.transform(features_list)
        except Exception:
            return

        scores      = self.anomaly_detector.decision_function(X)
        predictions = self.anomaly_detector.predict(X)

        for i, (pred, score) in enumerate(zip(predictions, scores)):
            score = float(score)

            # ── Only alert on clearly anomalous samples ────────────
            if pred != -1 or score >= ANOMALY_SCORE_THRESHOLD:
                continue

            ip = ip_list[i]

            # ── Per-IP cooldown ────────────────────────────────────
            last_alert = self.anomaly_cooldown.get(ip, 0)
            if current_time - last_alert < ML_COOLDOWN_SECONDS:
                continue

            self.anomaly_cooldown[ip] = current_time

            fv       = features_list[i]
            severity = self._severity_from_score(score)

            self._create_alert(
                attack_type='Network Anomaly Detected',
                src_ip=ip,
                severity=severity,
                confidence=min(abs(score) * 2, 1.0),   # Scaled to 0-1
                details={
                    'anomaly_score':  round(score, 4),
                    'severity_reason': (
                        f"Score {score:.4f} below threshold {ANOMALY_SCORE_THRESHOLD}"
                    ),
                    'pps':            round(fv[0], 2),
                    'byte_rate_bps':  round(fv[1], 2),
                    'avg_pkt_size':   round(fv[2], 2),
                    'syn_ratio':      round(fv[4], 4),
                    'unique_ports':   int(fv[6]),
                    'description':    'ML model detected statistically significant deviation '
                                      'from baseline traffic behaviour'
                }
            )

    # ──────────────────────────────────────────────────────────────
    # ✨ IMPROVED ML training — fits scaler + model together
    # ──────────────────────────────────────────────────────────────
    def _train_anomaly_detector(self):
        """
        Train (or re-train) the anomaly detector.
          • First fit: waits for 200 samples (locked baseline).
          • Re-trains every 500 new samples to adapt to network changes
            without forgetting the original baseline.
        """
        buf_len = len(self.training_buffer)

        if buf_len < 200:
            return  # Not enough data yet

        if self.ml_trained and self.baseline_locked:
            # Periodically retrain to adapt — every ~500 new packets
            if buf_len % 500 != 0:
                return

        try:
            data = np.array(list(self.training_buffer))

            # Fit scaler on current data
            self.scaler.fit(data)
            X_scaled = self.scaler.transform(data)

            # Fit isolation forest
            self.anomaly_detector.fit(X_scaled)

            if not self.ml_trained:
                self.ml_trained       = True
                self.baseline_locked  = True
                print(f"🤖 ML Anomaly Detector trained on {buf_len} baseline samples "
                      f"(threshold={ANOMALY_SCORE_THRESHOLD})")
            else:
                print(f"🔄 ML model retrained on {buf_len} samples")

        except Exception as e:
            print(f"⚠ ML training failed: {e}")

    # ──────────────────────────────────────────────────────────────
    # Utilities
    # ──────────────────────────────────────────────────────────────
    def _cleanup_stale_connections(self):
        cutoff = datetime.now() - timedelta(minutes=5)
        to_remove = [ip for ip, c in self.connections.items() if c['last_seen'] < cutoff]
        for ip in to_remove:
            del self.connections[ip]
            self.ip_feature_history.pop(ip, None)
            self.anomaly_cooldown.pop(ip, None)

    def _create_alert(self, attack_type, src_ip, severity, confidence, details):
        alert = {
            'timestamp':   datetime.now().isoformat(),
            'attack_type': attack_type,
            'src_ip':      src_ip,
            'severity':    severity,
            'confidence':  confidence,
            'details':     self._make_json_serializable(details)
        }
        safe_alert = self._make_json_serializable(alert)
        self.alerts.append(safe_alert)
        self.alert_counts[attack_type] += 1
        self.stats['alerts_generated'] += 1
        self._print_alert(alert)
        self._save_alert(alert)

    def _print_alert(self, alert):
        colors = {'Critical': '\033[91m', 'High': '\033[93m',
                  'Medium': '\033[94m',   'Low': '\033[92m'}
        reset = '\033[0m'
        c = colors.get(alert['severity'], '')
        print(f"\n{c}{'='*60}")
        print(f"🚨 ALERT: {alert['attack_type']}")
        print(f"{'='*60}{reset}")
        print(f"Timestamp  : {alert['timestamp']}")
        print(f"Source IP  : {alert['src_ip']}")
        print(f"Severity   : {alert['severity']}")
        print(f"Confidence : {alert['confidence']*100:.1f}%")
        for k, v in alert['details'].items():
            print(f"  - {k}: {v}")
        print(f"{c}{'='*60}{reset}\n")

    def _save_alert(self, alert):
        try:
            alerts = []
            if os.path.exists(self.alert_file):
                with open(self.alert_file, 'r') as f:
                    alerts = json.load(f)
            alerts.append(alert)
            alerts = alerts[-1000:]
            with open(self.alert_file, 'w') as f:
                json.dump(alerts, f, indent=2, default=str)
        except Exception as e:
            print(f"⚠ Error saving alert: {e}")

    def _make_json_serializable(self, obj):
        if isinstance(obj, dict):
            return {str(k): self._make_json_serializable(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [self._make_json_serializable(v) for v in obj]
        if isinstance(obj, set):
            return list(obj)
        if isinstance(obj, datetime):
            return obj.isoformat()
        if isinstance(obj, (np.integer, np.floating)):
            return float(obj)
        if isinstance(obj, np.ndarray):
            return obj.tolist()
        return obj

    def _print_realtime_stats(self):
        uptime = (datetime.now() - self.stats['start_time']).total_seconds()
        pps    = self.stats['total_packets'] / max(uptime, 1)
        print(f"\r📊 Packets: {self.stats['total_packets']:,} | "
              f"Rate: {pps:.1f} pps | "
              f"IPs: {self.stats['unique_ips']} | "
              f"Alerts: {self.stats['alerts_generated']}", end='', flush=True)

    def _print_final_statistics(self):
        uptime = (datetime.now() - self.stats['start_time']).total_seconds()
        print(f"""
╔══════════════════════════════════════════════════════════╗
║                  Final Statistics                        ║
╠══════════════════════════════════════════════════════════╣
  Runtime      : {uptime/60:.1f} minutes
  Total Packets: {self.stats['total_packets']:,}
  Total Bytes  : {self.stats['total_bytes']:,}
  TCP          : {self.stats['tcp_packets']:,}
  UDP          : {self.stats['udp_packets']:,}
  ICMP         : {self.stats['icmp_packets']:,}
  Unique IPs   : {self.stats['unique_ips']}
  Alerts       : {self.stats['alerts_generated']}
╠══════════════════════════════════════════════════════════╣
  Alert Breakdown:""")
        for t, c in sorted(self.alert_counts.items(), key=lambda x: x[1], reverse=True):
            print(f"    {t:40s} {c:6d}")
        print("╚══════════════════════════════════════════════════════════╝")

    def _identify_services(self, ports):
        smap = {22:'SSH',21:'FTP',23:'Telnet',25:'SMTP',80:'HTTP',
                443:'HTTPS',3306:'MySQL',5432:'PostgreSQL',3389:'RDP',
                1433:'MSSQL',27017:'MongoDB'}
        return ', '.join(smap.get(p, f'Port {p}') for p in ports)


# ──────────────────────────────────────────────────────────────
def main():
    import argparse
    parser = argparse.ArgumentParser(description='Standalone Network IDS')
    parser.add_argument('-i', '--interface')
    parser.add_argument('-o', '--output', default='network_alerts.json')
    args = parser.parse_args()

    ids = NetworkIDS(interface=args.interface, alert_file=args.output)

    if ids.start():
        try:
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