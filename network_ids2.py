"""
Standalone Network Intrusion Detection System
With PCAP Storage + ML-based Analysis on PCAP data
"""

import threading
import time
from datetime import datetime, timedelta
from collections import defaultdict, deque
from typing import Dict, List
import json
import os
import logging
from logging.handlers import RotatingFileHandler

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, wrpcap, rdpcap, PcapWriter
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("❌ Scapy not installed. Install with: pip install scapy")
    exit(1)

import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline


# ──────────────────────────────────────────────
# PCAP Manager – handles rolling PCAP file writes
# ──────────────────────────────────────────────
class PCAPManager:
    """
    Writes live packets to rotating PCAP files.

    Layout on disk:
        pcap_dir/
            session_YYYYMMDD_HHMMSS/
                capture_001.pcap   (up to max_packets_per_file packets each)
                capture_002.pcap
                ...
    """

    def __init__(self, pcap_dir: str = "pcap_captures", max_packets_per_file: int = 10_000):
        self.pcap_dir = pcap_dir
        self.max_packets_per_file = max_packets_per_file

        # Create session sub-folder
        session_name = f"session_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        self.session_dir = os.path.join(pcap_dir, session_name)
        os.makedirs(self.session_dir, exist_ok=True)

        self._lock = threading.Lock()
        self._file_index = 1
        self._packet_buffer: List = []
        self._current_file = self._new_filepath()

        print(f"💾 PCAP Manager ready → {self.session_dir}")

    # ── public API ──────────────────────────────
    def write_packet(self, packet):
        """Buffer a packet; flush to disk when buffer is full."""
        with self._lock:
            self._packet_buffer.append(packet)
            if len(self._packet_buffer) >= self.max_packets_per_file:
                self._flush()

    def flush_all(self):
        """Force-flush remaining buffered packets on shutdown."""
        with self._lock:
            if self._packet_buffer:
                self._flush()

    def load_recent_pcap(self, n_files: int = 3) -> List:
        """
        Load the N most-recently written PCAP files and return
        all packets as a flat list (used by the ML analyser).
        """
        pcap_files = sorted([
            os.path.join(self.session_dir, f)
            for f in os.listdir(self.session_dir)
            if f.endswith(".pcap")
        ])

        packets = []
        for fpath in pcap_files[-n_files:]:
            try:
                packets.extend(rdpcap(fpath))
            except Exception as e:
                print(f"⚠ Could not read {fpath}: {e}")
        return packets

    def list_files(self) -> List[str]:
        return sorted([
            os.path.join(self.session_dir, f)
            for f in os.listdir(self.session_dir)
            if f.endswith(".pcap")
        ])

    # ── private helpers ──────────────────────────
    def _flush(self):
        wrpcap(self._current_file, self._packet_buffer)
        print(f"\n💾 Saved {len(self._packet_buffer):,} packets → {os.path.basename(self._current_file)}")
        self._packet_buffer = []
        self._file_index += 1
        self._current_file = self._new_filepath()

    def _new_filepath(self) -> str:
        return os.path.join(self.session_dir, f"capture_{self._file_index:03d}.pcap")


# ──────────────────────────────────────────────
# PCAP Feature Extractor
# ──────────────────────────────────────────────
class PCAPFeatureExtractor:
    """
    Reads a list of Scapy packets and produces a 2-D numpy feature
    matrix where each row represents one source-IP flow.

    Features (per flow):
        0  pkt_count          total packets
        1  byte_total         total bytes
        2  avg_pkt_size       mean packet size
        3  std_pkt_size       std-dev of packet sizes
        4  duration           seconds from first to last packet
        5  pps                packets per second
        6  bps                bytes per second
        7  tcp_ratio          TCP / total
        8  udp_ratio          UDP / total
        9  icmp_ratio         ICMP / total
        10 syn_ratio          SYN / total TCP
        11 rst_ratio          RST / total TCP
        12 fin_ratio          FIN / total TCP
        13 unique_dst_ports   number of distinct destination ports
        14 unique_dst_ips     number of distinct destination IPs
    """

    FEATURE_NAMES = [
        "pkt_count", "byte_total", "avg_pkt_size", "std_pkt_size",
        "duration", "pps", "bps",
        "tcp_ratio", "udp_ratio", "icmp_ratio",
        "syn_ratio", "rst_ratio", "fin_ratio",
        "unique_dst_ports", "unique_dst_ips"
    ]

    def extract(self, packets: List) -> (np.ndarray, List[str]):
        """
        Returns:
            features  – shape (n_flows, 15)  float32 array
            src_ips   – list of source IPs (one per row)
        """
        flows: Dict[str, dict] = {}

        for pkt in packets:
            if IP not in pkt:
                continue

            src = pkt[IP].src
            if src not in flows:
                flows[src] = {
                    "sizes": [], "times": [],
                    "tcp": 0, "udp": 0, "icmp": 0,
                    "syn": 0, "rst": 0, "fin": 0,
                    "dst_ports": set(), "dst_ips": set()
                }

            f = flows[src]
            f["sizes"].append(len(pkt))
            f["times"].append(float(pkt.time))
            f["dst_ips"].add(pkt[IP].dst)

            if TCP in pkt:
                f["tcp"] += 1
                flags = pkt[TCP].flags
                if flags & 0x02: f["syn"] += 1
                if flags & 0x04: f["rst"] += 1
                if flags & 0x01: f["fin"] += 1
                f["dst_ports"].add(pkt[TCP].dport)
            elif UDP in pkt:
                f["udp"] += 1
                f["dst_ports"].add(pkt[UDP].dport)
            elif ICMP in pkt:
                f["icmp"] += 1

        if not flows:
            return np.empty((0, 15), dtype=np.float32), []

        rows, ips = [], []
        for src_ip, f in flows.items():
            n = len(f["sizes"])
            dur = max(f["times"][-1] - f["times"][0], 1e-6)
            total_bytes = sum(f["sizes"])
            tcp_n = max(f["tcp"], 1)

            rows.append([
                n,
                total_bytes,
                np.mean(f["sizes"]),
                np.std(f["sizes"]) if n > 1 else 0.0,
                dur,
                n / dur,
                total_bytes / dur,
                f["tcp"] / n,
                f["udp"] / n,
                f["icmp"] / n,
                f["syn"] / tcp_n,
                f["rst"] / tcp_n,
                f["fin"] / tcp_n,
                len(f["dst_ports"]),
                len(f["dst_ips"])
            ])
            ips.append(src_ip)

        return np.array(rows, dtype=np.float32), ips


# ──────────────────────────────────────────────
# PCAP ML Analyser
# ──────────────────────────────────────────────
class PCAPMLAnalyser:
    """
    Trains an IsolationForest on PCAP-derived features and
    classifies new flows as normal / anomalous.

    Also provides a rule-based labeller so you can see *why*
    a flow was flagged (port scan, SYN flood, etc.).
    """

    def __init__(self):
        self.extractor = PCAPFeatureExtractor()
        self.pipeline = Pipeline([
            ("scaler", StandardScaler()),
            ("isoforest", IsolationForest(
                n_estimators=200,
                contamination=0.05,
                random_state=42
            ))
        ])
        self.trained = False
        self._training_data: List[np.ndarray] = []

    # ── training ────────────────────────────────
    def train_on_pcap(self, packets: List) -> bool:
        """Extract features from packets and (re-)fit the model."""
        X, _ = self.extractor.extract(packets)
        if len(X) < 20:
            print(f"⚠ Only {len(X)} flows – need ≥20 to train. Skipping.")
            return False

        self._training_data.append(X)
        X_all = np.vstack(self._training_data)

        self.pipeline.fit(X_all)
        self.trained = True
        print(f"🤖 PCAP ML model trained on {len(X_all)} flows")
        return True

    # ── inference ───────────────────────────────
    def analyse(self, packets: List) -> List[Dict]:
        """
        Analyse a packet list and return a list of anomaly dicts.
        Works even before the model is trained (rule-based only).
        """
        X, ips = self.extractor.extract(packets)
        if len(X) == 0:
            return []

        results = []

        # ML scores (if trained)
        if self.trained:
            scores = self.pipeline.decision_function(X)
            preds  = self.pipeline.predict(X)           # -1 = anomaly
        else:
            scores = np.zeros(len(X))
            preds  = np.ones(len(X))

        for i, ip in enumerate(ips):
            row = X[i]
            ml_flag   = (preds[i] == -1)
            rule_label = self._rule_label(row)
            is_anomaly = ml_flag or (rule_label != "Normal")

            if is_anomaly:
                results.append({
                    "src_ip":       ip,
                    "ml_anomaly":   bool(ml_flag),
                    "ml_score":     float(scores[i]),
                    "rule_label":   rule_label,
                    "features":     dict(zip(PCAPFeatureExtractor.FEATURE_NAMES, row.tolist()))
                })

        return results

    # ── rule engine ─────────────────────────────
    def _rule_label(self, row: np.ndarray) -> str:
        """Simple threshold rules to name the attack type."""
        feat = dict(zip(PCAPFeatureExtractor.FEATURE_NAMES, row.tolist()))

        if feat["pps"] > 1000:
            return "DDoS / High-Rate Flood"
        if feat["syn_ratio"] > 0.80 and feat["tcp_ratio"] > 0.50:
            return "SYN Flood"
        if feat["udp_ratio"] > 0.90 and feat["pps"] > 500:
            return "UDP Flood"
        if feat["icmp_ratio"] > 0.80 and feat["pps"] > 50:
            return "ICMP Flood"
        if feat["unique_dst_ports"] > 50:
            return "Port Scan"
        if feat["rst_ratio"] > 0.60:
            return "TCP RST Flood / Stealth Scan"
        return "Normal"


# ──────────────────────────────────────────────
# Main Network IDS  (original + PCAP extensions)
# ──────────────────────────────────────────────
class NetworkIDS:
    """
    Standalone Network Intrusion Detection System
    with live PCAP storage and periodic PCAP-based ML analysis.
    """

    def __init__(self,
                 interface:   str = None,
                 alert_file:  str = "network_alerts.json",
                 pcap_dir:    str = "pcap_captures",
                 pcap_interval: int = 60):
        """
        Args:
            interface      – NIC to monitor (auto-detect if None)
            alert_file     – JSON file for alerts
            pcap_dir       – root directory for PCAP files
            pcap_interval  – how often (seconds) to run PCAP ML analysis
        """
        self.interface    = interface or self._get_default_interface()
        self.alert_file   = alert_file
        self.pcap_interval = pcap_interval

        self.running         = False
        self.capture_thread  = None
        self.analysis_thread = None
        self.pcap_ml_thread  = None

        # ── Logging ─────────────────────────────────
        self.logger = logging.getLogger("NetworkIDS")
        self.logger.setLevel(logging.INFO)
        if not self.logger.handlers:
            h = RotatingFileHandler("network_ids.log", maxBytes=5*1024*1024, backupCount=5)
            h.setFormatter(logging.Formatter("%(asctime)s | %(levelname)s | %(message)s"))
            self.logger.addHandler(h)
        self.logger.info("Network IDS Initialized")

        # ── PCAP layer ───────────────────────────────
        self.pcap_manager  = PCAPManager(pcap_dir=pcap_dir)
        self.pcap_analyser = PCAPMLAnalyser()

        # ── Connection tracking ──────────────────────
        self.connections = defaultdict(lambda: {
            'packet_count': 0, 'syn_count': 0, 'ack_count': 0,
            'fin_count': 0, 'rst_count': 0, 'udp_count': 0,
            'icmp_count': 0, 'tcp_count': 0, 'bytes_sent': 0,
            'ports_accessed': set(),
            'first_seen': datetime.now(), 'last_seen': datetime.now(),
            'packet_timestamps': deque(maxlen=200),
            'packet_sizes': deque(maxlen=200),
            'protocols': defaultdict(int)
        })

        # ── Thresholds ───────────────────────────────
        self.thresholds = {
            'ddos_pps': 1000, 'ddos_connections': 100,
            'syn_flood_ratio': 3.0,
            'udp_flood_pps': 500, 'icmp_flood_pps': 10,
            'port_scan_ports': 15, 'port_scan_time': 10,
            'brute_force_attempts': 30,
            'brute_force_ports': {22, 21, 3389, 23, 3306, 5432},
            'anomaly_packet_size': 1500, 'anomaly_connection_rate': 50
        }

        # ── Stats & alerts ───────────────────────────
        self.stats = {
            'total_packets': 0, 'total_bytes': 0,
            'tcp_packets': 0, 'udp_packets': 0,
            'icmp_packets': 0, 'arp_packets': 0, 'other_packets': 0,
            'unique_ips': 0, 'alerts_generated': 0,
            'start_time': datetime.now()
        }
        self.alerts       = deque(maxlen=1000)
        self.alert_counts = defaultdict(int)

        # ── Live ML anomaly detector ─────────────────
        self.anomaly_detector = IsolationForest(
            contamination=0.1, random_state=42, n_estimators=100)
        self.ml_trained     = False
        self.training_buffer = deque(maxlen=500)
        self.ml_enabled     = True
        self.anomaly_cooldown: Dict[str, float] = {}

        print(f"""
╔══════════════════════════════════════════════════════════╗
║       Network IDS  •  PCAP + ML Edition                  ║
╠══════════════════════════════════════════════════════════╣
║  Interface  : {self.interface:43s} ║
║  Alert File : {alert_file:43s} ║
║  PCAP Dir   : {pcap_dir:43s} ║
║  PCAP ML    : every {pcap_interval}s                              ║
╚══════════════════════════════════════════════════════════╝
        """)

    # ════════════════════════════════════════════
    # Start / Stop
    # ════════════════════════════════════════════
    def start(self):
        if not SCAPY_AVAILABLE:
            print("❌ Cannot start: Scapy not installed")
            return False
        if self.running:
            print("⚠ Already running")
            return True

        print("\n🚀 Starting Network IDS …")
        self.logger.info("IDS Started")
        self.running = True

        self.capture_thread  = threading.Thread(target=self._packet_capture,  daemon=True)
        self.analysis_thread = threading.Thread(target=self._analysis_loop,   daemon=True)
        self.pcap_ml_thread  = threading.Thread(target=self._pcap_ml_loop,    daemon=True)

        self.capture_thread.start()
        self.analysis_thread.start()
        self.pcap_ml_thread.start()

        print(f"✓ Monitoring  : {self.interface}")
        print(f"✓ Alerts file : {self.alert_file}")
        print(f"✓ PCAP folder : {self.pcap_manager.session_dir}")
        print("✓ Press Ctrl+C to stop\n")
        return True

    def stop(self):
        print("\n🛑 Stopping Network IDS …")
        self.running = False
        self.logger.info("IDS Stopped")

        self.pcap_manager.flush_all()   # Save remaining buffered packets

        for t in (self.capture_thread, self.analysis_thread, self.pcap_ml_thread):
            if t:
                t.join(timeout=5)

        self._print_final_statistics()
        print("✓ Network IDS stopped")

    # ════════════════════════════════════════════
    # Packet Capture
    # ════════════════════════════════════════════
    def _packet_capture(self):
        try:
            print(f"📡 Capturing on {self.interface} …")
            sniff(
                iface=self.interface,
                prn=self._process_packet,
                store=False,
                stop_filter=lambda x: not self.running
            )
        except PermissionError:
            print("\n❌ Permission denied! Run with: sudo python3 network_ids_pcap.py")
            self.running = False
        except Exception as e:
            print(f"❌ Capture error: {e}")
            self.running = False

    def _process_packet(self, packet):
        try:
            self.stats['total_packets'] += 1

            # ── Write to PCAP ──────────────────────
            self.pcap_manager.write_packet(packet)

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
        src_ip   = ip_layer.src
        conn     = self.connections[src_ip]

        conn['packet_count']   += 1
        conn['last_seen']       = datetime.now()
        conn['packet_timestamps'].append(time.time())

        pkt_size = len(packet)
        conn['bytes_sent']    += pkt_size
        conn['packet_sizes'].append(pkt_size)
        self.stats['total_bytes'] += pkt_size

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
        tcp  = packet[TCP]
        conn = self.connections[src_ip]
        conn['ports_accessed'].add(tcp.dport)
        flags = tcp.flags
        if flags & 0x02: conn['syn_count'] += 1
        if flags & 0x10: conn['ack_count'] += 1
        if flags & 0x01: conn['fin_count'] += 1
        if flags & 0x04: conn['rst_count'] += 1

    # ════════════════════════════════════════════
    # Real-time Analysis Loop
    # ════════════════════════════════════════════
    def _analysis_loop(self):
        print("🔍 Real-time analysis engine started\n")
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

    # ════════════════════════════════════════════
    # PCAP ML Loop  ← NEW
    # ════════════════════════════════════════════
    def _pcap_ml_loop(self):
        """
        Every `pcap_interval` seconds:
          1. Load the most recent PCAP files
          2. (Re-)train the PCAP ML model on that data
          3. Run inference and raise alerts for anomalous flows
        """
        print(f"🧠 PCAP ML engine started (interval={self.pcap_interval}s)\n")
        time.sleep(self.pcap_interval)  # Wait for initial capture data

        while self.running:
            try:
                self._run_pcap_ml_analysis()
            except Exception as e:
                print(f"PCAP ML error: {e}")
            time.sleep(self.pcap_interval)

        # Final analysis on shutdown
        self._run_pcap_ml_analysis()

    def _run_pcap_ml_analysis(self):
        """Load PCAP files, train, analyse, and emit alerts."""
        pcap_files = self.pcap_manager.list_files()
        if not pcap_files:
            return

        print(f"\n📂 PCAP ML: Loading {min(3, len(pcap_files))} recent file(s) …")
        packets = self.pcap_manager.load_recent_pcap(n_files=3)

        if not packets:
            print("📂 PCAP ML: No packets loaded.")
            return

        print(f"📂 PCAP ML: {len(packets):,} packets loaded → extracting features …")

        # Train / retrain
        self.pcap_analyser.train_on_pcap(packets)

        # Analyse
        anomalies = self.pcap_analyser.analyse(packets)

        if not anomalies:
            print("✅ PCAP ML: No anomalies detected in recent traffic.")
            return

        print(f"🚨 PCAP ML: {len(anomalies)} anomalous flow(s) found.")
        for a in anomalies:
            self._create_alert(
                attack_type=f"PCAP-ML: {a['rule_label']}",
                src_ip=a['src_ip'],
                severity='High' if a['ml_anomaly'] else 'Medium',
                confidence=max(0.0, min(1.0, abs(a['ml_score']) if a['ml_anomaly'] else 0.75)),
                details={
                    'ml_anomaly':  a['ml_anomaly'],
                    'ml_score':    round(a['ml_score'], 4),
                    'rule_label':  a['rule_label'],
                    'pps':         round(a['features'].get('pps', 0), 2),
                    'unique_ports':int(a['features'].get('unique_dst_ports', 0)),
                    'syn_ratio':   round(a['features'].get('syn_ratio', 0), 3),
                    'description': 'Detected via PCAP feature extraction + IsolationForest'
                }
            )

    # ════════════════════════════════════════════
    # Real-time Detection Methods (unchanged)
    # ════════════════════════════════════════════
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
                        details={'packets_per_second': f"{pps:.1f}",
                                 'total_packets': conn['packet_count'],
                                 'description': 'Abnormally high packet rate'})

    def _detect_syn_flood(self):
        for ip, conn in list(self.connections.items()):
            if conn['syn_count'] > 50 and conn['ack_count'] > 0:
                ratio = conn['syn_count'] / max(conn['ack_count'], 1)
                if ratio > self.thresholds['syn_flood_ratio']:
                    self._create_alert(
                        attack_type='SYN Flood Attack', src_ip=ip,
                        severity='Critical', confidence=0.96,
                        details={'syn_packets': conn['syn_count'],
                                 'ack_packets': conn['ack_count'],
                                 'syn_ack_ratio': f"{ratio:.2f}",
                                 'description': 'Half-open TCP connections – SYN flood'})
                    conn['syn_count'] = 0; conn['ack_count'] = 0

    def _detect_udp_flood(self):
        for ip, conn in list(self.connections.items()):
            if conn['udp_count'] > self.thresholds['udp_flood_pps']:
                self._create_alert(
                    attack_type='UDP Flood Attack', src_ip=ip,
                    severity='High', confidence=0.92,
                    details={'udp_packets': conn['udp_count'],
                             'description': 'Excessive UDP traffic'})
                conn['udp_count'] = 0

    def _detect_icmp_flood(self):
        for ip, conn in list(self.connections.items()):
            if conn['icmp_count'] > self.thresholds['icmp_flood_pps']:
                self._create_alert(
                    attack_type='ICMP Flood (Ping Flood)', src_ip=ip,
                    severity='Medium', confidence=0.90,
                    details={'icmp_packets': conn['icmp_count'],
                             'description': 'Excessive ICMP echo requests'})
                conn['icmp_count'] = 0

    def _detect_port_scans(self):
        now = datetime.now()
        for ip, conn in list(self.connections.items()):
            diff = (now - conn['first_seen']).total_seconds()
            if diff < self.thresholds['port_scan_time']:
                ports = len(conn['ports_accessed'])
                if ports >= self.thresholds['port_scan_ports']:
                    self._create_alert(
                        attack_type='Port Scan Detected', src_ip=ip,
                        severity='High', confidence=0.93,
                        details={'ports_scanned': ports,
                                 'sample_ports': list(conn['ports_accessed'])[:15],
                                 'scan_duration': f"{diff:.1f}s",
                                 'description': f'Scanned {ports} ports in {diff:.1f}s'})
                    conn['ports_accessed'].clear()
                    conn['first_seen'] = datetime.now()

    def _detect_brute_force(self):
        now = time.time()
        for ip, conn in list(self.connections.items()):
            sensitive = conn['ports_accessed'].intersection(self.thresholds['brute_force_ports'])
            if sensitive:
                recent = [t for t in conn['packet_timestamps'] if t > now - 60]
                if len(recent) > self.thresholds['brute_force_attempts']:
                    self._create_alert(
                        attack_type='Brute Force Attack', src_ip=ip,
                        severity='High', confidence=0.88,
                        details={'connection_attempts': len(recent),
                                 'target_ports': list(sensitive),
                                 'services': self._identify_services(sensitive),
                                 'description': 'Repeated authentication attempts'})

    def _detect_anomalies(self):
        if not self.ml_enabled:
            return
        features_list, ip_list = [], []
        now = time.time()

        for ip, conn in list(self.connections.items()):
            if conn['packet_count'] < 100:
                continue
            dur  = max(now - conn['packet_timestamps'][0], 1)
            pps  = conn['packet_count'] / dur
            bps  = conn['bytes_sent'] / dur
            avg  = np.mean(conn['packet_sizes']) if conn['packet_sizes'] else 0
            std  = np.std(conn['packet_sizes'])  if len(conn['packet_sizes']) > 1 else 0
            syn  = conn['syn_count'] / max(conn['packet_count'], 1)
            upts = len(conn['ports_accessed'])
            tu   = conn['tcp_count'] / max(conn['udp_count'], 1)
            features_list.append([pps, bps, avg, std, syn, upts, tu])
            ip_list.append(ip)
            self.training_buffer.append([pps, bps, avg, std, syn, upts, tu])

        if self.ml_trained and features_list:
            scores  = self.anomaly_detector.decision_function(features_list)
            preds   = self.anomaly_detector.predict(features_list)
            for i, pred in enumerate(preds):
                if pred == -1:
                    ip = ip_list[i]
                    if now - self.anomaly_cooldown.get(ip, 0) < 60:
                        continue
                    self.anomaly_cooldown[ip] = now
                    self._create_alert(
                        attack_type='Network Anomaly (Live ML)',
                        src_ip=ip, severity='Medium',
                        confidence=abs(float(scores[i])),
                        details={'anomaly_score': float(scores[i]),
                                 'pps': round(features_list[i][0], 2),
                                 'description': 'Live IsolationForest flagged abnormal traffic'})

    def _train_anomaly_detector(self):
        if not self.ml_trained and len(self.training_buffer) >= 100:
            try:
                self.anomaly_detector.fit(list(self.training_buffer))
                self.ml_trained = True
                print("🤖 Live ML Anomaly Detector trained on baseline traffic")
            except Exception as e:
                print(f"⚠ ML training failed: {e}")

    # ════════════════════════════════════════════
    # Helpers
    # ════════════════════════════════════════════
    def _cleanup_stale_connections(self):
        cutoff = datetime.now() - timedelta(minutes=5)
        stale  = [ip for ip, c in self.connections.items() if c['last_seen'] < cutoff]
        for ip in stale:
            del self.connections[ip]

    def _create_alert(self, attack_type, src_ip, severity, confidence, details):
        alert = {
            'timestamp':   datetime.now().isoformat(),
            'attack_type': attack_type,
            'src_ip':      src_ip,
            'severity':    severity,
            'confidence':  confidence,
            'details':     self._make_json_serializable(details)
        }
        safe = self._make_json_serializable(alert)
        self.alerts.append(safe)
        self.alert_counts[attack_type] += 1
        self.stats['alerts_generated'] += 1
        self._print_alert(alert)
        self._save_alert(safe)

    def _print_alert(self, alert):
        colors = {'Critical': '\033[91m', 'High': '\033[93m',
                  'Medium': '\033[94m',   'Low': '\033[92m'}
        R = '\033[0m'
        c = colors.get(alert['severity'], '')
        print(f"\n{c}{'='*60}")
        print(f"🚨 ALERT: {alert['attack_type']}")
        print(f"{'='*60}{R}")
        print(f"  Time      : {alert['timestamp']}")
        print(f"  Source IP : {alert['src_ip']}")
        print(f"  Severity  : {alert['severity']}")
        print(f"  Confidence: {alert['confidence']*100:.1f}%")
        for k, v in alert['details'].items():
            print(f"  {k}: {v}")
        print(f"{c}{'='*60}{R}\n")

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
        if isinstance(obj, (list, tuple)):
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
        up  = (datetime.now() - self.stats['start_time']).total_seconds()
        pps = self.stats['total_packets'] / max(up, 1)
        pcap_files = len(self.pcap_manager.list_files())
        print(f"\r📊 Pkts:{self.stats['total_packets']:,} | {pps:.0f}pps | "
              f"IPs:{self.stats['unique_ips']} | Alerts:{self.stats['alerts_generated']} | "
              f"PCAPs:{pcap_files}", end='', flush=True)

    def _print_final_statistics(self):
        up = (datetime.now() - self.stats['start_time']).total_seconds()
        print(f"""
╔══════════════════════════════════════════════════════════╗
║                   Final Statistics                       ║
╠══════════════════════════════════════════════════════════╣
  Runtime       : {up/60:.1f} min
  Total Packets : {self.stats['total_packets']:,}
  Total Bytes   : {self.stats['total_bytes']:,}
  TCP / UDP / ICMP : {self.stats['tcp_packets']:,} / {self.stats['udp_packets']:,} / {self.stats['icmp_packets']:,}
  Unique IPs    : {self.stats['unique_ips']}
  Alerts        : {self.stats['alerts_generated']}
  PCAP Files    : {len(self.pcap_manager.list_files())}
╠══════════════════════════════════════════════════════════╣
  Alert Breakdown:""")
        for at, cnt in sorted(self.alert_counts.items(), key=lambda x: -x[1]):
            print(f"    {at:45s} {cnt:5d}")
        print("╚══════════════════════════════════════════════════════════╝")

    def _identify_services(self, ports: set) -> str:
        svc = {22:'SSH',21:'FTP',23:'Telnet',25:'SMTP',80:'HTTP',
               443:'HTTPS',3306:'MySQL',5432:'PostgreSQL',3389:'RDP',
               1433:'MSSQL',27017:'MongoDB'}
        return ', '.join(svc.get(p, f'Port {p}') for p in ports)

    def _get_default_interface(self) -> str:
        from scapy.all import get_if_list, get_if_addr
        for iface in get_if_list():
            try:
                ip = get_if_addr(iface)
                if not ip or ip.startswith(("127.", "0.0.0.0", "169.254.")):
                    continue
                if ip.startswith(("192.168.", "10.", "172.")):
                    print(f"✓ Auto-selected: {iface} ({ip})")
                    return iface
            except Exception:
                continue
        raise RuntimeError("No suitable network interface found")


# ════════════════════════════════════════════════════════════
# CLI Entry Point
# ════════════════════════════════════════════════════════════
def main():
    import argparse

    parser = argparse.ArgumentParser(description='Network IDS with PCAP + ML')
    parser.add_argument('-i', '--interface', help='Network interface (auto if omitted)')
    parser.add_argument('-o', '--output',    default='network_alerts.json',
                        help='Alert JSON file')
    parser.add_argument('-p', '--pcap-dir',  default='pcap_captures',
                        help='Directory for PCAP files')
    parser.add_argument('--pcap-interval',   type=int, default=60,
                        help='Seconds between PCAP ML analyses (default 60)')
    # Offline PCAP analysis mode
    parser.add_argument('--analyse-pcap',    help='Analyse an existing PCAP file and exit')
    args = parser.parse_args()

    # ── Offline mode ──────────────────────────────
    if args.analyse_pcap:
        print(f"\n🔍 Offline PCAP analysis: {args.analyse_pcap}")
        from scapy.all import rdpcap
        pkts = rdpcap(args.analyse_pcap)
        print(f"   Loaded {len(pkts):,} packets")
        analyser = PCAPMLAnalyser()
        analyser.train_on_pcap(pkts)
        results = analyser.analyse(pkts)
        if results:
            print(f"\n🚨 {len(results)} anomalous flow(s):\n")
            for r in results:
                print(f"  IP: {r['src_ip']:18s}  label={r['rule_label']:30s}"
                      f"  ml={'YES' if r['ml_anomaly'] else 'no ':4s}"
                      f"  score={r['ml_score']:+.4f}")
        else:
            print("✅ No anomalies detected.")
        return

    # ── Live mode ─────────────────────────────────
    ids = NetworkIDS(
        interface=args.interface,
        alert_file=args.output,
        pcap_dir=args.pcap_dir,
        pcap_interval=args.pcap_interval
    )

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
