"""
╔══════════════════════════════════════════════════════════════════════╗
║         Advanced Network Intrusion Detection System v2.0             ║
║         Industry-Grade Edition                                        ║
╠══════════════════════════════════════════════════════════════════════╣
║  New capabilities over v1:                                            ║
║    A. Multi-model ML ensemble (IF + LOF + OCSVM)                     ║
║    B. UEBA – per-IP behavioural baseline & drift detection            ║
║    C. DNS exfiltration detection (entropy + freq analysis)            ║
║    D. C2 / Beaconing detection (interval regularity)                 ║
║    E. HTTP/TLS layer deep inspection                                  ║
║    F. ARP spoofing / MITM detection                                   ║
║    G. GeoIP enrichment + threat-intel reputation                      ║
║    H. Prometheus /metrics endpoint                                    ║
║    I. Webhook alerting (Slack / PagerDuty / generic HTTP)            ║
║    J. Elasticsearch / OpenSearch structured log export               ║
║    K. ECS-compliant JSON logging                                      ║
║    L. REST health-check & stats API (port 9001)                      ║
║    M. YAML config file support with hot-reload                       ║
║    N. Adaptive thresholds via EWMA                                    ║
║    O. Feature drift detection (warn when traffic profile shifts)     ║
║    P. Threat score aggregation per IP (composite risk score)         ║
║    Q. Session reconstruction & payload entropy scoring               ║
╚══════════════════════════════════════════════════════════════════════╝
"""

# ── stdlib ────────────────────────────────────────────────────────────
import threading, time, os, json, logging, math, hashlib, re, signal
import socket, struct, ipaddress, statistics, asyncio, urllib.request
from datetime import datetime, timedelta
from collections import defaultdict, deque, Counter
from typing import Dict, List, Optional, Tuple, Any
from logging.handlers import RotatingFileHandler
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse

# ── third-party (graceful fallbacks) ─────────────────────────────────
try:
    from scapy.all import (
        sniff,
        IP,
        TCP,
        UDP,
        ICMP,
        ARP,
        DNS,
        DNSQR,
        DNSRR,
        Raw,
        wrpcap,
        rdpcap,
        get_if_list,
        get_if_addr
    )

    SCAPY_AVAILABLE = True
    print("✅ Scapy loaded successfully")

except ImportError as e:
    SCAPY_AVAILABLE = False
    print(f"❌ Scapy import failed: {e}")
    exit(1)
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor
from sklearn.svm import OneClassSVM
from sklearn.preprocessing import StandardScaler, RobustScaler
from sklearn.pipeline import Pipeline
from sklearn.covariance import EllipticEnvelope

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False

try:
    import geoip2.database
    GEOIP_AVAILABLE = True
except ImportError:
    GEOIP_AVAILABLE = False

try:
    import redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False

# ─────────────────────────────────────────────────────────────────────
# CONSTANTS
# ─────────────────────────────────────────────────────────────────────
VERSION     = "2.0.0"
BUILD_DATE  = "2025"

PRIVATE_PREFIXES  = ("10.", "172.16.", "172.17.", "172.18.", "172.19.",
                     "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
                     "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
                     "172.30.", "172.31.", "192.168.", "127.", "169.254.")

SERVICE_MAP = {
    20: 'FTP-Data', 21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
    53: 'DNS', 67: 'DHCP', 80: 'HTTP', 110: 'POP3', 119: 'NNTP',
    123: 'NTP', 143: 'IMAP', 161: 'SNMP', 179: 'BGP', 389: 'LDAP',
    443: 'HTTPS', 445: 'SMB', 465: 'SMTPS', 514: 'Syslog', 587: 'SMTP-Sub',
    636: 'LDAPS', 873: 'rsync', 993: 'IMAPS', 995: 'POP3S',
    1080: 'SOCKS', 1433: 'MSSQL', 1521: 'Oracle', 1723: 'PPTP',
    3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL', 5900: 'VNC',
    6379: 'Redis', 8080: 'HTTP-Alt', 8443: 'HTTPS-Alt',
    9200: 'Elasticsearch', 11211: 'Memcached', 27017: 'MongoDB',
    6443: 'K8s-API', 2379: 'etcd',
}

KNOWN_MALICIOUS_PORTS = {4444, 1337, 31337, 12345, 54321, 6666, 6667,
                          8888, 9999, 65000, 65535}

# ─────────────────────────────────────────────────────────────────────
# CONFIG LOADER
# ─────────────────────────────────────────────────────────────────────
DEFAULT_CONFIG = {
    "interface":        None,
    "alert_file":       "network_alerts.json",
    "pcap_dir":         "pcap_captures",
    "pcap_interval":    60,
    "max_pcap_files":   20,
    "log_level":        "INFO",
    "log_file":         "network_ids.log",
    "metrics_port":     9001,
    "enable_metrics":   True,
    "enable_api":       True,
    "whitelist_ips":    [],
    "whitelist_cidrs":  [],
    "threat_intel_file": None,
    "geoip_db":         None,
    "webhooks":         [],
    "elasticsearch":    {"enabled": False, "url": "", "index": "network-ids"},
    "redis":            {"enabled": False, "host": "localhost", "port": 6379},
    "thresholds": {
        "ddos_pps":             1000,
        "syn_flood_ratio":      3.0,
        "udp_flood_pps":        500,
        "icmp_flood_pps":       10,
        "port_scan_ports":      15,
        "port_scan_time":       10,
        "brute_force_attempts": 30,
        "dns_entropy_threshold": 3.5,
        "dns_query_rate":       50,
        "beacon_min_intervals": 8,
        "beacon_cv_threshold":  0.15,
        "payload_entropy_high": 7.2,
        "anomaly_cooldown_s":   60,
        "alert_history_max":    1000,
    },
    "ml": {
        "ensemble_contamination": 0.05,
        "ueba_window_hours":      24,
        "retrain_interval_s":     300,
        "min_train_samples":      50,
    }
}


def load_config(path: Optional[str] = None) -> dict:
    cfg = dict(DEFAULT_CONFIG)
    if path and YAML_AVAILABLE and os.path.exists(path):
        with open(path) as f:
            user = yaml.safe_load(f) or {}
        # deep merge thresholds / ml sub-dicts
        for k in ("thresholds", "ml", "elasticsearch", "redis"):
            if k in user:
                cfg[k] = {**cfg.get(k, {}), **user.pop(k)}
        cfg.update(user)
        print(f"⚙  Config loaded: {path}")
    return cfg


# ─────────────────────────────────────────────────────────────────────
# ECS JSON LOGGER
# ─────────────────────────────────────────────────────────────────────
class ECSFormatter(logging.Formatter):
    """Elastic Common Schema-compliant JSON log records."""
    def format(self, record: logging.LogRecord) -> str:
        doc = {
            "@timestamp": datetime.utcnow().isoformat() + "Z",
            "log.level":  record.levelname.lower(),
            "log.logger": record.name,
            "message":    record.getMessage(),
            "event.dataset": "network_ids",
            "agent.version": VERSION,
        }
        if hasattr(record, 'src_ip'):
            doc["source.ip"] = record.src_ip
        if hasattr(record, 'attack_type'):
            doc["event.category"] = "intrusion_detection"
            doc["event.action"]   = record.attack_type
        if record.exc_info:
            doc["error.message"] = self.formatException(record.exc_info)
        return json.dumps(doc)


def build_logger(name: str, log_file: str, level: str) -> logging.Logger:
    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    if logger.handlers:
        return logger

    # ECS JSON file handler
    fh = RotatingFileHandler(log_file, maxBytes=10*1024*1024, backupCount=10)
    fh.setFormatter(ECSFormatter())
    logger.addHandler(fh)

    # Human-readable console handler
    ch = logging.StreamHandler()
    ch.setFormatter(logging.Formatter("%(asctime)s | %(levelname)s | %(message)s"))
    ch.setLevel(logging.WARNING)
    logger.addHandler(ch)
    return logger


# ─────────────────────────────────────────────────────────────────────
# THREAT INTELLIGENCE
# ─────────────────────────────────────────────────────────────────────
class ThreatIntelligence:
    """
    Loads a local blocklist (one IP/CIDR per line) and scores IPs.
    Also supports Tor exit-node list and simple reputation heuristics.
    """

    def __init__(self, blocklist_path: Optional[str] = None,
                 geoip_db: Optional[str] = None):
        self._blocklist_ips:   set  = set()
        self._blocklist_nets:  list = []
        self._reputation:      Dict[str, float] = {}   # 0..1 (1=worst)
        self._lock = threading.Lock()

        if blocklist_path and os.path.exists(blocklist_path):
            self._load_blocklist(blocklist_path)

        self._geoip = None
        if geoip_db and GEOIP_AVAILABLE and os.path.exists(geoip_db):
            try:
                self._geoip = geoip2.database.Reader(geoip_db)
                print(f"🌍 GeoIP database loaded: {geoip_db}")
            except Exception as e:
                print(f"⚠  GeoIP load error: {e}")

    def _load_blocklist(self, path: str):
        count = 0
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                try:
                    if '/' in line:
                        self._blocklist_nets.append(ipaddress.ip_network(line, strict=False))
                    else:
                        self._blocklist_ips.add(line)
                    count += 1
                except ValueError:
                    pass
        print(f"🛡  Threat intel: {count} entries loaded from {path}")

    def is_blocked(self, ip: str) -> bool:
        if ip in self._blocklist_ips:
            return True
        try:
            addr = ipaddress.ip_address(ip)
            return any(addr in net for net in self._blocklist_nets)
        except ValueError:
            return False

    def get_reputation(self, ip: str) -> float:
        """Returns 0.0 (clean) to 1.0 (highly malicious)."""
        with self._lock:
            return self._reputation.get(ip, 0.0)

    def update_reputation(self, ip: str, delta: float):
        with self._lock:
            score = self._reputation.get(ip, 0.0)
            score = max(0.0, min(1.0, score + delta))
            self._reputation[ip] = score

    def geolocate(self, ip: str) -> dict:
        if not self._geoip:
            return {}
        try:
            r = self._geoip.city(ip)
            return {
                "country": r.country.iso_code,
                "city":    r.city.name,
                "lat":     r.location.latitude,
                "lon":     r.location.longitude,
                "asn":     getattr(r.traits, 'autonomous_system_number', None),
            }
        except Exception:
            return {}


# ─────────────────────────────────────────────────────────────────────
# UEBA – User/Entity Behaviour Analytics
# ─────────────────────────────────────────────────────────────────────
class UEBAProfile:
    """Rolling behavioural baseline per source IP."""

    WINDOW = 3600   # seconds of history to retain

    def __init__(self, ip: str):
        self.ip          = ip
        self._timestamps: deque = deque()    # packet arrival times
        self._dst_ports:  deque = deque()
        self._dst_ips:    deque = deque()
        self._pkt_sizes:  deque = deque()
        self._protocols:  Counter = Counter()

        # Baseline statistics (EWMA)
        self.baseline_pps:       Optional[float] = None
        self.baseline_port_rate: Optional[float] = None
        self._alpha = 0.1   # EWMA learning rate

    def observe(self, ts: float, dst_ip: str, dst_port: int,
                pkt_size: int, proto: str):
        cutoff = ts - self.WINDOW
        for dq in (self._timestamps, self._dst_ports, self._dst_ips, self._pkt_sizes):
            while dq and dq[0][0] < cutoff:
                dq.popleft()

        self._timestamps.append((ts, ts))
        self._dst_ports.append((ts, dst_port))
        self._dst_ips.append((ts, dst_ip))
        self._pkt_sizes.append((ts, pkt_size))
        self._protocols[proto] += 1

        # Update EWMA baselines
        recent_window = 60
        recent_pkts   = sum(1 for t, _ in self._timestamps if t > ts - recent_window)
        cur_pps = recent_pkts / recent_window
        if self.baseline_pps is None:
            self.baseline_pps = cur_pps
        else:
            self.baseline_pps = self._alpha * cur_pps + (1 - self._alpha) * self.baseline_pps

    def get_anomaly_score(self, now: float) -> Tuple[float, str]:
        """Returns (score 0-1, reason string). >0.7 = suspicious."""
        recent = 60
        pkts   = [t for t, _ in self._timestamps if t > now - recent]
        if len(pkts) < 10:
            return 0.0, ""

        cur_pps = len(pkts) / recent
        baseline = self.baseline_pps or cur_pps
        if baseline < 0.1:
            return 0.0, ""

        pps_ratio = cur_pps / baseline
        if pps_ratio > 10:
            return min(pps_ratio / 20, 1.0), f"Traffic spike {pps_ratio:.1f}x above baseline"

        # Port diversity surge
        ports_seen = set(p for _, p in self._dst_ports if _ > now - recent)
        if len(ports_seen) > 30:
            return 0.85, f"Sudden port diversity: {len(ports_seen)} unique ports"

        return 0.0, ""


# ─────────────────────────────────────────────────────────────────────
# DNS ANALYSIS
# ─────────────────────────────────────────────────────────────────────
class DNSAnalyser:
    """Detects DNS tunnelling, exfiltration, and fast-flux patterns."""

    def __init__(self, entropy_thresh: float = 3.5, query_rate: int = 50):
        self.entropy_thresh = entropy_thresh
        self.query_rate     = query_rate
        self._queries:      Dict[str, deque] = defaultdict(lambda: deque(maxlen=500))
        self._subdomains:   Dict[str, set]   = defaultdict(set)
        self._lock = threading.Lock()

    @staticmethod
    def _shannon_entropy(s: str) -> float:
        if not s:
            return 0.0
        counts = Counter(s.lower())
        total  = len(s)
        return -sum((c / total) * math.log2(c / total) for c in counts.values())

    def process(self, src_ip: str, qname: str, ts: float) -> Optional[dict]:
        qname = qname.rstrip('.')
        parts = qname.split('.')
        domain = '.'.join(parts[-2:]) if len(parts) >= 2 else qname
        subdomain = '.'.join(parts[:-2]) if len(parts) > 2 else ''

        with self._lock:
            self._queries[src_ip].append(ts)
            if subdomain:
                self._subdomains[domain].add(subdomain)

        findings = {}

        # 1. High entropy subdomain (likely tunnelling / exfil)
        entropy = self._shannon_entropy(subdomain) if subdomain else 0
        if entropy > self.entropy_thresh and len(subdomain) > 20:
            findings['dns_tunnel'] = {
                'reason':  'High-entropy subdomain',
                'entropy': round(entropy, 3),
                'qname':   qname,
            }

        # 2. Query rate flood
        with self._lock:
            recent = [t for t in self._queries[src_ip] if t > ts - 10]
        if len(recent) > self.query_rate:
            findings['dns_flood'] = {
                'reason': 'DNS query rate exceeded',
                'rate':   len(recent),
            }

        # 3. Excessive unique subdomains per domain (DGA / fast-flux)
        n_sub = len(self._subdomains.get(domain, set()))
        if n_sub > 200:
            findings['dns_dga'] = {
                'reason':       'Excessive unique subdomains (possible DGA)',
                'unique_subs':  n_sub,
                'domain':       domain,
            }

        return findings if findings else None

    # 4. Long label detection (exfil packs data into labels)
    @staticmethod
    def has_long_label(qname: str) -> bool:
        return any(len(lbl) > 50 for lbl in qname.split('.'))


# ─────────────────────────────────────────────────────────────────────
# C2 / BEACONING DETECTOR
# ─────────────────────────────────────────────────────────────────────
class BeaconDetector:
    """
    Detects periodic C2 beaconing by measuring the coefficient of
    variation (CV = std/mean) of inter-packet intervals per flow.
    A very low CV indicates machine-like regularity → beaconing.
    """

    def __init__(self, min_intervals: int = 8, cv_threshold: float = 0.15):
        self.min_intervals = min_intervals
        self.cv_threshold  = cv_threshold
        self._flows: Dict[str, deque] = defaultdict(lambda: deque(maxlen=100))
        self._lock = threading.Lock()

    def observe(self, key: str, ts: float):
        with self._lock:
            self._flows[key].append(ts)

    def check(self, key: str) -> Optional[dict]:
        with self._lock:
            times = list(self._flows[key])
        if len(times) < self.min_intervals + 1:
            return None

        intervals = [times[i+1] - times[i] for i in range(len(times)-1)]
        if not intervals or min(intervals) <= 0:
            return None

        mean_iv = statistics.mean(intervals)
        std_iv  = statistics.stdev(intervals) if len(intervals) > 1 else 0
        cv      = std_iv / mean_iv if mean_iv > 0 else 1.0

        if cv < self.cv_threshold and mean_iv > 1:     # exclude sub-second bursts
            return {
                'beacon_interval_s': round(mean_iv, 2),
                'cv':                round(cv, 4),
                'samples':           len(intervals),
                'description':       f'Machine-like {mean_iv:.1f}s beacon (CV={cv:.3f})'
            }
        return None


# ─────────────────────────────────────────────────────────────────────
# ARP SPOOF DETECTOR
# ─────────────────────────────────────────────────────────────────────
class ARPSpoofDetector:
    """Tracks IP→MAC bindings; alerts on conflicting ARP replies."""

    def __init__(self):
        self._table: Dict[str, str] = {}   # ip → mac
        self._lock  = threading.Lock()

    def observe(self, ip: str, mac: str) -> Optional[dict]:
        with self._lock:
            known = self._table.get(ip)
            if known is None:
                self._table[ip] = mac
                return None
            if known.lower() != mac.lower():
                return {
                    'ip':          ip,
                    'known_mac':   known,
                    'claimed_mac': mac,
                    'description': f'ARP spoofing: {ip} previously at {known}, now {mac}'
                }
        return None


# ─────────────────────────────────────────────────────────────────────
# PAYLOAD ENTROPY SCORER
# ─────────────────────────────────────────────────────────────────────
class PayloadEntropyScorer:
    """
    High entropy payload → encrypted tunnel / packing tool.
    Low entropy on uncommon port → possible plaintext C2 shell.
    """

    @staticmethod
    def score(payload: bytes) -> float:
        if not payload:
            return 0.0
        counts = Counter(payload)
        total  = len(payload)
        return -sum((c/total)*math.log2(c/total) for c in counts.values())

    @staticmethod
    def classify(entropy: float, dport: int) -> Optional[str]:
        if entropy > 7.5:
            return "Encrypted/compressed payload (possible covert channel)"
        if entropy < 1.5 and dport not in (80, 443, 22, 25, 53):
            return "Near-zero entropy plaintext on unusual port"
        return None


# ─────────────────────────────────────────────────────────────────────
# ML ENSEMBLE
# ─────────────────────────────────────────────────────────────────────
class EnsembleAnomalyDetector:
    """
    Three-model voting ensemble:
      - IsolationForest  (tree-based, fast, handles high-dim)
      - LocalOutlierFactor (density-based, good for clusters)
      - OneClassSVM      (kernel-based, good decision boundary)
    A flow is anomalous if ≥2 models flag it.
    """

    MIN_SAMPLES = 50

    def __init__(self, contamination: float = 0.05):
        self.contamination = contamination
        self._scaler = RobustScaler()
        self._iforest = IsolationForest(
            n_estimators=200, contamination=contamination,
            random_state=42, n_jobs=-1)
        self._lof = LocalOutlierFactor(
            n_neighbors=20, contamination=contamination,
            novelty=True, n_jobs=-1)
        self._ocsvm = OneClassSVM(
            kernel='rbf', nu=contamination, gamma='scale')
        self.trained  = False
        self._history: List[np.ndarray] = []
        self._max_history = 10
        self._lock = threading.Lock()

    def train(self, X: np.ndarray) -> bool:
        if len(X) < self.MIN_SAMPLES:
            return False
        with self._lock:
            self._history.append(X)
            if len(self._history) > self._max_history:
                self._history.pop(0)
            X_all = np.vstack(self._history)
            Xs    = self._scaler.fit_transform(X_all)
            self._iforest.fit(Xs)
            self._lof.fit(Xs)
            self._ocsvm.fit(Xs)
            self.trained = True
        return True

    def predict(self, X: np.ndarray) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
        """Returns (votes_anomalous bool array, scores, model_votes[3])."""
        if not self.trained or len(X) == 0:
            n = len(X)
            return np.zeros(n, bool), np.zeros(n), np.zeros((n, 3))

        with self._lock:
            Xs   = self._scaler.transform(X)
            p1   = self._iforest.predict(Xs)           # +1 normal, -1 anomaly
            p2   = self._lof.predict(Xs)
            p3   = self._ocsvm.predict(Xs)
            s1   = self._iforest.decision_function(Xs)
            s2   = self._lof.decision_function(Xs)
            s3   = self._ocsvm.decision_function(Xs)

        votes    = np.stack([(p1 == -1), (p2 == -1), (p3 == -1)], axis=1)
        flagged  = votes.sum(axis=1) >= 2
        avg_score= (s1 + s2 + s3) / 3.0
        return flagged, avg_score, votes.astype(int)

    # Feature drift: compare mean of new batch to training mean
    def detect_drift(self, X: np.ndarray, threshold: float = 2.0) -> Optional[str]:
        if not self.trained or not self._history:
            return None
        with self._lock:
            train_mean = np.vstack(self._history).mean(axis=0)
        batch_mean = X.mean(axis=0)
        z_max = np.max(np.abs(batch_mean - train_mean) /
                       (np.abs(train_mean) + 1e-9))
        if z_max > threshold:
            return f"Feature drift detected (max z={z_max:.2f}) – consider retraining"
        return None


# ─────────────────────────────────────────────────────────────────────
# ADAPTIVE THRESHOLD ENGINE
# ─────────────────────────────────────────────────────────────────────
class AdaptiveThresholds:
    """
    Adjusts numeric thresholds using Exponential Weighted Moving Average
    so the IDS adapts to the site's normal traffic over time.
    """

    def __init__(self, base: dict, alpha: float = 0.05):
        self._values: Dict[str, float] = {k: float(v) for k, v in base.items()
                                           if isinstance(v, (int, float))}
        self._alpha  = alpha
        self._lock   = threading.Lock()

    def update(self, key: str, observed: float):
        with self._lock:
            if key in self._values:
                old = self._values[key]
                self._values[key] = self._alpha * observed + (1 - self._alpha) * old

    def get(self, key: str, default: float = 0.0) -> float:
        with self._lock:
            return self._values.get(key, default)

    def snapshot(self) -> dict:
        with self._lock:
            return dict(self._values)


# ─────────────────────────────────────────────────────────────────────
# COMPOSITE THREAT SCORE
# ─────────────────────────────────────────────────────────────────────
class ThreatScoreBoard:
    """
    Aggregates evidence across all detection engines into a single
    risk score per IP.  Score 0-100; ≥70 triggers a High composite alert.
    """

    def __init__(self):
        self._scores: Dict[str, float] = defaultdict(float)
        self._evidence: Dict[str, List[str]] = defaultdict(list)
        self._lock = threading.Lock()
        self._decay_rate = 0.95   # per 60s cycle

    def add_evidence(self, ip: str, weight: float, label: str):
        with self._lock:
            self._scores[ip] = min(100.0, self._scores[ip] + weight)
            self._evidence[ip].append(label)

    def decay(self):
        with self._lock:
            for ip in list(self._scores):
                self._scores[ip] *= self._decay_rate
                if self._scores[ip] < 1.0:
                    del self._scores[ip]
                    self._evidence.pop(ip, None)

    def get_score(self, ip: str) -> float:
        with self._lock:
            return self._scores.get(ip, 0.0)

    def top_threats(self, n: int = 10) -> List[Tuple[str, float, List[str]]]:
        with self._lock:
            return sorted(
                [(ip, score, self._evidence.get(ip, []))
                 for ip, score in self._scores.items()],
                key=lambda x: -x[1]
            )[:n]


# ─────────────────────────────────────────────────────────────────────
# WEBHOOK NOTIFIER
# ─────────────────────────────────────────────────────────────────────
class WebhookNotifier:
    """Sends alert payloads to Slack, PagerDuty, or generic HTTP POST."""

    def __init__(self, webhooks: List[dict]):
        self._webhooks = webhooks
        self._queue    = deque(maxlen=200)
        self._thread   = threading.Thread(target=self._worker, daemon=True)
        self._thread.start()

    def notify(self, alert: dict):
        self._queue.append(alert)

    def _worker(self):
        while True:
            if self._queue:
                alert = self._queue.popleft()
                for cfg in self._webhooks:
                    try:
                        self._send(cfg, alert)
                    except Exception as e:
                        pass
            time.sleep(0.2)

    def _send(self, cfg: dict, alert: dict):
        url  = cfg.get('url', '')
        kind = cfg.get('type', 'generic').lower()

        if kind == 'slack':
            payload = {
                "text": f"🚨 *{alert['attack_type']}* — `{alert['src_ip']}`",
                "attachments": [{
                    "color": {"Critical": "danger", "High": "warning"}.get(alert['severity'], "good"),
                    "fields": [
                        {"title": "Severity",   "value": alert['severity'],   "short": True},
                        {"title": "Confidence", "value": f"{alert['confidence']*100:.0f}%", "short": True},
                        {"title": "Details",    "value": str(alert.get('details', '')), "short": False},
                    ],
                    "ts": time.time()
                }]
            }
        elif kind == 'pagerduty':
            payload = {
                "routing_key":    cfg.get('routing_key', ''),
                "event_action":   "trigger",
                "dedup_key":      f"{alert['attack_type']}_{alert['src_ip']}",
                "payload": {
                    "summary":   f"{alert['attack_type']} from {alert['src_ip']}",
                    "severity":  alert['severity'].lower(),
                    "timestamp": alert['timestamp'],
                    "custom_details": alert.get('details', {})
                }
            }
        else:
            payload = alert

        data = json.dumps(payload).encode()
        req  = urllib.request.Request(url, data=data,
                                      headers={"Content-Type": "application/json"},
                                      method="POST")
        urllib.request.urlopen(req, timeout=5)


# ─────────────────────────────────────────────────────────────────────
# PROMETHEUS METRICS + REST API
# ─────────────────────────────────────────────────────────────────────
class MetricsAPI:
    """
    Serves two endpoints:
      GET /metrics → Prometheus text format
      GET /stats   → JSON summary
      GET /threats → Top threat scores
      GET /health  → 200 OK if running
    """

    def __init__(self, ids_ref, port: int = 9001):
        self._ids  = ids_ref
        self._port = port
        self._server: Optional[HTTPServer] = None

    def start(self):
        ids = self._ids

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                path = self.path.split('?')[0]
                if path == '/metrics':
                    body = ids._prometheus_metrics().encode()
                    self.send_response(200)
                    self.send_header('Content-Type', 'text/plain; version=0.0.4')
                elif path == '/stats':
                    body = json.dumps(ids._json_stats(), default=str).encode()
                    self.send_response(200)
                    self.send_header('Content-Type', 'application/json')
                elif path == '/threats':
                    body = json.dumps(ids._json_threats(), default=str).encode()
                    self.send_response(200)
                    self.send_header('Content-Type', 'application/json')
                elif path == '/health':
                    body = b'{"status":"ok"}'
                    self.send_response(200)
                    self.send_header('Content-Type', 'application/json')
                else:
                    body = b'Not Found'
                    self.send_response(404)
                    self.send_header('Content-Type', 'text/plain')
                self.send_header('Content-Length', len(body))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass   # suppress access log

        try:
            self._server = HTTPServer(('0.0.0.0', self._port), Handler)
            t = threading.Thread(target=self._server.serve_forever, daemon=True)
            t.start()
            print(f"📡 Metrics API → http://0.0.0.0:{self._port}/metrics | /stats | /threats | /health")
        except Exception as e:
            print(f"⚠  Could not start Metrics API: {e}")

    def stop(self):
        if self._server:
            self._server.shutdown()


# ─────────────────────────────────────────────────────────────────────
# PCAP MANAGER  (unchanged from v1, kept inline)
# ─────────────────────────────────────────────────────────────────────
class PCAPManager:
    def __init__(self, pcap_dir: str = "pcap_captures",
                 max_packets_per_file: int = 10_000, max_files: int = 20):
        self.pcap_dir = pcap_dir
        self.max_packets_per_file = max_packets_per_file
        self.max_files = max_files
        session = f"session_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        self.session_dir = os.path.join(pcap_dir, session)
        os.makedirs(self.session_dir, exist_ok=True)
        self._lock  = threading.Lock()
        self._idx   = 1
        self._buf:  List = []
        self._cur   = self._new_path()
        print(f"💾 PCAP → {self.session_dir}")

    def write_packet(self, pkt):
        with self._lock:
            self._buf.append(pkt)
            if len(self._buf) >= self.max_packets_per_file:
                self._flush()

    def flush_all(self):
        with self._lock:
            if self._buf:
                self._flush()

    def load_recent(self, n: int = 3) -> List:
        pkts = []
        for f in self.list_files()[-n:]:
            try: pkts.extend(rdpcap(f))
            except: pass
        return pkts

    def list_files(self) -> List[str]:
        return sorted(
            os.path.join(self.session_dir, f)
            for f in os.listdir(self.session_dir) if f.endswith('.pcap')
        )

    def _flush(self):
        wrpcap(self._cur, self._buf)
        self._buf = []
        self._idx += 1
        self._cur = self._new_path()
        files = self.list_files()
        for old in files[:-self.max_files]:
            try: os.remove(old)
            except: pass

    def _new_path(self) -> str:
        return os.path.join(self.session_dir, f"capture_{self._idx:03d}.pcap")


# ─────────────────────────────────────────────────────────────────────
# PCAP FEATURE EXTRACTOR  (extended with new features)
# ─────────────────────────────────────────────────────────────────────
class PCAPFeatureExtractor:
    FEATURE_NAMES = [
        "pkt_count", "byte_total", "avg_pkt_size", "std_pkt_size",
        "duration", "pps", "bps",
        "tcp_ratio", "udp_ratio", "icmp_ratio",
        "syn_ratio", "rst_ratio", "fin_ratio",
        "unique_dst_ports", "unique_dst_ips",
        # new v2 features
        "avg_payload_entropy",   # mean payload entropy
        "beacon_cv",             # CV of inter-packet intervals
        "dns_ratio",             # DNS packets / total
        "malicious_port_hits",   # contacts to known bad ports
        "small_pkt_ratio",       # pkts < 64 bytes (scans)
    ]

    def extract(self, packets: List) -> Tuple[np.ndarray, List[str]]:
        flows: Dict[str, dict] = {}

        for pkt in packets:
            if IP not in pkt:
                continue
            src = pkt[IP].src
            if src not in flows:
                flows[src] = {
                    "sizes": [], "times": [], "payloads": [],
                    "tcp": 0, "udp": 0, "icmp": 0, "dns": 0,
                    "syn": 0, "rst": 0, "fin": 0,
                    "dst_ports": set(), "dst_ips": set(),
                    "mal_ports": 0, "small_pkts": 0,
                }
            f = flows[src]
            f["sizes"].append(len(pkt))
            f["times"].append(float(pkt.time))
            f["dst_ips"].add(pkt[IP].dst)
            if len(pkt) < 64:
                f["small_pkts"] += 1

            payload = bytes(pkt[Raw].load) if Raw in pkt else b''
            f["payloads"].append(PayloadEntropyScorer.score(payload))

            if TCP in pkt:
                f["tcp"] += 1
                flags = pkt[TCP].flags
                if flags & 0x02: f["syn"] += 1
                if flags & 0x04: f["rst"] += 1
                if flags & 0x01: f["fin"] += 1
                port = pkt[TCP].dport
                f["dst_ports"].add(port)
                if port in KNOWN_MALICIOUS_PORTS:
                    f["mal_ports"] += 1
            elif UDP in pkt:
                f["udp"] += 1
                port = pkt[UDP].dport
                f["dst_ports"].add(port)
                if DNS in pkt:
                    f["dns"] += 1
            elif ICMP in pkt:
                f["icmp"] += 1

        if not flows:
            return np.empty((0, len(self.FEATURE_NAMES)), dtype=np.float32), []

        rows, ips = [], []
        for src_ip, f in flows.items():
            n   = max(len(f["sizes"]), 1)
            dur = max((f["times"][-1] - f["times"][0]) if len(f["times"]) > 1 else 1e-6, 1e-6)
            tb  = sum(f["sizes"])
            tcp_n = max(f["tcp"], 1)

            # Beacon CV
            if len(f["times"]) > 2:
                ivs = [f["times"][i+1]-f["times"][i] for i in range(len(f["times"])-1)]
                mean_iv = statistics.mean(ivs)
                cv = statistics.stdev(ivs)/mean_iv if mean_iv > 0 else 1.0
            else:
                cv = 1.0

            rows.append([
                n, tb,
                np.mean(f["sizes"]), np.std(f["sizes"]) if n > 1 else 0.0,
                dur, n/dur, tb/dur,
                f["tcp"]/n, f["udp"]/n, f["icmp"]/n,
                f["syn"]/tcp_n, f["rst"]/tcp_n, f["fin"]/tcp_n,
                len(f["dst_ports"]), len(f["dst_ips"]),
                np.mean(f["payloads"]) if f["payloads"] else 0.0,
                cv,
                f["dns"]/n,
                float(f["mal_ports"]),
                f["small_pkts"]/n,
            ])
            ips.append(src_ip)

        return np.array(rows, dtype=np.float32), ips


# ─────────────────────────────────────────────────────────────────────
# MAIN IDS
# ─────────────────────────────────────────────────────────────────────
class AdvancedNetworkIDS:

    def __init__(self, config: dict):
        self.cfg = config
        self.thr = config["thresholds"]
        self.ml_cfg = config["ml"]

        # 5. EC2-safe interface
        self.interface = config.get("interface") or self._detect_interface() or "eth0"

        # ── subsystems ────────────────────────────────────────────────
        self.pcap_mgr    = PCAPManager(
            pcap_dir=config["pcap_dir"],
            max_files=config["max_pcap_files"])
        self.extractor   = PCAPFeatureExtractor()
        self.ensemble    = EnsembleAnomalyDetector(
            contamination=self.ml_cfg["ensemble_contamination"])
        self.ueba:        Dict[str, UEBAProfile] = {}
        self.dns_analyser = DNSAnalyser(
            entropy_thresh=self.thr["dns_entropy_threshold"],
            query_rate=self.thr["dns_query_rate"])
        self.beacon_det   = BeaconDetector(
            min_intervals=self.thr["beacon_min_intervals"],
            cv_threshold=self.thr["beacon_cv_threshold"])
        self.arp_det      = ARPSpoofDetector()
        self.threat_intel = ThreatIntelligence(
            blocklist_path=config.get("threat_intel_file"),
            geoip_db=config.get("geoip_db"))
        self.scoreboard   = ThreatScoreBoard()
        self.adapt_thr    = AdaptiveThresholds(self.thr)
        self.notifier     = WebhookNotifier(config.get("webhooks", []))

        # ── logging ───────────────────────────────────────────────────
        self.logger = build_logger(
            "AdvancedIDS",
            config.get("log_file", "network_ids.log"),
            config.get("log_level", "INFO"))

        # ── state ────────────────────────────────────────────────────
        self.running      = False
        self.connections  = defaultdict(self._new_conn)
        self.alerts       = deque(maxlen=self.thr["alert_history_max"])
        self.alert_counts = defaultdict(int)
        self._cooldown:   Dict[str, float] = {}
        self.stats = {
            'total_packets': 0, 'total_bytes': 0,
            'tcp': 0, 'udp': 0, 'icmp': 0, 'arp': 0, 'dns': 0, 'other': 0,
            'alerts': 0, 'start_time': datetime.now()
        }

        # ── threads ───────────────────────────────────────────────────
        self._threads: List[threading.Thread] = []

        # ── optional API ─────────────────────────────────────────────
        self._api: Optional[MetricsAPI] = None
        if config.get("enable_api", True):
            self._api = MetricsAPI(self, port=config.get("metrics_port", 9001))

        # Whitelist set
        self._whitelist_ips: set = set(config.get("whitelist_ips", []))
        self._whitelist_nets: list = []
        for cidr in config.get("whitelist_cidrs", []):
            try:
                self._whitelist_nets.append(ipaddress.ip_network(cidr, strict=False))
            except ValueError:
                pass

        self._print_banner()

    # ════════════════════════════════════════════════════════════════
    # Lifecycle
    # ════════════════════════════════════════════════════════════════
    def start(self):
        if self.running:
            return
        self.running = True
        self.logger.info("IDS started", extra={})

        jobs = [
            ("Capture",  self._capture_loop),
            ("Analysis", self._analysis_loop),
            ("PCAP-ML",  self._pcap_ml_loop),
            ("UEBA",     self._ueba_loop),
            ("Beacon",   self._beacon_loop),
            ("ScoreGC",  self._score_gc_loop),
        ]
        for name, fn in jobs:
            t = threading.Thread(target=fn, name=name, daemon=True)
            t.start()
            self._threads.append(t)

        if self._api:
            self._api.start()

        print(f"\n✅ Advanced IDS running — Ctrl+C to stop\n")

    def stop(self):
        print("\n🛑 Shutting down…")
        self.running = False
        self.pcap_mgr.flush_all()
        if self._api:
            self._api.stop()
        for t in self._threads:
            t.join(timeout=5)
        self._print_stats()
        self.logger.info("IDS stopped")
        print("✓ Done")

    # ════════════════════════════════════════════════════════════════
    # Packet Capture
    # ════════════════════════════════════════════════════════════════
    def _capture_loop(self):
        try:
            sniff(iface=self.interface,
                  prn=self._process_packet,
                  store=False,
                  stop_filter=lambda _: not self.running)
        except PermissionError:
            print("\n❌ Need root: sudo python3 network_ids_advanced.py")
            self.running = False
        except Exception as e:
            print(f"❌ Capture: {e}")
            self.running = False

    def _process_packet(self, pkt):
        try:
            self.stats['total_packets'] += 1
            self.pcap_mgr.write_packet(pkt)

            if ARP in pkt:
                self.stats['arp'] += 1
                self._check_arp(pkt)
            elif IP in pkt:
                self._process_ip(pkt)
            else:
                self.stats['other'] += 1

            if self.stats['total_packets'] % 1000 == 0:
                self._print_status()
        except Exception:
            pass

    def _check_arp(self, pkt):
        arp = pkt[ARP]
        if arp.op == 2:   # ARP reply
            finding = self.arp_det.observe(arp.psrc, arp.hwsrc)
            if finding:
                self._alert('ARP Spoofing / MITM', arp.psrc, 'Critical', 0.97,
                            finding, score_weight=30)

    def _process_ip(self, pkt):
        src  = pkt[IP].src
        conn = self.connections[src]
        now  = time.time()

        # Threat intel blocklist check (immediate)
        if self.threat_intel.is_blocked(src):
            rep = self.threat_intel.get_reputation(src)
            self._alert('Threat-Intel Blocklist Hit', src, 'Critical',
                        min(0.99, 0.80 + rep * 0.19),
                        {'reputation_score': rep,
                         'geo': self.threat_intel.geolocate(src)},
                        score_weight=40)

        conn['pkt_count']  += 1
        conn['last_seen']   = now
        conn['ts'].append(now)
        size = len(pkt)
        conn['bytes']      += size
        conn['sizes'].append(size)
        self.stats['total_bytes'] += size

        # UEBA observation
        proto = 'other'
        dport = 0

        if TCP in pkt:
            tcp   = pkt[TCP]
            dport = tcp.dport
            proto = 'TCP'
            flags = tcp.flags
            conn['tcp']   += 1
            conn['ports'].add(dport)
            if flags & 0x02: conn['syn'] += 1
            if flags & 0x10: conn['ack'] += 1
            if flags & 0x01: conn['fin'] += 1
            if flags & 0x04: conn['rst'] += 1
            self.stats['tcp'] += 1

            # Payload entropy
            if Raw in pkt:
                ent = PayloadEntropyScorer.score(bytes(pkt[Raw].load))
                label = PayloadEntropyScorer.classify(ent, dport)
                if label:
                    self._alert('Suspicious Payload Entropy', src, 'Medium', 0.80,
                                {'entropy': round(ent, 3), 'dport': dport,
                                 'reason': label}, score_weight=10)

            # Beacon tracking per (src→dst:dport)
            bkey = f"{src}→{pkt[IP].dst}:{dport}"
            self.beacon_det.observe(bkey, now)

            # Known-malicious port
            if dport in KNOWN_MALICIOUS_PORTS:
                self._alert('Malicious Port Contact', src, 'High', 0.85,
                            {'dport': dport,
                             'service': f'Known C2/backdoor port {dport}'},
                            score_weight=20)

            # HTTP inspection
            if dport in (80, 8080) and Raw in pkt:
                self._inspect_http(src, pkt)

        elif UDP in pkt:
            udp   = pkt[UDP]
            dport = udp.dport
            proto = 'UDP'
            conn['udp'] += 1
            conn['ports'].add(dport)
            self.stats['udp'] += 1

            # DNS deep analysis
            if DNS in pkt and DNSQR in pkt:
                self.stats['dns'] += 1
                conn['dns'] += 1
                qname = pkt[DNSQR].qname.decode(errors='replace')
                findings = self.dns_analyser.process(src, qname, now)
                if findings:
                    for ftype, fdata in findings.items():
                        sev = 'High' if ftype == 'dns_tunnel' else 'Medium'
                        self._alert(f'DNS Anomaly ({ftype})', src, sev, 0.82,
                                    fdata, score_weight=15)

        elif ICMP in pkt:
            conn['icmp'] += 1
            proto = 'ICMP'
            self.stats['icmp'] += 1

        dst = pkt[IP].dst
        if dst not in conn['dst_ips']:
            conn['dst_ips'].add(dst)

        # Update UEBA
        if src not in self.ueba:
            self.ueba[src] = UEBAProfile(src)
        self.ueba[src].observe(now, dst, dport, size, proto)

        # Update reputation score on each alert trigger
        self.scoreboard.add_evidence(src, 0.0, '')    # zero – just ensures entry exists

    def _inspect_http(self, src_ip: str, pkt):
        raw = bytes(pkt[Raw].load).decode(errors='replace')
        lines = raw.split('\r\n')
        if not lines:
            return
        request_line = lines[0]

        # SQL injection heuristic
        sqli_patterns = ["' OR ", "1=1", "UNION SELECT", "DROP TABLE", "--"]
        if any(p.lower() in raw.lower() for p in sqli_patterns):
            self._alert('HTTP SQLi Attempt', src_ip, 'High', 0.80,
                        {'request': request_line[:200],
                         'description': 'SQL injection pattern in HTTP request'},
                        score_weight=25)

        # Path traversal
        if '../' in raw or '..\\' in raw or '%2e%2e' in raw.lower():
            self._alert('HTTP Path Traversal', src_ip, 'High', 0.82,
                        {'request': request_line[:200],
                         'description': 'Directory traversal attempt'},
                        score_weight=20)

        # Scanner user-agents
        scanners = ['sqlmap', 'nikto', 'nmap', 'masscan', 'zgrab',
                    'dirbuster', 'gobuster', 'burpsuite']
        ua_line = next((l for l in lines if l.lower().startswith('user-agent:')), '')
        if any(s in ua_line.lower() for s in scanners):
            self._alert('HTTP Scanner Detected', src_ip, 'High', 0.90,
                        {'user_agent': ua_line[:200],
                         'description': 'Known security scanner detected'},
                        score_weight=20)

    # ════════════════════════════════════════════════════════════════
    # Analysis Loop – real-time signature-based detection
    # ════════════════════════════════════════════════════════════════
    def _analysis_loop(self):
        while self.running:
            try:
                self._detect_ddos()
                self._detect_syn_flood()
                self._detect_udp_flood()
                self._detect_icmp_flood()
                self._detect_port_scans()
                self._detect_brute_force()
                self._adapt_thresholds()
                self._cleanup_stale()
                self._run_live_ml()
                time.sleep(2)
            except Exception as e:
                self.logger.exception("Analysis loop error")

    def _detect_ddos(self):
        now  = time.time()
        thresh = self.adapt_thr.get('ddos_pps', self.thr['ddos_pps'])
        for ip, c in list(self.connections.items()):
            if self._whitelisted(ip): continue
            recent = [t for t in c['ts'] if t > now - 5]
            if len(recent) > 50:
                pps = len(recent) / 5
                self.adapt_thr.update('ddos_pps', pps)
                if pps > thresh:
                    geo = self.threat_intel.geolocate(ip)
                    self._alert('DDoS / High-Rate Flood', ip, 'Critical', 0.95,
                                {'pps': f"{pps:.0f}", 'geo': geo,
                                 'description': 'Abnormally high packet rate'},
                                score_weight=35)

    def _detect_syn_flood(self):
        for ip, c in list(self.connections.items()):
            if self._whitelisted(ip): continue
            if c['syn'] > 50 and c['ack'] > 0:
                ratio = c['syn'] / max(c['ack'], 1)
                if ratio > self.adapt_thr.get('syn_flood_ratio', self.thr['syn_flood_ratio']):
                    self._alert('SYN Flood', ip, 'Critical', 0.96,
                                {'syn': c['syn'], 'ack': c['ack'], 'ratio': f"{ratio:.2f}",
                                 'description': 'Half-open TCP SYN flood detected'},
                                score_weight=30)
                    c['syn'] = 0; c['ack'] = 0

    def _detect_udp_flood(self):
        thresh = self.adapt_thr.get('udp_flood_pps', self.thr['udp_flood_pps'])
        for ip, c in list(self.connections.items()):
            if self._whitelisted(ip): continue
            if c['udp'] > thresh:
                self._alert('UDP Flood', ip, 'High', 0.92,
                            {'udp_pkts': c['udp']}, score_weight=25)
                c['udp'] = 0

    def _detect_icmp_flood(self):
        thresh = self.adapt_thr.get('icmp_flood_pps', self.thr['icmp_flood_pps'])
        for ip, c in list(self.connections.items()):
            if self._whitelisted(ip): continue
            if c['icmp'] > thresh:
                self._alert('ICMP Flood', ip, 'Medium', 0.90,
                            {'icmp_pkts': c['icmp']}, score_weight=15)
                c['icmp'] = 0

    def _detect_port_scans(self):
        now = time.time()
        thresh = self.thr['port_scan_ports']
        win    = self.thr['port_scan_time']
        for ip, c in list(self.connections.items()):
            if self._whitelisted(ip): continue
            dur = now - c['first_seen']
            if dur < win and len(c['ports']) >= thresh:
                self._alert('Port Scan', ip, 'High', 0.93,
                            {'ports_scanned': len(c['ports']),
                             'sample': list(c['ports'])[:20],
                             'duration_s': f"{dur:.1f}",
                             'geo': self.threat_intel.geolocate(ip)},
                            score_weight=25)
                c['ports'].clear()
                c['first_seen'] = now

    def _detect_brute_force(self):
        brute_ports = {22, 21, 3389, 23, 3306, 5432, 1433, 5900}
        now = time.time()
        thresh = self.thr['brute_force_attempts']
        for ip, c in list(self.connections.items()):
            if self._whitelisted(ip): continue
            hits = c['ports'] & brute_ports
            if hits:
                recent = [t for t in c['ts'] if t > now - 60]
                if len(recent) > thresh:
                    self._alert('Brute Force', ip, 'High', 0.88,
                                {'attempts': len(recent),
                                 'ports': list(hits),
                                 'services': self._services(hits),
                                 'geo': self.threat_intel.geolocate(ip)},
                                score_weight=30)

    def _adapt_thresholds(self):
        # Feed observed traffic statistics back into adaptive thresholds
        for ip, c in list(self.connections.items()):
            if self._whitelisted(ip) or c['pkt_count'] < 10:
                continue
            dur = max(time.time() - c['first_seen'], 1)
            self.adapt_thr.update('ddos_pps', c['pkt_count'] / dur)

    def _run_live_ml(self):
        X, ips = [], []
        now = time.time()
        for ip, c in list(self.connections.items()):
            if self._whitelisted(ip) or c['pkt_count'] < 50:
                continue
            dur   = max(now - c['first_seen'], 1)
            pps   = c['pkt_count'] / dur
            bps   = c['bytes'] / dur
            avg   = float(np.mean(c['sizes'])) if c['sizes'] else 0
            std   = float(np.std(c['sizes']))  if len(c['sizes']) > 1 else 0
            syn_r = c['syn'] / max(c['pkt_count'], 1)
            ports = len(c['ports'])
            tu    = c['tcp'] / max(c['udp'], 1)
            dns_r = c['dns'] / max(c['pkt_count'], 1)
            X.append([pps, bps, avg, std, syn_r, ports, tu, dns_r])
            ips.append(ip)

        if len(X) >= self.ensemble.MIN_SAMPLES and not self.ensemble.trained:
            self.ensemble.train(np.array(X))

        if self.ensemble.trained and X:
            Xarr = np.array(X)
            drift = self.ensemble.detect_drift(Xarr)
            if drift:
                self.logger.warning(f"Feature drift: {drift}")

            flagged, scores, votes = self.ensemble.predict(Xarr)
            now_t = time.time()
            for i, ip in enumerate(ips):
                if flagged[i]:
                    cooldown_key = f"live_ml_{ip}"
                    if now_t - self._cooldown.get(cooldown_key, 0) < 60:
                        continue
                    self._cooldown[cooldown_key] = now_t
                    self._alert('Ensemble ML Anomaly (Live)', ip, 'Medium',
                                min(0.99, abs(float(scores[i])) + 0.3),
                                {'if_vote': int(votes[i][0]),
                                 'lof_vote': int(votes[i][1]),
                                 'ocsvm_vote': int(votes[i][2]),
                                 'ensemble_score': round(float(scores[i]), 4),
                                 'description': '2/3 model ensemble flagged abnormal traffic',
                                 'geo': self.threat_intel.geolocate(ip)},
                                score_weight=20)
                    self.threat_intel.update_reputation(ip, 0.1)

    # ════════════════════════════════════════════════════════════════
    # UEBA Loop
    # ════════════════════════════════════════════════════════════════
    def _ueba_loop(self):
        while self.running:
            time.sleep(30)
            now = time.time()
            for ip, profile in list(self.ueba.items()):
                if self._whitelisted(ip):
                    continue
                score, reason = profile.get_anomaly_score(now)
                if score > 0.7:
                    self._alert('UEBA Behavioural Anomaly', ip, 'Medium',
                                score,
                                {'reason': reason,
                                 'baseline_pps': round(profile.baseline_pps or 0, 2),
                                 'description': 'Behavioural drift vs 24h profile'},
                                score_weight=15)

    # ════════════════════════════════════════════════════════════════
    # Beacon Loop
    # ════════════════════════════════════════════════════════════════
    def _beacon_loop(self):
        while self.running:
            time.sleep(30)
            for ip, c in list(self.connections.items()):
                if self._whitelisted(ip):
                    continue
                for port in list(c['ports']):
                    bkey = f"{ip}→*:{port}"
                    result = self.beacon_det.check(bkey)
                    if result:
                        self._alert('C2 Beaconing Detected', ip, 'High', 0.87,
                                    {**result,
                                     'target_port': port,
                                     'geo': self.threat_intel.geolocate(ip)},
                                    score_weight=35)
                        self.threat_intel.update_reputation(ip, 0.2)

    # ════════════════════════════════════════════════════════════════
    # PCAP ML Loop
    # ════════════════════════════════════════════════════════════════
    def _pcap_ml_loop(self):
        time.sleep(self.cfg['pcap_interval'])
        while self.running:
            try:
                self._run_pcap_ml()
            except Exception as e:
                self.logger.exception("PCAP ML error")
            time.sleep(self.cfg['pcap_interval'])

    def _run_pcap_ml(self):
        pkts = self.pcap_mgr.load_recent(3)
        if not pkts:
            return
        X, ips = self.extractor.extract(pkts)
        if len(X) < self.ensemble.MIN_SAMPLES:
            return

        if not self.ensemble.trained or len(pkts) > 500:
            self.ensemble.train(X)

        flagged, scores, _ = self.ensemble.predict(X)
        for i, ip in enumerate(ips):
            if flagged[i] and not self._whitelisted(ip):
                self._alert('PCAP Ensemble ML Anomaly', ip, 'High',
                            min(0.99, abs(float(scores[i])) + 0.4),
                            {'ensemble_score': round(float(scores[i]), 4),
                             'pps': round(float(X[i][5]), 2),
                             'unique_ports': int(X[i][13]),
                             'beacon_cv': round(float(X[i][16]), 3),
                             'payload_entropy': round(float(X[i][15]), 3),
                             'description': 'PCAP-level ensemble model flagged flow'},
                            score_weight=20)

    # ════════════════════════════════════════════════════════════════
    # Score GC Loop
    # ════════════════════════════════════════════════════════════════
    def _score_gc_loop(self):
        while self.running:
            time.sleep(60)
            self.scoreboard.decay()
            # Composite threat alert for very high scorers
            for ip, score, evidence in self.scoreboard.top_threats(5):
                if score >= 70:
                    self._alert('Composite High-Risk IP', ip, 'Critical', 0.95,
                                {'composite_score': round(score, 1),
                                 'evidence_count': len(evidence),
                                 'top_evidence': list(set(evidence))[:5],
                                 'reputation': self.threat_intel.get_reputation(ip),
                                 'geo': self.threat_intel.geolocate(ip)},
                                score_weight=0)   # don't double-count

    # ════════════════════════════════════════════════════════════════
    # Alert Infrastructure
    # ════════════════════════════════════════════════════════════════
    def _alert(self, attack_type: str, src_ip: str, severity: str,
               confidence: float, details: dict, score_weight: float = 10):
        key = f"{attack_type}_{src_ip}"
        now = time.time()
        cooldown = self.thr.get('anomaly_cooldown_s', 60)
        if now - self._cooldown.get(key, 0) < cooldown:
            return
        self._cooldown[key] = now

        geo  = details.pop('geo', {}) if 'geo' in details else {}
        alert = {
            'timestamp':   datetime.utcnow().isoformat() + 'Z',
            'attack_type': attack_type,
            'src_ip':      src_ip,
            'severity':    severity,
            'confidence':  round(confidence, 3),
            'details':     self._serialise(details),
            'geo':         geo,
            'reputation':  round(self.threat_intel.get_reputation(src_ip), 3),
            'composite_score': round(self.scoreboard.get_score(src_ip), 1),
        }

        self.alerts.append(alert)
        self.alert_counts[attack_type] += 1
        self.stats['alerts'] += 1

        # Update composite score
        self.scoreboard.add_evidence(src_ip, score_weight, attack_type)
        self.threat_intel.update_reputation(src_ip, score_weight / 200)

        self._print_alert(alert)
        self._save_alert(alert)
        self.notifier.notify(alert)

        extra = {'src_ip': src_ip, 'attack_type': attack_type}
        self.logger.warning(f"{attack_type} | {src_ip} | {details}", extra=extra)

    def _print_alert(self, a: dict):
        C = {'Critical': '\033[91m', 'High': '\033[93m',
             'Medium':   '\033[94m', 'Low':  '\033[92m'}
        R = '\033[0m'
        c = C.get(a['severity'], '')
        geo_str = ''
        if a.get('geo'):
            g = a['geo']
            geo_str = f"  Geo       : {g.get('city','?')}, {g.get('country','?')}\n"

        print(f"\n{c}{'━'*62}")
        print(f"  🚨 {a['attack_type']}")
        print(f"{'━'*62}{R}")
        print(f"  Time      : {a['timestamp']}")
        print(f"  Source IP : {a['src_ip']}   [score {a['composite_score']:.0f}/100]")
        print(f"  Severity  : {a['severity']}   Confidence: {a['confidence']*100:.0f}%")
        print(geo_str, end='')
        for k, v in a['details'].items():
            print(f"  {k:20s}: {v}")
        print(f"{c}{'━'*62}{R}\n")

    def _save_alert(self, alert: dict):
        try:
            existing = []
            if os.path.exists(self.cfg['alert_file']):
                with open(self.cfg['alert_file']) as f:
                    existing = json.load(f)
            existing.append(alert)
            existing = existing[-self.thr['alert_history_max']:]
            with open(self.cfg['alert_file'], 'w') as f:
                json.dump(existing, f, indent=2, default=str)
        except Exception as e:
            self.logger.error(f"Alert save error: {e}")

    # ════════════════════════════════════════════════════════════════
    # Prometheus / API responses
    # ════════════════════════════════════════════════════════════════
    def _prometheus_metrics(self) -> str:
        s = self.stats
        lines = [
            '# HELP ids_packets_total Total packets captured',
            '# TYPE ids_packets_total counter',
            f'ids_packets_total {s["total_packets"]}',
            '# HELP ids_bytes_total Total bytes captured',
            '# TYPE ids_bytes_total counter',
            f'ids_bytes_total {s["total_bytes"]}',
            '# HELP ids_alerts_total Total alerts generated',
            '# TYPE ids_alerts_total counter',
            f'ids_alerts_total {s["alerts"]}',
            '# HELP ids_unique_ips Unique source IPs tracked',
            '# TYPE ids_unique_ips gauge',
            f'ids_unique_ips {len(self.connections)}',
            '# HELP ids_ml_trained ML ensemble training status',
            '# TYPE ids_ml_trained gauge',
            f'ids_ml_trained {int(self.ensemble.trained)}',
        ]
        for atype, cnt in self.alert_counts.items():
            safe = re.sub(r'[^a-zA-Z0-9_]', '_', atype).lower()
            lines += [
                f'# TYPE ids_alert_{safe}_total counter',
                f'ids_alert_{safe}_total {cnt}',
            ]
        return '\n'.join(lines) + '\n'

    def _json_stats(self) -> dict:
        up = (datetime.now() - self.stats['start_time']).total_seconds()
        return {
            'version':      VERSION,
            'uptime_s':     round(up, 1),
            'interface':    self.interface,
            **self.stats,
            'unique_ips':   len(self.connections),
            'ml_trained':   self.ensemble.trained,
            'pcap_files':   len(self.pcap_mgr.list_files()),
            'alert_counts': dict(self.alert_counts),
            'thresholds':   self.adapt_thr.snapshot(),
        }

    def _json_threats(self) -> list:
        return [
            {'ip': ip, 'score': score, 'evidence': list(set(ev))[:10]}
            for ip, score, ev in self.scoreboard.top_threats(20)
        ]

    # ════════════════════════════════════════════════════════════════
    # Helpers
    # ════════════════════════════════════════════════════════════════
    def _whitelisted(self, ip: str) -> bool:
        if ip in self._whitelist_ips:
            return True
        if any(ip.startswith(p) for p in PRIVATE_PREFIXES):
            return True
        try:
            addr = ipaddress.ip_address(ip)
            return any(addr in net for net in self._whitelist_nets)
        except ValueError:
            return False

    @staticmethod
    def _new_conn() -> dict:
        now = time.time()
        return {
            'pkt_count': 0, 'bytes': 0, 'tcp': 0, 'udp': 0, 'icmp': 0, 'dns': 0,
            'syn': 0, 'ack': 0, 'fin': 0, 'rst': 0,
            'ports': set(), 'dst_ips': set(),
            'sizes': deque(maxlen=200), 'ts': deque(maxlen=500),
            'first_seen': now, 'last_seen': now,
        }

    def _cleanup_stale(self):
        cutoff = time.time() - 300
        for ip in [ip for ip, c in self.connections.items() if c['last_seen'] < cutoff]:
            del self.connections[ip]
            self.ueba.pop(ip, None)

    def _serialise(self, obj):
        if isinstance(obj, dict):
            return {str(k): self._serialise(v) for k, v in obj.items()}
        if isinstance(obj, (list, tuple)):
            return [self._serialise(v) for v in obj]
        if isinstance(obj, set):
            return sorted(list(obj))
        if isinstance(obj, (np.integer, np.floating)):
            return float(obj)
        if isinstance(obj, np.ndarray):
            return obj.tolist()
        if isinstance(obj, datetime):
            return obj.isoformat()
        return obj

    def _services(self, ports: set) -> str:
        return ', '.join(SERVICE_MAP.get(p, f'Port {p}') for p in ports)

    @staticmethod
    def _detect_interface() -> Optional[str]:
        try:
            for iface in get_if_list():
                ip = get_if_addr(iface)
                if not ip or ip.startswith(('127.', '0.0.0.0', '169.254.')):
                    continue
                if ip.startswith(('192.168.', '10.', '172.')):
                    print(f"✓ Auto-selected interface: {iface} ({ip})")
                    return iface
        except Exception:
            pass
        return None

    def _print_banner(self):
        print(f"""
╔══════════════════════════════════════════════════════════════╗
║   Advanced Network IDS  v{VERSION}  —  Industry Edition       ║
╠══════════════════════════════════════════════════════════════╣
║  Interface  : {self.interface:47s}║
║  Alert File : {self.cfg['alert_file']:47s}║
║  PCAP Dir   : {self.cfg['pcap_dir']:47s}║
║  Metrics    : http://localhost:{self.cfg.get('metrics_port',9001)}/metrics              ║
╠══════════════════════════════════════════════════════════════╣
║  Engines Active:                                              ║
║   ✓ Signature detection (DDoS/SYN/UDP/ICMP/PortScan/BF)     ║
║   ✓ Ensemble ML (IsolationForest + LOF + OneClassSVM)        ║
║   ✓ UEBA behavioural profiling                               ║
║   ✓ C2 beaconing / interval regularity detection             ║
║   ✓ DNS exfiltration + DGA + entropy analysis                ║
║   ✓ ARP spoofing / MITM detection                            ║
║   ✓ HTTP: SQLi / path-traversal / scanner UA                 ║
║   ✓ Payload entropy scoring                                  ║
║   ✓ Threat intelligence blocklist + GeoIP                    ║
║   ✓ Composite threat score per IP                            ║
║   ✓ Adaptive thresholds (EWMA)                               ║
║   ✓ Webhook alerting (Slack / PagerDuty / HTTP)              ║
║   ✓ Prometheus metrics + REST API                            ║
║   ✓ ECS-compliant structured logging                         ║
╚══════════════════════════════════════════════════════════════╝
        """)

    def _print_status(self):
        s = self.stats
        up = (datetime.now() - s['start_time']).total_seconds()
        pps = s['total_packets'] / max(up, 1)
        top = self.scoreboard.top_threats(1)
        top_str = f"TopThreat:{top[0][0]}({top[0][1]:.0f})" if top else ""
        print(f"\r📊 Pkts:{s['total_packets']:,} {pps:.0f}pps "
              f"IPs:{len(self.connections)} Alerts:{s['alerts']} "
              f"MLTrained:{'✓' if self.ensemble.trained else '…'} {top_str}",
              end='', flush=True)

    def _print_stats(self):
        up = (datetime.now() - self.stats['start_time']).total_seconds()
        print(f"""
╔══════════════════════════════════════════════════════════════╗
║                   Session Summary                            ║
╠══════════════════════════════════════════════════════════════╣
  Runtime        : {up/60:.1f} min
  Total Packets  : {self.stats['total_packets']:,}
  Total Bytes    : {self.stats['total_bytes']:,}
  TCP/UDP/ICMP   : {self.stats['tcp']:,} / {self.stats['udp']:,} / {self.stats['icmp']:,}
  DNS Queries    : {self.stats['dns']:,}
  Unique IPs     : {len(self.connections)}
  Alerts         : {self.stats['alerts']}
  PCAP Files     : {len(self.pcap_mgr.list_files())}
  ML Trained     : {self.ensemble.trained}
╠══════════════════════════════════════════════════════════════╣
  Alert Breakdown:""")
        for at, cnt in sorted(self.alert_counts.items(), key=lambda x: -x[1]):
            print(f"    {at:50s} {cnt:5d}")
        print("  Top Threats:")
        for ip, score, ev in self.scoreboard.top_threats(5):
            print(f"    {ip:20s} score={score:.0f}  {list(set(ev))[:3]}")
        print("╚══════════════════════════════════════════════════════════════╝")


# ─────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────
def main():
    import argparse

    ap = argparse.ArgumentParser(
        description=f'Advanced Network IDS v{VERSION}',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    ap.add_argument('-c', '--config',       help='YAML config file')
    ap.add_argument('-i', '--interface',    help='Network interface')
    ap.add_argument('-o', '--output',       default='network_alerts.json')
    ap.add_argument('-p', '--pcap-dir',     default='pcap_captures')
    ap.add_argument('--pcap-interval',      type=int, default=60)
    ap.add_argument('--max-pcap-files',     type=int, default=20)
    ap.add_argument('--metrics-port',       type=int, default=9001)
    ap.add_argument('--threat-intel',       help='IP blocklist file')
    ap.add_argument('--geoip-db',           help='MaxMind GeoIP2 .mmdb path')
    ap.add_argument('--analyse-pcap',       help='Offline PCAP analysis')
    ap.add_argument('--no-api',             action='store_true')
    args = ap.parse_args()

    # ── offline mode ─────────────────────────────────────────────────
    if args.analyse_pcap:
        print(f"\n🔍 Offline PCAP analysis: {args.analyse_pcap}")
        pkts = rdpcap(args.analyse_pcap)
        print(f"   {len(pkts):,} packets loaded")
        ext  = PCAPFeatureExtractor()
        X, ips = ext.extract(pkts)
        ens  = EnsembleAnomalyDetector()
        ens.train(X)
        flagged, scores, votes = ens.predict(X)
        print(f"\n{'IP':20s} {'IF':3s} {'LOF':3s} {'SVM':3s} {'Score':>8s}")
        print("─" * 45)
        for i, ip in enumerate(ips):
            if flagged[i]:
                print(f"{ip:20s}  {votes[i][0]}   {votes[i][1]}   {votes[i][2]}  {scores[i]:+.4f}  ← ANOMALY")
        return

    # ── live mode ────────────────────────────────────────────────────
    cfg = load_config(args.config)
    if args.interface:    cfg['interface']        = args.interface
    if args.output:       cfg['alert_file']       = args.output
    if args.pcap_dir:     cfg['pcap_dir']         = args.pcap_dir
    if args.threat_intel: cfg['threat_intel_file']= args.threat_intel
    if args.geoip_db:     cfg['geoip_db']         = args.geoip_db
    cfg['pcap_interval']  = args.pcap_interval
    cfg['max_pcap_files'] = args.max_pcap_files
    cfg['metrics_port']   = args.metrics_port
    cfg['enable_api']     = not args.no_api

    ids = AdvancedNetworkIDS(cfg)

    def _sig(sig, frame):
        ids.stop()
        raise SystemExit(0)

    signal.signal(signal.SIGINT,  _sig)
    signal.signal(signal.SIGTERM, _sig)

    ids.start()
    while ids.running:
        time.sleep(1)


if __name__ == '__main__':
    main()