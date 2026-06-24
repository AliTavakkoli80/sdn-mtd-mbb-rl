import time
import math
from collections import defaultdict
import numpy as np

class ThreatDetector:
    """
    Q1-Grade L2/L3/L4 Threat Detector for SDN-based MTD.
    Uses Information-Theoretic Entropy, EWMA Rate Smoothing, and IAT Fingerprinting.
    """
    def __init__(self, app, alpha=0.2, rate_threshold=15.0):
        self.app = app
        self.alpha = alpha
        self.RATE_THRESHOLD = rate_threshold
        
        # 🌟 FIX: Lowered threshold to 0.50 to ensure L2 sweeps trigger the alarm
        self.ATTACK_THRESHOLD = 0.50
        self.CLEAR_THRESHOLD = 0.25  # Hysteresis to prevent flapping
        
        self.sources = defaultdict(lambda: {
            'dst_ips': set(), 'dst_ports': set(),
            'packet_count': 0, 'ewma_rate': 0.0,
            'last_ts': 0.0, 'iat_list': [],
            'is_flagged': False
        })
        
        self.is_under_attack = False
        self.max_threat_score = 0.0
        self.clean_interval = 10.0
        self.last_cleanup = time.time()

    def process_packet(self, src_ip: str, dst_ip: str, dst_port: int, proto: int, timestamp: float = None):
        """Called by ipv4_handler.py for every IPv4/TCP/UDP packet."""
        self._update_source(src_ip, dst_ip, dst_port, timestamp)

    def process_arp_request(self, src_ip: str, dst_ip: str, timestamp: float = None):
        """Called by arp_handler.py for every ARP Request (Layer 2 Sweep Detection)."""
        self._update_source(src_ip, dst_ip, dst_port=None, timestamp=timestamp)

    def _update_source(self, src_ip, dst_ip, dst_port, timestamp):
        if timestamp is None:
            timestamp = time.time()
            
        src = self.sources[src_ip]
        dt = timestamp - src['last_ts'] if src['last_ts'] > 0 else 1.0
        src['last_ts'] = timestamp
        
        inst_rate = 1.0 / max(dt, 0.001)
        src['ewma_rate'] = self.alpha * inst_rate + (1 - self.alpha) * src['ewma_rate']
        
        src['dst_ips'].add(dst_ip)
        if dst_port is not None:
            src['dst_ports'].add(dst_port)
        src['packet_count'] += 1
        
        if dt < 5.0:
            src['iat_list'].append(dt)
            if len(src['iat_list']) > 50:
                src['iat_list'].pop(0)
                
        if time.time() - self.last_cleanup > self.clean_interval:
            self._cleanup_stale_sources()
            self.last_cleanup = time.time()
            
        score = self._compute_threat_score(src)
        if score > self.max_threat_score:
            self.max_threat_score = score
            
        if self.max_threat_score > self.ATTACK_THRESHOLD and not self.is_under_attack:
            self.is_under_attack = True
            self.app.logger.warning(f"🚨 [THREAT] Intelligent scan signature detected from {src_ip} (Score: {score:.3f})")
        elif self.max_threat_score < self.CLEAR_THRESHOLD and self.is_under_attack:
            self.is_under_attack = False
            self.app.logger.info("✅ [THREAT] Scan activity normalized. Network state cleared.")

    def _compute_threat_score(self, src: dict) -> float:
        """
        Returns a normalized threat score [0.0, 1.0].
        """
        # A. Shannon Entropy for Destination IPs
        n_ips = len(src['dst_ips'])
        ent_ip = math.log2(n_ips) if n_ips > 1 else 0.0
        # 🌟 FIX: Normalize by 4.0 (log2(16)). Scanning 16 unique IPs is a definitive sweep.
        ent_ip_norm = min(ent_ip / 4.0, 1.0)
            
        # B. Shannon Entropy for Destination Ports
        n_ports = len(src['dst_ports'])
        ent_port = math.log2(n_ports) if n_ports > 1 else 0.0
        ent_port_norm = min(ent_port / 4.0, 1.0)
        
        # C. IAT Coefficient of Variation
        cv = 1.0
        if len(src['iat_list']) >= 5:
            mean_iat = sum(src['iat_list']) / len(src['iat_list'])
            if mean_iat > 0:
                var_iat = sum((x - mean_iat) ** 2 for x in src['iat_list']) / len(src['iat_list'])
                cv = min(math.sqrt(var_iat) / mean_iat, 2.0)
        cv_norm = max(0.0, 1.0 - (cv / 1.5))
        
        # D. Rate normalization
        rate_norm = min(src['ewma_rate'] / self.RATE_THRESHOLD, 1.0)
        
        # 🌟 FIX: Rebalanced weights. 
        # IP Entropy and Rate are the most reliable indicators for both L2 and L3.
        score = (0.50 * ent_ip_norm) + (0.20 * ent_port_norm) + (0.10 * cv_norm) + (0.20 * rate_norm)
        return min(score, 1.0)

    def _cleanup_stale_sources(self):
        now = time.time()
        to_remove = [ip for ip, data in self.sources.items() if now - data['last_ts'] > self.clean_interval]
        for ip in to_remove:
            del self.sources[ip]

    def get_state(self) -> np.ndarray:
        """Returns the 5D DRL-ready state vector."""
        max_ent_ip, max_ent_port, max_rate, max_cv = 0.0, 0.0, 0.0, 0.0
        
        for src in self.sources.values():
            n_ips = len(src['dst_ips'])
            n_ports = len(src['dst_ports'])
            
            # Match the / 4.0 normalization from _compute_threat_score
            e_ip = min(math.log2(max(n_ips, 1)) / 4.0, 1.0)
            e_port = min(math.log2(max(n_ports, 1)) / 4.0, 1.0)
            rate = min(src['ewma_rate'] / self.RATE_THRESHOLD, 1.0)
            
            if len(src['iat_list']) >= 5:
                mean_iat = sum(src['iat_list']) / len(src['iat_list'])
                var_iat = sum((x - mean_iat) ** 2 for x in src['iat_list']) / len(src['iat_list'])
                cv = math.sqrt(var_iat) / max(mean_iat, 1e-6)
                cv_norm = max(0.0, 1.0 - (cv / 1.5))
            else:
                cv_norm = 0.0
                
            max_ent_ip = max(max_ent_ip, e_ip)
            max_ent_port = max(max_ent_port, e_port)
            max_rate = max(max_rate, rate)
            max_cv = max(max_cv, cv_norm)
            
        return np.array([
            max_ent_ip, max_ent_port, max_rate, max_cv, float(self.is_under_attack)
        ], dtype=np.float32)

    def get_scanned_targets(self):
        """
        Returns a list of Virtual IPs currently being targeted by the most aggressive scanner.
        """
        max_score = 0.0
        top_targets = []
        
        for src_ip, data in self.sources.items():
            score = self._compute_threat_score(data)
            # Only return targets if there's an actual, significant threat
            if score > 0.4 and score > max_score: 
                max_score = score
                # The attacker scans the Virtual IPs, so dst_ips contains the targeted VIPs
                top_targets = list(data['dst_ips'])
                
        return top_targets    

    def get_max_intensity(self):
        """Returns the continuous threat intensity (0.0 to 1.0) of the most aggressive source."""
        max_score = 0.0
        for data in self.sources.values():
            score = self._compute_threat_score(data)
            if score > max_score:
                max_score = score
        return max_score    