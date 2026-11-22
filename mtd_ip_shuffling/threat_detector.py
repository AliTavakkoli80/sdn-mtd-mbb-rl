import time
import math
from collections import defaultdict, deque
import numpy as np

class ThreatDetector:
    """
    Q1-Grade L2/L3/L4 Threat Detector for SDN-based MTD.
    Uses Information-Theoretic Entropy, Sustained Continuous-Time EWMA Rate Smoothing,
    and IAT Fingerprinting.
    """
    def __init__(self, app, alpha=0.2, rate_threshold=15.0, rate_tau=3.0):
        self.app = app
        self.alpha = alpha
        self.RATE_THRESHOLD = rate_threshold
        self.RATE_TAU = rate_tau  # Continuous-time decay window in seconds (matched to RL step duration)
        
        # Detection thresholds
        self.ATTACK_THRESHOLD = 0.40
        self.CLEAR_THRESHOLD = 0.20
        
        self.sources = defaultdict(lambda: {
            'dst_ips': set(), 'dst_ports': set(),
            'recent_dst_ips': deque(maxlen=50),
            'recent_dst_ports': deque(maxlen=50),
            'packet_count': 0, 'ewma_rate': 0.0,
            'last_ts': 0.0, 'iat_list': [],
            'is_flagged': False,
            'peak_score': 0.0,
            'peak_time': 0.0
        })
        
        self.is_under_attack = False
        self.max_threat_score = 0.0
        self.clean_interval = 10.0
        self.last_cleanup = time.time()
        
        # Threat memory - keeps score high during attack regimes
        self.threat_memory_duration = 10.0  # seconds
        self.last_high_threat_time = 0.0

    def process_packet(self, src_ip: str, dst_ip: str, dst_port: int, proto: int, timestamp: float = None):
        """Called by ipv4_handler.py for every IPv4/TCP/UDP packet."""
        self._update_source(src_ip, dst_ip, dst_port, timestamp)

    def process_arp_request(self, src_ip: str, dst_ip: str, timestamp: float = None):
        """Called by arp_handler.py for every ARP Request (Layer 2 Sweep Detection)."""
        self._update_source(src_ip, dst_ip, dst_port=None, timestamp=timestamp)

    def _get_current_rate(self, src: dict, now: float = None) -> float:
        """Returns the sustained continuous-time decayed packet rate."""
        if now is None:
            now = time.time()
        if src['last_ts'] > 0:
            dt = max(now - src['last_ts'], 0.0)
            return src['ewma_rate'] * math.exp(-dt / self.RATE_TAU)
        return src['ewma_rate']

    def _update_source(self, src_ip, dst_ip, dst_port, timestamp):
        dns_ip = getattr(self.app, 'dns_ip', '10.0.0.254')
        if src_ip == dns_ip:
            return
            
        if timestamp is None:
            timestamp = time.time()
            
        src = self.sources[src_ip]
        if src['last_ts'] > 0:
            dt = timestamp - src['last_ts']
            if 0.0 < dt < 5.0:
                src['iat_list'].append(dt)
                if len(src['iat_list']) > 50:
                    src['iat_list'].pop(0)
            # Continuous-time EWMA rate estimator:
            # Accumulates arrival volume decayed by inter-arrival gap.
            # Sustained packet rate (pps) is tracked without 1/dt micro-burst explosions.
            decay = math.exp(-max(dt, 0.0) / self.RATE_TAU)
            src['ewma_rate'] = (src['ewma_rate'] * decay) + (1.0 / self.RATE_TAU)
        else:
            dt = 0.0
            src['ewma_rate'] = 1.0 / self.RATE_TAU

        src['last_ts'] = timestamp

        # Protocol coexistence: Only record protected target IPs/ports for threat entropy.
        # Concurrent DNS port 53 queries by local carrier hosts must not inflate threat scores.
        if dst_ip != dns_ip:
            src['dst_ips'].add(dst_ip)
            src['recent_dst_ips'].append(dst_ip)

        if dst_port is not None and dst_port != 53:
            is_new_port = dst_port not in src['dst_ports']
            src['dst_ports'].add(dst_port)
            src['recent_dst_ports'].append(dst_port)
            if is_new_port and len(src['dst_ports']) >= 4:
                h_port = self._calculate_empirical_shannon_entropy(src['recent_dst_ports'], capacity=50)
                self.app.logger.info(
                    f"🔍 [L4 Telemetry] Multi-port probe detected from {src_ip} -> port {dst_port} "
                    f"(Total distinct ports: {len(src['dst_ports'])}, H_Port: {h_port:.4f})"
                )
        src['packet_count'] += 1
                
        if time.time() - self.last_cleanup > self.clean_interval:
            self._cleanup_stale_sources()
            self.last_cleanup = time.time()
            
        score = self._evaluate_threat(src, timestamp)
        
        # Track peak score and time
        if score > src['peak_score']:
            src['peak_score'] = score
            src['peak_time'] = timestamp
        
        if score > self.max_threat_score:
            self.max_threat_score = score
            self.last_high_threat_time = timestamp

        # Algorithm 1 Phase 2: Active Table 1 threat session eviction upon threshold breach
        if score >= self.ATTACK_THRESHOLD and not src.get('is_flagged', False):
            src['is_flagged'] = True
            if hasattr(self.app, 'flow_manager') and hasattr(self.app.flow_manager, 'evict_threat_source_from_grace'):
                self.app.flow_manager.evict_threat_source_from_grace(src_ip)
        elif score < self.CLEAR_THRESHOLD and src.get('is_flagged', False):
            src['is_flagged'] = False
            
        if self.max_threat_score > self.ATTACK_THRESHOLD and not self.is_under_attack:
            self.is_under_attack = True
            self.app.logger.warning(f"🚨 [THREAT] Intelligent scan signature detected from {src_ip} (Score: {score:.3f})")
        elif self.max_threat_score < self.CLEAR_THRESHOLD and self.is_under_attack:
            self.is_under_attack = False
            self.app.logger.info("✅ [THREAT] Scan activity normalized. Network state cleared.")

    @staticmethod
    def _calculate_empirical_shannon_entropy(rolling_buffer, capacity: int) -> float:
        """
        True empirical Shannon Entropy bounded in [0.0, 1.0]:
        H = - sum(p_i * log2(p_i)) where p_i = c_i / sum(c_k)
        Normalized by log2(capacity) (fixed address/port capacity threshold).
        If only 1 destination observed (or 0), returns 0.0 explicitly.
        """
        if not rolling_buffer or capacity <= 1:
            return 0.0
        counts = defaultdict(int)
        for item in rolling_buffer:
            counts[item] += 1
        k_seen = len(counts)
        if k_seen <= 1:
            return 0.0
        total = len(rolling_buffer)
        h = 0.0
        for c in counts.values():
            if c > 0:
                p = c / total
                h -= p * math.log2(p)
        denom = math.log2(capacity)
        if denom <= 0.0:
            return 0.0
        return min(max(h / denom, 0.0), 1.0)

    def _evaluate_threat(self, src: dict, now: float = None) -> float:
        """
        Returns a normalized threat score [0.0, 1.0] using dual-signal detection:
        1. Global-sweep signal (information-theoretic entropy across broad IP/port space)
        2. Targeted-burst signal (authentic vertical reconnaissance or focused 2-3 target horizontal probes)
        """
        dns_ip = getattr(self.app, 'dns_ip', '10.0.0.254')
        effective_ips = [ip for ip in src['recent_dst_ips'] if ip != dns_ip]
        if not effective_ips and src['dst_ips']:
            effective_ips = [ip for ip in src['dst_ips'] if ip != dns_ip]
            
        effective_ports = [p for p in src['recent_dst_ports'] if p != 53]
        if not effective_ports and src['dst_ports']:
            effective_ports = [p for p in src['dst_ports'] if p != 53]

        # A. True Empirical Shannon Entropy for Destination IPs
        num_protected = len(self.app.real_to_virtual) if (hasattr(self.app, 'real_to_virtual') and len(self.app.real_to_virtual) > 1) else 16
        ent_ip_norm = self._calculate_empirical_shannon_entropy(effective_ips, capacity=num_protected)
            
        # B. True Empirical Shannon Entropy for Destination Ports
        ent_port_norm = self._calculate_empirical_shannon_entropy(effective_ports, capacity=50)
        
        # C. IAT Coefficient of Variation
        cv = 1.0
        if len(src['iat_list']) >= 5:
            mean_iat = sum(src['iat_list']) / len(src['iat_list'])
            if mean_iat > 0:
                var_iat = sum((x - mean_iat) ** 2 for x in src['iat_list']) / len(src['iat_list'])
                cv = min(math.sqrt(var_iat) / mean_iat, 2.0)
        cv_norm = max(0.0, 1.0 - (cv / 1.5))
        
        # D. Rate normalization using sustained decayed rate
        rate = self._get_current_rate(src, now)
        rate_norm = min(rate / self.RATE_THRESHOLD, 1.0)
        
        # Base entropy score with activity gating for quiescent decay
        activity_gate = min(rate / 0.5, 1.0) if rate < 0.5 else 1.0
        entropy_score = ((0.50 * ent_ip_norm) + (0.20 * ent_port_norm) + (0.10 * cv_norm) + (0.20 * rate_norm)) * activity_gate
        
        # Dual-signal: targeted-burst signal
        # Benign dual-socket flows (e.g. DNS port 53 alongside TCP 5201, or dual application sockets)
        # must NOT trigger targeted alert. Require authentic vertical reconnaissance (n_ports >= 4 or H_port >= 0.35)
        # or targeted horizontal probing across 2-3 protected targets with sustained continuous rate >= 1.0 pps.
        n_ips = len(set(effective_ips))
        n_ports = len(set(effective_ports))
        is_vertical_recon = (n_ports >= 4 or ent_port_norm >= 0.35)
        is_targeted_horizontal = (2 <= n_ips <= 3)
        is_targeted = (
            (is_vertical_recon or is_targeted_horizontal)
            and rate >= 1.0
            and cv < 1.25
        )
        
        if is_targeted:
            # Map rate so >= 1.0 pps reaches >= 0.65, scaling up to 0.95
            targeted_score = min(0.65 + max(0.0, rate - 1.0) / 8.0, 0.95)
            score = max(entropy_score, targeted_score)
        else:
            score = entropy_score

        return min(score, 1.0)

    # Alias for backward-compatibility
    _compute_threat_score = _evaluate_threat

    def _cleanup_stale_sources(self):
        now = time.time()
        to_remove = [ip for ip, data in self.sources.items() if now - data['last_ts'] > self.clean_interval]
        for ip in to_remove:
            del self.sources[ip]

    def get_state(self) -> np.ndarray:
        """
        Returns the unified 5D state vector directly expected by the RL environment:
        [max_ent_ip, max_ent_port, max_rate, max_cv, continuous_threat_intensity].
        """
        max_ent_ip, max_ent_port, max_rate, max_cv = 0.0, 0.0, 0.0, 0.0
        now = time.time()
        num_protected = len(self.app.real_to_virtual) if (hasattr(self.app, 'real_to_virtual') and len(self.app.real_to_virtual) > 1) else 16
        dns_ip = getattr(self.app, 'dns_ip', '10.0.0.254')
        
        for src in self.sources.values():
            effective_ips = [ip for ip in src['recent_dst_ips'] if ip != dns_ip]
            if not effective_ips and src['dst_ips']:
                effective_ips = [ip for ip in src['dst_ips'] if ip != dns_ip]
            effective_ports = [p for p in src['recent_dst_ports'] if p != 53]
            if not effective_ports and src['dst_ports']:
                effective_ports = [p for p in src['dst_ports'] if p != 53]

            e_ip = self._calculate_empirical_shannon_entropy(effective_ips, capacity=num_protected)
            e_port = self._calculate_empirical_shannon_entropy(effective_ports, capacity=50)
            rate = min(self._get_current_rate(src, now) / self.RATE_THRESHOLD, 1.0)
            
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
            
        threat_intensity = self.get_max_intensity()
            
        return np.array([
            max_ent_ip, max_ent_port, max_rate, max_cv, float(threat_intensity)
        ], dtype=np.float32)

    def get_scanned_targets(self):
        """
        Returns a list of Virtual IPs/hosts currently being targeted by the most aggressive scanner.
        Returns hosts whose score exceeds 0.40 OR whose rate exceeds 1.0 during a targeted burst.
        """
        dns_ip = getattr(self.app, 'dns_ip', '10.0.0.254')
        max_score = 0.0
        top_targets = []
        now = time.time()
        
        for src_ip, data in self.sources.items():
            score = self._evaluate_threat(data, now)
            effective_ips = [ip for ip in data['recent_dst_ips'] if ip != dns_ip]
            if not effective_ips and data['dst_ips']:
                effective_ips = [ip for ip in data['dst_ips'] if ip != dns_ip]
            effective_ports = [p for p in data['recent_dst_ports'] if p != 53]
            if not effective_ports and data['dst_ports']:
                effective_ports = [p for p in data['dst_ports'] if p != 53]

            n_ips = len(set(effective_ips))
            n_ports = len(set(effective_ports))
            ent_port_norm = self._calculate_empirical_shannon_entropy(effective_ports, capacity=50)
            rate = self._get_current_rate(data, now)
            is_vertical_recon = (n_ports >= 4 or ent_port_norm >= 0.35)
            is_targeted_horizontal = (2 <= n_ips <= 3)
            is_targeted_burst = ((is_vertical_recon or is_targeted_horizontal) and rate >= 1.0)
            if (score >= self.ATTACK_THRESHOLD or is_targeted_burst) and score >= max_score: 
                max_score = score
                top_targets = list(set(effective_ips))
                
        return top_targets    

    def get_max_intensity(self):
        """Returns the continuous threat intensity with memory effect."""
        max_score = 0.0
        current_time = time.time()
        
        for data in self.sources.values():
            score = self._evaluate_threat(data, current_time)
            
            # Apply threat memory - use peak score if recent
            time_since_peak = current_time - data['peak_time']
            if 0 <= time_since_peak < self.threat_memory_duration:
                # Decay the peak score over time
                memory_factor = 1.0 - (time_since_peak / self.threat_memory_duration)
                memory_score = data['peak_score'] * memory_factor
                score = max(score, memory_score)
            
            if score > max_score:
                max_score = score
        
        return float(max_score)

    def get_flagged_threat_sources(self) -> set:
        """Returns the set of source IPs whose computed threat score currently exceeds ATTACK_THRESHOLD."""
        now = time.time()
        flagged = set()
        for src_ip, data in self.sources.items():
            if self._evaluate_threat(data, now) >= self.ATTACK_THRESHOLD or data.get('is_flagged', False):
                flagged.add(src_ip)
        return flagged
