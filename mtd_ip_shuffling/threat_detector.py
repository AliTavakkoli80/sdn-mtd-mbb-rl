import time
from collections import defaultdict

class ThreatDetector:
    """
    Monitors network traffic to detect anomalies like ARP Scanning.
    This class provides the 'State' observations for the future DRL Agent.
    """
    def __init__(self, app):
        self.app = app
        # Tracking ARP requests per source IP
        # Format: {src_ip: {'targets': set(), 'last_seen': float}}
        self.arp_stats = defaultdict(lambda: {'targets': set(), 'last_seen': 0})
        
        self.WINDOW_SIZE = 10.0  # Sliding window of 10 seconds
        self.SCAN_THRESHOLD = 10 # 10 unique targets in 10 seconds = scan
        
        # State flags
        self.is_under_attack = False

    def process_arp_request(self, src_ip, dst_ip):
        """Called by ARPHandler whenever an ARP Request is seen."""
        now = time.time()
        stats = self.arp_stats[src_ip]
        
        # Reset the target set if the sliding window has expired
        if now - stats['last_seen'] > self.WINDOW_SIZE:
            stats['targets'] = set()
            
        stats['last_seen'] = now
        
        # Ignore normal background noise like DNS requests
        if dst_ip == self.app.dns_ip:
            return

        # Add the target IP to the set of unique targets
        stats['targets'].add(dst_ip)
        unique_targets = len(stats['targets'])
        
        # Check if threshold is breached
        if unique_targets >= self.SCAN_THRESHOLD:
            if not self.is_under_attack:
                self.app.logger.warning(f"🚨 [THREAT] ARP Scan detected from {src_ip}! Targeted {unique_targets} unique IPs in {self.WINDOW_SIZE}s")
                self.is_under_attack = True
        else:
            # Clear flag if scan rate drops below threshold
            if self.is_under_attack:
                self.app.logger.info(f"✅ [THREAT] ARP Scan from {src_ip} has stopped.")
                self.is_under_attack = False

    def get_state(self):
        """
        Returns the current state of the environment for the DRL Agent.
        (We will expand this later as we build the RL model)
        """
        return {
            'is_under_attack': 1 if self.is_under_attack else 0,
            'time_since_last_shuffle': 0 # Placeholder for later
        }