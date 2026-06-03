import random
from ryu.lib import hub
from . import constants as const

class MTDEngine:
    """
    Manages Moving Target Defense IP Shuffling.
    Supports threat-responsive acceleration for DRL integration.
    """
    def __init__(self, app, normal_interval=300, attack_interval=5):
        self.app = app
        self.real_ips = list(app.real_to_virtual.keys())
        
        # Virtual IP pool for shuffling
        self.virtual_pool = [f"10.0.100.{i}" for i in range(10, 60)]
        
        # Dynamic timing parameters
        self.normal_interval = normal_interval   # 5 minutes (low overhead)
        self.attack_interval = attack_interval   # 5 seconds (aggressive defense)
        self.current_interval = normal_interval
        
        # State tracking
        self.current_mapping = app.real_to_virtual.copy()
        self.last_shuffle_time = 0
        self.is_accelerated = False
        
        self.app.logger.info(
            f"[MTD Engine] Initialized | Normal: {normal_interval}s | Attack: {attack_interval}s"
        )

    def start(self):
        """Starts the adaptive shuffling loop."""
        hub.spawn(self._adaptive_shuffle_loop)

    def _adaptive_shuffle_loop(self):
        """
        Polls threat state and adjusts shuffle frequency dynamically.
        Uses 1-second sleep increments to allow immediate reaction to threats.
        """
        self.app.logger.info("[MTD Engine] Adaptive shuffling started")
        while True:
            # Query threat detector for current state
            state = self.app.threat_detector.get_state()
            under_attack = state.get('is_under_attack', False)
            
            # Adjust interval based on threat state
            if under_attack and not self.is_accelerated:
                self.current_interval = self.attack_interval
                self.is_accelerated = True
                self.app.logger.warning(
                    f"⚡ [MTD] ATTACK DETECTED - Accelerating shuffle to {self.attack_interval}s"
                )
                # Execute immediate shuffle upon attack detection
                self.step()
                
            elif not under_attack and self.is_accelerated:
                self.current_interval = self.normal_interval
                self.is_accelerated = False
                self.app.logger.info(
                    f"✅ [MTD] Threat cleared - Returning to normal shuffle ({self.normal_interval}s)"
                )
                # Execute immediate shuffle when attack ends to reset mappings
                self.step()
                
            else:
                # Normal scheduled shuffle
                self.step()
            
            # 🛠️ INTERRUPTIBLE SLEEP: Sleep 1 second at a time
            for _ in range(self.current_interval):
                hub.sleep(1)
                # Check if threat status changed during sleep
                current_state = self.app.threat_detector.get_state()
                if current_state.get('is_under_attack', False) != self.is_accelerated:
                    break # Break early to adjust interval and shuffle immediately

    def step(self, action=None):
        """
        Executes one MTD shuffle step.
        Future DRL agent will pass specific actions here.
        """
        self.app.logger.info("🎲 [MTD] Executing IP Shuffle...")
        new_mapping = self._generate_random_mapping()
        self.apply_mapping(new_mapping)
        
    def _generate_random_mapping(self):
        """Generates random 1-to-1 Real→Virtual mapping."""
        available = self.virtual_pool.copy()
        random.shuffle(available)
        
        mapping = {}
        for real_ip in self.real_ips:
            if not available:
                self.app.logger.error("[MTD] Virtual IP pool exhausted!")
                break
            mapping[real_ip] = available.pop()
        return mapping

    def apply_mapping(self, new_mapping):
        """Safely transitions network to new IP mapping."""
        self._flush_old_flows()
        
        self.current_mapping = new_mapping
        self.app.real_to_virtual = new_mapping
        self.app.virtual_to_real = {v: k for k, v in new_mapping.items()}
        
        self.app.logger.info("✅ [MTD] New mapping applied:")
        for r, v in sorted(new_mapping.items()):
            self.app.logger.info(f"   {r} ⇄ {v}")

    def _flush_old_flows(self):
        """Removes all PRIORITY_TRANSLATION flows from all switches."""
        for dpid, dp in self.app.topology.datapath_list.items():
            self.app.flow_manager.flush_translation_flows(dp)