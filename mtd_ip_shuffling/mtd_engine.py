import random
import ipaddress
from ryu.lib import hub
from . import constants as const

class MTDEngine:
    """
    Manages the Moving Target Defense IP Shuffling.
    In the future, this class will act as the 'Environment' for the DRL Agent.
    """
    def __init__(self, app, shuffle_interval=30):
        self.app = app
        self.shuffle_interval = shuffle_interval
        
        # Extract the real IPs we need to protect
        self.real_ips = list(app.real_to_virtual.keys())
        
        # Define a pool of Virtual IPs to draw from
        # (Later, you could generate these dynamically from a subnet)
        self.virtual_pool = [f"10.0.100.{i}" for i in range(10, 50)]
        
        # The current active mapping
        self.current_mapping = app.real_to_virtual.copy()
        
        self.app.logger.info(f"[MTD Engine] Initialized with {len(self.real_ips)} real IPs and {len(self.virtual_pool)} virtual IPs.")

    def start(self):
        """Starts the background thread. (Later, the DRL agent will dictate the loop)."""
        hub.spawn(self._time_based_shuffle_loop)

    def _time_based_shuffle_loop(self):
        """Baseline: Shuffle every X seconds."""
        self.app.logger.info(f"[MTD Engine] Starting periodic shuffle (every {self.shuffle_interval}s)")
        while True:
            hub.sleep(self.shuffle_interval)
            self.step() # The RL Agent will eventually call `step(action)` directly

    def step(self, action=None):
        """
        Executes one step of MTD. 
        Currently uses random action. Later, the DRL agent will pass a specific action here.
        """
        self.app.logger.info("🎲 [MTD] Triggering IP Shuffle...")
        
        # 1. Get new mapping (Action)
        new_mapping = self._generate_random_mapping()
        
        # 2. Apply the mapping to the network
        self.apply_mapping(new_mapping)
        
        # 3. (Placeholder) Calculate Reward for RL
        # reward = self._calculate_reward()
        # return next_state, reward, done

    def _generate_random_mapping(self):
        """Generates a random 1-to-1 mapping of Real IPs to Virtual IPs."""
        available_virtuals = self.virtual_pool.copy()
        random.shuffle(available_virtuals)
        
        mapping = {}
        for real_ip in self.real_ips:
            if not available_virtuals:
                self.app.logger.error("[MTD] Virtual IP pool exhausted!")
                break
            mapping[real_ip] = available_virtuals.pop()
            
        return mapping

    def apply_mapping(self, new_mapping):
        """Safely transitions the network to the new IP mapping."""
        # 1. Flush old translation flows from all switches
        self._flush_old_flows()
        
        # 2. Update the controller's internal dictionaries
        self.current_mapping = new_mapping
        self.app.real_to_virtual = new_mapping
        self.app.virtual_to_real = {v: k for k, v in new_mapping.items()}
        
        self.app.logger.info(f"✅ [MTD] New mapping applied:")
        for r, v in new_mapping.items():
            self.app.logger.info(f"   {r} ⇄ {v}")
            
        # TODO (Next Step): Send Gratuitous ARPs to update host caches

    def _flush_old_flows(self):
        """Removes all PRIORITY_TRANSLATION flows from all switches."""
        for dpid, dp in self.app.topology.datapath_list.items():
            self.app.flow_manager.flush_translation_flows(dp)