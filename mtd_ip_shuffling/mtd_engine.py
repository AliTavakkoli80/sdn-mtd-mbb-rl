import random
import time
import os
import numpy as np
import ipaddress # 🌟 Added for dynamic subnet calculation
from ryu.lib import hub
from . import constants as const

# Import PPO for inference
try:
    from stable_baselines3 import PPO
    RL_AVAILABLE = True
except ImportError:
    RL_AVAILABLE = False

class MTDEngine:
    """
    Manages Moving Target Defense IP Shuffling.
    Supports AI-driven decision making via a trained PPO model.
    """
    def __init__(self, app, normal_interval=300, attack_interval=5):
        self.app = app
        self.real_ips = list(app.real_to_virtual.keys())
        
        # 🌟 DYNAMIC POOL GENERATION: Calculates the subnet based on real IPs
        self.virtual_pool = self._generate_virtual_pool()
        
        self.normal_interval = normal_interval
        self.attack_interval = attack_interval
        self.current_interval = normal_interval
        self.max_shuffle_interval = float(normal_interval)
        
        self.current_mapping = app.real_to_virtual.copy()
        self.last_shuffle_time = time.time()
        self.is_accelerated = False
        
        # 🧠 AI MODEL LOADING
        self.use_ai = False
        self.model = None
        
        if RL_AVAILABLE:
            # Look for the model in the project root (where you run ryu-manager)
            model_path = os.path.join(os.getcwd(), "mtd_ppo_agent.zip")
            if os.path.exists(model_path):
                try:
                    self.model = PPO.load(model_path)
                    self.use_ai = True
                    self.app.logger.info("🧠 [MTD Engine] AI Model loaded successfully! Switching to DRL Inference.")
                except Exception as e:
                    self.app.logger.error(f"❌ [MTD Engine] Failed to load AI model: {e}. Falling back to heuristics.")
            else:
                self.app.logger.warning("⚠️ [MTD Engine] mtd_ppo_agent.zip not found. Falling back to heuristic logic.")
        else:
            self.app.logger.warning("⚠️ [MTD Engine] Stable-Baselines3 not installed. Using heuristic logic.")

        self.app.logger.info(
            f"[MTD Engine] Initialized | Normal: {normal_interval}s | Attack: {attack_interval}s | AI: {self.use_ai}"
        )

    def _generate_virtual_pool(self):
        """
        🌟 Dynamically generates a pool of virtual IPs based on the subnet of the real IPs.
        It finds the smallest common network that contains all real IPs, ensuring the 
        virtual pool stays in the same local subnet for smoother ARP/L2 handling.
        """
        if not self.real_ips:
            self.app.logger.warning("[MTD Engine] No real IPs found. Virtual pool is empty.")
            return []
            
        try:
            # 1. Calculate the common subnet for all real IPs using bitwise XOR
            ip_ints = [int(ipaddress.IPv4Address(ip)) for ip in self.real_ips]
            xor_sum = 0
            for i in range(1, len(ip_ints)):
                xor_sum |= (ip_ints[0] ^ ip_ints[i])
                
            if xor_sum == 0:
                prefix_len = 32
            else:
                prefix_len = 32 - xor_sum.bit_length()
                
            # 2. Cap the prefix length at /24 to ensure a sufficiently large pool (254 IPs)
            # If the hosts are on different /24 subnets, it will dynamically expand to cover them
            prefix_len = min(prefix_len, 24)
            
            # 3. Create the network object
            network = ipaddress.IPv4Network(f"{self.real_ips[0]}/{prefix_len}", strict=False)
            
            # 4. Build the pool, excluding the actual real IPs
            pool = []
            for ip in network.hosts(): # .hosts() automatically excludes network/broadcast addresses
                ip_str = str(ip)
                if ip_str not in self.real_ips:
                    pool.append(ip_str)
                    
            self.app.logger.info(f"[MTD Engine] 🌐 Dynamically generated virtual pool: {network} ({len(pool)} available IPs)")
            return pool
            
        except Exception as e:
            self.app.logger.error(f"[MTD Engine] Failed to generate virtual pool dynamically: {e}")
            # Fallback to a default pool if something goes wrong
            return [f"10.0.100.{i}" for i in range(10, 60)]

    def start(self):
        """Starts the adaptive shuffling loop."""
        hub.spawn(self._adaptive_shuffle_loop)

    def _adaptive_shuffle_loop(self):
        """The main control loop. Routes to AI or Heuristic based on model availability."""
        self.app.logger.info("[MTD Engine] Control loop started")
        
        while True:
            if self.use_ai:
                self._ai_inference_step()
                # Poll the AI every 2 seconds for rapid response
                hub.sleep(2) 
            else:
                self._heuristic_step()
                # Fallback sleep logic
                for _ in range(self.current_interval):
                    hub.sleep(1)
                    state = self.app.threat_detector.get_state()
                    if state.get('is_under_attack', False) != self.is_accelerated:
                        break

    def _ai_inference_step(self):
        """Queries the live network state and asks the AI what to do."""
        obs = self._get_live_obs()
        
        action, _states = self.model.predict(obs, deterministic=True)
        
        # 🛡️ SAFETY GUARD: The PPO model is currently undertrained and may output 
        # random actions due to the Sim2Real gap. We force it to only shuffle if 
        # the threat detector actually confirms an attack (obs[4] is the threat_flag).
        if action == 1 and obs[4] > 0.5: 
            self.app.logger.info(f"🧠 [AI DECISION] SHUFFLE | Obs: {np.round(obs, 2)}")
            self.step()
            self.last_shuffle_time = time.time()
        else:
            # HOLD - Do nothing, save network overhead
            pass 

    def _heuristic_step(self):
        """The original hardcoded logic (Fallback)."""
        state = self.app.threat_detector.get_state()
        under_attack = state.get('is_under_attack', False)
        
        if under_attack and not self.is_accelerated:
            self.current_interval = self.attack_interval
            self.is_accelerated = True
            self.app.logger.warning(f"⚡ [Heuristic] ATTACK DETECTED - Accelerating to {self.attack_interval}s")
            self.step()
            self.last_shuffle_time = time.time()
            
        elif not under_attack and self.is_accelerated:
            self.current_interval = self.normal_interval
            self.is_accelerated = False
            self.app.logger.info(f"✅ [Heuristic] Threat cleared - Returning to {self.normal_interval}s")
            self.step()
            self.last_shuffle_time = time.time()
            
        else:
            self.step()
            self.last_shuffle_time = time.time()

    def _get_live_obs(self):
        """Builds the exact same 7D State Vector used during training."""
        # 1-5: Threat metrics
        threat_state = self.app.threat_detector.get_state()
        
        # 6: Time since last shuffle
        time_since = time.time() - self.last_shuffle_time
        time_norm = min(time_since / self.max_shuffle_interval, 1.0)
        
        # 7: Active flows (QoS Cost)
        active_flows = getattr(self.app.flow_manager, 'active_flow_count', 0)
        active_flows_norm = min(active_flows / 100.0, 1.0)
        
        return np.append(threat_state, [time_norm, active_flows_norm]).astype(np.float32)

    def step(self, action=None):
        """Executes the actual network shuffle."""
        self.app.logger.info("🎲 [MTD] Executing IP Shuffle...")
        new_mapping = self._generate_random_mapping()
        self.apply_mapping(new_mapping)
        
    def _generate_random_mapping(self):
        available = self.virtual_pool.copy()
        random.shuffle(available)
        mapping = {}
        for real_ip in self.real_ips:
            if not available: break
            mapping[real_ip] = available.pop()
        return mapping

    def apply_mapping(self, new_mapping):
        self._flush_old_flows()
        self.current_mapping = new_mapping
        self.app.real_to_virtual = new_mapping
        self.app.virtual_to_real = {v: k for k, v in new_mapping.items()}
        self.app.logger.info("✅ [MTD] New mapping applied:")
        for r, v in sorted(new_mapping.items()):
            self.app.logger.info(f"   {r} ⇄ {v}")

    def _flush_old_flows(self):
        for dpid, dp in self.app.topology.datapath_list.items():
            self.app.flow_manager.flush_translation_flows(dp)