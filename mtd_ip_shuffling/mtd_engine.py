import random
import time
import os
import numpy as np
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
        
        self.virtual_pool = [f"10.0.100.{i}" for i in range(10, 60)]
        
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
        
        # deterministic=True ensures the AI picks the absolute best action 
        # without random exploration (which is only for training).
        action, _states = self.model.predict(obs, deterministic=True)
        
        if action == 1: # SHUFFLE
            self.app.logger.info(f"🧠 [AI DECISION] SHUFFLE | Obs: {np.round(obs, 2)}")
            self.step()
            self.last_shuffle_time = time.time()
        else:
            # HOLD - Do nothing, save network overhead
            # We log this less frequently to avoid spamming the console
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
        """Builds the exact same State Vector used during training."""
        # 1. is_under_attack
        state = self.app.threat_detector.get_state()
        is_under_attack = float(state.get('is_under_attack', 0))
        
        # 2. scan_intensity
        max_targets = 0
        for stats in self.app.threat_detector.arp_stats.values():
            if len(stats['targets']) > max_targets:
                max_targets = len(stats['targets'])
        scan_intensity = min(max_targets / 20.0, 1.0)
        
        # 3. time_since_last_shuffle
        time_since = time.time() - self.last_shuffle_time
        time_norm = min(time_since / self.max_shuffle_interval, 1.0)
        
        # 4. active_connections
        active_conns = len(self.app.topology.host_table) / 10.0 
        active_conns = min(active_conns, 1.0)
        
        return np.array([is_under_attack, scan_intensity, time_norm, active_conns], dtype=np.float32)

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