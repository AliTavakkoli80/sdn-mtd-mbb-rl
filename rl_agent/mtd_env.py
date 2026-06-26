import gymnasium as gym
from gymnasium import spaces
import numpy as np
import math
import time

class MTDEnvironment(gym.Env):
    """
    Q1-Grade Cost-Aware MTD Environment.
    The agent learns to balance Security (disrupting scans) vs. QoS (preserving active TCP flows).
    """
    metadata = {"render_modes": ["human"], "render_fps": 1}

    def __init__(self, app, render_mode=None):
        super(MTDEnvironment, self).__init__()
        self.app = app
        self.render_mode = render_mode
        
        # 3 Actions: 0=HOLD, 1=GLOBAL, 2=TARGETED
        self.action_space = spaces.Discrete(3)
        
        # 7D State: [ent_ip, ent_port, ewma_rate, cv_reg, threat_intensity, time_norm, active_flows]
        self.observation_space = spaces.Box(low=0.0, high=1.0, shape=(7,), dtype=np.float32)
        
        self.last_shuffle_time = time.time()
        self.max_shuffle_interval = 60.0
        
        # Q1 TUNABLE WEIGHTS (Physically meaningful)
        self.W_TIME = 2.0   # Base penalty for network staleness
        self.W_RISK = 8.0   # Multiplier for high-threat staleness (I_t * tau_t)
        self.W_SEC = 10.0   # Reward for successful threat mitigation
        self.W_QOS = 15.0   # Penalty for disrupting active TCP flows
        self.ETA = 0.5      # Precision bonus for Targeted shuffling (50% extra security reward)

    def reset(self, seed=None, options=None):
        super().reset(seed=seed)
        self.last_shuffle_time = time.time()
        return self._get_obs(), {}

    def step(self, action):
        if action == 1:
            self.app.mtd_engine.step(action=1)
            self.last_shuffle_time = time.time()
        elif action == 2:
            self.app.mtd_engine.step(action=2)
            self.last_shuffle_time = time.time()
            
        obs = self._get_obs()
        reward = self._calculate_reward(action, obs)
        return obs, reward, False, False, {"action": action}

    def _get_obs(self):
        # 1-4: Threat metrics
        threat_state = self.app.threat_detector.get_state() 
        
        # INNOVATION 1: Replace binary flag with continuous intensity
        threat_intensity = self.app.threat_detector.get_max_intensity()
        
        # 6: Time since last shuffle
        time_since = time.time() - self.last_shuffle_time
        time_norm = min(time_since / self.max_shuffle_interval, 1.0)
        
        # 7: Active flows
        active_flows = getattr(self.app.flow_manager, 'active_flow_count', 0)
        active_flows_norm = min(active_flows / 100.0, 1.0)
        
        # Construct the 7D vector (Index 4 is now continuous intensity)
        return np.array([
            threat_state[0], threat_state[1], threat_state[2], threat_state[3],
            threat_intensity, time_norm, active_flows_norm
        ], dtype=np.float32)


    def _calculate_reward(self, action, obs):
        """
        Ambiguity-Aware Multi-Objective Reward Function with Control Plane Overhead.
        
        FIX: Staleness penalty only applies when there's actual threat.
        This prevents the agent from shuffling just to reset the timer.
        """
        I_t = obs[4]  # Continuous Threat Intensity (0.0 to 1.0)
        tau_t = obs[5] # Time Staleness (0.0 to 1.0)
        F_t = obs[6]  # Active Flows / Network Load (0.0 to 1.0)
        
        # Calculate Disruption Ratio (D_a)
        total_hosts = max(len(self.app.topology.host_table), 1)
        if action == 0:
            D_a = 0.0
        elif action == 1:
            D_a = 1.0 # Global disrupts 100%
        elif action == 2:
            scanned_targets = self.app.threat_detector.get_scanned_targets()
            D_a = min(len(scanned_targets) / total_hosts, 1.0) 

        # Ambiguity Multiplier (M_a)
        M_a = 1.5 if action == 1 else 1.0

        # Base Control Plane Overhead Penalty
        # Represents the CPU/Bandwidth cost of sending FLOW_MOD messages to switches
        W_OVERHEAD = 2.0 

        # --- MATHEMATICAL REWARD LOGIC ---
        
        # Only penalize staleness when there's actual threat
        # This prevents the agent from shuffling just to reset the timer
        if I_t < 0.1:
            # No significant threat - staleness doesn't matter
            staleness_penalty = 0.0
        else:
            # Threat present - staleness increases risk
            staleness_penalty = (self.W_TIME * tau_t) + (self.W_RISK * I_t * tau_t)
        
        if action == 0: # HOLD
            # Only penalize if there's a threat
            return -staleness_penalty
            
        elif action == 1: # SHUFFLE_GLOBAL
            # High Ambiguity Security Gain - High QoS Cost - Overhead
            security_gain = self.W_SEC * I_t * M_a
            qos_penalty = self.W_QOS * (D_a * F_t)
            return security_gain - qos_penalty - W_OVERHEAD

        elif action == 2: # SHUFFLE_TARGETED
            # Low Ambiguity Security Gain - Low QoS Cost - Overhead
            security_gain = self.W_SEC * I_t * M_a
            qos_penalty = self.W_QOS * (D_a * F_t)
            return security_gain - qos_penalty - W_OVERHEAD
            
        return 0.0

    def _render_human(self, action, reward, obs):
        # 1. Map the 3 actions
        action_names = ["HOLD", "GLOBAL", "TARGETED"]
        action_str = action_names[action] if 0 <= action < 3 else "UNKNOWN"
        
        # 2. Extract the new continuous metrics
        intensity = obs[4]    # Continuous Threat Intensity (0.0 to 1.0)
        time_norm = obs[5]    # Network Staleness (0.0 to 1.0)
        active_flows = obs[6] # Active TCP Flows / Load (0.0 to 1.0)
        
        # 3. Categorize threat intensity for quick visual scanning
        if intensity < 0.3:
            threat_str = "SAFE"
        elif intensity < 0.7:
            threat_str = "SCAN"
        else:
            threat_str = "STORM"
            
        # 4. Print a rich, aligned, and informative line
        # Note: Using {reward:+6.2f} aligns positive and negative numbers perfectly at the decimal
        print(f"[DRL] Act: {action_str:8s} | Threat: {threat_str:5s}({intensity:.2f}) | "
              f"Stale: {time_norm:.2f} | Flows: {active_flows:.2f} | R: {reward:+6.2f}")