"""
containernet_env.py - Real SDN Gymnasium Environment for Sim-to-Real Fine-Tuning

This environment connects to an already-running Containernet topology via:
  - REST API (http://127.0.0.1:8080) for observations and actions
  - Command socket (127.0.0.1:9999) for triggering attacks/traffic

The topology must be started separately with:
  sudo python3 containernet_topos/finetune_topo.py
"""

import os
import sys
import time
import json
import socket
import numpy as np
import gymnasium as gym
from gymnasium import spaces
import requests

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


class ContainernetEnv(gym.Env):
    """
    Real SDN environment for Sim-to-Real fine-tuning.
    
    Action Space:
        0 = HOLD (do nothing, preserve QoS)
        1 = GLOBAL shuffle (maximum security)
        2 = TARGETED shuffle (balanced)
    
    Observation Space (7D):
        [ent_ip, ent_port, ewma_rate, cv, threat_intensity, time_staleness, active_flows]
    
    This matches the mock environment EXACTLY to enable seamless fine-tuning.
    """
    
    metadata = {"render_modes": ["human"], "render_fps": 1}
    
    def __init__(
        self,
        ryu_api_url="http://127.0.0.1:8080",
        cmd_socket_host="127.0.0.1",
        cmd_socket_port=9999,
        step_duration=8.0,           # Seconds to wait after each action
        attack_probability=0.3,      # Probability of launching attack each step
        render_mode=None
    ):
        super().__init__()
        
        self.ryu_api_url = ryu_api_url
        self.cmd_socket_host = cmd_socket_host
        self.cmd_socket_port = cmd_socket_port
        self.step_duration = step_duration
        self.attack_probability = attack_probability
        self.render_mode = render_mode
        
        # Action space: HOLD, GLOBAL, TARGETED
        self.action_space = spaces.Discrete(3)
        
        # Observation space: 7D vector (MUST match mock environment!)
        self.observation_space = spaces.Box(
            low=0.0, high=1.0, shape=(7,), dtype=np.float32
        )
        
        # State tracking
        self.last_shuffle_time = time.time()
        self.max_shuffle_interval = 60.0
        self.step_count = 0
        self.episode_count = 0
        
        # Reward weights (MUST match mtd_env.py exactly!)
        self.W_TIME = 2.0
        self.W_RISK = 8.0
        self.W_SEC = 10.0
        self.W_QOS = 15.0
        
        # Scanned targets tracking (from Ryu state)
        self._last_scanned_targets = []
        
        # Verify connectivity
        self._verify_connectivity()
    
    def _verify_connectivity(self):
        """Verify that both Ryu API and command socket are accessible."""
        # Check Ryu REST API
        try:
            r = requests.get(f"{self.ryu_api_url}/mtd/state", timeout=5)
            if r.status_code != 200:
                raise ConnectionError(f"Ryu API returned {r.status_code}")
            print(f"✅ Connected to Ryu REST API at {self.ryu_api_url}")
        except Exception as e:
            raise ConnectionError(
                f"Cannot connect to Ryu REST API: {e}\n"
                f"Make sure Ryu is running: PYTHONPATH=. ryu-manager mtd_ip_shuffling.app"
            )
        
        # Check command socket
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((self.cmd_socket_host, self.cmd_socket_port))
            s.close()
            print(f"✅ Connected to command socket at {self.cmd_socket_host}:{self.cmd_socket_port}")
        except Exception as e:
            raise ConnectionError(
                f"Cannot connect to command socket: {e}\n"
                f"Make sure topology is running: sudo python3 containernet_topos/finetune_topo.py"
            )
    
    def reset(self, seed=None, options=None):
        """Reset the environment state (does NOT restart the topology)."""
        super().reset(seed=seed)
        self.episode_count += 1
        self.step_count = 0
        self.last_shuffle_time = time.time()
        self._last_scanned_targets = []
        
        print(f"\n{'='*60}")
        print(f"🔄 [ContainernetEnv] Reset (episode {self.episode_count})")
        print(f"{'='*60}")
        
        # Get initial observation
        obs = self._get_obs()
        
        print(f"✅ Environment ready. Initial state: {np.round(obs, 2)}")
        
        return obs, {}
    
    def step(self, action):
        """
        Execute one step in the real environment.
        
        1. Send action to Ryu (if shuffle)
        2. Optionally trigger an attack
        3. Wait for network dynamics
        4. Observe new state
        5. Calculate reward
        """
        self.step_count += 1
        
        # 1. Execute the agent's action
        if action == 1:
            print(f"   🎲 Agent chose GLOBAL shuffle")
            self._send_action_to_ryu(1)
            self.last_shuffle_time = time.time()
        elif action == 2:
            print(f"   🎯 Agent chose TARGETED shuffle")
            self._send_action_to_ryu(2)
            self.last_shuffle_time = time.time()
        else:
            print(f"   ⏸️  Agent chose HOLD")
        
        # 2. Optionally trigger an attack (environment dynamics)
        if np.random.random() < self.attack_probability:
            attack_type = np.random.choice(['attack_arp', 'attack_syn', 'attack_dns'])
            print(f"   🚨 Launching {attack_type}...")
            self._send_command_to_topology({'action': attack_type})
        
        # 3. Wait for network dynamics to play out
        time.sleep(self.step_duration)
        
        # 4. Observe new state
        obs = self._get_obs()
        
        # 5. Calculate reward
        reward = self._calculate_reward(action, obs)
        
        # Episode terminates after N steps
        terminated = False
        truncated = (self.step_count >= 50)  # 50 steps per episode
        
        if self.render_mode == "human":
            action_names = ["HOLD", "GLOBAL", "TARGETED"]
            print(f"   Step {self.step_count}: {action_names[action]} | "
                  f"Reward: {reward:+.2f} | Threat: {obs[4]:.2f} | "
                  f"Flows: {obs[6]:.2f}")
        
        return obs, reward, terminated, truncated, {"action": action}
    
    def _get_obs(self):
        """Query Ryu REST API for the current 7D observation vector."""
        try:
            response = requests.get(f"{self.ryu_api_url}/mtd/state", timeout=5)
            data = response.json()
            
            threat_state = np.array(data['threat_state'], dtype=np.float32)
            intensity = float(data['intensity'])
            flows = int(data['active_flows'])
            
            # Update scanned targets for reward calculation
            self._last_scanned_targets = data.get('scanned_targets', [])
            
            # Time staleness
            time_since = time.time() - self.last_shuffle_time
            time_norm = min(time_since / self.max_shuffle_interval, 1.0)
            
            # Normalize flows (same as mock)
            flows_norm = min(flows / 100.0, 1.0)
            
            # Construct 7D vector (MUST match mtd_env.py _get_obs() exactly!)
            obs = np.array([
                threat_state[0],  # ent_ip
                threat_state[1],  # ent_port
                threat_state[2],  # ewma_rate
                threat_state[3],  # cv
                intensity,        # threat_intensity (index 4)
                time_norm,        # time_staleness
                flows_norm        # active_flows
            ], dtype=np.float32)
            
            return obs
            
        except Exception as e:
            print(f"⚠️  Failed to get state from Ryu: {e}")
            # Return zero vector on failure
            return np.zeros(7, dtype=np.float32)
    
    def _calculate_reward(self, action, obs):
        """
        Calculate reward using the EXACT same formula as mtd_env.py.
        This ensures the fine-tuned agent maintains the same learned behavior.
        """
        I_t = obs[4]   # Threat intensity
        tau_t = obs[5] # Time staleness
        F_t = obs[6]   # Active flows
        
        # Disruption ratio (approximate using scanned targets)
        # In real env, we assume 10 hosts total (same as mock)
        total_hosts = 10
        if action == 0:
            D_a = 0.0
        elif action == 1:
            D_a = 1.0  # Global disrupts 100%
        elif action == 2:
            scanned = len(self._last_scanned_targets)
            D_a = min(scanned / total_hosts, 1.0)
        
        M_a = 1.5 if action == 1 else 1.0
        W_OVERHEAD = 2.0
        
        if action == 0:  # HOLD
            return -(self.W_TIME * tau_t) - (self.W_RISK * I_t * tau_t)
        elif action == 1:  # GLOBAL
            security_gain = self.W_SEC * I_t * M_a
            qos_penalty = self.W_QOS * (D_a * F_t)
            return security_gain - qos_penalty - W_OVERHEAD
        elif action == 2:  # TARGETED
            security_gain = self.W_SEC * I_t * M_a
            qos_penalty = self.W_QOS * (D_a * F_t)
            return security_gain - qos_penalty - W_OVERHEAD
        
        return 0.0
    
    def _send_action_to_ryu(self, action):
        """Send action to Ryu via REST API."""
        try:
            response = requests.post(
                f"{self.ryu_api_url}/mtd/action",
                json={'action': action},
                timeout=5
            )
            if response.status_code == 200:
                print(f"   ✅ Ryu executed action {action}")
            else:
                print(f"   ❌ Ryu returned {response.status_code}: {response.text}")
        except Exception as e:
            print(f"   ❌ Failed to send action to Ryu: {e}")
    
    def _send_command_to_topology(self, cmd_dict):
        """Send command to Containernet topology via socket."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((self.cmd_socket_host, self.cmd_socket_port))
            s.sendall(json.dumps(cmd_dict).encode())
            response = json.loads(s.recv(4096).decode())
            s.close()
            
            if response.get('status') == 'ok':
                print(f"   ✅ Topology executed: {cmd_dict.get('action')}")
            else:
                print(f"   ❌ Topology error: {response.get('message')}")
            
            return response
        except Exception as e:
            print(f"   ❌ Failed to send command to topology: {e}")
            return {'status': 'error', 'message': str(e)}
    
    def close(self):
        """Clean up resources (does NOT stop the topology)."""
        print("🔌 Closing ContainernetEnv (topology remains running)")