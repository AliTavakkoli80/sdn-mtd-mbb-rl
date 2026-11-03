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
import math
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
        ryu_api_url=None,
        cmd_socket_host="127.0.0.1",
        cmd_socket_port=9999,
        step_duration=0.6,
        max_steps=42,
        render_mode=None
    ):
        super().__init__()
        
        self.ryu_api_url = ryu_api_url or os.getenv("RYU_API_URL", "http://127.0.0.1:8088")
        self.cmd_socket_host = cmd_socket_host
        self.cmd_socket_port = cmd_socket_port
        self.step_duration = step_duration
        self.max_steps = max_steps
        self.render_mode = render_mode
        self._current_regime = None
        
        # Action space: HOLD, GLOBAL, TARGETED
        self.action_space = spaces.Discrete(3)
        
        # Observation space: 8D vector (MUST match mock environment!)
        self.observation_space = spaces.Box(
            low=0.0, high=1.0, shape=(8,), dtype=np.float32
        )
        
        # State tracking
        self.last_shuffle_time = time.time()
        self.max_shuffle_interval = 60.0
        self.step_count = 0
        self.episode_count = 0
        
        # Reward weights (MUST match mtd_env.py exactly!)
        self.W_TIME = 2.0
        self.W_RISK = 25.0
        self.W_SEC = 20.0
        self.W_QOS = 10.0
        self.W_FLOW = 4.0
        self.W_OVERHEAD = self.W_FLOW
        self.ETA = 0.5
        self.load_ewma = None
        
        # Scanned targets tracking (from Ryu state)
        self._last_scanned_targets = []
        
        # Verify connectivity
        self._verify_connectivity()
        
        # Enable fine-tuning mode in Ryu
        self._enable_fine_tune_mode()
    
    def _enable_fine_tune_mode(self):
        """Tell Ryu to disable its internal AI loop during fine-tuning."""
        try:
            response = requests.post(
                f"{self.ryu_api_url}/mtd/finetune_mode",
                json={'enabled': True},
                timeout=5
            )
            if response.status_code == 200:
                data = response.json()
                print(f"✅ {data['message']}")
            else:
                print(f"⚠️  Failed to enable fine-tune mode: {response.text}")
        except Exception as e:
            print(f"⚠️  Could not enable fine-tune mode: {e}")
            print("   Ryu's internal AI loop may interfere with fine-tuning!")
    
    def close(self):
        """Clean up resources and disable fine-tuning mode."""
        print("🔌 Closing ContainernetEnv...")
        try:
            # Disable fine-tuning mode so Ryu can resume normal operation
            requests.post(
                f"{self.ryu_api_url}/mtd/finetune_mode",
                json={'enabled': False},
                timeout=5
            )
            print("✅ Fine-tuning mode disabled - Ryu resumed normal operation")
        except Exception as e:
            print(f"⚠️  Could not disable fine-tune mode: {e}")
    
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
    
    def _clear_threat_in_ryu(self):
        """Request Ryu to clear its threat detector sources."""
        try:
            requests.post(f"{self.ryu_api_url}/mtd/clear_threat", timeout=2)
        except Exception:
            pass

    def reset(self, seed=None, options=None):
        """Reset the environment state (does NOT restart the topology)."""
        super().reset(seed=seed)
        self.episode_count += 1
        self.step_count = 0
        self.last_shuffle_time = time.time()
        self._last_scanned_targets = []
        self._current_regime = None
        self.load_ewma = None
        
        print(f"\n{'='*60}")
        print(f"🔄 [ContainernetEnv] Reset (episode {self.episode_count})")
        print(f"{'='*60}")
        
        # Stop any residual attacks and clear Ryu threat state
        self._send_command_to_topology({'action': 'stop_attacks'})
        self._clear_threat_in_ryu()
        time.sleep(1.0)
        
        # Get initial observation
        obs = self._get_obs()
        print(f"✅ Environment ready. Initial state: {np.round(obs, 2)}")
        return obs, {}
    
    def step(self, action, enable_mbb=True):
        """
        Execute one step in the real environment.
        
        1. Send action to Ryu (if shuffle) with enable_mbb parameter
        2. Cycle through multi-regime traffic dynamics
        3. Wait for network dynamics
        4. Observe new state
        5. Calculate reward
        """
        self.step_count += 1
        
        # 1. Execute the agent's action
        if action == 1:
            if self.render_mode == "human":
                print(f"   🎲 Agent chose GLOBAL shuffle (MBB={enable_mbb})")
            self._send_action_to_ryu(1, enable_mbb=enable_mbb)
            self.last_shuffle_time = time.time()
        elif action == 2:
            if self.render_mode == "human":
                print(f"   🎯 Agent chose TARGETED shuffle (MBB={enable_mbb})")
            self._send_action_to_ryu(2, enable_mbb=enable_mbb)
            self.last_shuffle_time = time.time()
        else:
            if self.render_mode == "human":
                print(f"   ⏸️  Agent chose HOLD")
        
        # 2. Cycle through multi-regime traffic dynamics across realistic horizon
        cycle_step = self.step_count % self.max_steps
        if cycle_step < 5:
            if cycle_step == 0 or self._current_regime != "quiescent":
                self._current_regime = "quiescent"
                if self.render_mode == "human":
                    print(f"   🕊️  [ContainernetEnv] Entering Quiescent Settling Regime (No Attacks)")
                self._send_command_to_topology({'action': 'stop_attacks'})
                self._clear_threat_in_ryu()
        elif cycle_step < 11:
            if self._current_regime != "targeted":
                self._current_regime = "targeted"
                if self.render_mode == "human":
                    print(f"   🎯 [ContainernetEnv] Entering Targeted Port-Scan Regime (hosts: 10.0.0.2, 10.0.0.3, ports: 80, 22, 443, 8080, 21)")
                self._send_command_to_topology({
                    'action': 'attack_targeted',
                    'targets': ['10.0.0.2', '10.0.0.3'],
                    'ports': [80, 22, 443, 8080, 21]
                })
        elif cycle_step < 15:
            if self._current_regime != "global":
                self._current_regime = "global"
                if self.render_mode == "human":
                    print(f"   ⛈️  [ContainernetEnv] Entering Global Subnet Sweep Regime")
                self._send_command_to_topology({'action': 'attack_arp'})
        else:
            if self._current_regime != "post_quiescent":
                self._current_regime = "post_quiescent"
                if self.render_mode == "human":
                    print(f"   🕊️  [ContainernetEnv] Entering Post-Attack Quiescent Regime (>15s Grace Expiration Window)")
                self._send_command_to_topology({'action': 'stop_attacks'})
                time.sleep(0.3)
                self._clear_threat_in_ryu()
            elif cycle_step == 16:
                self._clear_threat_in_ryu()
        
        # 3. Wait for network dynamics to play out
        time.sleep(self.step_duration)
        
        # 4. Observe new state
        obs = self._get_obs()
        
        # 5. Calculate reward
        reward = self._calculate_reward(action, obs)
        
        # Episode terminates after N steps
        terminated = False
        truncated = (self.step_count >= self.max_steps)
        
        if self.render_mode == "human":
            action_names = ["HOLD", "GLOBAL", "TARGETED"]
            print(f"   Step {self.step_count:3d}: {action_names[action]:8s} | "
                  f"Reward: {reward:+6.2f} | Threat: {obs[4]:.2f} | "
                  f"Flows: {obs[6]:.2f}")
        
        return obs, reward, terminated, truncated, {"action": action}
    
    def _get_obs(self):
        """Query Ryu REST API for the current 8D observation vector."""
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
            
            # Active flows / network load with EWMA smoothing (prevents post-flush zeroing)
            # In Containernet with 16-host fabric, 8 sessions = 32 flows
            curr_load = min(flows / 32.0, 1.0)
            if not hasattr(self, 'load_ewma') or self.load_ewma is None:
                self.load_ewma = curr_load
            else:
                self.load_ewma = 0.7 * self.load_ewma + 0.3 * curr_load
            flows_norm = float(np.clip(self.load_ewma, 0.0, 1.0))
            
            # Target cardinality (index 7)
            scanned = len(self._last_scanned_targets)
            mapping = data.get('real_to_virtual', {})
            total_hosts = float(len(mapping)) if (mapping and len(mapping) > 0) else getattr(self, '_total_hosts', 16.0)
            self._total_hosts = total_hosts
            scanned_norm = min(scanned / total_hosts, 1.0)
            
            # Construct 8D vector (MUST match mtd_env.py _get_obs() exactly!)
            obs = np.array([
                threat_state[0],  # ent_ip
                threat_state[1],  # ent_port
                threat_state[2],  # ewma_rate
                threat_state[3],  # cv
                intensity,        # threat_intensity (index 4)
                time_norm,        # time_staleness
                flows_norm,       # active_flows
                scanned_norm      # target_cardinality (index 7)
            ], dtype=np.float32)
            
            return obs
            
        except Exception as e:
            print(f"⚠️  Failed to get state from Ryu: {e}")
            # Return zero vector on failure
            return np.zeros(8, dtype=np.float32)
    
    def _calculate_reward(self, action, obs):
        """
        Calculate reward using the EXACT same unified continuous formula as mtd_env.py:
        R(s_t, a_t) =
          0.0                                                           if a_t = 0 and I_t < 0.15
          -(W_TIME * tau_t + W_RISK * I_t * tau_t)                     if a_t = 0 and I_t >= 0.15
          W_SEC * I_t * M_a(r) - W_QoS * (D_a * F_t) - W_FLOW * Cost(a_t)  if a_t in {1, 2}
        where:
          W_SEC = 20.0, W_QoS = 10.0, W_FLOW = 4.0, W_RISK = 25.0, W_TIME = 2.0
          r = n_scanned / 16.0 (target scanning ratio, r = 0 if no targets detected)
          M_2(r) = 2.0 * exp(-2.5 * r) if n_scanned > 0 else 0.0  (defense precision decays continuously)
          M_1(r) = 1.0 + 1.0 * (1.0 - exp(-3.0 * r)) if n_scanned > 0 else 1.5 (global entropy maximization)
          Cost(0) = 0.0, Cost(1) = 1.0, Cost(2) = max(0.15, r)
          D_1 = 1.0, D_2 = r
        """
        I_t = float(obs[4])   # Threat intensity
        tau_t = float(obs[5]) # Time staleness
        F_t = float(obs[6])   # Active flows
        
        if action == 0:
            if I_t < 0.15:
                return 0.0
            return -(self.W_TIME * tau_t + self.W_RISK * I_t * tau_t)

        elif action in (1, 2):
            total_hosts = getattr(self, '_total_hosts', 16.0)
            scanned = len(self._last_scanned_targets) if self._last_scanned_targets else int(round(float(obs[7]) * total_hosts)) if len(obs) > 7 else 0
            r = float(scanned) / total_hosts
            
            # Continuous multipliers and costs grounded in defense precision and entropy
            if action == 1:  # GLOBAL
                cost_a = 1.0
                D_a = 1.0
                M_a = (1.0 + 1.0 * (1.0 - math.exp(-3.0 * r))) if scanned > 0 else 1.5
            else:  # TARGETED (action == 2)
                cost_a = max(0.15, r)
                D_a = r
                M_a = (2.0 * math.exp(-2.5 * r)) if scanned > 0 else 0.0

            if I_t < 0.15:
                return -10.0 - (self.W_FLOW * cost_a)

            sec_gain = self.W_SEC * I_t * M_a
            return sec_gain - (self.W_QOS * (D_a * F_t)) - (self.W_FLOW * cost_a)
        
        return 0.0
    
    def _send_action_to_ryu(self, action, enable_mbb=True):
        """Send action to Ryu via REST API."""
        try:
            response = requests.post(
                f"{self.ryu_api_url}/mtd/action",
                json={'action': action, 'enable_mbb': enable_mbb},
                timeout=5
            )
            if response.status_code == 200:
                if self.render_mode == "human":
                    print(f"   ✅ Ryu executed action {action}")
            else:
                print(f"   ❌ Ryu returned {response.status_code}: {response.text}")
        except Exception as e:
            print(f"   ❌ Failed to send action to Ryu: {e}")
    
    def _send_command_to_topology(self, cmd_dict):
        """Send command to Containernet topology via socket."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(10)
            s.connect((self.cmd_socket_host, self.cmd_socket_port))
            s.sendall(json.dumps(cmd_dict).encode())
            response = json.loads(s.recv(4096).decode())
            s.close()
            
            if response.get('status') == 'ok':
                if self.render_mode == "human":
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