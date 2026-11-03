import sys
import os
import time
import math
import csv
import shutil
import numpy as np
from datetime import datetime
from stable_baselines3 import PPO
from stable_baselines3.common.env_checker import check_env
from stable_baselines3.common.callbacks import BaseCallback
from mtd_env import MTDEnvironment

# ==========================================
# PATH CONFIGURATION (Absolute Paths)
# ==========================================
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
RUNS_DIR = os.path.join(SCRIPT_DIR, "runs")

# ==========================================
# MOCK SDN ENVIRONMENT COMPONENTS
# ==========================================

class MockRyuApp:
    def __init__(self):
        self.mtd_engine = MockMTDEngine(self)
        self.threat_detector = MockThreatDetector()
        self.topology = MockTopology()
        self.flow_manager = MockFlowManager()

class MockMTDEngine:
    def __init__(self, app):
        self.app = app
        # Simulate 10 protected hosts
        self.current_mapping = {f'10.0.0.{i}': f'10.0.100.{i}' for i in range(1, 11)}

    def step(self, action=1):
        # Fast execution without sleeping for high-speed simulation
        if action == 1:
            self.current_mapping = {f'10.0.0.{i}': f'10.0.{np.random.randint(100, 200)}.{i}' for i in range(1, 11)}
        elif action == 2:
            scanned = self.app.threat_detector.get_scanned_targets()
            for host in scanned:
                if host in self.current_mapping:
                    self.current_mapping[host] = f'10.0.{np.random.randint(100, 200)}.{host.split(".")[-1]}'

class MockThreatDetector:
    def __init__(self):
        self.is_under_attack = False
        self.intensity = 0.0
        self.scanned_hosts = []

    def get_state(self):
        noise = np.random.normal(0, 0.01, size=5)
        if not self.is_under_attack or self.intensity < 0.1:
            base = np.array([0.02, 0.02, 0.02, 0.02, 0.0], dtype=np.float32)
        else:
            n_scanned = len(self.scanned_hosts)
            if n_scanned <= 3:
                # Targeted Scans: H_IP in [0.05, 0.40], H_Port in [0.0, 0.25], I_t follows self.intensity
                ent_ip = float(np.random.uniform(0.05, 0.40))
                ent_port = float(np.random.uniform(0.0, 0.25))
                rate = float(np.random.uniform(0.10, 0.80))
                cv_norm = float(np.random.uniform(0.0, 0.60))
                intensity = float(np.clip(self.intensity, 0.20, 0.85))
            else:
                # Global Sweeps: H_IP in [0.45, 1.0], H_Port in [0.0, 0.25], I_t follows self.intensity
                ent_ip = float(np.random.uniform(0.45, 1.0))
                ent_port = float(np.random.uniform(0.0, 0.25))
                rate = float(np.random.uniform(0.20, 1.0))
                cv_norm = float(np.random.uniform(0.0, 0.60))
                intensity = float(np.clip(self.intensity, 0.30, 1.0))

            base = np.array([ent_ip, ent_port, rate, cv_norm, intensity], dtype=np.float32)
        return np.clip(base + noise, 0.0, 1.0).astype(np.float32)

    def get_max_intensity(self):
        return float(np.clip(self.intensity, 0.0, 1.0))

    def get_scanned_targets(self):
        return list(self.scanned_hosts)

class MockTopology:
    def __init__(self):
        # 10 protected hosts
        self.host_table = {f'10.0.0.{i}': {'mac': '00:00:00:00:00:00', 'dpid': 1, 'port': i} for i in range(1, 11)}

class MockFlowManager:
    def __init__(self):
        self.active_flow_count = 0

# ==========================================
# TRAINING CALLBACK & 5-REGIME SIMULATOR
# ==========================================

class AttackSimulatorCallback(BaseCallback):
    """
    Simulates 5 realistic network regimes during training:
      1. Quiescent: I_t in [0.0, 0.08], scanned = 0, F_t in [0.20, 0.95]
      2. Targeted Scan + High Load: I_t in [0.65, 0.95], scanned = 1-2, F_t in [0.70, 0.95]
      3. Targeted Scan + Low Load: I_t in [0.65, 0.95], scanned = 1-2, F_t in [0.10, 0.35]
      4. Volumetric Global Sweep + Low/Mod Load: I_t in [0.75, 1.0], scanned = 8-10, F_t in [0.10, 0.45]
      5. Volumetric Global Sweep + High Load: I_t in [0.75, 1.0], scanned = 8-10, F_t in [0.75, 0.95]
    """
    def __init__(self, mock_app, is_binary=False, verbose=0):
        super(AttackSimulatorCallback, self).__init__(verbose)
        self.mock_app = mock_app
        self.is_binary = is_binary
        self.scenario = 0
        self.scenario_name = "INIT"
        self.step_in_scenario = 0
        self.scenario_duration = 250
        self.scenario_rewards = []
        self.action_counts = {0: 0, 1: 0, 2: 0}
        self._setup_regime(0)

    def _setup_regime(self, regime_idx):
        regime = regime_idx % 6
        if regime in (0, 3):
            # 1. Quiescent
            self.scenario_name = "Quiescent"
            self.mock_app.threat_detector.is_under_attack = False
            self.mock_app.threat_detector.intensity = float(np.random.uniform(0.0, 0.08))
            self.mock_app.threat_detector.scanned_hosts = []
            self.mock_app.flow_manager.active_flow_count = int(np.random.uniform(20, 95))
        elif regime == 1:
            # 2. Targeted Scan + High Load (Targeted saves QoS & flow churn)
            self.scenario_name = "Targeted Scan + High Load"
            self.mock_app.threat_detector.is_under_attack = True
            self.mock_app.threat_detector.intensity = float(np.random.uniform(0.28, 0.65))
            n_targets = np.random.choice([1, 2, 3])
            self.mock_app.threat_detector.scanned_hosts = [f'10.0.0.{i}' for i in range(1, n_targets + 1)]
            self.mock_app.flow_manager.active_flow_count = int(np.random.uniform(70, 95))
        elif regime == 2:
            # 3. Volumetric Global Sweep + Low/Mod Load (Global maximizes entropy)
            self.scenario_name = "Volumetric Global + Low/Mod Load"
            self.mock_app.threat_detector.is_under_attack = True
            self.mock_app.threat_detector.intensity = float(np.random.uniform(0.35, 0.95))
            n_targets = np.random.choice([8, 9, 10])
            self.mock_app.threat_detector.scanned_hosts = [f'10.0.0.{i}' for i in range(1, n_targets + 1)]
            self.mock_app.flow_manager.active_flow_count = int(np.random.uniform(10, 35))
        elif regime == 4:
            # 4. Targeted Scan + Low/Mod Load
            self.scenario_name = "Targeted Scan + Low/Mod Load"
            self.mock_app.threat_detector.is_under_attack = True
            self.mock_app.threat_detector.intensity = float(np.random.uniform(0.25, 0.60))
            n_targets = np.random.choice([1, 2])
            self.mock_app.threat_detector.scanned_hosts = [f'10.0.0.{i}' for i in range(1, n_targets + 1)]
            self.mock_app.flow_manager.active_flow_count = int(np.random.uniform(25, 60))
        elif regime == 5:
            # 5. Volumetric Global Sweep + High Load
            self.scenario_name = "Volumetric Global + High Load"
            self.mock_app.threat_detector.is_under_attack = True
            self.mock_app.threat_detector.intensity = float(np.random.uniform(0.35, 0.95))
            n_targets = np.random.choice([8, 9, 10])
            self.mock_app.threat_detector.scanned_hosts = [f'10.0.0.{i}' for i in range(1, n_targets + 1)]
            self.mock_app.flow_manager.active_flow_count = int(np.random.uniform(70, 95))

    def _on_step(self) -> bool:
        last_reward = self.locals.get('rewards', [0])[0]
        self.scenario_rewards.append(last_reward)
        action = self.locals.get('actions', [0])[0]
        self.action_counts[action] = self.action_counts.get(action, 0) + 1
        self.step_in_scenario += 1
        
        if self.step_in_scenario >= self.scenario_duration:
            self.step_in_scenario = 0
            self.scenario += 1
            
            # Print periodically every 20 scenarios (5,000 steps)
            if self.scenario % 20 == 0:
                avg_r = np.mean(self.scenario_rewards) if self.scenario_rewards else 0.0
                total = sum(self.action_counts.values())
                hold_pct = (self.action_counts.get(0, 0) / max(total, 1)) * 100
                global_pct = (self.action_counts.get(1, 0) / max(total, 1)) * 100
                target_pct = (self.action_counts.get(2, 0) / max(total, 1)) * 100
                act_str = f"HOLD={hold_pct:2.0f}% GLOBAL={global_pct:2.0f}%" + (f" TARGETED={target_pct:2.0f}%" if not self.is_binary else "")
                print(f"   [{self.num_timesteps:6d} steps | {self.scenario_name:32s}] AvgR: {avg_r:+5.2f} | {act_str}")
            
            self.scenario_rewards = []
            self.action_counts = {0: 0, 1: 0, 2: 0}
            regime_idx = self.scenario % 6
            self._setup_regime(regime_idx)
            
        return True

# ==========================================
# CSV LOGGER FOR TRAINING CONVERGENCE
# ==========================================

class CSVLoggerCallback(BaseCallback):
    def __init__(self, filename, verbose=0):
        super().__init__(verbose)
        self.filename = filename
        self.file = None
        self.writer = None

    def _on_training_start(self) -> None:
        os.makedirs(os.path.dirname(self.filename), exist_ok=True)
        self.file = open(self.filename, 'w', newline='')
        self.writer = csv.writer(self.file)
        self.writer.writerow(['timestep', 'reward'])

    def _on_step(self) -> bool:
        reward = self.locals['rewards'][0]
        timestep = self.num_timesteps
        self.writer.writerow([timestep, reward])
        if timestep % 10000 == 0:
            self.file.flush()
        return True
    
    def _on_training_end(self) -> None:
        if self.file:
            self.file.close()

# ==========================================
# MAIN EXECUTION
# ==========================================

def train_models():
    # 1. Create Unique Run Folder based on Timestamp
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    run_name = f"run_{timestamp}"
    RUN_DIR = os.path.join(RUNS_DIR, run_name)
    os.makedirs(RUN_DIR, exist_ok=True)
    
    print("=" * 70)
    print(f"🚀 STARTING MULTI-REGIME SIMULATION TRAINING")
    print(f"📁 Run Directory: {RUN_DIR}")
    print("=" * 70)

    # -------------------------------------------------------------
    # MODEL 1: Proposed 3-Action QoS-Aware DRL-MTD
    # -------------------------------------------------------------
    print("\n[1/2] Training Proposed 3-Action QoS-Aware Agent (300,000 steps on CPU)...")
    mock_app_3act = MockRyuApp()
    env_3act = MTDEnvironment(mock_app_3act, binary_action=False, render_mode=None)
    check_env(env_3act.unwrapped, warn=True)

    model_3act = PPO(
        "MlpPolicy",
        env_3act,
        verbose=0,
        learning_rate=0.0003,
        n_steps=2048,
        batch_size=64,
        gamma=0.99,
        device="cpu"
    )

    cb_scenario_3act = AttackSimulatorCallback(mock_app_3act, is_binary=False)
    cb_logger_3act = CSVLoggerCallback(os.path.join(RUN_DIR, "training_convergence.csv"))

    t0 = time.time()
    model_3act.learn(total_timesteps=300000, callback=[cb_scenario_3act, cb_logger_3act])
    t_elapsed_3act = time.time() - t0

    model_3act_path = os.path.join(RUN_DIR, "mtd_ppo_agent.zip")
    model_3act.save(model_3act_path)
    shutil.copy(model_3act_path, os.path.join(SCRIPT_DIR, "mtd_ppo_agent.zip"))
    shutil.copy(model_3act_path, os.path.join(SCRIPT_DIR, "mtd_ppo_agent_real.zip"))
    shutil.copy(model_3act_path, os.path.join(RUN_DIR, "mtd_ppo_agent_real.zip"))
    print(f"✅ Proposed model trained in {t_elapsed_3act:.1f}s ({300000/t_elapsed_3act:.0f} steps/s)")
    print(f"   Saved to: {model_3act_path}")
    print(f"   Copied to: {os.path.join(SCRIPT_DIR, 'mtd_ppo_agent.zip')} and mtd_ppo_agent_real.zip")

    # -------------------------------------------------------------
    # MODEL 2: Binary-Action Baseline DRL-MTD (Action space: HOLD, GLOBAL)
    # -------------------------------------------------------------
    print("\n[2/2] Training Binary-Action Baseline Agent (300,000 steps on CPU)...")
    mock_app_bin = MockRyuApp()
    env_bin = MTDEnvironment(mock_app_bin, binary_action=True, render_mode=None)
    check_env(env_bin.unwrapped, warn=True)

    model_bin = PPO(
        "MlpPolicy",
        env_bin,
        verbose=0,
        learning_rate=0.0003,
        n_steps=2048,
        batch_size=64,
        gamma=0.99,
        device="cpu"
    )

    cb_scenario_bin = AttackSimulatorCallback(mock_app_bin, is_binary=True)
    cb_logger_bin = CSVLoggerCallback(os.path.join(RUN_DIR, "training_convergence_binary.csv"))

    t0 = time.time()
    model_bin.learn(total_timesteps=300000, callback=[cb_scenario_bin, cb_logger_bin])
    t_elapsed_bin = time.time() - t0

    model_bin_path = os.path.join(RUN_DIR, "mtd_ppo_binary_baseline.zip")
    model_bin.save(model_bin_path)
    shutil.copy(model_bin_path, os.path.join(SCRIPT_DIR, "mtd_ppo_binary_baseline.zip"))
    print(f"✅ Binary model trained in {t_elapsed_bin:.1f}s ({300000/t_elapsed_bin:.0f} steps/s)")
    print(f"   Saved to: {model_bin_path}")
    print(f"   Copied to: {os.path.join(SCRIPT_DIR, 'mtd_ppo_binary_baseline.zip')}")

    print("\n" + "=" * 70)
    print("🎉 ALL MODELS SUCCESSFULLY TRAINED AND SAVED!")
    print("=" * 70)

if __name__ == "__main__":
    train_models()
