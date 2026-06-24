import sys
import time
import numpy as np
from stable_baselines3 import PPO
from stable_baselines3.common.env_checker import check_env
from stable_baselines3.common.callbacks import BaseCallback
from mtd_env import MTDEnvironment

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
        action_name = "GLOBAL" if action == 1 else "TARGETED"
        
        # Calculate real mock impact for logging
        if action == 1:
            disrupted = self.app.flow_manager.active_flow_count
        else:
            # Targeted only disrupts flows to scanned hosts
            scanned = self.app.threat_detector.get_scanned_targets()
            total_hosts = max(len(self.app.topology.host_table), 1)
            disrupted = int(self.app.flow_manager.active_flow_count * (len(scanned) / total_hosts))
            
        print(f"   [Mock Engine] Executed {action_name} Shuffle. Disrupted {disrupted} active flows.")
        time.sleep(0.01) # Simulate processing delay

class MockThreatDetector:
    def __init__(self):
        self.is_under_attack = False
        self.intensity = 0.0
        self.scanned_hosts = []

    def get_state(self):
        # Add slight noise to simulate real-world sensor imperfections
        noise = np.random.normal(0, 0.05)
        if self.is_under_attack:
            base = np.array([0.8, 0.9, 0.7, 0.8, self.intensity])
        else:
            base = np.array([0.1, 0.1, 0.1, 0.1, 0.0])
        return np.clip(base + noise, 0.0, 1.0).astype(np.float32)

    def get_max_intensity(self):
        return np.clip(self.intensity + np.random.normal(0, 0.02), 0.0, 1.0)

    def get_scanned_targets(self):
        return self.scanned_hosts

class MockTopology:
    def __init__(self):
        # 10 protected hosts
        self.host_table = {f'10.0.0.{i}': {'mac': '00:00:00:00:00:00', 'dpid': 1, 'port': i} for i in range(1, 11)}

class MockFlowManager:
    def __init__(self):
        self.active_flow_count = 0

# ==========================================
# TRAINING CALLBACK & SCENARIO SIMULATOR
# ==========================================

class AttackSimulatorCallback(BaseCallback):
    def __init__(self, mock_app, verbose=0):
        super(AttackSimulatorCallback, self).__init__(verbose)
        self.mock_app = mock_app
        self.scenario = 0
        self.scenario_name = "INIT"
        self.step_in_scenario = 0
        self.scenario_duration = 500
        self.scenario_rewards = []
        
        # Count actions per scenario
        self.action_counts = {0: 0, 1: 0, 2: 0}

    def _on_step(self) -> bool:
        last_reward = self.locals.get('rewards', [0])[0]
        self.scenario_rewards.append(last_reward)
        
        # Track which action was chosen
        action = self.locals.get('actions', [0])[0]
        self.action_counts[action] += 1
        
        self.step_in_scenario += 1
        
        if self.step_in_scenario >= self.scenario_duration:
            self.step_in_scenario = 0
            self.scenario += 1
            
            # Print action distribution for completed scenario
            if self.scenario > 1:
                avg_r = np.mean(self.scenario_rewards[:-1])
                total = sum(self.action_counts.values())
                hold_pct = (self.action_counts[0] / max(total, 1)) * 100
                global_pct = (self.action_counts[1] / max(total, 1)) * 100
                target_pct = (self.action_counts[2] / max(total, 1)) * 100
                
                print(f"   [{self.scenario_name}] Avg Reward: {avg_r:+.2f}")
                print(f"   Actions: HOLD={hold_pct:.0f}% | GLOBAL={global_pct:.0f}% | TARGETED={target_pct:.0f}%")
                
            # Reset counters
            self.scenario_rewards = []
            self.action_counts = {0: 0, 1: 0, 2: 0}
            
            # Setup next scenario
            if self.scenario % 3 == 1:
                self.scenario_name = "SCENARIO A: TARGETED ATTACK"
                self.mock_app.threat_detector.is_under_attack = True
                self.mock_app.threat_detector.intensity = 0.95 
                self.mock_app.threat_detector.scanned_hosts = ['10.0.0.11']
                self.mock_app.flow_manager.active_flow_count = 80 
                print(f"\n{'='*60}")
                print(f"[SCENARIO A] TARGETED ATTACK")
                print(f"   Intensity: 0.95 | Scanned: 1/10 | Flows: 80")
                print(f"   Expected Policy: ACTION 2 (TARGETED) to save QoS")
                print(f"{'='*60}")
                
            elif self.scenario % 3 == 2:
                self.scenario_name = "SCENARIO B: GLOBAL STORM"
                self.mock_app.threat_detector.is_under_attack = True
                self.mock_app.threat_detector.intensity = 0.90 
                self.mock_app.threat_detector.scanned_hosts = [f'10.0.0.{i}' for i in range(1, 11)]
                self.mock_app.flow_manager.active_flow_count = 40 
                print(f"\n{'='*60}")
                print(f"[SCENARIO B] GLOBAL STORM")
                print(f"   Intensity: 0.90 | Scanned: 10/10 | Flows: 40")
                print(f"   Expected Policy: ACTION 1 (GLOBAL) for Max Ambiguity")
                print(f"{'='*60}")
                
            else:
                self.scenario_name = "SCENARIO C: SAFE & STALE"
                self.mock_app.threat_detector.is_under_attack = False
                self.mock_app.threat_detector.intensity = 0.0
                self.mock_app.threat_detector.scanned_hosts = []
                self.mock_app.flow_manager.active_flow_count = 90 
                print(f"\n{'='*60}")
                print(f"[SCENARIO C] SAFE & STALE")
                print(f"   Intensity: 0.00 | Scanned: 0/10 | Flows: 90")
                print(f"   Expected Policy: ACTION 0 (HOLD) to preserve QoS")
                print(f"{'='*60}")
                
        return True

# ==========================================
# MAIN EXECUTION
# ==========================================

if __name__ == "__main__":
    print("Initializing Physics-Informed MTD Gymnasium Environment...")
    mock_app = MockRyuApp()
    env = MTDEnvironment(mock_app, render_mode=None) 

    print("Checking environment validity...")
    check_env(env.unwrapped, warn=True)
    print("Environment is valid!\n")

    print("Training Physics-Informed PPO Agent (500k steps)...")
    print("   (Using custom callback for scenario simulation and logging)\n")
    
    model = PPO("MlpPolicy", env, verbose=0, learning_rate=0.0003, n_steps=2048)
    callback = AttackSimulatorCallback(mock_app)

    try:
        model.learn(total_timesteps=500000, callback=callback) 
        print("\n" + "="*60)
        print("TRAINING COMPLETE!")
        print("="*60)
        print("Saving model to 'mtd_ppo_agent.zip'")
        model.save("mtd_ppo_agent")
        print("You can now run 'python generate_paper_plots.py' to visualize the policy!")
    except KeyboardInterrupt:
        print("\n\nTraining interrupted by user.")
        print("Saving partial model to 'mtd_ppo_agent_partial.zip'...")
        model.save("mtd_ppo_agent_partial")