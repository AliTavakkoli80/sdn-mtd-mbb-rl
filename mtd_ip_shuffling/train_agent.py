import sys
import time
import numpy as np
from stable_baselines3 import PPO
from stable_baselines3.common.env_checker import check_env
from stable_baselines3.common.callbacks import BaseCallback
from mtd_env import MTDEnvironment

class MockRyuApp:
    def __init__(self):
        self.mtd_engine = MockMTDEngine()
        self.threat_detector = MockThreatDetector()
        self.topology = MockTopology()
        self.flow_manager = MockFlowManager() 
        
class MockMTDEngine:
    def step(self):
        print("   [Network] IP Shuffling Executed!")
        time.sleep(0.01)

class MockThreatDetector:
    def __init__(self):
        self.is_under_attack = False

    def get_state(self):
        # Returns the 5D array expected by the environment
        attack_val = 1.0 if self.is_under_attack else 0.0
        if self.is_under_attack:
            return np.array([0.8, 0.9, 0.7, 0.8, attack_val], dtype=np.float32)
        else:
            return np.array([0.1, 0.1, 0.1, 0.1, attack_val], dtype=np.float32)

class MockTopology:
    def __init__(self):
        self.host_table = {'10.0.0.1': {}, '10.0.0.2': {}}

class MockFlowManager:
    def __init__(self):
        self.active_flow_count = 0 # Simulates network load

class AttackSimulatorCallback(BaseCallback):
    def __init__(self, mock_app, verbose=0):
        super(AttackSimulatorCallback, self).__init__(verbose)
        self.mock_app = mock_app

    def _on_step(self) -> bool:
        if self.num_timesteps % 500 == 0: 
            self.mock_app.threat_detector.is_under_attack = not self.mock_app.threat_detector.is_under_attack
            
            # 🌟 Simulate network load changing (High load during normal traffic, low during scan)
            if self.mock_app.threat_detector.is_under_attack:
                self.mock_app.flow_manager.active_flow_count = 10 
            else:
                self.mock_app.flow_manager.active_flow_count = 80 
                
            state = "STARTED 🚨" if self.mock_app.threat_detector.is_under_attack else "STOPPED ✅"
            print(f"\n--- 🚨 SIMULATION: Attack {state} | Flows: {self.mock_app.flow_manager.active_flow_count} ---")
        return True

if __name__ == "__main__":
    print("Initializing Cost-Aware MTD Gymnasium Environment...")
    mock_app = MockRyuApp()
    env = MTDEnvironment(mock_app, render_mode="human")

    print("Checking environment validity...")
    check_env(env.unwrapped, warn=True)
    print("✅ Environment is valid!\n")

    print("Training Cost-Aware PPO Agent...")
    model = PPO("MlpPolicy", env, verbose=1, learning_rate=0.0003, n_steps=2048)
    callback = AttackSimulatorCallback(mock_app)

    try:
        # Increased steps to allow the agent to learn the complex cost-aware reward
        model.learn(total_timesteps=30000, callback=callback) 
        print("\n✅ Training Complete! Saving model to 'mtd_ppo_agent.zip'")
        model.save("mtd_ppo_agent")
    except KeyboardInterrupt:
        print("\nTraining interrupted. Saving partial model...")
        model.save("mtd_ppo_agent_partial")