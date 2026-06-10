import sys
import time
from stable_baselines3 import PPO
from stable_baselines3.common.env_checker import check_env
from stable_baselines3.common.callbacks import BaseCallback
from mtd_env import MTDEnvironment

# Mock Ryu App for standalone training
class MockRyuApp:
    def __init__(self):
        self.mtd_engine = MockMTDEngine()
        self.threat_detector = MockThreatDetector()
        self.topology = MockTopology()

class MockMTDEngine:
    def step(self):
        print("   [Network] IP Shuffling Executed!")
        time.sleep(0.01) # Reduced from 0.1 to speed up training significantly

class MockThreatDetector:
    def __init__(self):
        self.arp_stats = {'10.0.0.1': {'targets': set()}}
        self.is_under_attack = False

    def get_state(self):
        return {'is_under_attack': self.is_under_attack}

class MockTopology:
    def __init__(self):
        self.host_table = {'10.0.0.1': {}, '10.0.0.2': {}}

# 🛠️ THE FIX: Use a proper Stable-Baselines3 Callback Class
class AttackSimulatorCallback(BaseCallback):
    def __init__(self, mock_app, verbose=0):
        super(AttackSimulatorCallback, self).__init__(verbose)
        self.mock_app = mock_app

    def _on_step(self) -> bool:
        # self.num_timesteps is guaranteed to exist in BaseCallback
        if self.num_timesteps % 500 == 0: 
            self.mock_app.threat_detector.is_under_attack = not self.mock_app.threat_detector.is_under_attack
            state = "STARTED 🚨" if self.mock_app.threat_detector.is_under_attack else "STOPPED ✅"
            print(f"\n--- 🚨 SIMULATION: Attack {state} at step {self.num_timesteps} ---")
        return True

if __name__ == "__main__":
    print("Initializing MTD Gymnasium Environment...")
    mock_app = MockRyuApp()
    env = MTDEnvironment(mock_app, render_mode="human")

    print("Checking environment validity...")
    check_env(env.unwrapped, warn=True)
    print("✅ Environment is valid!\n")

    print("Training PPO Agent... (Press Ctrl+C to stop)")
    # PPO hyperparameters
    model = PPO("MlpPolicy", env, verbose=1, learning_rate=0.0003, n_steps=2048)

    # Instantiate the callback
    callback = AttackSimulatorCallback(mock_app)

    try:
        # Train for 10,000 steps
        model.learn(total_timesteps=10000, callback=callback)
        print("\n✅ Training Complete! Saving model to 'mtd_ppo_agent.zip'")
        model.save("mtd_ppo_agent")
    except KeyboardInterrupt:
        print("\nTraining interrupted by user. Saving partial model...")
        model.save("mtd_ppo_agent_partial")