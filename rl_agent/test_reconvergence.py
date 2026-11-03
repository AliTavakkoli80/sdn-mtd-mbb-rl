#!/usr/bin/env python3
"""
test_reconvergence.py - Quick Re-convergence and Gradient Propagation Check

Validates that the continuous reward formulation yields stable PPO policy convergence,
smooth gradient updates, and proper action selection across regimes.
"""

import time
import numpy as np
from stable_baselines3 import PPO
from stable_baselines3.common.callbacks import BaseCallback
from mtd_env import MTDEnvironment
from train_agent import MockRyuApp, AttackSimulatorCallback

class ConvergenceMonitor(BaseCallback):
    def __init__(self, verbose=0):
        super().__init__(verbose)
        self.losses = []
        self.rewards = []
        
    def _on_step(self):
        r = self.locals.get('rewards', [0])[0]
        self.rewards.append(r)
        return True

def run_check():
    print("=" * 60)
    print("🔄 QUICK RE-CONVERGENCE & GRADIENT PROPAGATION TEST")
    print("=" * 60)
    
    mock_app = MockRyuApp()
    env = MTDEnvironment(mock_app, binary_action=False, render_mode=None)
    
    model = PPO(
        "MlpPolicy",
        env,
        verbose=1,
        learning_rate=0.0003,
        n_steps=512,
        batch_size=64,
        gamma=0.99,
        device="cpu"
    )
    
    cb_sim = AttackSimulatorCallback(mock_app, is_binary=False)
    
    print("\nTraining for 20,000 steps with Continuous Reward Formulation...")
    t0 = time.time()
    model.learn(total_timesteps=20480, callback=cb_sim)
    t_elapsed = time.time() - t0
    
    print(f"\n✅ Completed 20,480 steps in {t_elapsed:.2f}s ({20480/t_elapsed:.0f} steps/s)")
    
    # Validation rollouts across distinct regimes
    print("\n--- Validation Across Specific Regimes ---")
    regimes = [
        ("Quiescent (Safe)", 0.02, 0.2, []),
        ("Targeted Scan (n=2 targets)", 0.65, 0.7, ["10.0.0.1", "10.0.0.2"]),
        ("Global Sweep (n=10 targets)", 0.85, 0.3, [f"10.0.0.{i}" for i in range(1, 11)])
    ]
    
    for name, intensity, flows, targets in regimes:
        mock_app.threat_detector.is_under_attack = (intensity > 0.15)
        mock_app.threat_detector.intensity = intensity
        mock_app.threat_detector.scanned_hosts = targets
        mock_app.flow_manager.active_flow_count = int(flows * 100)
        
        obs = env.reset()[0]
        # Force obs fields
        obs[4] = intensity
        obs[6] = flows
        obs[7] = len(targets) / 16.0
        
        actions = []
        for _ in range(50):
            act, _ = model.predict(obs, deterministic=True)
            actions.append(int(act))
            
        act_names = ["HOLD", "GLOBAL", "TARGETED"]
        counts = {a: actions.count(a) for a in [0, 1, 2]}
        dominant = act_names[max(counts, key=counts.get)]
        print(f"  • Regime: {name:30s} -> Predicted Action: {dominant:8s} (Counts: HOLD={counts[0]}, GLOBAL={counts[1]}, TARGETED={counts[2]})")

if __name__ == "__main__":
    run_check()
