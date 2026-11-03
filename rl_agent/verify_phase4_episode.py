#!/usr/bin/env python3
"""
verify_phase4_episode.py - 1-Episode Physical Testbed Verification for Phase 4
Evaluates the fine-tuned PPO model across the 42-step multi-regime Containernet timeline.
Records step-by-step trajectory: Step, Regime, Threat Intensity, Scanned Targets, Action, Reward.
"""

import os
import sys
import time
import numpy as np
import pandas as pd
from stable_baselines3 import PPO

# Path configuration
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(SCRIPT_DIR)
sys.path.insert(0, SCRIPT_DIR)
sys.path.insert(0, PROJECT_DIR)

from containernet_env import ContainernetEnv

def run_verification_episode():
    model_path = os.path.join(SCRIPT_DIR, "mtd_ppo_agent_real.zip")
    print(f"Loading synchronized PPO model: {model_path}")
    model = PPO.load(model_path, device="cpu")

    env = ContainernetEnv(step_duration=0.6, max_steps=42, render_mode=None)

    # 1. Start continuous high background carrier traffic across testbed
    print("\n🚦 Starting continuous background traffic across testbed...")
    env._send_command_to_topology({'action': 'set_traffic_load', 'level': 'high'})
    time.sleep(1.0)

    print("\n" + "=" * 80)
    print("🚀 EXECUTING 1-EPISODE 42-STEP MULTI-REGIME VERIFICATION RUN")
    print("=" * 80)

    obs, _ = env.reset()
    action_names = {0: "HOLD", 1: "GLOBAL", 2: "TARGETED"}
    step_records = []

    for step_idx in range(1, 43):
        # Extract pre-step observation features
        I_t = float(obs[4])
        tau_t = float(obs[5])
        F_t = float(obs[6])
        n_scanned = len(env._last_scanned_targets) if hasattr(env, '_last_scanned_targets') else int(round(float(obs[7]) * 16.0))

        # PPO policy prediction
        action, _states = model.predict(obs, deterministic=True)
        action = int(action)

        current_regime = env._current_regime or "quiescent"

        # Step real testbed environment
        obs, reward, terminated, truncated, info = env.step(action, enable_mbb=True)

        record = {
            'Step': step_idx,
            'Regime': current_regime,
            'Threat_Intensity': round(I_t, 3),
            'Targets': n_scanned,
            'Load_Ft': round(F_t, 3),
            'Action': action_names.get(action, str(action)),
            'Reward': round(reward, 2)
        }
        step_records.append(record)

        print(f"Step {step_idx:2d} | Regime: {current_regime:14s} | "
              f"I_t: {I_t:4.2f} | Targets: {n_scanned:2d} | "
              f"F_t: {F_t:4.2f} | Action: {action_names.get(action):8s} | "
              f"Reward: {reward:+6.2f}")

        if terminated or truncated:
            break

    env.close()

    df = pd.DataFrame(step_records)
    csv_path = os.path.join(SCRIPT_DIR, "phase4_1episode_verification.csv")
    df.to_csv(csv_path, index=False)
    print("\n" + "=" * 80)
    print(f"✅ 1-Episode Verification Complete. Saved trace to {csv_path}")
    print("=" * 80)

    print("\nPolicy Distribution Across Regimes:")
    summary = df.groupby(['Regime', 'Action']).size().unstack(fill_value=0)
    print(summary)

if __name__ == "__main__":
    run_verification_episode()
