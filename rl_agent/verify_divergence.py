#!/usr/bin/env python3
"""
verify_divergence.py - Computes parameter divergence between simulation base model
(mtd_ppo_agent.zip) and fine-tuned testbed model (mtd_ppo_agent_real.zip).
"""

import os
import sys
import torch
import numpy as np
from stable_baselines3 import PPO

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
MOCK_PATH = os.path.join(SCRIPT_DIR, "mtd_ppo_agent.zip")
REAL_PATH = os.path.join(SCRIPT_DIR, "mtd_ppo_agent_real.zip")

def main():
    if not os.path.exists(MOCK_PATH):
        print(f"Error: {MOCK_PATH} not found.")
        sys.exit(1)
    if not os.path.exists(REAL_PATH):
        print(f"Error: {REAL_PATH} not found.")
        sys.exit(1)

    print("=" * 70)
    print("🔬 PPO PARAMETER DIVERGENCE AUDIT (SIMULATION VS. FINE-TUNED REAL)")
    print("=" * 70)
    print(f"Base Simulation Model:  {MOCK_PATH}")
    print(f"Fine-Tuned Real Model: {REAL_PATH}")
    print("-" * 70)

    model_sim = PPO.load(MOCK_PATH, device="cpu")
    model_real = PPO.load(REAL_PATH, device="cpu")

    params_sim = dict(model_sim.policy.named_parameters())
    params_real = dict(model_real.policy.named_parameters())

    total_params = 0
    total_l2_diff = 0.0
    cosine_sims = []

    print(f"{'Layer / Parameter Name':42s} | {'L2 Diff':10s} | {'Cosine Sim':10s} | {'Relative Change':15s}")
    print("-" * 85)

    for name in params_sim:
        p_sim = params_sim[name].detach()
        p_real = params_real[name].detach()

        diff = torch.norm(p_real - p_sim).item()
        total_l2_diff += diff ** 2
        total_params += p_sim.numel()

        sim_flat = p_sim.view(-1).float()
        real_flat = p_real.view(-1).float()

        cos = torch.nn.functional.cosine_similarity(sim_flat, real_flat, dim=0).item()
        cosine_sims.append(cos)

        norm_sim = torch.norm(p_sim).item()
        rel_change = (diff / norm_sim * 100.0) if norm_sim > 0 else 0.0

        print(f"{name:42s} | {diff:10.6f} | {cos:10.6f} | {rel_change:12.3f}%")

    global_l2 = np.sqrt(total_l2_diff)
    mean_cos = np.mean(cosine_sims)

    print("-" * 85)
    print(f"Global L2 Parameter Distance: {global_l2:.6f}")
    print(f"Mean Parameter Cosine Similarity: {mean_cos:.6f}")
    print(f"Total Model Parameters: {total_params:,}")
    print("=" * 70)

    if global_l2 > 0:
        print("✅ VERIFIED: Model parameters have genuinely adapted and diverged from base simulation!")
    else:
        print("❌ WARNING: Model parameters are completely identical (no adaptation detected).")

if __name__ == "__main__":
    main()
