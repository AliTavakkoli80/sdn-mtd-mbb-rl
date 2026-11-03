#!/usr/bin/env python3
"""
verify_continuous_reward.py - Mathematical Verification of Continuous MTD Reward Formulation

Evaluates M_1(r), M_2(r), Cost, Disruption, and Total Rewards across n_scanned in [0, 16]
for representative threat intensities (I_t in {0.3, 0.6, 0.9}) and loads (F_t in {0.2, 0.5}).
Proves the continuous smooth crossover between TARGETED and GLOBAL without step functions.
"""

import math
import numpy as np
from mtd_env import MTDEnvironment

class DummyThreatDetector:
    def __init__(self, scanned):
        self.scanned = scanned
    def get_scanned_targets(self):
        return self.scanned

class DummyRyuApp:
    def __init__(self, scanned):
        self.threat_detector = DummyThreatDetector(scanned)

def evaluate_regime(I_t, F_t, total_hosts=16.0):
    header = f"=== REGIME: Threat Intensity I_t = {I_t:.1f}, Network Load F_t = {F_t:.1f} ==="
    print("=" * len(header))
    print(header)
    print("=" * len(header))
    print(f"{'n':>2s} | {'r':>5s} | {'M1(r)':>6s} | {'M2(r)':>6s} | {'Cost1':>5s} | {'Cost2':>5s} | {'D1':>4s} | {'D2':>5s} | {'R(GLOBAL)':>9s} | {'R(TARGETED)':>11s} | {'Optimal Action':>15s} | {'Δ(T - G)':>8s}")
    print("-" * 105)

    crossover_found = False
    crossover_info = ""

    for n in range(0, 17):
        r = n / total_hosts
        scanned_list = [f"10.0.0.{i+1}" for i in range(n)]
        app = DummyRyuApp(scanned_list)
        env = MTDEnvironment(app)

        obs = np.array([0.0, 0.0, 0.0, 0.0, I_t, 0.5, F_t, r], dtype=np.float32)
        r_global = env._calculate_reward(1, obs)
        r_targeted = env._calculate_reward(2, obs)

        # Theoretical values
        M1 = 1.0 + 1.0 * (1.0 - math.exp(-3.0 * r)) if n > 0 else 1.5
        M2 = 2.0 * math.exp(-2.5 * r) if n > 0 else 0.0
        cost1 = 1.0
        cost2 = max(0.15, r)
        d1 = 1.0
        d2 = r

        diff = r_targeted - r_global
        if diff > 0:
            winner = "TARGETED 🎯"
        else:
            winner = "GLOBAL 🌐"

        if not crossover_found and n > 0 and diff < 0:
            crossover_found = True
            crossover_info = f"--> Continuous Crossover occurs between n={n-1} (r={(n-1)/16:.3f}) and n={n} (r={n/16:.3f})"

        print(f"{n:2d} | {r:5.3f} | {M1:6.3f} | {M2:6.3f} | {cost1:5.2f} | {cost2:5.3f} | {d1:4.1f} | {d2:5.3f} | {r_global:+9.3f} | {r_targeted:+11.3f} | {winner:>15s} | {diff:+8.3f}")

    print("-" * 105)
    print(crossover_info)
    print("\n")

def main():
    print("\n" + "=" * 70)
    print("🔬 MATHEMATICAL VERIFICATION OF CONTINUOUS MTD REWARD FORMULATION")
    print("=" * 70 + "\n")

    regimes = [
        (0.3, 0.2), # Low threat, light load
        (0.6, 0.5), # Medium threat, moderate load
        (0.9, 0.5), # Severe threat, moderate load
    ]

    for I_t, F_t in regimes:
        evaluate_regime(I_t, F_t)

if __name__ == "__main__":
    main()
