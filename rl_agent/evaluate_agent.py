import os
import shutil
import numpy as np
import pandas as pd
from stable_baselines3 import PPO
from mtd_env import MTDEnvironment
from train_agent import MockRyuApp

# ==========================================
# PATH CONFIGURATION (Absolute Paths)
# ==========================================
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
RUNS_DIR = os.path.join(SCRIPT_DIR, "runs")

def get_latest_run_dir():
    """Returns the path to the most recent run folder, or SCRIPT_DIR if none exists."""
    if os.path.exists(RUNS_DIR):
        runs = [d for d in os.listdir(RUNS_DIR) if os.path.isdir(os.path.join(RUNS_DIR, d)) and d.startswith('run_')]
        if runs:
            runs.sort(reverse=True)
            return os.path.join(RUNS_DIR, runs[0])
    return SCRIPT_DIR

def evaluate_all():
    RUN_DIR = get_latest_run_dir()
    print("=" * 70)
    print(f"📊 BENCHMARKING LITERATURE BASELINES & PROPOSED QOS-AWARE DRL-MTD")
    print(f"📁 Target Directory: {RUN_DIR}")
    print("=" * 70)

    # 1. Locate and load models
    proposed_path = os.path.join(RUN_DIR, "mtd_ppo_agent.zip")
    if not os.path.exists(proposed_path):
        proposed_path = os.path.join(SCRIPT_DIR, "mtd_ppo_agent.zip")
    if not os.path.exists(proposed_path):
        raise FileNotFoundError(f"Proposed model not found at {proposed_path}!")

    binary_path = os.path.join(RUN_DIR, "mtd_ppo_binary_baseline.zip")
    if not os.path.exists(binary_path):
        binary_path = os.path.join(SCRIPT_DIR, "mtd_ppo_binary_baseline.zip")
    if not os.path.exists(binary_path):
        raise FileNotFoundError(f"Binary model not found at {binary_path}!")

    print(f"🧠 Loading Proposed Agent: {proposed_path}")
    model_proposed = PPO.load(proposed_path, device="cpu")

    print(f"🧠 Loading Binary Agent:   {binary_path}")
    model_binary = PPO.load(binary_path, device="cpu")

    # ==========================================
    # PART 1: ACTION REWARD ANALYSIS (action_rewards.csv)
    # ==========================================
    print("\n--- Part 1: Generating Action Rewards Across 5 Scenarios ---")
    mock_app = MockRyuApp()
    env = MTDEnvironment(mock_app, render_mode=None)

    scenarios = [
        ("Quiescent (Low Load)", False, 0.0, 20, []),
        ("Quiescent (High Load)", False, 0.0, 90, []),
        ("Targeted Exploit (High Load)", True, 0.90, 85, ['10.0.0.2']),
        ("Volumetric Storm (Low Load)", True, 0.95, 25, [f'10.0.0.{i}' for i in range(1, 11)]),
        ("Volumetric Storm (High Load)", True, 0.95, 90, [f'10.0.0.{i}' for i in range(1, 11)]),
    ]

    reward_data = []
    for scenario_name, is_attack, intensity, flows, scanned in scenarios:
        mock_app.threat_detector.is_under_attack = is_attack
        mock_app.threat_detector.intensity = intensity
        mock_app.threat_detector.scanned_hosts = scanned
        mock_app.flow_manager.active_flow_count = flows

        obs = env._get_obs()
        obs[5] = 1.0  # Force tau_t = 1.0 to reflect network staleness

        hold_r = env._calculate_reward(0, obs)
        global_r = env._calculate_reward(1, obs)
        target_r = env._calculate_reward(2, obs)

        reward_data.append({
            'Scenario': scenario_name,
            'HOLD_Reward': round(hold_r, 2),
            'GLOBAL_Reward': round(global_r, 2),
            'TARGETED_Reward': round(target_r, 2)
        })
        print(f"   {scenario_name:30s} | HOLD={hold_r:+6.2f} | GLOBAL={global_r:+6.2f} | TARGETED={target_r:+6.2f}")

    df_rewards = pd.DataFrame(reward_data)
    rewards_run_path = os.path.join(RUN_DIR, "action_rewards.csv")
    rewards_root_path = os.path.join(SCRIPT_DIR, "action_rewards.csv")
    df_rewards.to_csv(rewards_run_path, index=False)
    shutil.copy(rewards_run_path, rewards_root_path)
    print(f"✅ Saved action rewards to: {rewards_run_path} and {rewards_root_path}")

    # ==========================================
    # PART 2: 5-POLICY DYNAMIC BENCHMARKING (baseline_results.csv)
    # ==========================================
    print("\n--- Part 2: Benchmarking 5 Policies Across 100 Dynamic 4-Phase Episodes ---")
    
    policies = [
        ('Static (No MTD)', 'static'),
        ('OF-RHM / Periodic MTD', 'periodic'),
        ('Event-Driven / IDS-Triggered MTD', 'ids_triggered'),
        ('Binary-Action DRL-MTD', 'binary_drl'),
        ('Proposed QoS-Aware DRL-MTD', 'proposed_drl')
    ]

    num_episodes = 100
    steps_per_episode = 50
    results_list = []

    # Phase schedule definition:
    # Steps 0-11: Quiescent (Low threat, normal-high load)
    # Steps 12-24: Targeted Scan + High Load (1-2 hosts, high load)
    # Steps 25-37: Global Subnet Sweep + Mod Load (8-10 hosts, mod load)
    # Steps 38-49: Post-Attack Quiescent (Normalized threat)

    for policy_name, policy_type in policies:
        ep_attack_success_rates = []
        ep_qos_disruption_rates = []
        ep_shuffle_frequencies = []
        ep_flowmods_list = []
        ep_rewards = []

        for ep in range(num_episodes):
            env_eval = MTDEnvironment(mock_app, render_mode=None)
            obs, _ = env_eval.reset()

            total_attack_steps = 0
            successful_attack_steps = 0.0
            total_active_flows = 0.0
            total_disrupted_flows = 0.0
            total_shuffles = 0
            total_flowmods = 0
            total_reward = 0.0

            for t in range(steps_per_episode):
                # 1. Update dynamic environment state according to phase
                if t < 12:
                    # Phase 1: Quiescent
                    phase = "Quiescent"
                    mock_app.threat_detector.is_under_attack = False
                    mock_app.threat_detector.intensity = float(np.random.uniform(0.01, 0.07))
                    mock_app.threat_detector.scanned_hosts = []
                    mock_app.flow_manager.active_flow_count = int(np.random.uniform(60, 90))
                elif t < 25:
                    # Phase 2: Targeted Scan + High Load
                    phase = "Targeted+HighLoad"
                    mock_app.threat_detector.is_under_attack = True
                    mock_app.threat_detector.intensity = float(np.random.uniform(0.70, 0.95))
                    mock_app.threat_detector.scanned_hosts = ['10.0.0.2', '10.0.0.3']
                    mock_app.flow_manager.active_flow_count = int(np.random.uniform(75, 95))
                elif t < 38:
                    # Phase 3: Global Subnet Scan + Mod Load
                    phase = "Global+ModLoad"
                    mock_app.threat_detector.is_under_attack = True
                    mock_app.threat_detector.intensity = float(np.random.uniform(0.80, 1.00))
                    mock_app.threat_detector.scanned_hosts = [f'10.0.0.{i}' for i in range(1, 11)]
                    mock_app.flow_manager.active_flow_count = int(np.random.uniform(20, 45))
                else:
                    # Phase 4: Post-Attack Quiescent
                    phase = "PostQuiescent"
                    mock_app.threat_detector.is_under_attack = False
                    mock_app.threat_detector.intensity = float(np.random.uniform(0.01, 0.06))
                    mock_app.threat_detector.scanned_hosts = []
                    mock_app.flow_manager.active_flow_count = int(np.random.uniform(50, 85))

                obs = env_eval._get_obs()
                I_t = obs[4]
                F_t = obs[6]

                # 2. Select policy action
                if policy_type == 'static':
                    action = 0
                elif policy_type == 'periodic':
                    # OF-RHM: Periodic Global Shuffle every 5 steps
                    action = 1 if (t % 5 == 0) else 0
                elif policy_type == 'ids_triggered':
                    # Threshold IDS-MTD: Trigger Global Shuffle when I_t > 0.40
                    action = 1 if I_t > 0.40 else 0
                elif policy_type == 'binary_drl':
                    action, _ = model_binary.predict(obs, deterministic=True)
                    action = int(action)
                elif policy_type == 'proposed_drl':
                    action, _ = model_proposed.predict(obs, deterministic=True)
                    action = int(action)

                # 3. Assess Security (Attacker Success Rate)
                is_attack_active = mock_app.threat_detector.is_under_attack or (I_t > 0.40)
                if is_attack_active:
                    total_attack_steps += 1
                    if action == 0:
                        # Attacker successfully maps targets without disruption
                        successful_attack_steps += 1.0
                    elif action == 1:
                        # Global shuffle invalidates attacker's entire mapping
                        successful_attack_steps += 0.0
                    elif action == 2:
                        # Targeted shuffle
                        if phase == "Targeted+HighLoad":
                            # Covers the targeted hosts -> completely thwarted
                            successful_attack_steps += 0.0
                        else:
                            # In global sweep, targeted shuffle only protects 2/10 hosts
                            successful_attack_steps += 0.8

                # 4. Assess QoS & Control Plane Overhead
                active_flows = mock_app.flow_manager.active_flow_count
                total_active_flows += active_flows

                if action == 0:
                    disrupted_flows = 0.0
                    flowmods = 0
                elif action == 1:
                    disrupted_flows = 1.0 * active_flows
                    flowmods = 40  # 10 hosts * 4 OpenFlow rules
                    total_shuffles += 1
                elif action == 2:
                    n_scanned = len(mock_app.threat_detector.scanned_hosts)
                    disrupted_flows = (min(n_scanned, 10) / 10.0) * active_flows
                    flowmods = 4 * min(n_scanned, 2)
                    total_shuffles += 1

                total_disrupted_flows += disrupted_flows
                total_flowmods += flowmods

                # 5. Step Environment & Collect Reward
                obs, reward, _, _, _ = env_eval.step(action)
                total_reward += reward

            # Compute Episode Rates
            asr = (successful_attack_steps / max(total_attack_steps, 1)) * 100.0
            qdr = (total_disrupted_flows / max(total_active_flows, 1.0)) * 100.0
            shf = (total_shuffles / float(steps_per_episode)) * 100.0

            ep_attack_success_rates.append(asr)
            ep_qos_disruption_rates.append(qdr)
            ep_shuffle_frequencies.append(shf)
            ep_flowmods_list.append(total_flowmods)
            ep_rewards.append(total_reward)

        mean_asr = float(np.mean(ep_attack_success_rates))
        mean_qdr = float(np.mean(ep_qos_disruption_rates))
        mean_shf = float(np.mean(ep_shuffle_frequencies))
        mean_fmd = float(np.mean(ep_flowmods_list))
        mean_rew = float(np.mean(ep_rewards))

        results_list.append({
            'Policy': policy_name,
            'Attack_Success_Rate': round(mean_asr, 2),
            'QoS_Disruption_Rate': round(mean_qdr, 2),
            'Shuffle_Frequency': round(mean_shf, 2),
            'Control_Plane_FlowMods': round(mean_fmd, 1),
            'Mean_Episode_Reward': round(mean_rew, 2)
        })

        print(f"   ✅ {policy_name:32s} | ASR: {mean_asr:5.1f}% | QDR: {mean_qdr:5.1f}% | Shf: {mean_shf:5.1f}% | FlowMods: {mean_fmd:6.1f} | Rew: {mean_rew:+6.1f}")

    df_baselines = pd.DataFrame(results_list)
    baselines_run_path = os.path.join(RUN_DIR, "baseline_results.csv")
    baselines_root_path = os.path.join(SCRIPT_DIR, "baseline_results.csv")
    df_baselines.to_csv(baselines_run_path, index=False)
    shutil.copy(baselines_run_path, baselines_root_path)
    print(f"\n✅ Saved baseline comparison to: {baselines_run_path} and {baselines_root_path}")

    # ==========================================
    # PART 3: SINGLE EPISODE TIMELINE TRACE (episode_trace.csv)
    # ==========================================
    print("\n--- Part 3: Generating Single-Episode Timeline Trace for Proposed Agent ---")
    mock_app_trace = MockRyuApp()
    env_trace = MTDEnvironment(mock_app_trace, render_mode=None)
    obs, _ = env_trace.reset()
    trace_data = []

    for t in range(50):
        if t < 12:
            mock_app_trace.threat_detector.is_under_attack = False
            mock_app_trace.threat_detector.intensity = 0.04
            mock_app_trace.threat_detector.scanned_hosts = []
            mock_app_trace.flow_manager.active_flow_count = 75
        elif t < 25:
            mock_app_trace.threat_detector.is_under_attack = True
            mock_app_trace.threat_detector.intensity = 0.88
            mock_app_trace.threat_detector.scanned_hosts = ['10.0.0.2']
            mock_app_trace.flow_manager.active_flow_count = 85
        elif t < 38:
            mock_app_trace.threat_detector.is_under_attack = True
            mock_app_trace.threat_detector.intensity = 0.92
            mock_app_trace.threat_detector.scanned_hosts = [f'10.0.0.{i}' for i in range(1, 11)]
            mock_app_trace.flow_manager.active_flow_count = 30
        else:
            mock_app_trace.threat_detector.is_under_attack = False
            mock_app_trace.threat_detector.intensity = 0.03
            mock_app_trace.threat_detector.scanned_hosts = []
            mock_app_trace.flow_manager.active_flow_count = 65

        obs = env_trace._get_obs()
        action, _ = model_proposed.predict(obs, deterministic=True)
        action = int(action)
        reward = env_trace._calculate_reward(action, obs)

        trace_data.append({
            'Step': t,
            'Threat_Intensity': round(float(obs[4]), 3),
            'Network_Load': round(float(obs[6]), 3),
            'Action': action,
            'Reward': round(float(reward), 2)
        })
        obs, _, _, _, _ = env_trace.step(action)

    df_trace = pd.DataFrame(trace_data)
    trace_run_path = os.path.join(RUN_DIR, "episode_trace.csv")
    trace_root_path = os.path.join(SCRIPT_DIR, "episode_trace.csv")
    df_trace.to_csv(trace_run_path, index=False)
    shutil.copy(trace_run_path, trace_root_path)
    print(f"✅ Saved episode trace to: {trace_run_path} and {trace_root_path}")

    # ==========================================
    # PART 4: POLICY DECISION HEATMAP (policy_evaluation.csv)
    # ==========================================
    print("\n--- Part 4: Generating Policy Decision Heatmap (11x11 Grid) ---")
    heatmap_data = []
    mock_app_hm = MockRyuApp()
    env_hm = MTDEnvironment(mock_app_hm, render_mode=None)

    for threat in np.linspace(0, 1, 11):
        for load in np.linspace(0, 1, 11):
            mock_app_hm.threat_detector.is_under_attack = (threat > 0.3)
            mock_app_hm.threat_detector.intensity = float(threat)
            mock_app_hm.threat_detector.scanned_hosts = ['10.0.0.2'] if threat > 0.3 else []
            mock_app_hm.flow_manager.active_flow_count = int(load * 100)

            obs = env_hm._get_obs()
            action, _ = model_proposed.predict(obs, deterministic=True)

            heatmap_data.append({
                'Threat_Intensity': round(threat, 2),
                'Network_Load': round(load, 2),
                'Action': int(action)
            })

    df_hm = pd.DataFrame(heatmap_data)
    hm_run_path = os.path.join(RUN_DIR, "policy_evaluation.csv")
    hm_root_path = os.path.join(SCRIPT_DIR, "policy_evaluation.csv")
    df_hm.to_csv(hm_run_path, index=False)
    shutil.copy(hm_run_path, hm_root_path)
    print(f"✅ Saved policy evaluation heatmap to: {hm_run_path} and {hm_root_path}")

    print("\n" + "=" * 70)
    print("🎉 ALL BENCHMARKING COMPLETED SUCCESSFULLY!")
    print("=" * 70)

if __name__ == "__main__":
    evaluate_all()
