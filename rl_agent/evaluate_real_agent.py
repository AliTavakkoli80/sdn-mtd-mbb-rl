import os
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
    if not os.path.exists(RUNS_DIR):
        raise FileNotFoundError(f"No 'runs' directory found at {RUNS_DIR}. Train a model first.")
    runs = [d for d in os.listdir(RUNS_DIR) if os.path.isdir(os.path.join(RUNS_DIR, d)) and d.startswith('run_')]
    if not runs:
        raise FileNotFoundError("No experiment runs found in the 'runs' directory.")
    runs.sort(reverse=True)
    return os.path.join(RUNS_DIR, runs[0])

def evaluate_real_model():
    # 1. Locate the latest run automatically
    RUN_DIR = get_latest_run_dir()
    print(f"🔍 Auto-detected latest experiment run: {os.path.basename(RUN_DIR)}")
    
    # 2. Load the FINE-TUNED (REAL) model
    model_path = os.path.join(RUN_DIR, "mtd_ppo_agent_real.zip")
    if not os.path.exists(model_path):
        raise FileNotFoundError(f"Fine-tuned model not found at {model_path}. Run fine_tune_agent.py first!")
    
    print(f"🧠 Loading FINE-TUNED (REAL) model from: {model_path}")
    model = PPO.load(model_path)
    
    print("🌐 Initializing Environment for Real Evaluation...")
    mock_app = MockRyuApp()
    env = MTDEnvironment(mock_app, render_mode=None)
    
    # ==========================================
    # 1. GENERATE ACTION REWARD DATA (REAL)
    # ==========================================
    print("\n📊 Collecting Real Action Reward Data...")
    scenarios = [
        ("Quiescent (Low Load)", False, 0.0, 20),
        ("Quiescent (High Load)", False, 0.0, 90),
        ("Targeted Exploit (High Load)", True, 0.9, 85),
        ("Volumetric Storm (Low Load)", True, 0.95, 25),
        ("Volumetric Storm (High Load)", True, 0.95, 90),
    ]
    reward_data = []
    for scenario_name, is_attack, intensity, flows in scenarios:
        mock_app.threat_detector.is_under_attack = is_attack
        mock_app.threat_detector.intensity = intensity
        mock_app.flow_manager.active_flow_count = flows
        obs = env._get_obs()
        # Force max staleness (tau_t = 1.0) to show true penalty
        obs[5] = 1.0 
        reward_data.append({
            'Scenario': scenario_name,
            'HOLD_Reward': env._calculate_reward(0, obs),
            'GLOBAL_Reward': env._calculate_reward(1, obs),
            'TARGETED_Reward': env._calculate_reward(2, obs)
        })
    pd.DataFrame(reward_data).to_csv(os.path.join(RUN_DIR, "action_rewards_real.csv"), index=False)
    print(f"   -> Saved to {os.path.join(RUN_DIR, 'action_rewards_real.csv')}")
    
    # ==========================================
    # 2. GENERATE BASELINE COMPARISON DATA (REAL)
    # ==========================================
    print("\n📊 Running Real Baseline Comparisons...")
    policies = {
        'Static (No MTD)': 'static',
        'Fixed-Periodic MTD': 'periodic',
        'DRL Agent (Ours)': 'drl'
    }
    baseline_results = []
    for policy_name, policy_type in policies.items():
        attack_successes = 0
        qos_disruptions = 0
        episodes = 100
        for ep in range(episodes):
            obs, _ = env.reset()
            done = False
            steps = 0
            
            # Reset per-episode metrics
            episode_attacks = 0
            episode_successful_attacks = 0
            episode_shuffles = 0
            episode_total_flows = 0
            
            while not done and steps < 50:
                # Get action
                if policy_type == 'drl':
                    action, _ = model.predict(obs, deterministic=True)
                elif policy_type == 'periodic':
                    action = 1 if steps % 10 == 0 else 0
                else:
                    action = 0
                    
                # Track threat level
                threat_intensity = obs[4]
                if threat_intensity > 0.5:
                    episode_attacks += 1
                    if action == 0:  # HOLD during high threat = failure
                        episode_successful_attacks += 1
                        
                # Execute action
                obs, reward, done, _, _ = env.step(action)
                steps += 1
                
                if action > 0:
                    episode_shuffles += 1
                    
                # Track flows
                episode_total_flows += obs[6]

        # Calculate rates
        attack_success_rate = (episode_successful_attacks / max(episode_attacks, 1)) * 100
        qos_disruption_rate = (episode_shuffles / steps) * 100
        
        baseline_results.append({
            'Policy': policy_name,
            'Attack_Success_Rate': attack_success_rate,
            'QoS_Disruption_Rate': qos_disruption_rate
        })
        print(f"   ✅ {policy_name} evaluated.")
    pd.DataFrame(baseline_results).to_csv(os.path.join(RUN_DIR, "baseline_results_real.csv"), index=False)
    print(f"   -> Saved to {os.path.join(RUN_DIR, 'baseline_results_real.csv')}")

    # ==========================================
    # 3. GENERATE EPISODE TIMELINE TRACE DATA (REAL)
    # ==========================================
    print("\n📈 Generating Real Episode Timeline Trace...")
    obs, _ = env.reset()
    trace_data = []
    scenario_script = [(20, False, 0.1, 20), (20, True, 0.9, 20), (20, False, 0.1, 80), (20, True, 0.95, 80)]
    step = 0
    for duration, is_attack, intensity, flows in scenario_script:
        mock_app.threat_detector.is_under_attack = is_attack
        mock_app.threat_detector.intensity = intensity
        mock_app.flow_manager.active_flow_count = flows
        for _ in range(duration):
            obs = env._get_obs()
            action, _ = model.predict(obs, deterministic=True)
            trace_data.append({
                'Step': step, 'Threat_Intensity': obs[4], 'Network_Load': obs[6], 
                'Action': action, 'Reward': env._calculate_reward(action, obs)
            })
            obs, _, done, _, _ = env.step(action)
            step += 1
            if done: break
    pd.DataFrame(trace_data).to_csv(os.path.join(RUN_DIR, "episode_trace_real.csv"), index=False)
    print(f"   -> Saved to {os.path.join(RUN_DIR, 'episode_trace_real.csv')}")
    
    # ==========================================
    # 4. GENERATE POLICY HEATMAP DATA (REAL)
    # ==========================================
    print("\n🗺️ Generating Real Policy Heatmap Data...")
    heatmap_data = []
    for threat in np.linspace(0, 1, 11):
        for load in np.linspace(0, 1, 11):
            mock_app.threat_detector.is_under_attack = threat > 0.3
            mock_app.threat_detector.intensity = threat
            mock_app.flow_manager.active_flow_count = int(load * 100)
            obs = env._get_obs()
            action, _ = model.predict(obs, deterministic=True)
            heatmap_data.append({
                'Threat_Intensity': round(threat, 2), 'Network_Load': round(load, 2), 'Action': action
            })
    pd.DataFrame(heatmap_data).to_csv(os.path.join(RUN_DIR, "policy_evaluation_real.csv"), index=False)
    print(f"   -> Saved to {os.path.join(RUN_DIR, 'policy_evaluation_real.csv')}")
    
    print("\n" + "="*60)
    print(f"🎉 REAL EVALUATION COMPLETE!")
    print(f"📁 All data saved to: {RUN_DIR}")
    print("="*60)
    print("\nYou can now run 'python visualize_results.py' to generate the final PDF plots.")

if __name__ == "__main__":
    evaluate_real_model()