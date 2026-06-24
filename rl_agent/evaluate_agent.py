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
    """
    Scans the 'runs' directory and returns the absolute path 
    to the most recent experiment folder based on the timestamp in its name.
    """
    if not os.path.exists(RUNS_DIR):
        raise FileNotFoundError(f"No 'runs' directory found at {RUNS_DIR}. Train a model first.")
    
    # List all directories inside RUNS_DIR that start with 'run_'
    runs = [d for d in os.listdir(RUNS_DIR) if os.path.isdir(os.path.join(RUNS_DIR, d)) and d.startswith('run_')]
    if not runs:
        raise FileNotFoundError("No experiment runs found in the 'runs' directory.")
    
    # Sort by name (which is a timestamp string) descending to get the latest
    runs.sort(reverse=True)
    return os.path.join(RUNS_DIR, runs[0])

def evaluate_model():
    # 1. Locate the latest run automatically
    RUN_DIR = get_latest_run_dir()
    print(f"🔍 Auto-detected latest experiment run: {os.path.basename(RUN_DIR)}")
    
    # 2. Define paths inside that specific run folder
    model_path = os.path.join(RUN_DIR, "mtd_ppo_agent.zip")
    if not os.path.exists(model_path):
        raise FileNotFoundError(f"Model not found at {model_path}. Was training completed successfully?")
    
    print(f"🧠 Loading trained model from: {model_path}")
    model = PPO.load(model_path)
    
    print("🌐 Initializing Environment for Evaluation...")
    mock_app = MockRyuApp()
    env = MTDEnvironment(mock_app, render_mode=None)
    
    # ==========================================
    # 1. GENERATE ACTION REWARD DATA (For action_comparison.pdf)
    # ==========================================
    print("\n📊 Collecting Action Reward Data for Each Scenario...")
    
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
        
        # Get observation for this scenario
        obs = env._get_obs()
        
        # Calculate reward for each action
        hold_reward = env._calculate_reward(0, obs)
        global_reward = env._calculate_reward(1, obs)
        target_reward = env._calculate_reward(2, obs)
        
        reward_data.append({
            'Scenario': scenario_name,
            'HOLD_Reward': hold_reward,
            'GLOBAL_Reward': global_reward,
            'TARGETED_Reward': target_reward
        })
        
        print(f"   ✅ {scenario_name}: HOLD={hold_reward:.1f}, GLOBAL={global_reward:.1f}, TARGETED={target_reward:.1f}")
    
    df_rewards = pd.DataFrame(reward_data)
    df_rewards.to_csv(os.path.join(RUN_DIR, "action_rewards.csv"), index=False)
    print(f"   -> Saved to {os.path.join(RUN_DIR, 'action_rewards.csv')}")
    
    # ==========================================
    # 2. GENERATE BASELINE COMPARISON DATA
    # ==========================================
    print("\n📊 Running Baseline Comparisons (Simulating 100 episodes per policy)...")
    
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
            
            # Simulate an attack happening randomly
            mock_app.threat_detector.is_under_attack = True
            mock_app.threat_detector.intensity = 0.9
            mock_app.flow_manager.active_flow_count = 50
            
            while not done and steps < 50:
                if policy_type == 'drl':
                    action, _ = model.predict(obs, deterministic=True)
                elif policy_type == 'periodic':
                    action = 1 if steps % 10 == 0 else 0
                else:
                    action = 0
                    
                obs, reward, done, _, _ = env.step(action)
                steps += 1
                
                if action > 0:
                    qos_disruptions += 1
                
                if obs[4] > 0.5 and action == 0:
                    attack_successes += 1

        baseline_results.append({
            'Policy': policy_name,
            'Attack_Success_Rate': (attack_successes / (episodes * 50)) * 100,
            'QoS_Disruption_Rate': (qos_disruptions / (episodes * 50)) * 100
        })
        print(f"   ✅ {policy_name} evaluated.")

    df_baseline = pd.DataFrame(baseline_results)
    df_baseline.to_csv(os.path.join(RUN_DIR, "baseline_results.csv"), index=False)
    print(f"   -> Saved to {os.path.join(RUN_DIR, 'baseline_results.csv')}")

    # ==========================================
    # 3. GENERATE EPISODE TIMELINE TRACE DATA
    # ==========================================
    print("\n📈 Generating Single-Episode Timeline Trace...")
    
    obs, _ = env.reset()
    trace_data = []
    
    scenario_script = [
        (20, False, 0.1, 20),
        (20, True, 0.9, 20),
        (20, False, 0.1, 80),
        (20, True, 0.95, 80)
    ]
    
    step = 0
    for duration, is_attack, intensity, flows in scenario_script:
        mock_app.threat_detector.is_under_attack = is_attack
        mock_app.threat_detector.intensity = intensity
        mock_app.flow_manager.active_flow_count = flows
        
        for _ in range(duration):
            obs = env._get_obs()
            action, _ = model.predict(obs, deterministic=True)
            
            trace_data.append({
                'Step': step,
                'Threat_Intensity': obs[4],
                'Network_Load': obs[6],
                'Action': action,
                'Reward': env._calculate_reward(action, obs)
            })
            
            obs, _, done, _, _ = env.step(action)
            step += 1
            if done: break

    df_trace = pd.DataFrame(trace_data)
    df_trace.to_csv(os.path.join(RUN_DIR, "episode_trace.csv"), index=False)
    print(f"   -> Saved to {os.path.join(RUN_DIR, 'episode_trace.csv')}")
    
    # ==========================================
    # 4. GENERATE POLICY HEATMAP DATA
    # ==========================================
    print("\n🗺️  Generating Policy Heatmap Data...")
    
    heatmap_data = []
    
    for threat in np.linspace(0, 1, 11):
        for load in np.linspace(0, 1, 11):
            mock_app.threat_detector.is_under_attack = threat > 0.3
            mock_app.threat_detector.intensity = threat
            mock_app.flow_manager.active_flow_count = int(load * 100)
            
            obs = env._get_obs()
            action, _ = model.predict(obs, deterministic=True)
            
            heatmap_data.append({
                'Threat_Intensity': round(threat, 2),
                'Network_Load': round(load, 2),
                'Action': action
            })
    
    df_heatmap = pd.DataFrame(heatmap_data)
    df_heatmap.to_csv(os.path.join(RUN_DIR, "policy_evaluation.csv"), index=False)
    print(f"   -> Saved to {os.path.join(RUN_DIR, 'policy_evaluation.csv')}")
    
    print("\n" + "="*60)
    print(f"🎉 EVALUATION COMPLETE!")
    print(f"📁 All data saved to: {RUN_DIR}")
    print("="*60)
    print("   - action_rewards.csv")
    print("   - baseline_results.csv")
    print("   - episode_trace.csv")
    print("   - policy_evaluation.csv")
    print("\nYou can now run 'python visualize_results.py' to generate the PDF plots for this run.")

if __name__ == "__main__":
    evaluate_model()