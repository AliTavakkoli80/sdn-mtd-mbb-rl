import os
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from matplotlib.colors import LinearSegmentedColormap

# ==========================================
# PATH CONFIGURATION (Absolute Paths)
# ==========================================
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
RUNS_DIR = os.path.join(SCRIPT_DIR, "runs")

# ==========================================
# ACADEMIC STYLING
# ==========================================
plt.rcParams['font.family'] = 'serif'
plt.rcParams['mathtext.fontset'] = 'cm'
sns.set_context("paper", font_scale=1.2)
sns.set_style("whitegrid", {'grid.linestyle': '--', 'grid.alpha': 0.6})

def get_latest_run_dir():
    """Finds the most recent run folder based on timestamp name."""
    if not os.path.exists(RUNS_DIR):
        raise FileNotFoundError("No 'runs' directory found. Train a model first.")
    
    runs = [d for d in os.listdir(RUNS_DIR) if os.path.isdir(os.path.join(RUNS_DIR, d))]
    if not runs:
        raise FileNotFoundError("No experiment runs found.")
    
    runs.sort(reverse=True) # Sort by name (timestamp) descending
    return os.path.join(RUNS_DIR, runs[0])

# ==========================================
# PLOT GENERATORS
# ==========================================

def generate_training_convergence_plot(csv_path, save_path):
    """
    Generates the training convergence plot showing how the agent's reward
    improved over timesteps. This proves the agent actually learned!
    """
    print("[Plotter] Generating Training Convergence Curve...")
    
    if not os.path.exists(csv_path):
        print(f"⚠️  {csv_path} not found. Skipping.")
        return
    
    df = pd.read_csv(csv_path)
    timesteps = df['timestep'].values
    rewards = df['reward'].values
    
    # Calculate rolling average (window of 1000 steps)
    window_size = 1000
    if len(rewards) > window_size:
        rolling_mean = pd.Series(rewards).rolling(window=window_size, center=True).mean()
        rolling_std = pd.Series(rewards).rolling(window=window_size, center=True).std()
    else:
        rolling_mean = pd.Series(rewards)
        rolling_std = pd.Series(np.zeros_like(rewards))
    
    # Fill NaN values at edges
    rolling_mean = rolling_mean.bfill().ffill()
    rolling_std = rolling_std.fillna(0)
    
    fig, ax = plt.subplots(figsize=(10, 6))
    
    # Plot the rolling mean
    ax.plot(timesteps, rolling_mean, color='#4c72b0', linewidth=2.5, 
            label='Rolling Mean Reward (1000 steps)')
    
    # Plot the variance envelope
    ax.fill_between(timesteps, 
                    rolling_mean - rolling_std, 
                    rolling_mean + rolling_std, 
                    color='#4c72b0', alpha=0.2, 
                    label=r'$\pm 1\sigma$ Variance')
    
    ax.axhline(y=0, color='black', linewidth=1, linestyle='--', alpha=0.5)
    
    ax.set_xlabel('Training Timesteps', fontsize=12, fontweight='bold')
    ax.set_ylabel('Reward per Timestep', fontsize=12, fontweight='bold')
    ax.set_title('PPO Agent Training Convergence', fontsize=13, pad=15, fontweight='bold')
    ax.set_xlim(0, max(timesteps))
    ax.legend(loc='lower right', frameon=True, fancybox=False, edgecolor='black')
    ax.grid(True, linestyle='--', alpha=0.6)
    
    plt.tight_layout()
    plt.savefig(save_path, format='pdf', dpi=300, bbox_inches='tight')
    print(f"   -> Saved to {save_path}")
    plt.close()


def generate_action_comparison_plot(csv_path, save_path):
    """
    Generates a comprehensive comparison showing calculated reward outcomes
    for each action (HOLD, GLOBAL, TARGETED) across different network scenarios.
    """
    print("[Plotter] Generating Action Comparison...")
    
    if not os.path.exists(csv_path):
        print(f"⚠️  {csv_path} not found. Skipping.")
        return
    
    df = pd.read_csv(csv_path)
    scenarios = df['Scenario'].tolist()
    hold_rewards = df['HOLD_Reward'].tolist()
    global_rewards = df['GLOBAL_Reward'].tolist()
    target_rewards = df['TARGETED_Reward'].tolist()
    
    x = np.arange(len(scenarios))
    width = 0.25
    
    fig, ax = plt.subplots(figsize=(14, 7))
    
    bars1 = ax.bar(x - width, hold_rewards, width, label='HOLD', 
                   color='#4c72b0', edgecolor='black', linewidth=1.2, hatch='///')
    bars2 = ax.bar(x, global_rewards, width, label='GLOBAL SHUFFLE', 
                   color='#c44e52', edgecolor='black', linewidth=1.2, hatch='\\\\\\')
    bars3 = ax.bar(x + width, target_rewards, width, label='TARGETED SHUFFLE', 
                   color='#55a868', edgecolor='black', linewidth=1.2, hatch='...')
    
    for bars in [bars1, bars2, bars3]:
        for bar in bars:
            height = bar.get_height()
            va = 'bottom' if height >= 0 else 'top'
            y_offset = 0.3 if height >= 0 else -0.5
            ax.annotate(f'{height:.1f}',
                       xy=(bar.get_x() + bar.get_width() / 2, height),
                       xytext=(0, y_offset),
                       textcoords="offset points",
                       ha='center', va=va, fontsize=10, fontweight='bold')
    
    ax.set_xlabel('Network Scenario', fontsize=12, fontweight='bold')
    ax.set_ylabel('Calculated Reward Outcome ($R_t$)', fontsize=12, fontweight='bold')
    ax.set_title('Action Reward Comparison Across Network States', fontsize=13, pad=15, fontweight='bold')
    ax.set_xticks(x)
    ax.set_xticklabels(scenarios, ha='center', fontsize=10)
    ax.axhline(y=0, color='black', linewidth=1.5, linestyle='-')
    ax.legend(loc='lower left', frameon=True, fancybox=False, edgecolor='black')
    
    # Auto-scale Y axis based on data
    all_vals = hold_rewards + global_rewards + target_rewards
    y_min = min(0, min(all_vals)) - 2
    y_max = max(0, max(all_vals)) + 2
    ax.set_ylim(y_min, y_max)
    
    plt.tight_layout()
    plt.savefig(save_path, format='pdf', dpi=300, bbox_inches='tight')
    print(f"   -> Saved to {save_path}")
    plt.close()


def generate_baseline_comparison_plot(csv_path, save_path):
    """
    Compares the DRL agent against standard network engineering baselines.
    """
    print("[Plotter] Generating Baseline Comparison...")
    
    if not os.path.exists(csv_path):
        print(f"⚠️  {csv_path} not found. Skipping.")
        return
    
    df = pd.read_csv(csv_path)
    baselines = df['Policy'].tolist()
    attack_success = df['Attack_Success_Rate'].tolist()
    qos_disruption = df['QoS_Disruption_Rate'].tolist()
    
    x = np.arange(len(baselines))
    width = 0.35
    
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))
    
    colors = ['#c44e52', '#fe9929', '#55a868']
    bars1 = ax1.bar(x, attack_success, width, color=colors, edgecolor='k', linewidth=1.2)
    bars1[0].set_hatch('//')
    bars1[1].set_hatch('\\\\')
    bars1[2].set_hatch('..')
    ax1.set_ylabel('Attacker Reconnaissance Success Rate (%)', fontsize=12)
    ax1.set_xticks(x)
    ax1.set_xticklabels(baselines, rotation=15, ha='right')
    ax1.set_ylim(0, 115)
    ax1.set_title('(a) Security Defense Efficacy', fontsize=13, pad=10)
    
    for bar in bars1:
        height = bar.get_height()
        ax1.annotate(f'{height:.1f}%', xy=(bar.get_x() + bar.get_width()/2, height),
                    xytext=(0, 3), textcoords="offset points", ha='center', va='bottom', fontweight='bold')
        
    colors2 = ['#4c72b0', '#fe9929', '#55a868']
    bars2 = ax2.bar(x, qos_disruption, width, color=colors2, edgecolor='k', linewidth=1.2)
    bars2[0].set_hatch('//')
    bars2[1].set_hatch('\\\\')
    bars2[2].set_hatch('..')
    ax2.set_ylabel('Average Session Disruption Rate (%)', fontsize=12)
    ax2.set_xticks(x)
    ax2.set_xticklabels(baselines, rotation=15, ha='right')
    ax2.set_ylim(0, 115)
    ax2.set_title('(b) Collateral Quality-of-Service Cost', fontsize=13, pad=10)
    
    for bar in bars2:
        height = bar.get_height()
        ax2.annotate(f'{height:.1f}%', xy=(bar.get_x() + bar.get_width()/2, height),
                    xytext=(0, 3), textcoords="offset points", ha='center', va='bottom', fontweight='bold')

    plt.tight_layout()
    plt.savefig(save_path, format='pdf', dpi=300, bbox_inches='tight')
    print(f"   -> Saved to {save_path}")
    plt.close()


def generate_episode_timeline_trace(csv_path, save_path):
    """
    Generates a continuous single-episode timeline trace.
    """
    print("[Plotter] Generating Episode Timeline Trace...")
    
    if not os.path.exists(csv_path):
        print(f"⚠️  {csv_path} not found. Skipping.")
        return
    
    df = pd.read_csv(csv_path)
    
    fig, (ax1, ax2, ax3) = plt.subplots(3, 1, figsize=(12, 8), sharex=True, 
                                         gridspec_kw={'height_ratios': [1, 1, 1.5]})
    
    # Top Plot: Threat Intensity
    ax1.fill_between(df['Step'], 0, df['Threat_Intensity'], 
                     color='#c44e52', alpha=0.3, label=r'Threat Intensity ($I_t$)')
    ax1.plot(df['Step'], df['Threat_Intensity'], color='#c44e52', linewidth=2)
    ax1.set_ylabel('Threat Level', fontsize=11)
    ax1.set_ylim(0, 1.1)
    ax1.legend(loc='upper right', frameon=True)
    ax1.grid(True, linestyle='--', alpha=0.6)
    
    # Middle Plot: Network Load
    ax2.fill_between(df['Step'], 0, df['Network_Load'], 
                     color='#4c72b0', alpha=0.3, label=r'Network Load ($F_t$)')
    ax2.plot(df['Step'], df['Network_Load'], color='#4c72b0', linewidth=2)
    ax2.set_ylabel('Traffic Load', fontsize=11)
    ax2.set_ylim(0, 1.1)
    ax2.legend(loc='upper right', frameon=True)
    ax2.grid(True, linestyle='--', alpha=0.6)
    
    # Bottom Plot: Actions & Rewards
    action_colors = {0: '#4c72b0', 1: '#c44e52', 2: '#55a868'}
    action_labels = {0: 'HOLD', 1: 'GLOBAL', 2: 'TARGETED'}
    action_markers = {0: 'o', 1: 'X', 2: '^'}
    
    for action in [0, 1, 2]:
        mask = df['Action'] == action
        if mask.any():
            ax3.scatter(df[mask]['Step'], df[mask]['Reward'], 
                       c=action_colors[action], marker=action_markers[action], 
                       s=80, label=f'{action_labels[action]} (R={df[mask]["Reward"].mean():.2f})',
                       edgecolor='k', linewidth=0.8, alpha=0.7)
    
    ax3.set_xlabel('Time Step', fontsize=11)
    ax3.set_ylabel('Immediate Reward', fontsize=11)
    ax3.legend(loc='lower right', frameon=True, ncol=3)
    ax3.grid(True, linestyle='--', alpha=0.6)
    
    plt.suptitle('Real-Time Agent Decision-Making Process', fontsize=14, y=0.995)
    plt.tight_layout()
    
    plt.savefig(save_path, format='pdf', dpi=300, bbox_inches='tight')
    print(f"   -> Saved to {save_path}")
    plt.close()


def generate_policy_heatmap(csv_path, save_path):
    """
    2D heatmap showing the agent's policy as a function of Threat Intensity and Network Load.
    This is the KEY visualization for DRL papers!
    """
    print("[Plotter] Generating Policy Heatmap...")
    
    if not os.path.exists(csv_path):
        print(f"⚠️  {csv_path} not found. Skipping.")
        return
    
    df = pd.read_csv(csv_path)
    
    # Create a pivot table for the heatmap
    pivot_data = df.pivot(index='Threat_Intensity', columns='Network_Load', values='Action')
    
    fig, ax = plt.subplots(figsize=(10, 8))
    
    # Custom colormap: Blue (HOLD) -> Yellow (TARGETED) -> Red (GLOBAL)
    colors = ['#4c72b0', '#ddc755', '#c44e52']  # Blue, Yellow, Red
    cmap = LinearSegmentedColormap.from_list('policy_cmap', colors, N=3)
    
    im = ax.imshow(pivot_data.values, cmap=cmap, aspect='auto', 
                   origin='lower', extent=[0, 1, 0, 1], vmin=0, vmax=2)
    
    # Add action labels in each cell
    for i in range(len(pivot_data.index)):
        for j in range(len(pivot_data.columns)):
            val = pivot_data.values[i, j]
            if not np.isnan(val):
                action_name = ['HOLD', 'GLOBAL', 'TARGETED'][int(val)]
                ax.text(pivot_data.columns[j], pivot_data.index[i], action_name, ha='center', va='center', 
                       fontsize=9, fontweight='bold', color='white')
    
    ax.set_xlabel('Network Load ($F_t$)', fontsize=12)
    ax.set_ylabel('Threat Intensity ($I_t$)', fontsize=12)
    ax.set_title('Optimal Policy Surface: Action Selection as a Function of State', 
                fontsize=13, pad=15)
    
    # Add colorbar with custom labels
    cbar = plt.colorbar(im, ax=ax, ticks=[0, 1, 2])
    cbar.ax.set_yticklabels(['HOLD (QoS)', 'GLOBAL (Security)', 'TARGETED (Balanced)'])
    
    plt.tight_layout()
    
    plt.savefig(save_path, format='pdf', dpi=300, bbox_inches='tight')
    print(f"   -> Saved to {save_path}")
    plt.close()


# ==========================================
# MAIN EXECUTION
# ==========================================

if __name__ == "__main__":
    print("="*60)
    print("📊 GENERATING ACADEMIC-QUALITY VISUALIZATIONS")
    print("="*60)
    
    # 1. Find the latest run
    try:
        RUN_DIR = get_latest_run_dir()
        print(f"🔍 Found latest experiment run: {os.path.basename(RUN_DIR)}")
    except FileNotFoundError as e:
        print(f"❌ Error: {e}")
        exit(1)
    
    # 2. Create plots directory inside the run folder
    PLOTS_DIR = os.path.join(RUN_DIR, "plots")
    os.makedirs(PLOTS_DIR, exist_ok=True)
    
    # 3. Generate all plots
    generate_training_convergence_plot(
        os.path.join(RUN_DIR, "training_convergence.csv"),
        os.path.join(PLOTS_DIR, "drl_training_convergence.pdf")
    )
    
    generate_action_comparison_plot(
        os.path.join(RUN_DIR, "action_rewards.csv"),
        os.path.join(PLOTS_DIR, "action_comparison.pdf")
    )
    
    generate_baseline_comparison_plot(
        os.path.join(RUN_DIR, "baseline_results.csv"),
        os.path.join(PLOTS_DIR, "baseline_performance_comparison.pdf")
    )
    
    generate_episode_timeline_trace(
        os.path.join(RUN_DIR, "episode_trace.csv"),
        os.path.join(PLOTS_DIR, "episode_timeline_trace.pdf")
    )
    
    generate_policy_heatmap(
        os.path.join(RUN_DIR, "policy_evaluation.csv"),
        os.path.join(PLOTS_DIR, "policy_heatmap.pdf")
    )
    
    print("\n" + "="*60)
    print(f"✅ All visualizations saved to: {PLOTS_DIR}")
    print("="*60)