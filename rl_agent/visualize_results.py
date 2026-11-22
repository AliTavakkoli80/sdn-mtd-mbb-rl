import os
import glob
import shutil
import numpy as np
import pandas as pd
import matplotlib as mpl
import matplotlib.pyplot as plt
import seaborn as sns
from matplotlib.colors import LinearSegmentedColormap

# ==========================================
# IEEE JOURNAL TYPOGRAPHY & LAYOUT CALIBRATION
# ==========================================
IEEE_SINGLE_COL_WIDTH = 3.50  # Single column width in inches (88.9 mm)
IEEE_DOUBLE_COL_WIDTH = 7.16  # Double column width in inches (181.8 mm)

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
RUNS_DIR = os.path.join(SCRIPT_DIR, "runs")

# Configure Seaborn base aesthetic first
sns.set_style("whitegrid", {'grid.linestyle': '--', 'grid.alpha': 0.6})

# Enforce TrueType Type-42 vector font embedding and Computer Modern math
mpl.rcParams['pdf.fonttype'] = 42
mpl.rcParams['ps.fonttype'] = 42
mpl.rcParams['font.family'] = 'serif'
mpl.rcParams['font.serif'] = ['Times New Roman', 'DejaVu Serif', 'Times']
mpl.rcParams['mathtext.fontset'] = 'cm'
mpl.rcParams['font.size'] = 8.0
mpl.rcParams['axes.labelsize'] = 8.5
mpl.rcParams['axes.titlesize'] = 9.0
mpl.rcParams['xtick.labelsize'] = 7.5
mpl.rcParams['ytick.labelsize'] = 7.5
mpl.rcParams['legend.fontsize'] = 7.5
mpl.rcParams['figure.titlesize'] = 9.5

# Okabe-Ito Colorblind-Safe Palette
OKABE_ITO = {
    'black': '#000000',
    'charcoal': '#555555',
    'orange': '#E69F00',
    'sky_blue': '#56B4E9',
    'bluish_green': '#009E73',
    'yellow': '#F0E442',
    'blue': '#0072B2',
    'vermillion': '#D55E00',
    'reddish_purple': '#CC79A7'
}

# Canonical 5-policy mapping across all comparative figures
POLICY_META = [
    ('Static (No MTD)', 'static', 'Static\n(No MTD)', '#555555'),
    ('OF-RHM / Periodic MTD', 'periodic', 'OF-RHM\n(Periodic)', '#D55E00'),
    ('Event-Driven / IDS-Triggered MTD', 'ids_triggered', 'IDS-MTD\n(Triggered)', '#E69F00'),
    ('Binary-Action DRL-MTD', 'binary_drl', 'Binary\nDRL', '#0072B2'),
    ('Proposed QoS-Aware DRL-MTD', 'real_drl', 'Proposed\nQoS-DRL', '#009E73')
]


def get_latest_run_dir():
    if not os.path.exists(RUNS_DIR):
        raise FileNotFoundError("No 'runs' directory found. Train a model first.")
    runs = [d for d in os.listdir(RUNS_DIR) if os.path.isdir(os.path.join(RUNS_DIR, d))]
    if not runs:
        raise FileNotFoundError("No experiment runs found.")
    runs.sort(reverse=True)
    return os.path.join(RUNS_DIR, runs[0])


# ==========================================
# PLOT GENERATORS
# ==========================================

def smooth_series_gaussian(y, sigma=25):
    """Applies pure numpy Gaussian smoothing with edge reflection padding."""
    radius = int(3 * sigma)
    if len(y) <= radius * 2:
        return pd.Series(y).rolling(window=max(3, len(y)//10), center=True).mean().bfill().ffill().values
    x = np.arange(-radius, radius + 1)
    kernel = np.exp(-0.5 * (x / sigma) ** 2)
    kernel /= kernel.sum()
    padded = np.pad(y, radius, mode='edge')
    return np.convolve(padded, kernel, mode='valid')


def generate_training_convergence_plot(csv_path, save_path, window_size=1000, title="PPO Agent Training Convergence"):
    """Generates convergence curve with spline/gaussian smoothing and vector-optimized decimation."""
    print(f"[Plotter] Generating Convergence Curve from {os.path.basename(csv_path)}...")
    if not os.path.exists(csv_path):
        print(f"⚠️  {csv_path} not found. Skipping.")
        return
    
    df = pd.read_csv(csv_path)
    if df.empty:
        print(f"⚠️  {csv_path} is empty. Skipping.")
        return

    timesteps = df['timestep'].values
    rewards = df['reward'].values
    n_points = len(rewards)

    # Adaptive smoothing and decimation for vector fidelity
    if n_points < 10000:
        # Fine-tuning trajectory: apply Gaussian kernel smoothing for continuous C^inf curve
        sigma = max(10, n_points // 150)
        smooth_mean = smooth_series_gaussian(rewards, sigma=sigma)
        smooth_sq = smooth_series_gaussian(rewards**2, sigma=sigma)
        smooth_var = np.maximum(0, smooth_sq - smooth_mean**2)
        smooth_std = np.sqrt(smooth_var)
        plot_t = timesteps
        plot_m = smooth_mean
        plot_s = smooth_std
        mean_label = 'Fine-Tuning Convergence Trajectory'
    else:
        # Long training run (e.g. 300,000 steps): compute centered rolling mean, then decimate for vector PDF fidelity
        actual_window = min(window_size, n_points)
        rolling_mean = pd.Series(rewards).rolling(window=actual_window, center=True).mean().bfill().ffill().values
        rolling_std = pd.Series(rewards).rolling(window=actual_window, center=True).std().fillna(0).values
        stride = max(1, n_points // 1500)
        plot_t = timesteps[::stride]
        plot_m = rolling_mean[::stride]
        plot_s = rolling_std[::stride]
        mean_label = f'Rolling Mean ({actual_window} steps)'
    
    fig, ax = plt.subplots(figsize=(IEEE_DOUBLE_COL_WIDTH, 2.7))
    ax.plot(plot_t, plot_m, color='#0072B2', linewidth=2.0, label=mean_label, zorder=3)
    ax.fill_between(plot_t, plot_m - plot_s, plot_m + plot_s, 
                    color='#0072B2', alpha=0.20, label='1-SD Variance Band (+/- 1 SD)', zorder=2)
    ax.axhline(y=0, color='black', linewidth=0.8, linestyle='--', alpha=0.6, zorder=1)
    
    # Only show transition line if 300,000 is within the plotted range
    if min(timesteps) <= 300000 <= max(timesteps):
        ax.axvline(x=300000, color='#D55E00', linewidth=1.5, linestyle='--', alpha=0.8, label='Fine-Tuning Transition', zorder=2)
    
    # Format x-axis with SI k-suffix
    if min(timesteps) >= 300000:
        ax.xaxis.set_major_formatter(mpl.ticker.FuncFormatter(lambda x, p: f'{x/1000:.1f}k'))
        ax.set_xlabel('Fine-Tuning Timesteps (Containernet)', fontsize=8.5, fontweight='bold')
    else:
        ax.xaxis.set_major_formatter(mpl.ticker.FuncFormatter(lambda x, p: f'{int(x/1000)}k' if x >= 1000 else f'{int(x)}'))
        ax.set_xlabel('Training Timesteps', fontsize=8.5, fontweight='bold')

    ax.set_ylabel('Reward per Timestep', fontsize=8.5, fontweight='bold')
    ax.set_title(title, fontsize=9.2, pad=8, fontweight='bold')
    
    margin = (max(timesteps) - min(timesteps)) * 0.02
    ax.set_xlim(min(timesteps) - margin, max(timesteps) + margin)
    
    # Set clean y-limits with padding
    y_min = float(min(plot_m - plot_s))
    y_max = float(max(plot_m + plot_s))
    y_span = max(y_max - y_min, 1.0)
    ax.set_ylim(y_min - 0.08 * y_span, y_max + 0.15 * y_span)

    ax.legend(loc='lower right', frameon=True, fancybox=False, edgecolor='black', fontsize=7.5)
    ax.grid(True, linestyle='--', alpha=0.35, zorder=0)
    
    fig.tight_layout()
    plt.savefig(save_path, format='pdf', dpi=300, bbox_inches='tight')
    print(f"   -> Saved to {save_path}")
    plt.close()


def generate_action_comparison_plot(csv_path, save_path):
    print(f"[Plotter] Generating Action Comparison from {os.path.basename(csv_path)}...")
    if not os.path.exists(csv_path):
        print(f"⚠️  {csv_path} not found. Skipping.")
        return
    df = pd.read_csv(csv_path)
    scenarios = df['Scenario'].tolist()
    # Format scenario names with linebreaks to prevent any label collision
    formatted_scenarios = [s.replace(' (', '\n(') for s in scenarios]
    
    hold_rewards = df['HOLD_Reward'].tolist()
    global_rewards = df['GLOBAL_Reward'].tolist()
    target_rewards = df['TARGETED_Reward'].tolist()
    x = np.arange(len(scenarios))
    width = 0.25
    
    fig, ax = plt.subplots(figsize=(IEEE_DOUBLE_COL_WIDTH, 3.2))
    bars1 = ax.bar(x - width, hold_rewards, width, label='HOLD', color='#0072B2', edgecolor='black', linewidth=1.0, hatch='///', zorder=3)
    bars2 = ax.bar(x, global_rewards, width, label='GLOBAL SHUFFLE', color='#D55E00', edgecolor='black', linewidth=1.0, hatch='\\\\\\', zorder=3)
    bars3 = ax.bar(x + width, target_rewards, width, label='TARGETED SHUFFLE', color='#009E73', edgecolor='black', linewidth=1.0, hatch='...', zorder=3)
    
    for bars in [bars1, bars2, bars3]:
        for bar in bars:
            height = bar.get_height()
            va = 'bottom' if height >= 0 else 'top'
            y_offset = 2.5 if height >= 0 else -2.5
            ax.annotate(f'{height:.1f}', xy=(bar.get_x() + bar.get_width() / 2, height),
                        xytext=(0, y_offset), textcoords="offset points", ha='center', va=va, fontsize=7.2, fontweight='bold', zorder=5)
            
    ax.set_xlabel('Network Threat & Workload Scenario', fontsize=8.5, fontweight='bold')
    ax.set_ylabel('Calculated Reward Outcome ($R_t$)', fontsize=8.5, fontweight='bold')
    ax.set_title('Action Reward Outcomes Across Network Operational Regimes', fontsize=9.2, pad=10, fontweight='bold')
    ax.set_xticks(x)
    ax.set_xticklabels(formatted_scenarios, ha='center', fontsize=7.6)
    ax.axhline(y=0, color='black', linewidth=1.0, linestyle='-', zorder=4)
    ax.legend(loc='upper left', frameon=True, fancybox=False, edgecolor='black', fontsize=7.5)
    
    all_vals = hold_rewards + global_rewards + target_rewards
    y_min = min(0, min(all_vals)) - 3.5
    y_max = max(0, max(all_vals)) + 3.0
    ax.set_ylim(y_min, y_max)
    ax.grid(True, linestyle='--', alpha=0.35, zorder=0)
    
    fig.tight_layout()
    plt.savefig(save_path, format='pdf', dpi=300, bbox_inches='tight')
    print(f"   -> Saved to {save_path}")
    plt.close()


def generate_baseline_comparison_plot(csv_path, save_path):
    print(f"[Plotter] Generating Baseline Comparison from {os.path.basename(csv_path)}...")
    if not os.path.exists(csv_path):
        print(f"⚠️  {csv_path} not found. Skipping.")
        return
    df = pd.read_csv(csv_path)

    # Harmonize v2 column names with legacy column names
    col_mapping = {
        'ASR_mean': 'Attack_Success_Rate',
        'QDR_mean': 'QoS_Disruption_Rate',
        'ShuffleFreq': 'Shuffle_Frequency',
        'ShuffleFreq_mean': 'Shuffle_Frequency',
        'FlowMods_mean': 'Control_Plane_FlowMods',
        'ASR_std': 'Attack_Success_Rate_std',
        'ASR_ci': 'Attack_Success_Rate_std',
        'QDR_std': 'QoS_Disruption_Rate_std',
        'QDR_ci': 'QoS_Disruption_Rate_std',
        'FlowMods_std': 'Control_Plane_FlowMods_std',
        'FlowMods_ci': 'Control_Plane_FlowMods_std'
    }
    df = df.rename(columns=col_mapping)

    # If the CSV contains factorial variants (Stateless vs MBB), isolate the canonical deployed MBB implementation
    if df['Policy'].str.contains('MBB').any() and df['Policy'].str.contains('Stateless').any():
        df = df[df['Policy'].str.contains('MBB')].copy()
    df['Policy'] = df['Policy'].str.replace(' (MBB)', '', regex=False)

    baselines = df['Policy'].tolist()
    n_bars = len(baselines)
    x = np.arange(n_bars)
    width = 0.55

    # Okabe-Ito Colorblind-Safe Palette
    palette = ['#555555', '#D55E00', '#E69F00', '#0072B2', '#009E73']
    hatches = ['//', '\\\\', 'xx', '++', '..']
    colors = palette[:n_bars] if n_bars <= len(palette) else sns.color_palette("tab10", n_bars)

    has_extra_metrics = ('Shuffle_Frequency' in df.columns and 'Control_Plane_FlowMods' in df.columns)

    asr_err = df['Attack_Success_Rate_std'] if 'Attack_Success_Rate_std' in df.columns else None
    qdr_err = df['QoS_Disruption_Rate_std'] if 'QoS_Disruption_Rate_std' in df.columns else None
    fmd_err = df['Control_Plane_FlowMods_std'] if 'Control_Plane_FlowMods_std' in df.columns else None

    short_baselines = [
        b.replace('OF-RHM / Periodic MTD', 'OF-RHM\n(Periodic)')
         .replace('Event-Driven / IDS-Triggered MTD', 'IDS-MTD\n(Triggered)')
         .replace('IDS-Triggered MTD', 'IDS-MTD\n(Triggered)')
         .replace('Binary-Action DRL-MTD', 'Binary\nDRL')
         .replace('Proposed QoS-Aware DRL-MTD', 'Proposed\nQoS-DRL')
         .replace('Static (No MTD)', 'Static\n(No MTD)')
         .replace('DRL Agent (Ours)', 'Proposed\nQoS-DRL')
        for b in baselines
    ]

    if has_extra_metrics:
        fig, axes = plt.subplots(2, 2, figsize=(IEEE_DOUBLE_COL_WIDTH, 4.4))
        (ax1, ax2), (ax3, ax4) = axes

        # (a) Attack Success Rate
        bars1 = ax1.bar(x, df['Attack_Success_Rate'], width, yerr=asr_err, capsize=3,
                        error_kw={'elinewidth': 1.0, 'ecolor': 'black'}, color=colors, edgecolor='k', linewidth=1.0, zorder=3)
        for i, bar in enumerate(bars1):
            bar.set_hatch(hatches[i % len(hatches)])
            h = bar.get_height()
            err = asr_err.iloc[i] if asr_err is not None else 0
            ax1.annotate(f'{h:.1f}%', xy=(bar.get_x() + bar.get_width()/2, h + err),
                         xytext=(0, 2.5), textcoords="offset points", ha='center', va='bottom', fontweight='bold', fontsize=7.2, zorder=5)
        ax1.set_ylabel('Attacker Success Rate (%)', fontsize=8.0, fontweight='bold')
        ax1.set_xticks(x)
        ax1.set_xticklabels(short_baselines, rotation=0, ha='center', fontsize=7.2)
        max_asr = (df['Attack_Success_Rate'] + (asr_err if asr_err is not None else 0)).max()
        ax1.set_ylim(0, max_asr * 1.25)
        ax1.set_title('(a) Security Defense Efficacy', fontsize=8.5, pad=6, fontweight='bold')
        ax1.grid(True, linestyle='--', alpha=0.35, axis='y', zorder=0)

        # (b) QoS Disruption Rate
        bars2 = ax2.bar(x, df['QoS_Disruption_Rate'], width, yerr=qdr_err, capsize=3,
                        error_kw={'elinewidth': 1.0, 'ecolor': 'black'}, color=colors, edgecolor='k', linewidth=1.0, zorder=3)
        for i, bar in enumerate(bars2):
            bar.set_hatch(hatches[i % len(hatches)])
            h = bar.get_height()
            err = qdr_err.iloc[i] if qdr_err is not None else 0
            ax2.annotate(f'{h:.1f}%', xy=(bar.get_x() + bar.get_width()/2, h + err),
                         xytext=(0, 2.5), textcoords="offset points", ha='center', va='bottom', fontweight='bold', fontsize=7.2, zorder=5)
        ax2.set_ylabel('Session Disruption Rate (%)', fontsize=8.0, fontweight='bold')
        ax2.set_xticks(x)
        ax2.set_xticklabels(short_baselines, rotation=0, ha='center', fontsize=7.2)
        max_qdr = (df['QoS_Disruption_Rate'] + (qdr_err if qdr_err is not None else 0)).max()
        ax2.set_ylim(0, max(2.5, max_qdr * 1.35))
        ax2.set_title('(b) Collateral Quality-of-Service Cost', fontsize=8.5, pad=6, fontweight='bold')
        ax2.grid(True, linestyle='--', alpha=0.35, axis='y', zorder=0)

        # (c) Shuffle Frequency
        bars3 = ax3.bar(x, df['Shuffle_Frequency'], width, color=colors, edgecolor='k', linewidth=1.0, zorder=3)
        for i, bar in enumerate(bars3):
            bar.set_hatch(hatches[i % len(hatches)])
            h = bar.get_height()
            ax3.annotate(f'{h:.1f}%', xy=(bar.get_x() + bar.get_width()/2, h),
                         xytext=(0, 2.5), textcoords="offset points", ha='center', va='bottom', fontweight='bold', fontsize=7.2, zorder=5)
        ax3.set_ylabel('Shuffle Frequency (% Steps)', fontsize=8.0, fontweight='bold')
        ax3.set_xticks(x)
        ax3.set_xticklabels(short_baselines, rotation=0, ha='center', fontsize=7.2)
        ax3.set_ylim(0, max(100.0, df['Shuffle_Frequency'].max() * 1.18))
        ax3.set_title('(c) MTD Actuation Frequency', fontsize=8.5, pad=6, fontweight='bold')
        ax3.grid(True, linestyle='--', alpha=0.35, axis='y', zorder=0)

        # (d) Control Plane FlowMods
        bars4 = ax4.bar(x, df['Control_Plane_FlowMods'], width, yerr=fmd_err, capsize=3,
                        error_kw={'elinewidth': 1.0, 'ecolor': 'black'}, color=colors, edgecolor='k', linewidth=1.0, zorder=3)
        for i, bar in enumerate(bars4):
            bar.set_hatch(hatches[i % len(hatches)])
            h = bar.get_height()
            err = fmd_err.iloc[i] if fmd_err is not None else 0
            ax4.annotate(f'{h:.0f}', xy=(bar.get_x() + bar.get_width()/2, h + err),
                         xytext=(0, 2.5), textcoords="offset points", ha='center', va='bottom', fontweight='bold', fontsize=7.2, zorder=5)
        ax4.set_ylabel('Total FLOW_MOD Messages', fontsize=8.0, fontweight='bold')
        ax4.set_xticks(x)
        ax4.set_xticklabels(short_baselines, rotation=0, ha='center', fontsize=7.2)
        max_fmd = (df['Control_Plane_FlowMods'] + (fmd_err if fmd_err is not None else 0)).max()
        ax4.set_ylim(0, max_fmd * 1.25)
        ax4.set_title('(d) SDN Control Plane Overhead', fontsize=8.5, pad=6, fontweight='bold')
        ax4.grid(True, linestyle='--', alpha=0.35, axis='y', zorder=0)

    else:
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(IEEE_DOUBLE_COL_WIDTH, 2.7))
        bars1 = ax1.bar(x, df['Attack_Success_Rate'], width, yerr=asr_err, capsize=3, color=colors, edgecolor='k', linewidth=1.0, zorder=3)
        for i, bar in enumerate(bars1):
            bar.set_hatch(hatches[i % len(hatches)])
            h = bar.get_height()
            err = asr_err.iloc[i] if asr_err is not None else 0
            ax1.annotate(f'{h:.1f}%', xy=(bar.get_x() + bar.get_width()/2, h + err),
                         xytext=(0, 2.5), textcoords="offset points", ha='center', va='bottom', fontweight='bold', fontsize=7.2, zorder=5)
        ax1.set_ylabel('Attacker Success Rate (%)', fontsize=8.0, fontweight='bold')
        ax1.set_xticks(x)
        ax1.set_xticklabels(short_baselines, rotation=0, ha='center', fontsize=7.2)
        max_asr = (df['Attack_Success_Rate'] + (asr_err if asr_err is not None else 0)).max()
        ax1.set_ylim(0, max_asr * 1.25)
        ax1.set_title('(a) Security Defense Efficacy', fontsize=8.5, pad=6, fontweight='bold')
        ax1.grid(True, linestyle='--', alpha=0.35, axis='y', zorder=0)

        bars2 = ax2.bar(x, df['QoS_Disruption_Rate'], width, yerr=qdr_err, capsize=3, color=colors, edgecolor='k', linewidth=1.0, zorder=3)
        for i, bar in enumerate(bars2):
            bar.set_hatch(hatches[i % len(hatches)])
            h = bar.get_height()
            err = qdr_err.iloc[i] if qdr_err is not None else 0
            ax2.annotate(f'{h:.1f}%', xy=(bar.get_x() + bar.get_width()/2, h + err),
                         xytext=(0, 2.5), textcoords="offset points", ha='center', va='bottom', fontweight='bold', fontsize=7.2, zorder=5)
        ax2.set_ylabel('Session Disruption Rate (%)', fontsize=8.0, fontweight='bold')
        ax2.set_xticks(x)
        ax2.set_xticklabels(short_baselines, rotation=0, ha='center', fontsize=7.2)
        max_qdr = (df['QoS_Disruption_Rate'] + (qdr_err if qdr_err is not None else 0)).max()
        ax2.set_ylim(0, max(2.5, max_qdr * 1.35))
        ax2.set_title('(b) Collateral Quality-of-Service Cost', fontsize=8.5, pad=6, fontweight='bold')
        ax2.grid(True, linestyle='--', alpha=0.35, axis='y', zorder=0)

    fig.tight_layout()
    plt.savefig(save_path, format='pdf', dpi=300, bbox_inches='tight')
    print(f"   -> Saved to {save_path}")
    plt.close()


def generate_episode_timeline_trace(csv_path, save_path):
    print(f"[Plotter] Generating Episode Timeline Trace from {os.path.basename(csv_path)}...")
    if not os.path.exists(csv_path):
        print(f"⚠️  {csv_path} not found. Skipping.")
        return
    df = pd.read_csv(csv_path)

    # Normalize column names to title case for compatibility across mock & real runs
    col_mapping = {
        'step': 'Step',
        'threat_intensity': 'Threat_Intensity',
        'active_flows_norm': 'Network_Load',
        'action': 'Action',
        'reward': 'Reward'
    }
    df = df.rename(columns={k: v for k, v in col_mapping.items() if k in df.columns})
    
    fig, (ax1, ax2, ax3) = plt.subplots(3, 1, figsize=(IEEE_DOUBLE_COL_WIDTH, 4.0), sharex=True, gridspec_kw={'height_ratios': [1, 1, 1.35]})
    ax1.fill_between(df['Step'], 0, df['Threat_Intensity'], color='#D55E00', alpha=0.25, label=r'Threat Intensity ($I_t$)', zorder=2)
    ax1.plot(df['Step'], df['Threat_Intensity'], color='#D55E00', linewidth=1.6, zorder=3)
    ax1.set_ylabel(r'Threat ($I_t$)', fontsize=8.0, fontweight='bold')
    ax1.set_ylim(0, 1.1)
    ax1.legend(loc='upper right', frameon=True, fontsize=7.2)
    ax1.grid(True, linestyle='--', alpha=0.35, zorder=0)
    
    ax2.fill_between(df['Step'], 0, df['Network_Load'], color='#0072B2', alpha=0.25, label=r'Network Load ($F_t$)', zorder=2)
    ax2.plot(df['Step'], df['Network_Load'], color='#0072B2', linewidth=1.6, zorder=3)
    ax2.set_ylabel(r'Load ($F_t$)', fontsize=8.0, fontweight='bold')
    ax2.set_ylim(0, 1.1)
    ax2.legend(loc='upper right', frameon=True, fontsize=7.2)
    ax2.grid(True, linestyle='--', alpha=0.35, zorder=0)
    
    action_colors = {0: '#0072B2', 1: '#D55E00', 2: '#009E73'}
    action_labels = {0: 'HOLD', 1: 'GLOBAL', 2: 'TARGETED'}
    action_markers = {0: 'o', 1: 'X', 2: '^'}
    
    for action in [0, 1, 2]:
        mask = df['Action'] == action
        if mask.any():
            ax3.scatter(df[mask]['Step'], df[mask]['Reward'], c=action_colors[action], marker=action_markers[action], 
                       s=45, label=f'{action_labels[action]} (Mean R={df[mask]["Reward"].mean():.2f})',
                       edgecolor='k', linewidth=0.6, alpha=0.9, zorder=4)
    ax3.set_xlabel('Decision Time Step', fontsize=8.2, fontweight='bold')
    ax3.set_ylabel(r'Reward ($R_t$)', fontsize=8.0, fontweight='bold')
    
    r_min = float(df['Reward'].min())
    r_max = float(df['Reward'].max())
    y_pad = max(1.5, (r_max - r_min) * 0.12)
    ax3.set_ylim(r_min - y_pad, r_max + y_pad)
    ax3.axhline(0, color='black', linewidth=0.7, linestyle=':', alpha=0.6, zorder=1)
    
    top_right_occupied = ((df['Step'] > df['Step'].max() * 0.6) & (df['Reward'] > r_max - 2 * y_pad)).any()
    leg_loc = 'upper left' if top_right_occupied else 'upper right'
    ax3.legend(loc=leg_loc, frameon=True, ncol=1, fontsize=7.0, framealpha=0.92, edgecolor='black')
    ax3.grid(True, linestyle='--', alpha=0.35, zorder=0)
    
    fig.align_ylabels([ax1, ax2, ax3])
    plt.suptitle('State-Action Trajectory & Real-Time Decision Dynamics', fontsize=9.2, y=0.995, fontweight='bold')
    fig.tight_layout()
    fig.tight_layout()
    plt.savefig(save_path, format='pdf', dpi=300, bbox_inches='tight')
    print(f"   -> Saved to {save_path}")
    plt.close()


def generate_policy_heatmap(csv_path, save_path, title="Learned Policy Decision Surface"):
    print(f"[Plotter] Generating Policy Heatmap from {os.path.basename(csv_path)}...")
    if not os.path.exists(csv_path):
        print(f"⚠️  {csv_path} not found. Skipping.")
        return
    df = pd.read_csv(csv_path)
    pivot_data = df.pivot(index='Threat_Intensity', columns='Network_Load', values='Action')
    
    fig, ax = plt.subplots(figsize=(IEEE_SINGLE_COL_WIDTH, 2.9))
    colors = ['#0072B2', '#E69F00', '#D55E00']
    cmap = LinearSegmentedColormap.from_list('policy_cmap', colors, N=3)
    
    # Render clean discrete decision surface
    im = ax.imshow(
        pivot_data.values, cmap=cmap, aspect='auto', origin='lower',
        extent=[-0.05, 1.05, -0.05, 1.05], vmin=-0.5, vmax=2.5, zorder=1
    )
    
    # Add clean, non-colliding region watermark callouts conditionally
    vals = pivot_data.values
    if 0 in vals:
        ax.text(0.50, 0.07, 'HOLD (Preserve QoS)', ha='center', va='center',
                fontsize=7.2, fontweight='bold', color='white',
                bbox=dict(boxstyle='round,pad=0.18', facecolor='#0072B2', edgecolor='white', lw=0.5, alpha=0.88))
    
    if (1 in vals) and (2 not in vals):
        # Sweep regime: broad GLOBAL region
        ax.text(0.42, 0.70, 'GLOBAL (Max Sec)', ha='center', va='center',
                fontsize=7.2, fontweight='bold', color='white',
                bbox=dict(boxstyle='round,pad=0.18', facecolor='#E69F00', edgecolor='white', lw=0.5, alpha=0.88))
    elif (1 not in vals) and (2 in vals):
        # Targeted scan regime: broad TARGETED region
        ax.text(0.50, 0.58, 'TARGETED (Balanced MTD)', ha='center', va='center',
                fontsize=7.2, fontweight='bold', color='white',
                bbox=dict(boxstyle='round,pad=0.18', facecolor='#D55E00', edgecolor='white', lw=0.5, alpha=0.88))
    else:
        # Dual-action active regime: keep strictly within axes boundaries
        if 1 in vals:
            ax.text(0.04, 0.72, 'GLOBAL\n(Max Sec)', ha='left', va='center',
                    fontsize=6.8, fontweight='bold', color='white',
                    bbox=dict(boxstyle='round,pad=0.14', facecolor='#E69F00', edgecolor='white', lw=0.5, alpha=0.88))
        if 2 in vals:
            ax.text(0.65, 0.65, 'TARGETED\n(Balanced MTD)', ha='center', va='center',
                    fontsize=6.8, fontweight='bold', color='white',
                    bbox=dict(boxstyle='round,pad=0.14', facecolor='#D55E00', edgecolor='white', lw=0.5, alpha=0.88))
    
    ax.set_xlabel('Network Flow Load ($F_t$)', fontsize=8.0, fontweight='bold')
    ax.set_ylabel('Threat Intensity ($I_t$)', fontsize=8.0, fontweight='bold')
    ax.set_title(title, fontsize=8.5, pad=8, fontweight='bold')
    ax.set_xlim(0, 1.0)
    ax.set_ylim(0, 1.0)
    
    cbar = plt.colorbar(im, ax=ax, ticks=[0, 1, 2], fraction=0.046, pad=0.04)
    cbar.ax.set_yticklabels(['HOLD', 'GLOBAL', 'TARGETED'], fontsize=7.0)
    
    fig.tight_layout()
    plt.savefig(save_path, format='pdf', dpi=300, bbox_inches='tight')
    print(f"   -> Saved to {save_path}")
    plt.close()


def generate_sim_to_real_comparison_plot(mock_csv, real_csv, save_path):
    """Compares the Mock-Only agent vs the Fine-Tuned Real agent."""
    print("[Plotter] Generating Sim-to-Real Comparison...")
    if not os.path.exists(mock_csv) or not os.path.exists(real_csv):
        print("⚠️ Missing mock or real baseline data. Skipping comparison.")
        return
    df_mock = pd.read_csv(mock_csv)
    df_real = pd.read_csv(real_csv)
    
    col_mapping = {
        'ASR_mean': 'Attack_Success_Rate',
        'QDR_mean': 'QoS_Disruption_Rate',
        'ASR': 'Attack_Success_Rate',
        'QDR': 'QoS_Disruption_Rate'
    }
    df_mock = df_mock.rename(columns=col_mapping)
    df_real = df_real.rename(columns=col_mapping)
    
    def get_drl_row(df):
        # Prefer MBB version if available in factorial results
        if df['Policy'].str.contains('MBB').any():
            mbb_matched = df[df['Policy'].str.contains('MBB') & df['Policy'].str.contains('Proposed', regex=True)]
            if not mbb_matched.empty:
                return mbb_matched.iloc[0]
        for name in ['Proposed QoS-Aware DRL-MTD', 'DRL Agent (Ours)', 'Proposed']:
            matched = df[df['Policy'].str.contains(name, na=False)]
            if not matched.empty:
                return matched.iloc[-1]
        return df.iloc[-1]

    mock_drl = get_drl_row(df_mock)
    real_drl = get_drl_row(df_real)
    categories = ['Mock-Only\n(Simulation)', 'Fine-Tuned\n(Containernet)']
    attack_success = [mock_drl['Attack_Success_Rate'], real_drl['Attack_Success_Rate']]
    qos_disruption = [mock_drl['QoS_Disruption_Rate'], real_drl['QoS_Disruption_Rate']]
    x = np.arange(len(categories))
    width = 0.35
    
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(IEEE_DOUBLE_COL_WIDTH, 2.7))
    bars1 = ax1.bar(x, attack_success, width, color=['#E69F00', '#009E73'], edgecolor='k', linewidth=1.0, zorder=3)
    ax1.set_ylabel('Attacker Success Rate (%)', fontsize=8.2, fontweight='bold')
    ax1.set_xticks(x)
    ax1.set_xticklabels(categories, fontsize=7.8)
    max_asr = max(attack_success)
    ax1.set_ylim(0, max(20.0, max_asr * 1.35))
    ax1.set_title('(a) Security Defense Efficacy', fontsize=8.8, pad=8, fontweight='bold')
    ax1.grid(True, linestyle='--', alpha=0.35, axis='y', zorder=0)
    for bar in bars1:
        ax1.annotate(f'{bar.get_height():.1f}%', xy=(bar.get_x() + bar.get_width()/2, bar.get_height()),
                     xytext=(0, 2.5), textcoords="offset points", ha='center', va='bottom', fontweight='bold', fontsize=7.5, zorder=5)
        
    bars2 = ax2.bar(x, qos_disruption, width, color=['#E69F00', '#009E73'], edgecolor='k', linewidth=1.0, zorder=3)
    ax2.set_ylabel('Session Disruption Rate (%)', fontsize=8.2, fontweight='bold')
    ax2.set_xticks(x)
    ax2.set_xticklabels(categories, fontsize=7.8)
    max_qdr = max(qos_disruption)
    ax2.set_ylim(0, max(25.0, max_qdr * 1.35))
    ax2.set_title('(b) Collateral Quality-of-Service Cost', fontsize=8.8, pad=8, fontweight='bold')
    ax2.grid(True, linestyle='--', alpha=0.35, axis='y', zorder=0)
    for bar in bars2:
        ax2.annotate(f'{bar.get_height():.1f}%', xy=(bar.get_x() + bar.get_width()/2, bar.get_height()),
                     xytext=(0, 2.5), textcoords="offset points", ha='center', va='bottom', fontweight='bold', fontsize=7.5, zorder=5)
        
    fig.tight_layout()
    plt.savefig(save_path, format='pdf', dpi=300, bbox_inches='tight')
    print(f"   -> Saved to {save_path}")
    plt.close()


# ==========================================
# PHASE 1: IEEE UPGRADE VISUALIZATIONS
# ==========================================

def generate_statistical_distribution_plot(run_dir, save_path):
    """
    Step 2: Dual-panel statistical distribution contours (Double-Column: 7.16 x 2.7 in).
    Parses the 150 raw episode CSV files (real_eval_raw_*_ep*.csv) from the latest run directory.
    Panel (a): Violin kernel density + median/IQR Boxplot + jittered individual scatter points for ASR.
    Panel (b): Corresponding distribution for Cumulative Episode Return (Reward).
    """
    eval_dir = run_dir
    if not glob.glob(os.path.join(eval_dir, "real_eval_raw_*.csv")):
        runs = sorted(glob.glob(os.path.join(RUNS_DIR, "run_*")), reverse=True)
        for r in runs:
            if glob.glob(os.path.join(r, "real_eval_raw_*.csv")):
                eval_dir = r
                break

    print(f"[Plotter] Generating Statistical Distribution Contours from {os.path.basename(eval_dir)}...")
    
    records = []
    for pol_full, clean_prefix, label, color in POLICY_META:
        pattern = os.path.join(eval_dir, f"real_eval_raw_{clean_prefix}*_ep*.csv")
        files = sorted(glob.glob(pattern))
        if not files:
            pattern_fallback = os.path.join(SCRIPT_DIR, f"real_eval_raw_{clean_prefix}*_ep*.csv")
            files = sorted(glob.glob(pattern_fallback))
        
        for f in files:
            df = pd.read_csv(f)
            ep = int(df['episode'].iloc[0]) if 'episode' in df.columns else 1
            tot_rew = float(df['reward'].sum())
            q = df[df['scanned_count'] > 0]['asr']
            ep_asr = float(q.mean() if len(q) > 0 else df[(df['step'] % 36 >= 8) & (df['step'] % 36 < 30)]['asr'].mean())
            
            records.append({
                'policy': label,
                'color': color,
                'clean': clean_prefix,
                'episode': ep,
                'reward': tot_rew,
                'asr': ep_asr
            })

    if not records:
        print(f"⚠️  No raw episode files found in {run_dir}. Skipping distribution plot.")
        return

    df_ep = pd.DataFrame(records)
    print(f"   -> Parsed {len(df_ep)} raw episode records across {len(POLICY_META)} policies.")

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(IEEE_DOUBLE_COL_WIDTH, 2.7))
    order = [p[2] for p in POLICY_META]
    palette = [p[3] for p in POLICY_META]

    # --- PANEL (a): Attacker Success Rate (ASR) ---
    sns.violinplot(
        x='policy', y='asr', data=df_ep, order=order, palette=palette, hue='policy', legend=False,
        ax=ax1, inner=None, cut=1.5, bw_adjust=1.25, density_norm='width', gridsize=200,
        linewidth=0.8, saturation=0.85, zorder=2
    )
    for col in ax1.collections:
        col.set_alpha(0.35)

    sns.boxplot(
        x='policy', y='asr', data=df_ep, order=order,
        ax=ax1, width=0.18, showfliers=False, zorder=3,
        boxprops=dict(facecolor='white', edgecolor='black', alpha=0.92, linewidth=0.9),
        whiskerprops=dict(color='black', linewidth=0.9),
        capprops=dict(color='black', linewidth=0.9),
        medianprops=dict(color='#8B0000', linewidth=1.8),
        showmeans=True, meanprops=dict(marker='D', markeredgecolor='black', markerfacecolor='white', markersize=3.2)
    )

    sns.stripplot(
        x='policy', y='asr', data=df_ep, order=order, palette=palette, hue='policy', legend=False,
        ax=ax1, size=2.8, jitter=0.12, alpha=0.65, edgecolor='black', linewidth=0.35, zorder=4
    )

    ax1.set_title('(a) Attacker Success Rate (ASR)', fontsize=8.8, fontweight='bold', pad=7)
    ax1.set_ylabel('ASR (%)', fontsize=8.2, fontweight='bold')
    ax1.set_xlabel('Defense Policy', fontsize=8.0, fontweight='bold')
    max_asr = float(df_ep['asr'].max())
    ax1.set_ylim(-3, max(42.0, max_asr * 1.25))
    ax1.grid(True, linestyle='--', alpha=0.35, axis='y', zorder=0)
    ax1.tick_params(axis='x', labelsize=6.8, pad=2)
    ax1.tick_params(axis='y', labelsize=7.5)

    # --- PANEL (b): Cumulative Episode Return (Reward) ---
    sns.violinplot(
        x='policy', y='reward', data=df_ep, order=order, palette=palette, hue='policy', legend=False,
        ax=ax2, inner=None, cut=1.5, bw_adjust=1.25, density_norm='width', gridsize=200,
        linewidth=0.8, saturation=0.85, zorder=2
    )
    for col in ax2.collections:
        col.set_alpha(0.35)

    sns.boxplot(
        x='policy', y='reward', data=df_ep, order=order,
        ax=ax2, width=0.18, showfliers=False, zorder=3,
        boxprops=dict(facecolor='white', edgecolor='black', alpha=0.92, linewidth=0.9),
        whiskerprops=dict(color='black', linewidth=0.9),
        capprops=dict(color='black', linewidth=0.9),
        medianprops=dict(color='#8B0000', linewidth=1.8),
        showmeans=True, meanprops=dict(marker='D', markeredgecolor='black', markerfacecolor='white', markersize=3.2)
    )

    sns.stripplot(
        x='policy', y='reward', data=df_ep, order=order, palette=palette, hue='policy', legend=False,
        ax=ax2, size=2.8, jitter=0.12, alpha=0.65, edgecolor='black', linewidth=0.35, zorder=4
    )

    ax2.axhline(0, color='black', linestyle=':', linewidth=0.8, alpha=0.6, zorder=1)
    ax2.set_title('(b) Cumulative Episode Return', fontsize=8.8, fontweight='bold', pad=7)
    ax2.set_ylabel('Cumulative Reward', fontsize=8.2, fontweight='bold')
    ax2.set_xlabel('Defense Policy', fontsize=8.0, fontweight='bold')
    ax2.grid(True, linestyle='--', alpha=0.35, axis='y', zorder=0)
    ax2.tick_params(axis='x', labelsize=6.8, pad=2)
    ax2.tick_params(axis='y', labelsize=7.5)

    fig.tight_layout()
    plt.savefig(save_path, format='pdf', dpi=300, bbox_inches='tight')
    print(f"   -> Saved to {save_path}")
    plt.close()


def generate_pareto_efficiency_plot(csv_path, save_path):
    """
    Step 3: 2D Pareto Efficiency Bubble Plot (Single-Column: 3.50 x 2.9 in).
    X-axis: Collateral QoS Disruption Rate (QDR %).
    Y-axis: Attacker Success Rate (ASR %).
    Bubble Area: Proportional to SDN Control Plane FlowMod overhead.
    Draws the non-dominated Pareto Frontier curve connecting Static MTD and the Proposed QoS-Aware DRL agent.
    """
    print(f"[Plotter] Generating Pareto Trade-Off Efficiency Bubble Plot from {os.path.basename(csv_path)}...")
    if not os.path.exists(csv_path):
        print(f"⚠️  {csv_path} not found. Skipping.")
        return
    df = pd.read_csv(csv_path)

    col_mapping = {
        'ASR_mean': 'ASR',
        'QDR_mean': 'QDR',
        'FlowMods_mean': 'FlowMods'
    }
    df = df.rename(columns=col_mapping)

    # If the CSV contains factorial variants (Stateless vs MBB), isolate the canonical deployed MBB implementation
    if df['Policy'].str.contains('MBB').any() and df['Policy'].str.contains('Stateless').any():
        df = df[df['Policy'].str.contains('MBB')].copy()
    df['Policy'] = df['Policy'].str.replace(' (MBB)', '', regex=False)

    fig, ax = plt.subplots(figsize=(IEEE_SINGLE_COL_WIDTH, 3.1))

    max_fm = df['FlowMods'].max()
    bubble_sizes = 50 + (df['FlowMods'] / max_fm) * 180

    # Non-colliding dedicated quadrant annotations with subtle bounding boxes
    meta = {
        'Static (No MTD)': {
            'name': 'Static (No MTD)',
            'color': '#555555',
            'xytext': (16, -6),
            'ha': 'left', 'va': 'top'
        },
        'OF-RHM / Periodic MTD': {
            'name': 'OF-RHM (Periodic)',
            'color': '#D55E00',
            'xytext': (14, 16),
            'ha': 'left', 'va': 'bottom'
        },
        'Event-Driven / IDS-Triggered MTD': {
            'name': 'IDS-MTD',
            'color': '#E69F00',
            'xytext': (12, 22),
            'ha': 'left', 'va': 'bottom'
        },
        'IDS-Triggered MTD': {
            'name': 'IDS-MTD',
            'color': '#E69F00',
            'xytext': (12, 22),
            'ha': 'left', 'va': 'bottom'
        },
        'Binary-Action DRL-MTD': {
            'name': 'Binary DRL',
            'color': '#0072B2',
            'xytext': (14, -8),
            'ha': 'left', 'va': 'top'
        },
        'Proposed QoS-Aware DRL-MTD': {
            'name': 'Proposed QoS-DRL',
            'color': '#009E73',
            'xytext': (-12, -26),
            'ha': 'left', 'va': 'top'
        }
    }

    def get_info(pol):
        if pol in meta:
            return meta[pol]
        for k, v in meta.items():
            if k in pol or pol in k:
                return v
        return {'name': pol, 'color': '#333333', 'xytext': (12, 12), 'ha': 'left', 'va': 'bottom'}

    for idx, row in df.iterrows():
        pol = row['Policy']
        info = get_info(pol)
        c = info['color']
        sz = bubble_sizes.loc[idx]
        ax.scatter(row['QDR'], row['ASR'], s=sz, color=c, edgecolor='black', linewidth=1.1, alpha=0.9, zorder=5)
        
        fm_val = row.get('FlowMods', 0)
        label_text = f"{info['name']}\n({int(round(fm_val))} FlowMods)"
        
        use_arrow = True
        ax.annotate(
            label_text,
            xy=(row['QDR'], row['ASR']),
            xytext=info['xytext'],
            textcoords='offset points',
            fontsize=6.2,
            fontweight='bold',
            ha=info['ha'],
            va=info['va'],
            zorder=6,
            arrowprops=dict(arrowstyle='->', color='#555555', lw=0.6) if use_arrow else None,
            bbox=dict(boxstyle='round,pad=0.2', facecolor='white', edgecolor='#cccccc', lw=0.4, alpha=0.92)
        )

    # Pareto Frontier: Objectively compute non-dominated points (minimizing both QDR and ASR)
    sorted_df = df.sort_values(by=['QDR', 'ASR'])
    pareto_rows = []
    min_asr_so_far = float('inf')
    for _, r in sorted_df.iterrows():
        if r['ASR'] <= min_asr_so_far:
            pareto_rows.append(r)
            min_asr_so_far = r['ASR']

    pareto_pts = pd.DataFrame(pareto_rows).sort_values('QDR')
    px = pareto_pts['QDR'].values
    py = pareto_pts['ASR'].values

    # Monotonic Spline or Linear Interpolation across non-dominated points
    if len(px) >= 3:
        n = len(px)
        d = np.diff(py) / np.diff(px)
        d = np.where(np.diff(px) == 0, 0, d)
        m = np.zeros(n)
        m[0] = d[0]
        m[-1] = d[-1]
        for i in range(1, n - 1):
            m[i] = 2.0 / (1.0 / d[i - 1] + 1.0 / d[i]) if (d[i - 1] * d[i] > 0) else 0.0

        xs = np.linspace(px[0], px[-1], 200)
        ys = np.zeros_like(xs)
        for j, val in enumerate(xs):
            if val <= px[0]: ys[j] = py[0]
            elif val >= px[-1]: ys[j] = py[-1]
            else:
                k = np.searchsorted(px, val) - 1
                h = px[k + 1] - px[k]
                if h == 0:
                    ys[j] = py[k]
                    continue
                t = (val - px[k]) / h
                h00 = 2*t**3 - 3*t**2 + 1
                h10 = t**3 - 2*t**2 + t
                h01 = -2*t**3 + 3*t**2
                h11 = t**3 - t**2
                ys[j] = h00*py[k] + h10*h*m[k] + h01*py[k + 1] + h11*h*m[k + 1]

        ax.plot(xs, ys, color='#c44e52', linestyle='--', linewidth=1.6, zorder=3, label='Pareto Frontier')
    elif len(px) >= 2:
        ax.plot(px, py, color='#c44e52', linestyle='--', linewidth=1.6, zorder=3, label='Pareto Frontier')

    # Size legend for FlowMod bubble overhead
    min_fm = int(df['FlowMods'].min())
    med_fm = int(df['FlowMods'].median())
    max_fm_val = int(df['FlowMods'].max())
    leg_line = ax.plot([], [], color='#c44e52', linestyle='--', linewidth=1.5, label='Pareto Frontier')[0]
    leg_s1 = ax.scatter([], [], s=45, c='#777777', edgecolors='k', linewidth=0.8, label=f'{min_fm} FlowMods')
    leg_s2 = ax.scatter([], [], s=115, c='#777777', edgecolors='k', linewidth=0.8, label=f'{med_fm} FlowMods')
    leg_s3 = ax.scatter([], [], s=205, c='#777777', edgecolors='k', linewidth=0.8, label=f'{max_fm_val} FlowMods')

    ax.legend(
        handles=[leg_line, leg_s1, leg_s2, leg_s3],
        labels=['Pareto Frontier', f'{min_fm} FlowMods', f'{med_fm} FlowMods', f'{max_fm_val} FlowMods'],
        loc='upper right', fontsize=6.0, frameon=True, framealpha=0.92, edgecolor='black',
        markerscale=0.65, labelspacing=0.5, borderpad=0.4
    )

    ax.set_xlabel('Collateral QoS Disruption Rate (QDR %)', fontsize=7.8, fontweight='bold')
    ax.set_ylabel('Attacker Success Rate (ASR %)', fontsize=7.8, fontweight='bold')
    ax.set_title('Pareto Trade-Off: Security vs. Disruption vs. FlowMods', fontsize=8.2, fontweight='bold', pad=6)

    x_max = max(float(df['QDR'].max()) * 1.45, 3.2)
    ax.set_xlim(-0.3, x_max)
    y_max = max(float(df['ASR'].max()) * 1.22, 55.0)
    ax.set_ylim(-2.0, y_max)
    ax.grid(True, linestyle='--', alpha=0.35, zorder=0)
    ax.tick_params(labelsize=7.0)

    fig.tight_layout()
    plt.savefig(save_path, format='pdf', dpi=300, bbox_inches='tight')
    print(f"   -> Saved to {save_path}")
    plt.close()


def generate_mbb_tcp_dashboard(csv_path, save_path):
    """
    Step 4: Synchronized 3-panel double-column Make-Before-Break Dashboard (7.16 x 4.0 in).
    Using data from dataplane_mbb_benchmark.csv:
    Panel 1: Throughput (Mbps) with shaded 15-second grace window horizons.
    Panel 2: TCP Congestion Window (cwnd) stability vs. collapse.
    Panel 3: Retransmissions (Rx) impulses.
    """
    print(f"[Plotter] Generating Make-Before-Break Dashboard from {os.path.basename(csv_path)}...")
    if not os.path.exists(csv_path):
        print(f"⚠️  {csv_path} not found. Skipping.")
        return
    df = pd.read_csv(csv_path)

    # Okabe-Ito Colorblind-Safe Colors
    c_mbb = '#009E73'        # Bluish Green
    c_stateless = '#D55E00'  # Vermillion
    c_events = '#0072B2'     # Blue
    c_grace = '#009E73'      # Grace Horizon

    shuffle_times = [8, 16, 24]
    max_t = float(df['Time'].max()) if 'Time' in df.columns else 30.0

    # Authentic TCP cwnd dynamics (KB)
    if 'Cwnd_MBB' in df.columns and 'Cwnd_Stateless' in df.columns:
        cwnd_mbb = df['Cwnd_MBB']
        cwnd_stateless = df['Cwnd_Stateless']
    else:
        cwnd_mbb = pd.Series([0.0] * len(df))
        cwnd_stateless = pd.Series([0.0] * len(df))

    fig, (ax1, ax2, ax3) = plt.subplots(
        3, 1, figsize=(IEEE_DOUBLE_COL_WIDTH, 4.0), sharex=True,
        gridspec_kw={'height_ratios': [1.15, 1.0, 0.95]}
    )

    # --- PANEL 1: Throughput & Grace Window Horizons ---
    for idx, t in enumerate(shuffle_times):
        grace_end = min(t + 15.0, max_t)
        lbl = 'Table 1 Grace Window (15s Horizon)' if idx == 0 else None
        ax1.axvspan(t, grace_end, color=c_grace, alpha=0.07, label=lbl, zorder=1)
        ax2.axvspan(t, grace_end, color=c_grace, alpha=0.05, zorder=1)
        ax3.axvspan(t, grace_end, color=c_grace, alpha=0.05, zorder=1)

    ax1.plot(df['Time'], df['Throughput_MBB'], color=c_mbb, linewidth=2.0, marker='o', markersize=3.8,
             label='Stateful Make-Before-Break (Table Chaining)', zorder=4)
    ax1.plot(df['Time'], df['Throughput_Stateless'], color=c_stateless, linewidth=1.8, linestyle='--', marker='s', markersize=3.8,
             label='Baseline Stateless MTD (Hard Flow Invalidation)', zorder=4)

    for t in shuffle_times:
        ax1.axvline(x=t, color=c_events, linestyle=':', linewidth=1.5, alpha=0.85, zorder=2)
        ax1.text(t, 24.2, f'Shuffle @ t={t}s', color=c_events, fontsize=6.8, fontweight='bold', ha='center', va='bottom', zorder=5)

    max_th = max(float(df['Throughput_MBB'].max()), float(df['Throughput_Stateless'].max()), 20.0)
    ax1.set_ylabel('Throughput (Mbps)', fontsize=8.0, fontweight='bold')
    ax1.set_title('(a) Data-Plane TCP Throughput Under Dynamic IP Shuffling (15s Grace Window Chaining)', fontsize=8.8, fontweight='bold', pad=12)
    ax1.set_ylim(-1, max_th * 1.25)
    ax1.grid(True, linestyle='--', alpha=0.35, zorder=0)
    ax1.legend(loc='center right', bbox_to_anchor=(0.985, 0.42), fontsize=7.0, frameon=True, framealpha=0.92, edgecolor='black')

    # --- PANEL 2: TCP cwnd Stability vs Collapse ---
    max_cwnd = max(float(cwnd_mbb.max()), float(cwnd_stateless.max()), 10.0)
    ax2.plot(df['Time'], cwnd_mbb, color=c_mbb, linewidth=2.0, marker='o', markersize=3.5,
             label=f'MBB: Steady-State cwnd (~{int(max_cwnd)} KB)', zorder=4)
    ax2.plot(df['Time'], cwnd_stateless, color=c_stateless, linewidth=1.8, linestyle='--', marker='s', markersize=3.5,
             label='Stateless: cwnd Collapse to 1 MSS (1.41 KB)', zorder=4)

    for t in shuffle_times:
        ax2.axvline(x=t, color=c_events, linestyle=':', linewidth=1.5, alpha=0.85, zorder=2)

    # Callout annotation at collapse point (safely away from legend)
    collapse_y = float(cwnd_stateless.iloc[9]) if len(cwnd_stateless) > 9 and cwnd_stateless.iloc[9] > 0 else 1.41
    ax2.annotate(
        'RTO Timeout:\ncwnd Collapses',
        xy=(8.5, collapse_y), xytext=(11.5, max_cwnd * 0.45),
        arrowprops=dict(facecolor='#8B0000', edgecolor='black', arrowstyle='->', lw=1.0),
        fontsize=6.8, fontweight='bold', color='#8B0000',
        bbox=dict(boxstyle='round,pad=0.2', facecolor='white', edgecolor='#8B0000', alpha=0.92),
        zorder=6
    )

    ax2.set_ylabel(r'TCP $cwnd$ (KB)', fontsize=8.0, fontweight='bold')
    ax2.set_title('(b) TCP Congestion Window ($cwnd$) Dynamics: Lossless Chaining vs. RTO Collapse', fontsize=8.8, fontweight='bold', pad=5)
    ax2.set_ylim(0, max_cwnd * 1.15)
    ax2.grid(True, linestyle='--', alpha=0.35, zorder=0)
    ax2.legend(loc='center right', bbox_to_anchor=(0.985, 0.42), fontsize=7.0, frameon=True, framealpha=0.92, edgecolor='black')

    # --- PANEL 3: Retransmissions Impulses ---
    w = 0.35
    ax3.bar(df['Time'] - w/2, df['Retransmits_MBB'], width=w, color=c_mbb, alpha=0.85, edgecolor='k', linewidth=0.7,
            label=r'MBB ($R_x=0$)', zorder=4)
    ax3.bar(df['Time'] + w/2, df['Retransmits_Stateless'], width=w, color=c_stateless, alpha=0.85, edgecolor='k', linewidth=0.7,
            label=r'Stateless ($R_x$ Impulses)', zorder=4)

    for t in shuffle_times:
        ax3.axvline(x=t, color=c_events, linestyle=':', linewidth=1.5, alpha=0.85, zorder=2)

    ax3.set_ylabel(r'Retransmits ($R_x$)', fontsize=8.0, fontweight='bold')
    ax3.set_xlabel('Benchmark Execution Time (seconds)', fontsize=8.5, fontweight='bold')
    ax3.set_title('(c) TCP Retransmission Impulses ($R_x$)', fontsize=8.8, fontweight='bold', pad=5)
    ax3.set_ylim(0, 3.8)
    ax3.set_yticks([0, 1, 2, 3])
    ax3.set_xlim(0.5, 30.5)
    ax3.grid(True, linestyle='--', alpha=0.35, zorder=0)
    ax3.legend(loc='upper left', bbox_to_anchor=(0.015, 0.96), fontsize=7.0, frameon=True, framealpha=0.92, edgecolor='black')

    fig.align_ylabels([ax1, ax2, ax3])
    fig.tight_layout()
    plt.savefig(save_path, format='pdf', dpi=300, bbox_inches='tight')
    print(f"   -> Saved to {save_path}")
    plt.close()


def generate_factorial_comparison_plot(csv_path, save_path):
    """
    IEEE Journal Double-Column Factorial Disentanglement Figure (3 panels).
    Disentangles DRL Policy Scheduling from OpenFlow Table-1 MBB Data-Plane Mechanism:
      (a) QoS Disruption Rate (QDR %) across Stateless vs. MBB
      (b) Attacker Success Rate (ASR %) across Stateless vs. MBB
      (c) Control Plane FlowMod Overhead across Stateless vs. MBB
    """
    print(f"[Plotter] Generating Factorial MBB Disentanglement Plot from {os.path.basename(csv_path)}...")
    if not os.path.exists(csv_path):
        print(f"⚠️  {csv_path} not found. Skipping.")
        return

    df = pd.read_csv(csv_path)
    if df.empty:
        print(f"⚠️  {csv_path} is empty. Skipping.")
        return

    # 5 canonical policy categories
    policy_defs = [
        ('Static', 'Static'),
        ('Periodic', 'OF-RHM'),
        ('IDS', 'IDS-Triggered'),
        ('Binary', 'Binary DRL'),
        ('Proposed', 'Proposed QoS-DRL')
    ]

    stateless_rows = []
    mbb_rows = []
    labels = []

    for key, label in policy_defs:
        labels.append(label)
        # Match Stateless row
        st_row = df[(df['Policy'].str.contains(key, case=False, na=False)) & 
                    (df['Policy'].str.contains('Stateless', case=False, na=False))]
        if not st_row.empty:
            stateless_rows.append(st_row.iloc[0])
        else:
            stateless_rows.append(pd.Series({
                'ASR_mean': 0.0, 'ASR_ci': 0.0,
                'QDR_mean': 0.0, 'QDR_ci': 0.0,
                'FlowMods_mean': 0.0, 'FlowMods_ci': 0.0,
                'Reward_mean': 0.0, 'Reward_ci': 0.0
            }))

        # Match MBB row
        mb_row = df[(df['Policy'].str.contains(key, case=False, na=False)) & 
                    (df['Policy'].str.contains('MBB', case=False, na=False))]
        if not mb_row.empty:
            mbb_rows.append(mb_row.iloc[0])
        else:
            mb_row_alt = df[(df['Policy'].str.contains(key, case=False, na=False)) & 
                            (~df['Policy'].str.contains('Stateless', case=False, na=False))]
            if not mb_row_alt.empty:
                mbb_rows.append(mb_row_alt.iloc[0])
            else:
                mbb_rows.append(pd.Series({
                    'ASR_mean': 0.0, 'ASR_ci': 0.0,
                    'QDR_mean': 0.0, 'QDR_ci': 0.0,
                    'FlowMods_mean': 0.0, 'FlowMods_ci': 0.0,
                    'Reward_mean': 0.0, 'Reward_ci': 0.0
                }))

    df_st = pd.DataFrame(stateless_rows).reset_index(drop=True)
    df_mb = pd.DataFrame(mbb_rows).reset_index(drop=True)

    n_groups = len(labels)
    x = np.arange(n_groups)
    width = 0.35
    pair_offset = 0.19

    fig, (ax1, ax2, ax3) = plt.subplots(1, 3, figsize=(7.1, 2.6))

    c_stateless = '#D55E00'  # Vermillion (Okabe-Ito)
    c_mbb = '#009E73'        # Bluish Green (Okabe-Ito)

    def annotate_bars(ax, bars, errs, fmt_str):
        for bar, err in zip(bars, errs):
            h = bar.get_height()
            err_val = float(err) if pd.notna(err) else 0.0
            y_top = h + err_val
            ax.annotate(
                fmt_str.format(h),
                xy=(bar.get_x() + bar.get_width() / 2.0, y_top),
                xytext=(0, 3.0),
                textcoords="offset points",
                ha='center', va='bottom',
                rotation=90,
                fontweight='bold',
                fontsize=6.8,
                color='#111111',
                zorder=5
            )

    def style_xticks(ax):
        ax.set_xticks(x)
        ax.set_xticklabels(
            labels,
            rotation=25,
            ha='right',
            rotation_mode='anchor',
            fontsize=8.5,
            fontweight='semibold'
        )
        ax.tick_params(axis='x', pad=3)
        ax.tick_params(axis='y', labelsize=7.5)
        ax.set_xlim(-0.55, n_groups - 0.45)

    # ----------------------------------------------------
    # PANEL (a): QoS Disruption Rate (QDR %)
    # ----------------------------------------------------
    qdr_st_err = np.minimum(df_st['QDR_mean'], df_st['QDR_ci'])
    qdr_mb_err = np.minimum(df_mb['QDR_mean'], df_mb['QDR_ci'])
    bars_qdr_st = ax1.bar(
        x - pair_offset, df_st['QDR_mean'], width,
        yerr=[qdr_st_err, df_st['QDR_ci']], capsize=2.2,
        error_kw={'elinewidth': 0.85, 'ecolor': '#111111', 'capthick': 0.85},
        color=c_stateless, hatch='///', edgecolor='k', linewidth=0.8,
        label='Stateless (Hard Drop)', zorder=3
    )
    bars_qdr_mb = ax1.bar(
        x + pair_offset, df_mb['QDR_mean'], width,
        yerr=[qdr_mb_err, df_mb['QDR_ci']], capsize=2.2,
        error_kw={'elinewidth': 0.85, 'ecolor': '#111111', 'capthick': 0.85},
        color=c_mbb, edgecolor='k', linewidth=0.8,
        label='Stateful (Table-1 MBB)', zorder=3
    )
    annotate_bars(ax1, bars_qdr_st, df_st['QDR_ci'], '{:.1f}%')
    annotate_bars(ax1, bars_qdr_mb, df_mb['QDR_ci'], '{:.1f}%')

    ax1.set_ylabel('Disruption Rate (%)', fontsize=8.2, fontweight='bold')
    style_xticks(ax1)
    max_qdr = max(float((df_st['QDR_mean'] + df_st['QDR_ci']).max()),
                  float((df_mb['QDR_mean'] + df_mb['QDR_ci']).max()), 2.0)
    ax1.set_ylim(0, max_qdr * 1.40)
    ax1.set_title('(a) QoS Disruption (QDR)', fontsize=8.5, pad=6, fontweight='bold')
    ax1.grid(True, linestyle='--', alpha=0.35, axis='y', zorder=0)

    # ----------------------------------------------------
    # PANEL (b): Attacker Success Rate (ASR %)
    # ----------------------------------------------------
    asr_st_err = np.minimum(df_st['ASR_mean'], df_st['ASR_ci'])
    asr_mb_err = np.minimum(df_mb['ASR_mean'], df_mb['ASR_ci'])
    bars_asr_st = ax2.bar(
        x - pair_offset, df_st['ASR_mean'], width,
        yerr=[asr_st_err, df_st['ASR_ci']], capsize=2.2,
        error_kw={'elinewidth': 0.85, 'ecolor': '#111111', 'capthick': 0.85},
        color=c_stateless, hatch='///', edgecolor='k', linewidth=0.8,
        label='Stateless (Hard Drop)', zorder=3
    )
    bars_asr_mb = ax2.bar(
        x + pair_offset, df_mb['ASR_mean'], width,
        yerr=[asr_mb_err, df_mb['ASR_ci']], capsize=2.2,
        error_kw={'elinewidth': 0.85, 'ecolor': '#111111', 'capthick': 0.85},
        color=c_mbb, edgecolor='k', linewidth=0.8,
        label='Stateful (Table-1 MBB)', zorder=3
    )
    annotate_bars(ax2, bars_asr_st, df_st['ASR_ci'], '{:.1f}%')
    annotate_bars(ax2, bars_asr_mb, df_mb['ASR_ci'], '{:.1f}%')

    ax2.set_ylabel('Attack Success (%)', fontsize=8.2, fontweight='bold')
    style_xticks(ax2)
    max_asr = max(float((df_st['ASR_mean'] + df_st['ASR_ci']).max()),
                  float((df_mb['ASR_mean'] + df_mb['ASR_ci']).max()), 10.0)
    ax2.set_ylim(0, max_asr * 1.46)
    ax2.set_title('(b) Defense Efficacy (ASR)', fontsize=8.5, pad=6, fontweight='bold')
    ax2.grid(True, linestyle='--', alpha=0.35, axis='y', zorder=0)

    # ----------------------------------------------------
    # PANEL (c): Control Plane FlowMods
    # ----------------------------------------------------
    fmd_st_err = np.minimum(df_st['FlowMods_mean'], df_st['FlowMods_ci'])
    fmd_mb_err = np.minimum(df_mb['FlowMods_mean'], df_mb['FlowMods_ci'])
    bars_fmd_st = ax3.bar(
        x - pair_offset, df_st['FlowMods_mean'], width,
        yerr=[fmd_st_err, df_st['FlowMods_ci']], capsize=2.2,
        error_kw={'elinewidth': 0.85, 'ecolor': '#111111', 'capthick': 0.85},
        color=c_stateless, hatch='///', edgecolor='k', linewidth=0.8,
        label='Stateless (Hard Drop)', zorder=3
    )
    bars_fmd_mb = ax3.bar(
        x + pair_offset, df_mb['FlowMods_mean'], width,
        yerr=[fmd_mb_err, df_mb['FlowMods_ci']], capsize=2.2,
        error_kw={'elinewidth': 0.85, 'ecolor': '#111111', 'capthick': 0.85},
        color=c_mbb, edgecolor='k', linewidth=0.8,
        label='Stateful (Table-1 MBB)', zorder=3
    )
    annotate_bars(ax3, bars_fmd_st, df_st['FlowMods_ci'], '{:.0f}')
    annotate_bars(ax3, bars_fmd_mb, df_mb['FlowMods_ci'], '{:.0f}')

    ax3.set_ylabel('FlowMods / Episode', fontsize=8.2, fontweight='bold')
    style_xticks(ax3)
    max_fmd = max(float((df_st['FlowMods_mean'] + df_st['FlowMods_ci']).max()),
                  float((df_mb['FlowMods_mean'] + df_mb['FlowMods_ci']).max()), 100.0)
    ax3.set_ylim(0, max_fmd * 1.40)
    ax3.yaxis.set_major_formatter(
        mpl.ticker.FuncFormatter(lambda v, p: f'{int(v/1000)}k' if v >= 1000 else f'{int(v)}')
    )
    ax3.set_title('(c) Control-Plane Overhead', fontsize=8.5, pad=6, fontweight='bold')
    ax3.grid(True, linestyle='--', alpha=0.35, axis='y', zorder=0)

    # Shared top legend centered above the three panels
    handles, leg_labels = ax1.get_legend_handles_labels()
    fig.legend(
        handles, leg_labels,
        loc='upper center', bbox_to_anchor=(0.53, 0.995),
        ncol=2, frameon=True, fancybox=False, edgecolor='#333333',
        fontsize=8.0, columnspacing=1.8, handlelength=1.8
    )

    fig.subplots_adjust(left=0.075, right=0.99, top=0.80, bottom=0.26, wspace=0.28)

    base_out, ext = os.path.splitext(save_path)
    pdf_out = save_path if ext.lower() == '.pdf' else f"{base_out}.pdf"
    png_out = f"{base_out}.png"
    plt.savefig(pdf_out, format='pdf', dpi=300, bbox_inches='tight', pad_inches=0.04)
    plt.savefig(png_out, format='png', dpi=300, bbox_inches='tight', pad_inches=0.04)
    print(f"   -> Saved to {pdf_out} and {png_out}")
    plt.close()


# Alias for backwards compatibility
generate_dataplane_mbb_throughput_plot = generate_mbb_tcp_dashboard


# ==========================================
# MAIN EXECUTION
# ==========================================
if __name__ == "__main__":
    print("="*60)
    print("📊 GENERATING IEEE PUBLICATION-GRADE VISUALIZATIONS")
    print("="*60)
    
    try:
        RUN_DIR = get_latest_run_dir()
        print(f"🔍 Found latest experiment run: {os.path.basename(RUN_DIR)}")
    except FileNotFoundError as e:
        print(f"❌ Error: {e}")
        exit(1)
    
    # Create separate folders for Mock and Real plots
    PLOTS_DIR = os.path.join(RUN_DIR, "plots")
    MOCK_PLOTS_DIR = os.path.join(PLOTS_DIR, "mock")
    REAL_PLOTS_DIR = os.path.join(PLOTS_DIR, "real")
    os.makedirs(MOCK_PLOTS_DIR, exist_ok=True)
    os.makedirs(REAL_PLOTS_DIR, exist_ok=True)
    
    # 1. Generate Standard (Mock) Plots
    print("\n📦 Generating Mock-Only Model Plots...")
    conv_mock_csv = os.path.join(RUN_DIR, "training_convergence.csv")
    if not os.path.exists(conv_mock_csv):
        prev_conv = sorted(glob.glob(os.path.join(RUNS_DIR, "run_*", "training_convergence.csv")))
        if prev_conv:
            conv_mock_csv = prev_conv[-1]

    generate_training_convergence_plot(
        conv_mock_csv,
        os.path.join(MOCK_PLOTS_DIR, "drl_training_convergence.pdf"),
        window_size=1000,
        title="Mock Environment: PPO Agent Training Convergence"
    )

    act_mock_csv = os.path.join(RUN_DIR, "action_rewards_sim.csv")
    if not os.path.exists(act_mock_csv):
        act_mock_csv = os.path.join(SCRIPT_DIR, "action_rewards_sim.csv")
    if not os.path.exists(act_mock_csv):
        act_mock_csv = os.path.join(RUN_DIR, "action_rewards.csv")
    if not os.path.exists(act_mock_csv):
        act_mock_csv = os.path.join(SCRIPT_DIR, "action_rewards.csv")
    generate_action_comparison_plot(
        act_mock_csv,
        os.path.join(MOCK_PLOTS_DIR, "action_comparison.pdf")
    )

    base_mock_csv = os.path.join(RUN_DIR, "baseline_results.csv")
    if not os.path.exists(base_mock_csv):
        base_mock_csv = os.path.join(SCRIPT_DIR, "baseline_results.csv")
    generate_baseline_comparison_plot(
        base_mock_csv,
        os.path.join(MOCK_PLOTS_DIR, "baseline_performance_comparison.pdf")
    )

    ep_mock_csv = os.path.join(RUN_DIR, "episode_trace.csv")
    if not os.path.exists(ep_mock_csv):
        ep_mock_csv = os.path.join(SCRIPT_DIR, "episode_trace.csv")
    generate_episode_timeline_trace(
        ep_mock_csv,
        os.path.join(MOCK_PLOTS_DIR, "episode_timeline_trace.pdf")
    )

    pol_mock_csv = os.path.join(RUN_DIR, "policy_evaluation_sim.csv")
    if not os.path.exists(pol_mock_csv):
        pol_mock_csv = os.path.join(SCRIPT_DIR, "policy_evaluation_sim.csv")
    if not os.path.exists(pol_mock_csv):
        pol_mock_csv = os.path.join(RUN_DIR, "policy_evaluation.csv")
    if not os.path.exists(pol_mock_csv):
        pol_mock_csv = os.path.join(SCRIPT_DIR, "policy_evaluation.csv")
    generate_policy_heatmap(
        pol_mock_csv,
        os.path.join(MOCK_PLOTS_DIR, "policy_heatmap.pdf"),
        title="Simulation Policy Decision Surface"
    )
    
    # 2. Check for Real (Fine-Tuned) Model Data
    real_csv_candidates = [
        os.path.join(RUN_DIR, "baseline_results_real_v2.csv"),
        os.path.join(SCRIPT_DIR, "baseline_results_real_v2.csv"),
        os.path.join(RUN_DIR, "baseline_results_real.csv"),
        os.path.join(SCRIPT_DIR, "baseline_results_real.csv")
    ]
    real_baseline_csv = None
    for cand in real_csv_candidates:
        if os.path.exists(cand):
            real_baseline_csv = cand
            break

    has_real_data = real_baseline_csv is not None
    
    if has_real_data:
        print("\n🚀 DETECTED FINE-TUNED (REAL) MODEL DATA!")
        print(f"   Using real baseline file: {real_baseline_csv}")
        print("   Generating IEEE-calibrated real-model figures...\n")
        
        # Training / Fine-tuning Convergence
        finetune_csv = os.path.join(RUN_DIR, "finetune_log.csv")
        if not os.path.exists(finetune_csv):
            finetune_csv = os.path.join(SCRIPT_DIR, "finetune_log.csv")
        generate_training_convergence_plot(
            finetune_csv,
            os.path.join(REAL_PLOTS_DIR, "finetune_convergence.pdf"),
            window_size=50,
            title="Real Environment: Fine-Tuning Convergence"
        )

        act_sim_csv = os.path.join(RUN_DIR, "action_rewards_sim.csv")
        if not os.path.exists(act_sim_csv):
            act_sim_csv = os.path.join(SCRIPT_DIR, "action_rewards_sim.csv")
        if not os.path.exists(act_sim_csv):
            act_sim_csv = os.path.join(RUN_DIR, "action_rewards.csv")
        if not os.path.exists(act_sim_csv):
            act_sim_csv = os.path.join(SCRIPT_DIR, "action_rewards.csv")
        if os.path.exists(act_sim_csv):
            generate_action_comparison_plot(
                act_sim_csv,
                os.path.join(REAL_PLOTS_DIR, "action_comparison_sim.pdf")
            )

        generate_baseline_comparison_plot(
            real_baseline_csv,
            os.path.join(REAL_PLOTS_DIR, "baseline_performance_comparison_real.pdf")
        )

        ep_real_csv = os.path.join(RUN_DIR, "episode_trace_real.csv")
        if not os.path.exists(ep_real_csv):
            ep_real_csv = os.path.join(SCRIPT_DIR, "episode_trace_real.csv")
        generate_episode_timeline_trace(
            ep_real_csv,
            os.path.join(REAL_PLOTS_DIR, "episode_timeline_trace_real.pdf")
        )

        pol_eval_csv = os.path.join(RUN_DIR, "policy_evaluation_sim.csv")
        if not os.path.exists(pol_eval_csv):
            pol_eval_csv = os.path.join(SCRIPT_DIR, "policy_evaluation_sim.csv")
        if not os.path.exists(pol_eval_csv):
            pol_eval_csv = os.path.join(RUN_DIR, "policy_evaluation.csv")
        if not os.path.exists(pol_eval_csv):
            pol_eval_csv = os.path.join(SCRIPT_DIR, "policy_evaluation.csv")
        generate_policy_heatmap(
            pol_eval_csv,
            os.path.join(REAL_PLOTS_DIR, "policy_heatmap_eval.pdf"),
            title="Evaluated Policy Decision Surface (QoS-Aware DRL)"
        )
        generate_policy_heatmap(
            pol_eval_csv,
            os.path.join(REAL_PLOTS_DIR, "policy_heatmap_real.pdf"),
            title="Evaluated Policy Decision Surface (QoS-Aware DRL)"
        )

        pol_targ_csv = os.path.join(SCRIPT_DIR, "policy_evaluation_targeted_sim.csv")
        if os.path.exists(pol_targ_csv):
            generate_policy_heatmap(
                pol_targ_csv,
                os.path.join(REAL_PLOTS_DIR, "policy_heatmap_targeted.pdf"),
                title="Policy Surface: Localized Scan Regime ($n=2$ targets, Sim)"
            )
        pol_swp_csv = os.path.join(SCRIPT_DIR, "policy_evaluation_sweep_sim.csv")
        if os.path.exists(pol_swp_csv):
            generate_policy_heatmap(
                pol_swp_csv,
                os.path.join(REAL_PLOTS_DIR, "policy_heatmap_sweep.pdf"),
                title="Policy Surface: Distributed Sweep Regime ($n=10$ targets, Sim)"
            )
        
        # Sim-to-Real Comparison
        generate_sim_to_real_comparison_plot(
            base_mock_csv,
            real_baseline_csv,
            os.path.join(PLOTS_DIR, "sim_to_real_comparison.pdf")
        )
        
        # Step 2: Statistical Distribution Contours
        generate_statistical_distribution_plot(
            RUN_DIR,
            os.path.join(REAL_PLOTS_DIR, "baseline_statistical_distributions.pdf")
        )

        # Step 3: 2D Pareto Efficiency Bubble Plot
        generate_pareto_efficiency_plot(
            real_baseline_csv,
            os.path.join(REAL_PLOTS_DIR, "pareto_tradeoff_efficiency.pdf")
        )

        # Step 4: Make-Before-Break Dashboard
        mbb_csv = os.path.join(RUN_DIR, "dataplane_mbb_benchmark.csv")
        if not os.path.exists(mbb_csv):
            mbb_csv = os.path.join(SCRIPT_DIR, "dataplane_mbb_benchmark.csv")
        if os.path.exists(mbb_csv):
            generate_mbb_tcp_dashboard(
                mbb_csv,
                os.path.join(REAL_PLOTS_DIR, "dataplane_mbb_throughput.pdf")
            )

        # Step 5: Factorial MBB Disentanglement (Stateless vs. MBB across 5 Policies)
        fac_csv = os.path.join(RUN_DIR, "factorial_results_real.csv")
        if not os.path.exists(fac_csv):
            fac_csv = os.path.join(SCRIPT_DIR, "factorial_results_real.csv")
        if os.path.exists(fac_csv):
            generate_factorial_comparison_plot(
                fac_csv,
                os.path.join(REAL_PLOTS_DIR, "factorial_mbb_disentanglement.pdf")
            )
        
        print("\n✅ IEEE real-model visualizations generated!")
    else:
        print("\nℹ️ No fine-tuned (real) model data found. Run evaluate_real_agent.py to generate it.")
    
    # Also sync plots to rl_agent/plots/ for easy direct reference
    ROOT_PLOTS_DIR = os.path.join(SCRIPT_DIR, "plots")
    if RUN_DIR != SCRIPT_DIR:
        shutil.copytree(PLOTS_DIR, ROOT_PLOTS_DIR, dirs_exist_ok=True)

    print("\n" + "="*60)
    print(f"✅ All visualizations saved to: {PLOTS_DIR}")
    print(f"   - Mock plots: {MOCK_PLOTS_DIR}")
    if has_real_data:
        print(f"   - Real plots: {REAL_PLOTS_DIR}")
    print(f"   - Synced to root: {ROOT_PLOTS_DIR}")
    print("="*60)
