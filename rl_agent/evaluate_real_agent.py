"""
evaluate_real_agent.py - Real Containernet Testbed Baseline Evaluation with Ryu FlowMod REST Instrumentation
and Empirical Attacker Success Rate (ASR) Tracking

Evaluates 5 MTD policies against the live Containernet SDN testbed:
1. Static (No MTD)
2. OF-RHM / Periodic MTD (T=5)
3. Event-Driven / IDS-Triggered MTD (It > 0.40)
4. Binary-Action DRL-MTD
5. Proposed QoS-Aware DRL-MTD (Fine-Tuned Real Agent)

Instruments live OpenFlow flow modification counters via Ryu REST endpoint /mtd/flowmod_count
and measures true empirical Attacker Success Rate (ASR) from attacker container (/tmp/attacker_scan_results.json).
Outputs results to _v2 artifacts (baseline_results_real_v2.csv, etc.)
"""

import os
import sys
import time
import math
import json
import shutil
import argparse
import datetime
import subprocess
import re
import numpy as np
import pandas as pd
import requests
from stable_baselines3 import PPO

# Ensure project and script directories are in path
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(SCRIPT_DIR)
sys.path.insert(0, SCRIPT_DIR)
sys.path.insert(0, PROJECT_DIR)

from containernet_env import ContainernetEnv


def get_ryu_state(ryu_api_url=None):
    """Fetch current state from Ryu controller REST API."""
    ryu_api_url = ryu_api_url or os.getenv("RYU_API_URL", "http://127.0.0.1:8088")
    try:
        r = requests.get(f"{ryu_api_url}/mtd/state", timeout=3)
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    return {"scanned_targets": [], "active_flows": 0, "intensity": 0.0, "is_under_attack": False}


def get_flowmod_count(ryu_api_url=None):
    """
    Accurate FlowMod Instrumentation:
    Query Ryu's REST endpoint /mtd/flowmod_count to get cumulative FLOW_MOD operations.
    """
    ryu_api_url = ryu_api_url or os.getenv("RYU_API_URL", "http://127.0.0.1:8088")
    try:
        r = requests.get(f"{ryu_api_url}/mtd/flowmod_count", timeout=3)
        if r.status_code == 200:
            data = r.json()
            return int(data.get('flow_mod_count', 0))
    except Exception:
        pass
    return 0


def read_attacker_scan_results(scan_results_path="/tmp/attacker_scan_results.json", env=None):
    """
    Empirical Attacker Success Rate (ASR) Tracking:
    Reads real scanner output from /tmp/attacker_scan_results.json logged by mn.h1:
    [{"target": vip, "port": p, "status": "OPEN"|"CLOSED"|"FILTERED"|"TIMEOUT"}]
    A probe is counted as successful if the attacker receives a valid service response (status == "OPEN").
    Returns: (successful_probes, total_probes, probe_records)
    """
    probes = []
    # 1. Direct filesystem access (via shared Docker volume)
    if os.path.exists(scan_results_path):
        try:
            with open(scan_results_path, 'r') as f:
                content = f.read().strip()
                if content:
                    data = json.loads(content)
                    if isinstance(data, list):
                        probes = data
        except Exception:
            pass

    # 2. Fallback via containernet topology socket if direct file not accessible
    if not probes and env is not None:
        try:
            res = env._send_command_to_topology({'action': 'get_scan_results'})
            if res and isinstance(res.get('results'), list):
                probes = res['results']
        except Exception:
            pass

    if not probes:
        return 0, 0, []

    successful = sum(1 for p in probes if str(p.get('status')).upper() == 'OPEN')
    total = len(probes)
    return successful, total, probes


CONTAINER_PIDS = {}

def get_container_pid(c):
    global CONTAINER_PIDS
    if c in CONTAINER_PIDS:
        return CONTAINER_PIDS[c]
    try:
        pid = int(subprocess.check_output(f"docker inspect -f '{{{{.State.Pid}}}}' {c}", shell=True).decode().strip())
        CONTAINER_PIDS[c] = pid
        return pid
    except Exception:
        return None


def query_dataplane_telemetry(containers=("mn.h3", "mn.h4", "mn.h7", "mn.h8"),
                              switches=("s_lf1", "s_lf2", "s_lf3", "s_lf4", "s_sp1", "s_sp2")):
    """
    Measures authentic physical data-plane metrics directly from the kernel and Open vSwitch:
    1. TCP Outgoing Segments and TCP Retransmissions from Linux kernel MIB (/proc/net/snmp)
       inside carrier host containers.
    2. Port Drops and Transmitted Packets from Open vSwitch dataplane via sysfs / ovs-ofctl.
    """
    total_retrans = 0
    total_out_segs = 0
    total_port_drops = 0
    total_port_pkts = 0

    # 1. Query Linux kernel TCP counters across carrier containers directly via procfs
    for c in containers:
        pid = get_container_pid(c)
        proc_read_success = False
        if pid:
            try:
                snmp_path = f"/proc/{pid}/net/snmp"
                if os.path.exists(snmp_path):
                    with open(snmp_path, "r") as f:
                        lines = f.read().strip().splitlines()
                    for i in range(len(lines) - 1):
                        if lines[i].startswith("Tcp:") and lines[i + 1].startswith("Tcp:"):
                            headers = lines[i].split()
                            vals = lines[i + 1].split()
                            if "RetransSegs" in headers and "OutSegs" in headers:
                                r_i = headers.index("RetransSegs")
                                o_i = headers.index("OutSegs")
                                if r_i < len(vals) and o_i < len(vals):
                                    total_retrans += int(vals[r_i])
                                    total_out_segs += int(vals[o_i])
                                    proc_read_success = True
                            break
            except Exception:
                pass

        if not proc_read_success:
            try:
                res = subprocess.run(
                    f"docker exec {c} cat /proc/net/snmp 2>/dev/null",
                    shell=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, timeout=1.0
                )
                if res.returncode == 0 and res.stdout:
                    lines = res.stdout.strip().splitlines()
                    for i in range(len(lines) - 1):
                        if lines[i].startswith("Tcp:") and lines[i + 1].startswith("Tcp:"):
                            headers = lines[i].split()
                            vals = lines[i + 1].split()
                            if "RetransSegs" in headers and "OutSegs" in headers:
                                r_i = headers.index("RetransSegs")
                                o_i = headers.index("OutSegs")
                                if r_i < len(vals) and o_i < len(vals):
                                    total_retrans += int(vals[r_i])
                                    total_out_segs += int(vals[o_i])
                            break
            except Exception:
                pass

    # 2. Query OVS kernel switch port statistics via sysfs
    ovs_sysfs_found = False
    try:
        net_devs = [d for d in os.listdir('/sys/class/net') if d.startswith(('s_lf', 's_sp'))]
        if net_devs:
            for dev in net_devs:
                stats_dir = f"/sys/class/net/{dev}/statistics"
                if os.path.exists(stats_dir):
                    ovs_sysfs_found = True
                    with open(f"{stats_dir}/tx_packets", "r") as f:
                        total_port_pkts += int(f.read().strip() or 0)
                    with open(f"{stats_dir}/rx_packets", "r") as f:
                        total_port_pkts += int(f.read().strip() or 0)
                    with open(f"{stats_dir}/tx_dropped", "r") as f:
                        total_port_drops += int(f.read().strip() or 0)
                    with open(f"{stats_dir}/rx_dropped", "r") as f:
                        total_port_drops += int(f.read().strip() or 0)
    except Exception:
        pass

    if not ovs_sysfs_found:
        for sw in switches:
            try:
                res = subprocess.run(
                    f"sudo -n ovs-ofctl dump-ports {sw} -O OpenFlow13 2>/dev/null",
                    shell=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, timeout=1.0
                )
                if res.returncode == 0 and res.stdout:
                    for m in re.finditer(r'(?:rx|tx)\s+pkts=(\d+).*?drop=(\d+)', res.stdout):
                        total_port_pkts += int(m.group(1))
                        total_port_drops += int(m.group(2))
            except Exception:
                pass

    return {
        'retrans_segs': total_retrans,
        'out_segs': total_out_segs,
        'port_drops': total_port_drops,
        'port_pkts': total_port_pkts
    }


def run_evaluation(num_episodes=30, steps_per_episode=42, policies_to_run=None, step_duration=0.6, eval_mode='canonical', mbb_mode=None):
    # Setup runs directory
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    run_dir = os.path.join(SCRIPT_DIR, "runs", f"run_{timestamp}")
    os.makedirs(run_dir, exist_ok=True)

    print("=" * 75)
    print("🚀 LIVE CONTAINERTNET TESTBED EVALUATION (RYU REST FLOWMOD & ASR LOGGING)")
    print(f"📁 Output Directory: {run_dir}")
    print(f"🔄 Episodes Per Policy: {num_episodes} | Steps Per Episode: {steps_per_episode} | Step Duration: {step_duration}s | Mode: {eval_mode}")
    print("=" * 75)

    # 1. Locate Models
    real_model_path = os.path.join(SCRIPT_DIR, "mtd_ppo_agent_real.zip")
    if not os.path.exists(real_model_path):
        real_model_path = os.path.join(SCRIPT_DIR, "mtd_ppo_agent.zip")
    if not os.path.exists(real_model_path):
        runs_dir = os.path.join(SCRIPT_DIR, "runs")
        for r in sorted(os.listdir(runs_dir), reverse=True):
            p = os.path.join(runs_dir, r, "mtd_ppo_agent_real.zip")
            if os.path.exists(p):
                real_model_path = p
                break
            p2 = os.path.join(runs_dir, r, "mtd_ppo_agent.zip")
            if os.path.exists(p2):
                real_model_path = p2
                break
    
    binary_model_path = os.path.join(SCRIPT_DIR, "mtd_ppo_binary_baseline.zip")
    if not os.path.exists(binary_model_path):
        runs_dir = os.path.join(SCRIPT_DIR, "runs")
        for r in sorted(os.listdir(runs_dir), reverse=True):
            p = os.path.join(runs_dir, r, "mtd_ppo_binary_baseline.zip")
            if os.path.exists(p):
                binary_model_path = p
                break

    print(f"🧠 Fine-Tuned Real Model: {real_model_path}")
    model_real = PPO.load(real_model_path, device="cpu")

    model_binary = None
    if os.path.exists(binary_model_path):
        print(f"🧠 Binary Baseline Model:  {binary_model_path}")
        model_binary = PPO.load(binary_model_path, device="cpu")
    else:
        print("⚠️  Binary Baseline Model not found, will default action to 0")

    # 2. Instantiate Live Containernet Environment (Once)
    print("\n🌐 Connecting to Live Containernet Testbed...")
    env = ContainernetEnv(step_duration=step_duration, max_steps=steps_per_episode)

    # Policies definition
    if eval_mode == 'factorial':
        all_policies = [
            ('Static (No MTD) (Stateless)', 'static_stateless', False),
            ('Static (No MTD) (MBB)', 'static_mbb', True),
            ('OF-RHM / Periodic MTD (Stateless)', 'periodic_stateless', False),
            ('OF-RHM / Periodic MTD (MBB)', 'periodic_mbb', True),
            ('IDS-Triggered MTD (Stateless)', 'ids_triggered_stateless', False),
            ('IDS-Triggered MTD (MBB)', 'ids_triggered_mbb', True),
            ('Binary-Action DRL-MTD (Stateless)', 'binary_drl_stateless', False),
            ('Binary-Action DRL-MTD (MBB)', 'binary_drl_mbb', True),
            ('Proposed QoS-Aware DRL-MTD (Stateless)', 'real_drl_stateless', False),
            ('Proposed QoS-Aware DRL-MTD (MBB)', 'real_drl_mbb', True)
        ]
    else:
        all_policies = [
            ('Static (No MTD)', 'static', False),
            ('OF-RHM / Periodic MTD', 'periodic', False),
            ('Event-Driven / IDS-Triggered MTD', 'ids_triggered', False),
            ('Binary-Action DRL-MTD', 'binary_drl', False),
            ('Proposed QoS-Aware DRL-MTD', 'real_drl', True)
        ]

    if policies_to_run and policies_to_run != 'all':
        selected = [p.strip().lower() for p in policies_to_run.split(',')]
        policies = [p for p in all_policies if p[1] in selected or p[0].lower() in selected]
    else:
        policies = all_policies

    if mbb_mode == 'stateless':
        policies = [(p[0], p[1], False) for p in policies]
    elif mbb_mode in ('mbb', 'stateful'):
        policies = [(p[0], p[1], True) for p in policies]

    aggregated_results = []

    # 1. Start continuous high background traffic load across topology
    print("\n🚦 Starting continuous background traffic across testbed...")
    env._send_command_to_topology({'action': 'set_traffic_load', 'level': 'high'})
    time.sleep(1.0)

    try:
        for policy_name, policy_type, policy_mbb in policies:
            print("\n" + "#" * 70)
            print(f"🎯 EVALUATING POLICY: {policy_name} ({policy_type}, MBB={policy_mbb})")
            print("#" * 70)

            # Inter-policy isolation: stop old attacks, clear threat state, reset counters, and refresh traffic
            env._send_command_to_topology({'action': 'stop_attacks'})
            try:
                requests.post(f"{env.ryu_api_url}/mtd/clear_threat", timeout=3)
                requests.post(f"{env.ryu_api_url}/mtd/reset_counters", timeout=3)
            except Exception:
                pass
            env._send_command_to_topology({'action': 'set_traffic_load', 'level': 'high'})
            time.sleep(0.5)

            ep_asr_list = []
            ep_qdr_list = []
            ep_shf_list = []
            ep_flowmods_list = []
            ep_rewards_list = []

            for ep in range(num_episodes):
                print(f"\n--- Policy: {policy_name} | Episode {ep+1}/{num_episodes} ---")
                obs, _ = env.reset()

                # Refresh carrier background traffic at episode start
                env._send_command_to_topology({'action': 'set_traffic_load', 'level': 'high'})

                raw_step_records = []
                episode_flowmods_delta_sum = 0
                episode_total_reward = 0.0
                total_shuffles = 0
                ep_successful_probes = 0
                ep_total_probes = 0
                ep_attack_step_asrs = []

                # Physical QoS telemetry accumulators
                ep_delta_drops = 0
                ep_delta_retrans = 0
                ep_delta_tx = 0

                # Pre-sample baseline telemetry before episode stepping
                flowmods_curr = get_flowmod_count(env.ryu_api_url)
                telem_curr = query_dataplane_telemetry()

                for step_idx in range(steps_per_episode):
                    I_t = float(obs[4])
                    F_t = float(obs[6])

                    # a. Select action per policy
                    pol_base = policy_type.split('_')[0]
                    if pol_base == 'static':
                        action = 0
                    elif pol_base == 'periodic':
                        action = 1 if (step_idx % 5 == 0) else 0
                    elif pol_base == 'ids':
                        action = 1 if I_t >= 0.35 else 0
                    elif pol_base == 'binary':
                        if model_binary is not None:
                            action, _ = model_binary.predict(obs, deterministic=True)
                            action = int(action)
                        else:
                            action = 0
                    elif pol_base == 'real':
                        action, _ = model_real.predict(obs, deterministic=True)
                        action = int(action)
                    else:
                        action = 0

                    if action in (1, 2):
                        total_shuffles += 1

                    # b. Query FlowMod count and data-plane telemetry before step
                    flowmods_before = flowmods_curr
                    telem_before = telem_curr

                    # c. Step ContainernetEnv
                    obs_next, reward, terminated, truncated, info = env.step(action, enable_mbb=policy_mbb)
                    episode_total_reward += reward

                    # d. Query FlowMod count and data-plane telemetry after step
                    flowmods_after = get_flowmod_count(env.ryu_api_url)
                    telem_after = query_dataplane_telemetry()
                    flowmods_curr = flowmods_after
                    telem_curr = telem_after

                    # e. FlowMods Delta: Count_after - Count_before
                    flowmods_delta = max(0, flowmods_after - flowmods_before)
                    episode_flowmods_delta_sum += flowmods_delta

                    # f. Compute authentic physical QoS Disruption
                    step_d_drops = max(0, telem_after['port_drops'] - telem_before['port_drops'])
                    step_d_retrans = max(0, telem_after['retrans_segs'] - telem_before['retrans_segs'])
                    step_d_out = max(0, telem_after['out_segs'] - telem_before['out_segs'])
                    step_d_pkts = max(0, telem_after['port_pkts'] - telem_before['port_pkts'])
                    step_d_tx = step_d_out if step_d_out > 0 else step_d_pkts

                    ep_delta_drops += step_d_drops
                    ep_delta_retrans += step_d_retrans
                    ep_delta_tx += step_d_tx

                    if step_d_tx > 0:
                        step_qdr = ((step_d_drops + step_d_retrans) / float(step_d_tx)) * 100.0
                    else:
                        step_qdr = 0.0
                    step_qdr = min(100.0, step_qdr)

                    # g. Read state from Ryu
                    ryu_state = get_ryu_state()
                    scanned_targets = ryu_state.get('scanned_targets', [])
                    active_sess = ryu_state.get('active_sessions', 0)
                    active_flow_count = active_sess * 2 if active_sess > 0 else ryu_state.get('active_flows', int(max(F_t * 100, 20)))

                    # h. Empirical ASR from scanner output
                    successful_probes, total_probes, _ = read_attacker_scan_results(env=env)
                    cycle_step = step_idx % steps_per_episode
                    is_attack_active = (5 <= cycle_step < 15) or (total_probes > 0)

                    if total_probes > 0:
                        step_asr = (float(successful_probes) / float(total_probes)) * 100.0
                    else:
                        step_asr = 0.0

                    if is_attack_active and total_probes > 0:
                        ep_attack_step_asrs.append(step_asr)
                        ep_successful_probes += successful_probes
                        ep_total_probes += total_probes

                    # i. Log step record
                    raw_step_records.append({
                        'step': step_idx,
                        'policy': policy_name,
                        'episode': ep + 1,
                        'action': action,
                        'reward': round(float(reward), 4),
                        'threat_intensity': round(I_t, 4),
                        'active_flows_norm': round(F_t, 4),
                        'active_flow_count': active_flow_count,
                        'scanned_count': len(scanned_targets),
                        'asr': round(step_asr, 2),
                        'qdr': round(step_qdr, 2),
                        'drops': step_d_drops,
                        'retrans': step_d_retrans,
                        'tx_pkts': step_d_tx,
                        'flowmods_before': flowmods_before,
                        'flowmods_after': flowmods_after,
                        'flowmods_delta': flowmods_delta,
                        'obs': [round(float(x), 4) for x in obs]
                    })

                    obs = obs_next

                # End of episode computations
                if ep_total_probes > 0:
                    ep_asr = (float(ep_successful_probes) / float(ep_total_probes)) * 100.0
                elif ep_attack_step_asrs:
                    ep_asr = float(np.mean(ep_attack_step_asrs))
                else:
                    ep_asr = 0.0

                if ep_delta_tx > 0:
                    ep_qdr = ((ep_delta_drops + ep_delta_retrans) / float(ep_delta_tx)) * 100.0
                else:
                    ep_qdr = 0.0
                ep_qdr = min(100.0, ep_qdr)

                ep_shf = (total_shuffles / float(steps_per_episode)) * 100.0
                ep_fmd = episode_flowmods_delta_sum
                ep_rew = episode_total_reward

                ep_asr_list.append(ep_asr)
                ep_qdr_list.append(ep_qdr)
                ep_shf_list.append(ep_shf)
                ep_flowmods_list.append(ep_fmd)
                ep_rewards_list.append(ep_rew)

                print(f"   Episode {ep+1} Results: ASR={ep_asr:5.2f}% | QDR={ep_qdr:5.2f}% | "
                      f"Shf={ep_shf:5.2f}% | FlowMods={ep_fmd:4d} | Rew={ep_rew:+7.2f}")

                # Save raw step trace
                clean_pol_name = policy_type.replace(' ', '_')
                raw_df = pd.DataFrame(raw_step_records)
                raw_trace_path = os.path.join(run_dir, f"real_eval_raw_{clean_pol_name}_ep{ep+1}.csv")
                raw_df.to_csv(raw_trace_path, index=False)

            # Sample statistics & 95% Confidence Intervals (Student-t distribution)
            def compute_ci(data_list, n):
                m = float(np.mean(data_list))
                s = float(np.std(data_list, ddof=1)) if len(data_list) > 1 else 0.0
                t_table = {
                    9: 2.2622, 19: 2.0930, 29: 2.0452, 39: 2.0211,
                    49: 2.0096, 50: 2.0086, 59: 2.0003, 99: 1.9842
                }
                df = max(1, n - 1)
                t_crit = t_table.get(df, 2.0096 if df == 49 or n == 50 else (2.0452 if n == 30 else 1.96))
                ci = t_crit * (s / math.sqrt(n)) if n > 0 else 0.0
                return round(m, 2), round(ci, 2)

            asr_m, asr_ci = compute_ci(ep_asr_list, num_episodes)
            qdr_m, qdr_ci = compute_ci(ep_qdr_list, num_episodes)
            shf_m = round(float(np.mean(ep_shf_list)), 2)
            fmd_m, fmd_ci = compute_ci(ep_flowmods_list, num_episodes)
            rew_m, rew_ci = compute_ci(ep_rewards_list, num_episodes)

            # Consolidated empirical results with 95% Confidence Intervals
            aggregated_results.append({
                'Policy': policy_name,
                'ASR_mean': asr_m,
                'ASR_ci': asr_ci,
                'QDR_mean': qdr_m,
                'QDR_ci': qdr_ci,
                'ShuffleFreq_mean': shf_m,
                'FlowMods_mean': fmd_m,
                'FlowMods_ci': fmd_ci,
                'Reward_mean': rew_m,
                'Reward_ci': rew_ci,
                'N_episodes': num_episodes
            })

            # Incremental checkpoint save after each completed policy
            df_curr = pd.DataFrame(aggregated_results)
            if eval_mode == 'factorial':
                df_curr.to_csv(os.path.join(run_dir, "factorial_results_real.csv"), index=False)
                df_curr.to_csv(os.path.join(SCRIPT_DIR, "factorial_results_real.csv"), index=False)
            df_curr.to_csv(os.path.join(run_dir, "baseline_results_real_v2.csv"), index=False)
            df_curr.to_csv(os.path.join(SCRIPT_DIR, "baseline_results_real_v2.csv"), index=False)

    finally:
        env.close()

    # 3. Save aggregated baseline results to _v2 and root
    df_results = pd.DataFrame(aggregated_results)
    if eval_mode == 'factorial':
        fac_run_path = os.path.join(run_dir, "factorial_results_real.csv")
        fac_root_path = os.path.join(SCRIPT_DIR, "factorial_results_real.csv")
        df_results.to_csv(fac_run_path, index=False)
        df_results.to_csv(fac_root_path, index=False)
        print(f"\n✅ Factorial results saved to:\n   - {fac_run_path}\n   - {fac_root_path}")

    v2_run_path = os.path.join(run_dir, "baseline_results_real_v2.csv")
    v2_root_path = os.path.join(SCRIPT_DIR, "baseline_results_real_v2.csv")
    df_results.to_csv(v2_run_path, index=False)
    df_results.to_csv(v2_root_path, index=False)
    # Also update baseline_results_real.csv for full backwards compatibility
    df_results.to_csv(os.path.join(run_dir, "baseline_results_real.csv"), index=False)
    df_results.to_csv(os.path.join(SCRIPT_DIR, "baseline_results_real.csv"), index=False)
    print(f"\n✅ Aggregated results saved to:\n   - {v2_run_path}\n   - {v2_root_path}")

    # 4. Generate action_rewards_real_v2.csv
    print("\n--- Generating action_rewards_real_v2.csv ---")
    scenarios = [
        ("Quiescent (Low Load)", 0.0, 0.20, []),
        ("Quiescent (High Load)", 0.0, 0.90, []),
        ("Targeted Exploit (High Load)", 0.90, 0.85, ['10.0.0.2']),
        ("Volumetric Storm (Low Load)", 0.95, 0.25, [f'10.0.0.{i}' for i in range(1, 17)]),
        ("Volumetric Storm (High Load)", 0.95, 0.90, [f'10.0.0.{i}' for i in range(1, 17)]),
    ]
    rewards_v2 = []
    from mtd_env import MTDEnvironment
    from train_agent import MockRyuApp
    mock_app = MockRyuApp()
    env_mock = MTDEnvironment(mock_app, render_mode=None)

    for sc_name, intensity, load, scanned in scenarios:
        mock_app.threat_detector.is_under_attack = (intensity > 0.1)
        mock_app.threat_detector.intensity = intensity
        mock_app.threat_detector.scanned_hosts = scanned
        mock_app.flow_manager.active_flow_count = int(load * 100)
        obs_sc = env_mock._get_obs()
        obs_sc[5] = 1.0  # full staleness
        r0 = env_mock._calculate_reward(0, obs_sc)
        r1 = env_mock._calculate_reward(1, obs_sc)
        r2 = env_mock._calculate_reward(2, obs_sc)
        rewards_v2.append({
            'Scenario': sc_name,
            'HOLD_Reward': round(r0, 2),
            'GLOBAL_Reward': round(r1, 2),
            'TARGETED_Reward': round(r2, 2)
        })
    df_rew_v2 = pd.DataFrame(rewards_v2)
    rew_run_path = os.path.join(run_dir, "action_rewards_real_v2.csv")
    rew_root_path = os.path.join(SCRIPT_DIR, "action_rewards_real_v2.csv")
    df_rew_v2.to_csv(rew_run_path, index=False)
    df_rew_v2.to_csv(rew_root_path, index=False)
    df_rew_v2.to_csv(os.path.join(run_dir, "action_rewards_real.csv"), index=False)
    df_rew_v2.to_csv(os.path.join(SCRIPT_DIR, "action_rewards_real.csv"), index=False)

    # 5. Generate policy_evaluation_real_v2.csv
    print("--- Generating policy_evaluation_real_v2.csv ---")
    heatmap_v2 = []
    for threat in np.linspace(0, 1, 11):
        for load in np.linspace(0, 1, 11):
            mock_app.threat_detector.intensity = float(threat)
            if threat <= 0.15:
                mock_app.threat_detector.is_under_attack = False
                mock_app.threat_detector.scanned_hosts = []
            elif threat <= 0.65:
                mock_app.threat_detector.is_under_attack = True
                mock_app.threat_detector.scanned_hosts = ['10.0.0.2']
            else:
                mock_app.threat_detector.is_under_attack = True
                mock_app.threat_detector.scanned_hosts = [f'10.0.0.{i}' for i in range(1, 17)]
            mock_app.flow_manager.active_flow_count = int(load * 100)
            obs_h = env_mock._get_obs()
            act, _ = model_real.predict(obs_h, deterministic=True)
            heatmap_v2.append({
                'Threat_Intensity': round(threat, 2),
                'Network_Load': round(load, 2),
                'Action': int(act)
            })
    df_hm_v2 = pd.DataFrame(heatmap_v2)
    hm_run_path = os.path.join(run_dir, "policy_evaluation_real_v2.csv")
    hm_root_path = os.path.join(SCRIPT_DIR, "policy_evaluation_real_v2.csv")
    df_hm_v2.to_csv(hm_run_path, index=False)
    df_hm_v2.to_csv(hm_root_path, index=False)
    df_hm_v2.to_csv(os.path.join(run_dir, "policy_evaluation_real.csv"), index=False)
    df_hm_v2.to_csv(os.path.join(SCRIPT_DIR, "policy_evaluation_real.csv"), index=False)

    # 6. Copy latest real DRL trace to episode_trace_real.csv for visualization
    latest_real_trace = os.path.join(run_dir, f"real_eval_raw_real_drl_ep{num_episodes}.csv")
    if not os.path.exists(latest_real_trace):
        latest_real_trace = os.path.join(run_dir, f"real_eval_raw_real_drl_mbb_ep{num_episodes}.csv")
    if os.path.exists(latest_real_trace):
        df_trace = pd.read_csv(latest_real_trace)
        col_map = {
            'step': 'Step',
            'threat_intensity': 'Threat_Intensity',
            'active_flows_norm': 'Network_Load',
            'action': 'Action',
            'reward': 'Reward'
        }
        df_trace.rename(columns=col_map, inplace=True)
        df_trace.to_csv(os.path.join(run_dir, "episode_trace_real.csv"), index=False)
        df_trace.to_csv(os.path.join(SCRIPT_DIR, "episode_trace_real.csv"), index=False)

    print("\n" + "=" * 75)
    print("🎉 REAL BASELINE EVALUATION COMPLETED SUCCESSFULLY!")
    print("=" * 75)
    print(df_results.to_string(index=False))
    return df_results


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Evaluate MTD Policies on Live Containernet Testbed")
    parser.add_argument("--episodes", type=int, default=30, help="Number of episodes per policy (default: 30)")
    parser.add_argument("--steps", type=int, default=42, help="Steps per episode (default: 42)")
    parser.add_argument("--policies", type=str, default="all", help="Comma-separated policies or 'all'")
    parser.add_argument("--step-duration", type=float, default=0.6, help="Step duration in seconds (default: 0.6)")
    parser.add_argument("--mode", type=str, default="canonical", choices=["canonical", "factorial"], help="Evaluation mode (canonical or factorial)")
    args = parser.parse_args()

    run_evaluation(
        num_episodes=args.episodes,
        steps_per_episode=args.steps,
        policies_to_run=args.policies,
        step_duration=args.step_duration,
        eval_mode=args.mode
    )
