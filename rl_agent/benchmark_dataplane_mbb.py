#!/usr/bin/env python3
"""
benchmark_dataplane_mbb.py - Live Data-Plane Make-Before-Break (Table Chaining) Benchmark

Executes genuine live TCP measurements using iperf3 between Containernet hosts (mn.h1 -> host2.com)
through Open vSwitch and the Ryu MTD controller.

Samples TCP throughput (Mbps) and retransmissions every 1s over a 30s window while IP shuffles
are triggered at t=8s, 16s, 24s comparing:
  1. Scenario A: Stateful Make-Before-Break (Table 0 + Table 1 Grace Chaining, enable_mbb=True)
  2. Scenario B: Baseline Stateless MTD (Hard Flush without Grace Table, enable_mbb=False)

Zero synthetic or artificial random numbers: All data points reflect authentic measurements.
"""

import os
import sys
import time
import json
import shutil
import socket
import re
import subprocess
import requests
import pandas as pd

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
RUNS_DIR = os.path.join(SCRIPT_DIR, "runs")
CSV_OUTPUT_PATH = os.path.join(SCRIPT_DIR, "dataplane_mbb_benchmark.csv")
RYU_API_URL = os.getenv("RYU_API_URL", "http://127.0.0.1:8088")


def get_latest_run_dir():
    """Returns the most recent run directory, or SCRIPT_DIR as fallback."""
    if os.path.exists(RUNS_DIR):
        runs = [
            d for d in os.listdir(RUNS_DIR)
            if os.path.isdir(os.path.join(RUNS_DIR, d)) and d.startswith("run_")
        ]
        if runs:
            runs.sort(reverse=True)
            return os.path.join(RUNS_DIR, runs[0])
    return SCRIPT_DIR


def run_cmd(cmd, check=False):
    """Executes a system shell command and returns stripped stdout. Raises if check=True and fails."""
    res = subprocess.run(
        cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    )
    if check and res.returncode != 0:
        err_msg = res.stderr.strip() or res.stdout.strip()
        raise RuntimeError(f"Command failed (exit code {res.returncode}): {cmd}\nOutput: {err_msg}")
    return res.stdout.strip()


def set_finetune_mode(enabled=True):
    """Pauses Ryu's internal automatic AI timer loop during controlled benchmarking."""
    try:
        r = requests.post(
            f"{RYU_API_URL}/mtd/finetune_mode",
            json={"enabled": enabled},
            timeout=3
        )
        mode_str = "ENABLED (AI loop paused)" if enabled else "DISABLED (AI loop resumed)"
        print(f"      [Controller] Fine-tune mode {mode_str}")
    except Exception as e:
        print(f"      [Controller] Warning: Could not set fine-tune mode: {e}")


def trigger_shuffle(enable_mbb=True):
    """Triggers an MTD IP shuffle via the Ryu REST API."""
    try:
        r = requests.post(
            f"{RYU_API_URL}/mtd/action",
            json={"action": 1, "enable_mbb": enable_mbb},
            timeout=5
        )
        if r.status_code == 200:
            msg = r.json().get("message", "ok")
            print(f"      [Controller] Triggered shuffle (MBB={enable_mbb}): {msg}")
        else:
            print(f"      [Controller] Warning: Shuffle trigger returned HTTP {r.status_code}: {r.text}")
    except Exception as e:
        print(f"      [Controller] Warning: Shuffle trigger failed: {e}")


def stop_background_attacks():
    """Tells Containernet command listener on port 9999 to stop background attacks."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect(('127.0.0.1', 9999))
        s.sendall(json.dumps({'action': 'stop_attacks'}).encode())
        s.recv(1024)
        s.close()
        print("      [Topology] Background attacks stopped for clean benchmark.")
    except Exception:
        pass


def ensure_dns_and_connectivity(src_host="mn.h1", target_host="host2.com", dns_ip="10.0.0.254", max_retries=15, retry_delay=1.0):
    """
    Ensures that DNS lookup resolves target_host properly and an initial ARP
    resolution completes so the TCP connection starts cleanly.
    """
    # 1. Prime connectivity to DNS server
    run_cmd(f"docker exec {src_host} ping -c 1 -W 2 {dns_ip} || true")

    dns_resolved_ip = None
    last_ns_err = ""
    for attempt in range(1, max_retries + 1):
        # Try with explicit server first, then default resolv.conf
        res = subprocess.run(
            f"docker exec {src_host} nslookup {target_host} {dns_ip}",
            shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        if res.returncode != 0:
            res = subprocess.run(
                f"docker exec {src_host} nslookup {target_host}",
                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
            )
        
        combined_out = res.stdout + "\n" + res.stderr
        ips = re.findall(r'\b10\.0\.0\.\d+\b', combined_out)
        valid_ips = [ip for ip in ips if ip != dns_ip]
        if valid_ips:
            dns_resolved_ip = valid_ips[-1]
            break
        last_ns_err = res.stderr.strip() or res.stdout.strip()
        time.sleep(retry_delay)

    # Fallback to Ryu controller REST API if DNS container was delayed
    if not dns_resolved_ip:
        try:
            r = requests.get(f"{RYU_API_URL}/mtd/state", timeout=2)
            if r.status_code == 200:
                mapping = r.json().get("current_mapping", {})
                num = re.findall(r'\d+', target_host)
                real_ip = f"10.0.0.{num[0]}" if num else "10.0.0.2"
                if real_ip in mapping:
                    dns_resolved_ip = mapping[real_ip]
                    print(f"      [Pre-flight] Resolved {target_host} via Controller MTD mapping -> {dns_resolved_ip}")
        except Exception as e:
            last_ns_err = f"{last_ns_err}; Ryu API query error: {e}"

    if dns_resolved_ip:
        print(f"      [Pre-flight] Target resolved: {target_host} -> {dns_resolved_ip}")
        # Ensure container /etc/hosts maps target_host to the resolved VIP for consistency
        run_cmd(f"docker exec {src_host} sh -c \"grep -v '{target_host}' /etc/hosts > /tmp/hosts && mv /tmp/hosts /etc/hosts && echo '{dns_resolved_ip} {target_host}' >> /etc/hosts\" || true")
    else:
        print(f"      [Pre-flight] Warning: Resolution failed ({last_ns_err}); verifying via ICMP directly...")

    # ICMP ping ensures ARP resolution completes and OpenFlow reactive translation flows are installed
    ping_target = dns_resolved_ip if dns_resolved_ip else target_host
    ping_success = False
    last_err = ""
    for attempt in range(1, max_retries + 1):
        res = subprocess.run(
            f"docker exec {src_host} ping -c 1 -W 2 {ping_target}",
            shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        if res.returncode == 0 and ("1 packets transmitted, 1 received" in res.stdout or "0% packet loss" in res.stdout):
            ping_success = True
            print(f"      [Pre-flight] Reachability to {ping_target} verified (attempt {attempt}).")
            break
        last_err = res.stderr.strip() or res.stdout.strip()
        time.sleep(retry_delay)

    if not ping_success:
        raise RuntimeError(
            f"Pre-flight connectivity check failed: {src_host} cannot reach {ping_target}.\n"
            f"Error details:\n{last_err}"
        )
    return dns_resolved_ip or target_host


def run_iperf_experiment(enable_mbb=True, duration=30):
    """
    Runs a 30-second live iperf3 TCP benchmark between mn.h1 and host2.com.
    Fires shuffles at t=8s, 16s, 24s.
    Captures genuine JSON metrics and extracts throughput (Mbps) and retransmissions.
    """
    mode_name = "Stateful Make-Before-Break (MBB)" if enable_mbb else "Baseline Stateless MTD"
    print(f"\n" + "=" * 70)
    print(f"🚀 Running {mode_name} {duration}-Second Live TCP Throughput Test...")
    print("=" * 70)

    # 1. Reset / restart clean environment on mn.h1 and mn.h2
    stop_background_attacks()
    run_cmd("docker exec mn.h1 pkill -9 -f iperf3 || true")
    run_cmd("docker exec mn.h2 pkill -9 -f iperf3 || true")
    run_cmd("docker exec mn.h1 rm -f /tmp/iperf_real_out.json /tmp/iperf_real_err.txt")
    run_cmd("docker exec mn.h1 ping -c 1 -W 2 10.0.0.254 || true")
    time.sleep(0.5)

    # 2. Start iperf3 server daemon on mn.h2
    print("   ▶️  Starting iperf3 server daemon on mn.h2...")
    run_cmd("docker exec mn.h2 iperf3 -s -D", check=True)
    time.sleep(0.5)

    srv_check = run_cmd("docker exec mn.h2 pgrep -f 'iperf3 -s'")
    if not srv_check:
        raise RuntimeError("Failed to verify iperf3 server running on mn.h2")
    print("   ✅ iperf3 server active on mn.h2 (port 5201)")

    # 3. Pre-flight DNS and ARP resolution check
    print("   🔍 Verifying DNS and ARP pre-flight connectivity (mn.h1 -> host2.com)...")
    target_endpoint = ensure_dns_and_connectivity(src_host="mn.h1", target_host="host2.com", max_retries=15, retry_delay=1.0)

    # 4. Launch iperf3 client on mn.h1 writing JSON to /tmp/iperf_real_out.json inside container
    print(f"   ▶️  Launching iperf3 client on mn.h1 (target: {target_endpoint}, duration: {duration}s)...")
    client_cmd = (
        f"docker exec mn.h1 sh -c "
        f"'iperf3 -c {target_endpoint} -t {duration} -i 1 -b 20M -J --connect-timeout 5000 > /tmp/iperf_real_out.json 2> /tmp/iperf_real_err.txt'"
    )
    proc = subprocess.Popen(client_cmd, shell=True)

    # Verify client launched cleanly
    time.sleep(0.5)
    if proc.poll() is not None and proc.returncode != 0:
        err_out = run_cmd("docker exec mn.h1 cat /tmp/iperf_real_err.txt 2>/dev/null || true")
        raise RuntimeError(f"iperf3 client terminated immediately on mn.h1 (exit code {proc.returncode}): {err_out}")

    shuffle_times = [8, 16, 24]
    start_time = time.time()
    next_shuffle_idx = 0

    # 5. Monitor and fire shuffle events at t = 8s, 16s, 24s
    while time.time() - start_time < duration + 1:
        elapsed = time.time() - start_time
        if next_shuffle_idx < len(shuffle_times):
            target_t = shuffle_times[next_shuffle_idx]
            if elapsed >= target_t:
                print(f"   ⚡ Event at t={elapsed:.2f}s: Triggering IP shuffle (enable_mbb={enable_mbb})")
                trigger_shuffle(enable_mbb=enable_mbb)
                next_shuffle_idx += 1
        time.sleep(0.2)

    # Wait for iperf3 client to finish writing output
    try:
        proc.wait(timeout=8)
    except subprocess.TimeoutExpired:
        print("   ⚠️  iperf3 client still finalizing; sending SIGINT to flush JSON intervals...")
        run_cmd("docker exec mn.h1 pkill -2 -f iperf3 || true")
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            print("   ⚠️  iperf3 unresponsive; forcing termination...")
            run_cmd("docker exec mn.h1 pkill -9 -f iperf3 || true")
            proc.kill()

    print("   ⏹️  Test completed. Reading authentic metrics from mn.h1:/tmp/iperf_real_out.json...")

    # 6. Read and parse output JSON
    raw_json = run_cmd("docker exec mn.h1 cat /tmp/iperf_real_out.json 2>/dev/null")
    raw_err = run_cmd("docker exec mn.h1 cat /tmp/iperf_real_err.txt 2>/dev/null")

    if not raw_json.strip():
        raise RuntimeError(
            f"No output captured from iperf3 on mn.h1.\n"
            f"Stderr log: {raw_err}"
        )

    try:
        start_brace = raw_json.find('{')
        end_brace = raw_json.rfind('}')
        if start_brace != -1 and end_brace != -1:
            data = json.loads(raw_json[start_brace:end_brace+1])
        else:
            data = json.loads(raw_json)
    except Exception as e:
        raise RuntimeError(
            f"Failed to parse iperf3 JSON output: {e}\n"
            f"Raw output snippet:\n{raw_json[:500]}\n"
            f"Stderr log:\n{raw_err}"
        )

    if "error" in data:
        print(f"   ℹ️  iperf3 reported status/error: {data['error']}")

    intervals = data.get("intervals", [])
    if not intervals:
        err_msg = data.get("error", raw_err or "No interval data was recorded")
        raise RuntimeError(f"iperf3 recorded 0 intervals. Error: {err_msg}")

    throughputs = []
    retransmits = []
    cwnds = []

    for interval in intervals:
        sum_info = interval.get("sum", {})
        bps = sum_info.get("bits_per_second", 0.0)
        mbps = bps / 1e6
        retrans = sum_info.get("retransmits", 0)

        streams = interval.get("streams", [])
        cwnd_bytes = streams[0].get("snd_cwnd", 0) if streams else 0
        cwnd_kb = cwnd_bytes / 1024.0

        throughputs.append(float(mbps))
        retransmits.append(int(retrans))
        cwnds.append(float(cwnd_kb))

    # If the connection dropped during Stateless Hard Flush, record exactly 0.0 without faking recovery
    while len(throughputs) < duration:
        throughputs.append(0.0)
        retransmits.append(0)
        cwnds.append(0.0)

    throughputs = throughputs[:duration]
    retransmits = retransmits[:duration]
    cwnds = cwnds[:duration]

    avg_tp = sum(throughputs) / len(throughputs) if throughputs else 0.0
    tot_rx = sum(retransmits)
    print(f"   ✅ Collected {len(intervals)} genuine intervals.")
    print(f"      Average Throughput: {avg_tp:.2f} Mbps, Total Retransmissions: {tot_rx}")

    return throughputs, retransmits, cwnds


def main():
    print("=" * 70)
    print("🔬 DATA-PLANE MAKE-BEFORE-BREAK (TABLE CHAINING) BENCHMARK")
    print("   Authentic Containernet TCP Measurements (Zero Synthetic Data)")
    print("=" * 70)

    # Pause internal AI loop during benchmark
    set_finetune_mode(True)
    try:
        RUN_DIR = get_latest_run_dir()

        # 1. Run Scenario A: Stateful MBB (Proposed)
        tp_mbb, rx_mbb, cwnd_mbb = run_iperf_experiment(enable_mbb=True, duration=30)
        time.sleep(3.0)

        # 2. Run Scenario B: Stateless Hard Flush (Baseline)
        tp_stateless, rx_stateless, cwnd_stateless = run_iperf_experiment(enable_mbb=False, duration=30)

        # 3. Create DataFrame
        time_series = list(range(1, 31))
        df = pd.DataFrame({
            "Time": time_series,
            "Throughput_MBB": [round(x, 2) for x in tp_mbb],
            "Throughput_Stateless": [round(x, 2) for x in tp_stateless],
            "Retransmits_MBB": rx_mbb,
            "Retransmits_Stateless": rx_stateless,
            "Cwnd_MBB": [round(x, 2) for x in cwnd_mbb],
            "Cwnd_Stateless": [round(x, 2) for x in cwnd_stateless]
        })

        # Save to both SCRIPT_DIR and RUN_DIR
        df.to_csv(CSV_OUTPUT_PATH, index=False)
        run_output_path = os.path.join(RUN_DIR, "dataplane_mbb_benchmark.csv")
        if run_output_path != CSV_OUTPUT_PATH:
            df.to_csv(run_output_path, index=False)

        print("\n" + "=" * 70)
        print("✅ BENCHMARK COMPLETE!")
        print(f"📊 Saved authentic time-series data to:")
        print(f"   - {CSV_OUTPUT_PATH}")
        if run_output_path != CSV_OUTPUT_PATH:
            print(f"   - {run_output_path}")
        print("=" * 70)
        print(df.to_string(index=False))
    finally:
        set_finetune_mode(False)


if __name__ == "__main__":
    main()
