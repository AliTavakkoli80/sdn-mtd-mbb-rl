# Zero-Downtime Moving Target Defense in Software-Defined Networks: Stateful Make-Before-Break Mutation via Multi-Objective Reinforcement Learning

[![DOI](https://zenodo.org/badge/latestdoi/000000000.svg)](https://zenodo.org/badge/latestdoi/000000000)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.9](https://img.shields.io/badge/Python-3.9-blue.svg)](https://www.python.org/downloads/release/python-3925/)
[![SDN: OpenFlow 1.3](https://img.shields.io/badge/SDN-OpenFlow_1.3-green.svg)](https://opennetworking.org/)
[![Controller: Ryu 4.34](https://img.shields.io/badge/Ryu-4.34-0078D7.svg)](https://ryu-sdn.org/)

> **Official code and reproducibility artifact** for the Elsevier *Array* manuscript:  
> *"Zero-Downtime Moving Target Defense in Software-Defined Networks: Stateful Make-Before-Break Mutation via Multi-Objective Reinforcement Learning"*

---

## Abstract

Software-Defined Networking (SDN) enables Moving Target Defense (MTD) through dynamic IP address mutation to impede adversarial network reconnaissance. Conventional address mutation schemes, however, face a fundamental trade-off: stateless flow-table flushing invalidates in-flight transport-layer state, causing TCP packet drops, congestion window ($cwnd$) collapse to initial slow-start values, and throughput interruption. Existing mutation triggers also rely on fixed periodic intervals or heuristic thresholds that disregard control-plane signaling budgets and data-plane disruption costs.

This repository implements a stateful, zero-downtime SDN-MTD framework that addresses the competing constraints of proactive address agility and transport-layer session continuity:
1. **Hardware-Compliant OpenFlow 1.3 Make-Before-Break (MBB) Pipeline:** Decouples active and mutating flows across two cascaded OpenFlow tables (`Table 0` Active and `Table 1` Grace), preserving forwarding for established benign TCP sessions while assigning updated virtual IPs to new traffic and immediately evicting flagged adversary sources from the grace table.
2. **Cost-Aware MOMDP-PPO Control Engine:** Models mutation timing and scope as an 8-dimensional Multi-Objective Markov Decision Process (MOMDP) solved via Proximal Policy Optimization (PPO). Using empirical Shannon entropy ($H_{\text{IP}}, H_{\text{port}}$), continuous-time EWMA packet rate estimation ($\tau = 3.0\,\text{s}$), and inter-arrival time coefficient of variation ($CV_{\text{IAT}}$), the agent selects among `HOLD`, `GLOBAL`, and `TARGETED` mutations to balance threat mitigation against data-plane disruption and OpenFlow `FLOW_MOD` signaling cost.
3. **Two-Stage Sim-to-Real Pipeline:** Combines fast Stage 1 offline PPO pre-training in an analytical Gymnasium environment with Stage 2 online fine-tuning and $2 \times 5$ factorial benchmarking on a 16-host, 2-Spine / 4-Leaf Containernet + Open vSwitch testbed.

---

## Repository Structure

```text
MTD/
├── mtd_ip_shuffling/              # Modular Ryu OpenFlow 1.3 SDN-MTD controller
│   ├── app.py                     # Main RyuApp, OpenFlow event hooks, and WSGI REST API (/mtd/*)
│   ├── config.py                  # Protected 16-host real-to-virtual IP mappings & DNS config
│   ├── constants.py               # OpenFlow 1.3 tables, priorities, cookies, and grace timeouts
│   ├── topology.py                # LLDP Clos fabric discovery, leaf/spine detection, ECMP routing
│   ├── flow_manager.py            # Dual-table MBB flow lifecycle, grace migration & threat eviction
│   ├── packet_handler.py          # Top-level PacketIn dispatcher
│   ├── arp_handler.py             # Topology-aware ARP proxy & virtual MAC translation
│   ├── ipv4_handler.py            # Edge IPv4 NAT & dnslib DNS reconstruction (RFC 1071/768)
│   ├── threat_detector.py         # Information-theoretic detector (H_IP, H_port, EWMA, CV_IAT)
│   ├── mtd_engine.py              # MBB mutation engine & PPO inference loop (heuristic fallback)
│   └── utils.py                   # Logging utilities
├── rl_agent/                      # Stage 1 pre-training, Stage 2 fine-tuning & evaluation suite
│   ├── mtd_env.py                 # 8D MOMDP Gymnasium environment (continuous multi-objective reward)
│   ├── train_agent.py             # Stage 1 offline PPO training (3-action & 2-action binary baseline)
│   ├── evaluate_agent.py          # Analytical simulation evaluation across threat/load regimes
│   ├── containernet_env.py        # Stage 2 live Containernet Gymnasium wrapper (Ryu REST + socket IPC)
│   ├── fine_tune_agent.py         # Sim-to-Real online PPO fine-tuning on Containernet
│   ├── evaluate_real_agent.py     # Canonical (5-policy) & 2x5 Factorial (10-policy) live evaluator
│   ├── benchmark_dataplane_mbb.py # Live iperf3 TCP throughput & retransmission MBB benchmark
│   ├── ovs_instrument.py          # Open vSwitch flow-table inspection helpers
│   ├── visualize_results.py       # Publication-grade PDF/PNG plot generator
│   ├── run_dataplane_benchmark.sh # Automated runner for the live data-plane MBB benchmark
│   ├── verify_continuous_reward.py# Unit verification for continuous reward monotonicity
│   ├── verify_divergence.py       # Audit verifying parameter divergence after Sim-to-Real fine-tuning
│   ├── verify_phase4_episode.py   # 42-step multi-regime episode verification script
│   └── test_reconvergence.py      # PPO convergence sanity check
├── testbed/                       # Network emulation & host container definitions
│   ├── containernet_topos/
│   │   ├── finetune_topo.py       # 2-Spine / 4-Leaf Clos fabric (16 Docker hosts + DNS + IPC server)
│   │   ├── scan_worker.py         # Empirical TCP/ARP scanner worker for ASR instrumentation
│   │   ├── carrier_worker.py      # Background benign TCP carrier traffic generator
│   │   ├── base_topo.py           # Minimal baseline topology
│   │   ├── large_topology.py      # Extended topology template
│   │   └── host-docker/Dockerfile # Alpine Linux container image (dnsmasq, iperf3, curl, python3)
│   └── GNS3/                      # Legacy GNS3 OVS setup notes and dnsmasq appliance template
├── paper/
│   └── main.pdf                   # Compiled manuscript PDF
├── finetune_pipeline.sh           # End-to-end Stage 2 Sim-to-Real fine-tuning & evaluation pipeline
├── run_factorial_benchmark.sh     # Automated 2x5 factorial benchmark runner (10 policy x dataplane cells)
├── run_all_benchmarks.sh          # Automated MBB dataplane + canonical baseline benchmark runner
├── run_eval_pipeline.sh           # Automated N=50 live canonical evaluation & plot runner
├── requirements.txt               # Pinned Python 3.9 dependencies
├── environment.yml                # Conda environment specification
├── CITATION.cff                   # Zenodo / GitHub citation metadata (CFF 1.2.0)
└── LICENSE                        # MIT License
```

---

## Architecture Overview

### 1. OpenFlow 1.3 Make-Before-Break Dual-Table Pipeline

To eliminate TCP `cwnd` collapse and session drops during IP shuffling, `mtd_ip_shuffling/flow_manager.py` and `mtd_ip_shuffling/mtd_engine.py` split datapath forwarding across two cascaded OpenFlow 1.3 tables on leaf switches (`s_lf1`–`s_lf4`):

```text
                     +------------------------------------------+
   Packet-In / Wire  |             Leaf OpenFlow Switch         |
  ------------------>|  Table 0 (TABLE_ACTIVE)                  |
                     |   • COOKIE_MTD_TRANSLATION (0x01)        |
                     |   • DNS interception -> Controller       |
                     |   • New / updated VIP <-> Real IP rules  |
                     |   • Table-miss -> GOTO Table 1           |
                     +--------------------+---------------------+
                                          | (unmatched in Table 0)
                                          v
                     +------------------------------------------+
                     |  Table 1 (TABLE_GRACE)                   |
                     |   • COOKIE_MTD_GRACE (0x02)              |
                     |   • Migrated established TCP sessions    |
                     |   • idle_timeout=15s, hard_timeout=120s  |
                     |   • Immediate eviction for flagged IPs   |
                     |   • Table-miss -> PacketIn to Controller |
                     +------------------------------------------+
```

- **Phase 1 (Grace Migration):** Before flushing `Table 0`, active benign 4-tuple sessions are installed into `Table 1` (`TABLE_GRACE`) bound to their prior virtual IPs with `GRACE_PERIOD_IDLE_TIMEOUT = 15` s and `GRACE_PERIOD_HARD_TIMEOUT = 120` s.
- **Phase 2 (Adversary Eviction & Active Update):** Any source IP flagged by `ThreatDetector` is immediately evicted from `Table 1` via `evict_threat_source_from_grace()`, while fresh `Real <-> Virtual` mappings are installed in `Table 0` (`TABLE_ACTIVE`).
- **RFC-Compliant DNS Interception:** `IPv4Handler` intercepts authoritative DNS replies from `10.0.0.254` and reconstructs A-records via `dnslib` with recalculated RFC 1071/768 IP and UDP pseudo-header checksums so new connections seamlessly resolve to the updated virtual IPs.

### 2. MOMDP-PPO Control Plane

The RL environment (`rl_agent/mtd_env.py` and `rl_agent/containernet_env.py`) exposes an **8-dimensional normalized observation vector**:

$$s_t = \big[\, H_{\text{IP}}, \; H_{\text{port}}, \; R_{\text{EWMA}}, \; CV_{\text{IAT}}, \; I_t, \; \tau_t, \; F_t, \; C_{\text{target}} \,\big] \in [0, 1]^8$$

and **3 discrete mutation actions**:
- `0` (`HOLD`): Maintain current virtual IP mappings.
- `1` (`GLOBAL`): Shuffle all 16 protected hosts (`10.0.0.1`–`10.0.0.16`) to maximize network-wide entropy.
- `2` (`TARGETED`): Shuffle only hosts actively targeted by reconnaissance (`scanned_targets`), minimizing data-plane churn and `FLOW_MOD` signaling overhead.

---

## Installation & Reproduction Guide

### Prerequisites (Ubuntu Linux)

Containernet requires a Linux host with Docker and Open vSwitch kernel/user-space support.

```bash
sudo apt-get update
sudo apt-get install -y \
    python3.9 python3.9-venv python3-pip git \
    openvswitch-switch docker.io iperf3 iputils-ping net-tools
sudo systemctl enable --now docker openvswitch-switch
```

### 1. Clone the Repository & Build Python Environment

Choose either `venv` (recommended for matching the reference testbed) or `conda`:

#### Option A: Python `venv`
```bash
git clone https://github.com/AliTavakkoli80/MTD.git
cd MTD

python3.9 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

#### Option B: Conda / Mamba
```bash
git clone https://github.com/AliTavakkoli80/MTD.git
cd MTD

conda env create -f environment.yml
conda activate sdn-mtd
```

### 2. Install Containernet & Build Host Docker Image (Required for Stage 2)

Install Containernet (`mininet==3.0`) into your active virtual environment and build the Alpine testbed host image (`mtd-host:latest`) expected by `testbed/containernet_topos/finetune_topo.py`:

```bash
# Install Containernet Python package into the active environment
git clone https://github.com/containernet/containernet.git /tmp/containernet
pip install /tmp/containernet

# Build the lightweight Alpine host image (iperf3, dnsmasq, curl, python3)
sudo docker build -t mtd-host:latest testbed/containernet_topos/host-docker/
```

---

### Stage 1: Offline PPO Pre-Training & Analytical Simulation

Stage 1 trains both the **3-action MOMDP-PPO agent** (`mtd_ppo_agent.zip`) and the **2-action Binary DRL baseline** (`mtd_ppo_binary_baseline.zip`) for 300,000 timesteps on CPU using `rl_agent/mtd_env.py`:

```bash
source .venv/bin/activate

# Train Stage 1 policies (saves checkpoints & training CSVs to rl_agent/runs/run_<timestamp>/ and rl_agent/)
python rl_agent/train_agent.py

# Run analytical simulation evaluation across threat/load regimes
python rl_agent/evaluate_agent.py
```

Optional verification checks for the reward formulation and convergence:
```bash
python rl_agent/verify_continuous_reward.py
python rl_agent/test_reconvergence.py
```

---

### Stage 2: Containernet Online Fine-Tuning & 2x5 Factorial Benchmarks

Stage 2 launches the Ryu SDN controller (`mtd_ip_shuffling.app` on OpenFlow port `6653` and WSGI REST API port `8088`), starts the 2-Spine / 4-Leaf Containernet fabric (`finetune_topo.py` with command socket on port `9999`), and executes live fine-tuning and empirical evaluations.

> **Note:** Containernet requires `sudo` privileges to manage OVS bridges, veth pairs, and Docker network namespaces.

#### A. Online Sim-to-Real Fine-Tuning
Fine-tunes `rl_agent/mtd_ppo_agent.zip` on the live Containernet testbed (producing `rl_agent/mtd_ppo_agent_real.zip`), then runs the MBB throughput benchmark, canonical evaluation, and plot generation:
```bash
./finetune_pipeline.sh --steps 5000 --step_duration 0.06 --lr 0.0001
```
Verify parameter divergence between the Stage 1 simulation checkpoint and Stage 2 fine-tuned checkpoint:
```bash
python rl_agent/verify_divergence.py
```

#### B. Live $2 \times 5$ Factorial Benchmark (10 Policy $\times$ Dataplane Cells)
Evaluates all 5 control policies (`Static`, `Periodic`, `IDS-Triggered`, `Binary DRL`, `Proposed DRL`) across both data-plane modes (`Stateless Hard Flush` vs. `Stateful Table-1 MBB`) and regenerates the figures:
```bash
# Usage: ./run_factorial_benchmark.sh [EPISODES] [STEPS] [STEP_DURATION]
./run_factorial_benchmark.sh 15 42 0.6
```

#### C. Live Data-Plane Make-Before-Break Throughput Benchmark
Runs controlled `iperf3` TCP sessions across mutation events at $t = 8\,\text{s}, 16\,\text{s}, 24\,\text{s}$ comparing Stateful MBB vs. Stateless Hard Flush:
```bash
./rl_agent/run_dataplane_benchmark.sh
```

#### D. Full Benchmark Suite & Plot Regeneration
```bash
# Run MBB data-plane benchmark + 5-policy canonical evaluation + figure generation
./run_all_benchmarks.sh

# Or regenerate plots directly from recorded CSV artifacts
python rl_agent/visualize_results.py
```

Outputs (CSVs, trained `.zip` checkpoints, and `.pdf`/`.png` figures) are written to `rl_agent/runs/run_<timestamp>/` and mirrored under `rl_agent/`.

---

## Citation

If you use this software or benchmark suite in your research, please cite our Elsevier *Array* paper and software archive:

```bibtex
@article{tavakkoli2026zerodowntime,
  title   = {Zero-Downtime Moving Target Defense in Software-Defined Networks: Stateful Make-Before-Break Mutation via Multi-Objective Reinforcement Learning},
  author  = {Tavakkoli, Ali},
  journal = {Array},
  publisher = {Elsevier},
  year    = {2026},
  note    = {Submitted for publication}
}

@software{tavakkoli2026mtd_software,
  author  = {Tavakkoli, Ali},
  title   = {{MTD}: Zero-Downtime Stateful SDN Moving Target Defense Framework},
  version = {v1.0.0},
  year    = {2026},
  url     = {https://github.com/AliTavakkoli80/MTD},
  license = {MIT}
}
```

---

## Disclaimer & License

This project is released under the [MIT License](LICENSE) for academic research and reproducibility. Moving Target Defense increases reconnaissance complexity and should be deployed as part of a defense-in-depth architecture alongside standard perimeter security controls.
