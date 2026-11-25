# Zero-Downtime Moving Target Defense in Software-Defined Networks: Stateful Make-Before-Break Mutation via Multi-Objective Reinforcement Learning

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.9](https://img.shields.io/badge/Python-3.9.25-blue.svg)](https://www.python.org/downloads/release/python-3925/)
[![OpenFlow 1.3](https://img.shields.io/badge/SDN-OpenFlow_1.3-green.svg)](https://opennetworking.org/)
[![Ryu 4.34](https://img.shields.io/badge/Controller-Ryu_4.34-0078D7.svg)](https://ryu-sdn.org/)
[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.24515480.svg)](https://doi.org/10.5281/zenodo.24515480)

> **Official reproducibility artifact** for the Elsevier *Array* manuscript:  
> *Zero-Downtime Moving Target Defense in Software-Defined Networks: Stateful Make-Before-Break Mutation via Multi-Objective Reinforcement Learning*

---

## Overview

Software-Defined Networking (SDN) enables Moving Target Defense (MTD) through dynamic IP address mutation to impede adversarial network reconnaissance. However, conventional stateless MTD schemes flush flow tables upon mutation, invalidating in-flight transport-layer state and causing TCP packet drops, congestion window ($cwnd$) collapse, and throughput interruptions. Furthermore, fixed-interval or threshold-based triggers disregard OpenFlow control-plane signaling budgets and data-plane disruption costs.

This repository provides a stateful, zero-downtime SDN-MTD framework integrating three core components:

1. **OpenFlow 1.3 Make-Before-Break (MBB) Dual-Table Pipeline:** Decouples active and mutating flows across two cascaded OpenFlow tables (`Table 0` Active and `Table 1` Grace), preserving established benign TCP streams across IP rotations while immediately evicting flagged adversary sources from the grace table.
2. **Information-Theoretic L2/L3/L4 Threat Detector:** Quantifies reconnaissance online using empirical destination IP and port Shannon entropy ($H_{\mathrm{IP}}, H_{\mathrm{port}}$), continuous-time EWMA packet rate estimation ($\tau = 3.0\,\mathrm{s}$), and inter-arrival time regularity ($CV_{\mathrm{IAT}}$).
3. **Cost-Aware MOMDP-PPO Engine & Sim-to-Real Pipeline:** Formulates mutation timing and scope (`HOLD`, `GLOBAL`, `TARGETED`) as an 8-dimensional Multi-Objective Markov Decision Process (MOMDP) solved with Proximal Policy Optimization (PPO), pre-trained offline in Gymnasium (`rl_agent/mtd_env.py`) and fine-tuned/evaluated on a 16-host, 2-Spine / 4-Leaf Containernet + Open vSwitch testbed (`testbed/containernet_topos/finetune_topo.py`).

### Key Experimental Results

| Metric | Result (16-Host Containernet Testbed) | Verification Script |
| :--- | :--- | :--- |
| **TCP Data-Plane Continuity (MBB)** | Line-rate throughput, **0 retransmissions**, **0 $cwnd$ collapse** across mutations | `rl_agent/run_dataplane_benchmark.sh` |
| **Reconnaissance Mitigation** | **12.7% Attack Success Rate (ASR)** under adaptive scanning | `run_factorial_benchmark.sh` |
| **Control-Plane Efficiency** | **42% lower OpenFlow signaling overhead** vs. Binary DRL baseline | `run_factorial_benchmark.sh` |

---

## Architecture

### 1. OpenFlow 1.3 Make-Before-Break Dual-Table Pipeline

`mtd_ip_shuffling/flow_manager.py` and `mtd_ip_shuffling/mtd_engine.py` split leaf-switch forwarding (`s_lf1`–`s_lf4`) across two cascaded OpenFlow 1.3 tables:

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

- **Grace Migration:** Prior to updating `Table 0`, active benign 4-tuple sessions are migrated into `Table 1` (`TABLE_GRACE`) bound to their previous virtual IPs (`GRACE_PERIOD_IDLE_TIMEOUT = 15` s, `GRACE_PERIOD_HARD_TIMEOUT = 120` s).
- **Adversary Eviction:** Any source IP flagged by `ThreatDetector` is immediately evicted from `Table 1` via `evict_threat_source_from_grace()`, while fresh mappings (`10.0.0.1`–`10.0.0.16` $\leftrightarrow$ `10.0.0.101`–`10.0.0.116`) are installed in `Table 0`.
- **RFC-Compliant DNS Interception:** `IPv4Handler` intercepts DNS responses from `10.0.0.254` (UDP port `53`) and reconstructs A-records via `dnslib` with recalculated RFC 1071/768 IP and UDP pseudo-header checksums.

### 2. MOMDP-PPO Control Plane

`ThreatDetector.get_state()` produces the first 5 telemetry features, and `rl_agent/mtd_env.py` / `rl_agent/containernet_env.py` append 3 control-state features to form the **8-dimensional normalized state vector** $s_t \in [0, 1]^8$:

| Index | Feature | Description |
| :--- | :--- | :--- |
| `0` | $H_{\mathrm{IP}}$ | Normalized destination IP Shannon entropy |
| `1` | $H_{\mathrm{port}}$ | Normalized destination port Shannon entropy |
| `2` | $R_{\mathrm{EWMA}}$ | Continuous-time EWMA packet rate ($\tau = 3.0\,\mathrm{s}$) |
| `3` | $CV_{\mathrm{IAT}}$ | Normalized inter-arrival time regularity (`max(0, 1 - CV / 1.5)`) |
| `4` | $I_t$ | Aggregate threat intensity score |
| `5` | $\tau_t$ | Normalized time elapsed since last mutation |
| `6` | $F_t$ | Normalized active network session load (EWMA-smoothed) |
| `7` | $C_{\mathrm{target}}$ | Normalized cardinality of scanned target hosts |

And **3 discrete actions**:
- `0` (`HOLD`): Retain current virtual IP mappings.
- `1` (`GLOBAL`): Rotate virtual IPs across all 16 protected hosts (`10.0.0.1`–`10.0.0.16`).
- `2` (`TARGETED`): Rotate virtual IPs only for hosts in `scanned_targets`, minimizing data-plane churn and OpenFlow `FLOW_MOD` overhead.

---

## Repository Structure

```text
sdn-mtd-mbb-rl/
├── mtd_ip_shuffling/              # Modular Ryu OpenFlow 1.3 SDN-MTD controller
│   ├── app.py                     # Main RyuApp, OpenFlow hooks & WSGI REST API (/mtd/*)
│   ├── config.py                  # Protected 16-host real-to-virtual IP mappings & DNS IP
│   ├── constants.py               # OpenFlow 1.3 tables, priorities, cookies & timeouts
│   ├── topology.py                # LLDP Clos fabric discovery, leaf/spine detection & ECMP
│   ├── flow_manager.py            # Dual-table MBB flow lifecycle, grace migration & eviction
│   ├── packet_handler.py          # Top-level PacketIn dispatcher
│   ├── arp_handler.py             # Topology-aware ARP proxy & virtual MAC translation
│   ├── ipv4_handler.py            # Edge IPv4 NAT & dnslib DNS reconstruction (RFC 1071/768)
│   ├── threat_detector.py         # Information-theoretic detector (H_IP, H_port, EWMA, CV_IAT)
│   ├── mtd_engine.py              # MBB mutation engine & PPO inference loop (heuristic fallback)
│   └── utils.py                   # Logging configuration
├── rl_agent/                      # Stage 1 pre-training, Stage 2 fine-tuning & evaluation
│   ├── mtd_env.py                 # 8D MOMDP Gymnasium environment (continuous reward)
│   ├── train_agent.py             # Stage 1 offline PPO training (3-action & 2-action binary)
│   ├── evaluate_agent.py          # Stage 1 analytical evaluation across threat/load regimes
│   ├── containernet_env.py        # Stage 2 live Containernet Gymnasium wrapper
│   ├── fine_tune_agent.py         # Sim-to-Real online PPO fine-tuning on Containernet
│   ├── evaluate_real_agent.py     # Canonical (5-policy) & 2x5 Factorial (10-policy) evaluator
│   ├── benchmark_dataplane_mbb.py # Live iperf3 TCP throughput & retransmission benchmark
│   ├── ovs_instrument.py          # Open vSwitch flow-table inspection helpers
│   ├── visualize_results.py       # Publication-grade PDF/PNG figure generator
│   ├── run_dataplane_benchmark.sh # Automated live data-plane MBB benchmark runner
│   ├── verify_continuous_reward.py# Continuous reward monotonicity verification
│   ├── verify_divergence.py       # Sim-to-Real parameter divergence audit
│   ├── verify_phase4_episode.py   # 42-step multi-regime episode verification
│   └── test_reconvergence.py      # PPO convergence sanity check
├── testbed/                       # Network emulation & host container definitions
│   ├── containernet_topos/
│   │   ├── finetune_topo.py       # 2-Spine / 4-Leaf Clos fabric (16 Docker hosts + DNS + IPC)
│   │   ├── scan_worker.py         # Empirical TCP/ARP scanner worker for ASR instrumentation
│   │   ├── carrier_worker.py      # Background benign TCP carrier traffic generator
│   │   ├── base_topo.py           # Minimal baseline topology
│   │   ├── large_topology.py      # Extended topology template
│   │   └── host-docker/Dockerfile # Alpine Linux host image (dnsmasq, iperf3, curl, python3)
│   └── GNS3/                      # Legacy GNS3 OVS setup notes and dnsmasq template
├── finetune_pipeline.sh           # End-to-end Stage 2 Sim-to-Real fine-tuning & evaluation
├── run_factorial_benchmark.sh     # Automated 2x5 factorial benchmark runner (10 cells)
├── run_all_benchmarks.sh          # Automated MBB dataplane + canonical baseline runner
├── run_eval_pipeline.sh           # Automated N=50 live canonical evaluation & plot runner
├── consolidate_code.py            # Helper script used by benchmark runners to archive source snapshots
├── requirements.txt               # Pinned Python 3.9 dependencies
├── environment.yml                # Conda environment specification
├── CITATION.cff                   # GitHub / Zenodo citation metadata (CFF 1.2.0)
├── .zenodo.json                   # Zenodo deposit metadata
└── LICENSE                        # MIT License
```

---

## Installation & Setup

### Prerequisites (Ubuntu Linux)

Stage 1 (offline RL training & analytical evaluation) runs on any Linux/CPU environment with Python 3.9.  
Stage 2 (live SDN emulation & benchmarks) requires Ubuntu Linux with **Docker**, **Open vSwitch**, and `sudo` privileges:

```bash
sudo apt-get update
sudo apt-get install -y \
    python3.9 python3.9-venv python3-pip git \
    openvswitch-switch docker.io iperf3 iputils-ping net-tools
sudo systemctl enable --now docker openvswitch-switch
```

### 1. Clone & Set Up Python Environment

Choose either `venv` (recommended to match the reference testbed) or `conda`:

#### Option A: Python `venv`
```bash
git clone https://github.com/AliTavakkoli80/sdn-mtd-mbb-rl.git
cd sdn-mtd-mbb-rl

python3.9 -m venv .venv
source .venv/bin/activate
pip install "pip<24.3" "setuptools==57.5.0" "wheel<0.44"
pip install -r requirements.txt
```

#### Option B: Conda / Mamba
```bash
git clone https://github.com/AliTavakkoli80/sdn-mtd-mbb-rl.git
cd sdn-mtd-mbb-rl

conda env create -f environment.yml
conda activate sdn-mtd
```

> **Note on `ryu==4.34`:** `ryu==4.34` requires `setuptools==57.5.0` and `eventlet==0.30.2` on Python 3.9. Avoid upgrading `setuptools` inside the active environment after installation.

### 2. Install Containernet & Build Host Docker Image (Required for Stage 2)

```bash
# Install Containernet Python package into the active environment
git clone https://github.com/containernet/containernet.git /tmp/containernet
pip install /tmp/containernet

# Build the lightweight Alpine host image (dnsmasq, iperf3, curl, python3)
sudo docker build -t alpine-mn testbed/containernet_topos/host-docker/
```

---

## Reproduction Pipeline

> **Important:** Model checkpoints (`.zip`), evaluation logs (`.csv`), and generated figures (`.pdf`/`.png`) are excluded from version control via `.gitignore`. Run the stages below **in order** to generate checkpoints and reproduce all results locally.

### Stage 1: Offline PPO Pre-Training & Analytical Simulation

Stage 1 trains both the **3-action MOMDP-PPO agent** (`rl_agent/mtd_ppo_agent.zip`) and the **2-action Binary DRL baseline** (`rl_agent/mtd_ppo_binary_baseline.zip`) for 300,000 timesteps each on CPU:

```bash
source .venv/bin/activate

# 1. Train Stage 1 policies (saves checkpoints to rl_agent/runs/run_<timestamp>/ and rl_agent/)
python rl_agent/train_agent.py

# 2. Evaluate policies across analytical threat/load regimes
python rl_agent/evaluate_agent.py
```

Optional verification checks:
```bash
python rl_agent/verify_continuous_reward.py
python rl_agent/verify_phase4_episode.py
python rl_agent/test_reconvergence.py
```

### Stage 2: Containernet Online Fine-Tuning & Live Benchmarks

Stage 2 automatically launches the Ryu SDN controller (`mtd_ip_shuffling.app` on OpenFlow port `6653` and REST port `8088`) alongside the 2-Spine / 4-Leaf Containernet fabric (`testbed/containernet_topos/finetune_topo.py` on IPC port `9999`).

#### Step 1: Online Sim-to-Real Fine-Tuning
Requires `rl_agent/mtd_ppo_agent.zip` from Stage 1. Fine-tunes the policy on the live testbed and saves `rl_agent/mtd_ppo_agent_real.zip`, then runs the MBB throughput benchmark, canonical evaluation, and figure generation:
```bash
./finetune_pipeline.sh --steps 5000 --step_duration 0.06 --lr 0.0001
```
Audit parameter divergence between the Stage 1 simulation checkpoint and Stage 2 fine-tuned checkpoint:
```bash
python rl_agent/verify_divergence.py
```

#### Step 2: Live $2 \times 5$ Factorial Benchmark (10 Policy $\times$ Dataplane Cells)
Requires `rl_agent/mtd_ppo_agent_real.zip` and `rl_agent/mtd_ppo_binary_baseline.zip`. Evaluates 5 control policies (`Static`, `Periodic`, `IDS-Triggered`, `Binary DRL`, `Proposed DRL`) across both data-plane modes (`Stateless Hard Flush` vs. `Stateful Table-1 MBB`) and regenerates plots:
```bash
# Usage: ./run_factorial_benchmark.sh [EPISODES] [STEPS] [STEP_DURATION]
./run_factorial_benchmark.sh 15 42 0.6
```

#### Step 3: Live Data-Plane Make-Before-Break Throughput Benchmark
Measures live `iperf3` TCP throughput, $cwnd$, and retransmissions across IP shuffles at $t = 8, 16, 24\,\mathrm{s}$ (Stateful MBB vs. Stateless Hard Flush):
```bash
./rl_agent/run_dataplane_benchmark.sh
```

#### Additional Runners & Plot Regeneration
```bash
# Run MBB data-plane benchmark + 5-policy canonical evaluation + figure generation
./run_all_benchmarks.sh

# Run N=50 live canonical evaluation + figure generation
./run_eval_pipeline.sh

# Regenerate publication figures after CSV artifacts have been generated
python rl_agent/visualize_results.py
```

All generated CSVs, model checkpoints (`.zip`), and figures (`.pdf`/`.png`) are saved under `rl_agent/runs/run_<timestamp>/` and mirrored under `rl_agent/`.

---

## Authors

- **Ali Tavakkoli** — [![ORCID](https://img.shields.io/badge/ORCID-0009--0002--9036--730X-A6CE39?logo=orcid&logoColor=white)](https://orcid.org/0009-0002-9036-730X)  
  *Department of Computer Engineering, Shahed University, Tehran, Iran*
- **Hamid H.S. Javadi** *(Corresponding Author)* — [![ORCID](https://img.shields.io/badge/ORCID-0000--0003--0082--036X-A6CE39?logo=orcid&logoColor=white)](https://orcid.org/0000-0003-0082-036X)  
  *Department of Computer Engineering, Shahed University, Tehran, Iran*
- **M.K. Dadsetani** — [![ORCID](https://img.shields.io/badge/ORCID-0009--0002--9540--7593-A6CE39?logo=orcid&logoColor=white)](https://orcid.org/0009-0002-9540-7593)  
  *Department of Computer Engineering, Shahed University, Tehran, Iran*
- **Mohsen Niknezhad** — [![ORCID](https://img.shields.io/badge/ORCID-0009--0002--8657--367X-A6CE39?logo=orcid&logoColor=white)](https://orcid.org/0009-0002-8657-367X)  
  *Department of Computer Engineering, Shahed University, Tehran, Iran*

---

## Citation

Machine-readable citation metadata is provided in [`CITATION.cff`](CITATION.cff) and [`.zenodo.json`](.zenodo.json). If you use this software or benchmark suite in your research, please cite:

```bibtex
@article{tavakkoli2026zerodowntime,
  title     = {Zero-Downtime Moving Target Defense in Software-Defined Networks: Stateful Make-Before-Break Mutation via Multi-Objective Reinforcement Learning},
  author    = {Tavakkoli, Ali and Javadi, Hamid H.S. and Dadsetani, M.K. and Niknezhad, Mohsen},
  journal   = {Array},
  publisher = {Elsevier},
  year      = {2026},
  note      = {Submitted for publication}
}

@misc{tavakkoli2026mtd_software,
  author       = {Tavakkoli, Ali and Javadi, Hamid H.S. and Dadsetani, M.K. and Niknezhad, Mohsen},
  title        = {{sdn-mtd-mbb-rl}: Zero-Downtime Stateful SDN Moving Target Defense Framework},
  year         = {2026},
  publisher    = {Zenodo},
  doi          = {10.5281/zenodo.24515480},
  url          = {https://doi.org/10.5281/zenodo.24515480},
  note         = {Version v1.0.1, MIT License}
}
```

---

## License

This project is released under the [MIT License](LICENSE) for academic research and reproducibility. Moving Target Defense increases reconnaissance complexity and should be deployed as part of a defense-in-depth architecture alongside standard perimeter security controls.
