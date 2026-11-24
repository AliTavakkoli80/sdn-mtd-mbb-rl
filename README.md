# Zero-Downtime Moving Target Defense in Software-Defined Networks: Stateful Make-Before-Break Mutation via Multi-Objective Reinforcement Learning

[![DOI](https://img.shields.io/badge/DOI-Zenodo_(pending)-blue.svg)](https://zenodo.org/badge/latestdoi/000000000)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.9](https://img.shields.io/badge/Python-3.9-blue.svg)](https://www.python.org/downloads/release/python-3925/)
[![OpenFlow 1.3](https://img.shields.io/badge/SDN-OpenFlow_1.3-green.svg)](https://opennetworking.org/)
[![Ryu 4.34](https://img.shields.io/badge/Controller-Ryu_4.34-0078D7.svg)](https://ryu-sdn.org/)

> **Official reproducibility artifact** for the Elsevier *Array* submission:  
> *Zero-Downtime Moving Target Defense in Software-Defined Networks: Stateful Make-Before-Break Mutation via Multi-Objective Reinforcement Learning*  
> Manuscript PDF: [`paper/main.pdf`](paper/main.pdf)

---

## Overview

Software-Defined Networking (SDN) enables Moving Target Defense (MTD) via dynamic IP address mutation to impede network reconnaissance. However, conventional stateless MTD implementations flush flow tables upon mutation, invalidating active transport-layer state and causing TCP packet drops, congestion window ($cwnd$) collapse, and throughput interruptions. Moreover, fixed-interval or threshold-based triggers ignore data-plane disruption and OpenFlow control-plane signaling budgets.

This repository provides a stateful, zero-downtime SDN-MTD framework integrating three core components:

1. **OpenFlow 1.3 Make-Before-Break (MBB) Dual-Table Pipeline:** Decouples active and mutating sessions across two cascaded tables (`Table 0` Active and `Table 1` Grace), preserving established benign TCP streams across IP rotations while immediately evicting flagged adversary sources from the grace table.
2. **Information-Theoretic L2/L3/L4 Threat Detector:** Quantifies reconnaissance activity online using empirical destination IP/port Shannon entropy ($H_{\mathrm{IP}}, H_{\mathrm{port}}$), continuous-time EWMA packet rate estimation ($\tau = 3.0\,\mathrm{s}$), and inter-arrival time coefficient of variation ($CV_{\mathrm{IAT}}$).
3. **Cost-Aware MOMDP-PPO Engine & Two-Stage Sim-to-Real Pipeline:** Formulates mutation timing and scope (`HOLD`, `GLOBAL`, `TARGETED`) as an 8-dimensional Multi-Objective MDP solved with Proximal Policy Optimization (PPO), pre-trained offline in Gymnasium (`rl_agent/mtd_env.py`) and fine-tuned/evaluated on a 16-host, 2-Spine / 4-Leaf Containernet + Open vSwitch testbed (`testbed/containernet_topos/finetune_topo.py`).

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
├── paper/
│   └── main.pdf                   # Compiled manuscript PDF
├── finetune_pipeline.sh           # End-to-end Stage 2 Sim-to-Real fine-tuning & evaluation
├── run_factorial_benchmark.sh     # Automated 2x5 factorial benchmark runner (10 cells)
├── run_all_benchmarks.sh          # Automated MBB dataplane + canonical baseline runner
├── run_eval_pipeline.sh           # Automated N=50 live canonical evaluation & plot runner
├── requirements.txt               # Pinned Python 3.9 dependencies
├── environment.yml                # Conda environment specification
├── CITATION.cff                   # Zenodo / GitHub citation metadata (CFF 1.2.0)
└── LICENSE                        # MIT License
```

---

## Architecture Overview

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

- **Phase 1 (Grace Migration):** Prior to flushing `Table 0`, active benign 4-tuple sessions are migrated into `Table 1` (`TABLE_GRACE`) bound to their previous virtual IPs (`GRACE_PERIOD_IDLE_TIMEOUT = 15` s, `GRACE_PERIOD_HARD_TIMEOUT = 120` s).
- **Phase 2 (Adversary Eviction & Active Table Update):** Any source IP flagged by `ThreatDetector` is immediately evicted from `Table 1` via `evict_threat_source_from_grace()`, while fresh mappings are installed in `Table 0` (`TABLE_ACTIVE`).
- **RFC-Compliant DNS Interception:** `IPv4Handler` intercepts DNS responses from `10.0.0.254` and reconstructs A-records via `dnslib` with recalculated RFC 1071/768 IP and UDP pseudo-header checksums so new sessions resolve transparently to current virtual IPs.

### 2. MOMDP-PPO Control Plane

The Gymnasium environments (`rl_agent/mtd_env.py` and `rl_agent/containernet_env.py`) share an **8-dimensional normalized state vector** $s_t \in [0, 1]^8$:

| Index | Feature | Description |
| :--- | :--- | :--- |
| `0` | $H_{\mathrm{IP}}$ | Normalized destination IP Shannon entropy |
| `1` | $H_{\mathrm{port}}$ | Normalized destination port Shannon entropy |
| `2` | $R_{\mathrm{EWMA}}$ | Continuous-time EWMA packet rate ($\tau = 3.0\,\mathrm{s}$) |
| `3` | $CV_{\mathrm{IAT}}$ | Inter-arrival time coefficient of variation |
| `4` | $I_t$ | Aggregate threat intensity score |
| `5` | $\tau_t$ | Normalized time elapsed since last mutation |
| `6` | $F_t$ | Normalized active network session load (EWMA-smoothed) |
| `7` | $C_{\mathrm{target}}$ | Normalized cardinality of scanned target hosts |

And **3 discrete actions**:
- `0` (`HOLD`): Retain current virtual IP mappings.
- `1` (`GLOBAL`): Rotate virtual IPs across all 16 protected hosts (`10.0.0.1`–`10.0.0.16`).
- `2` (`TARGETED`): Rotate virtual IPs only for hosts in `scanned_targets`, reducing data-plane churn and OpenFlow `FLOW_MOD` overhead.

---

## Installation & Reproduction Guide

### Prerequisites (Ubuntu Linux)

Stage 2 live emulation requires Linux with Docker and Open vSwitch:

```bash
sudo apt-get update
sudo apt-get install -y \
    python3.9 python3.9-venv python3-pip git \
    openvswitch-switch docker.io iperf3 iputils-ping net-tools
sudo systemctl enable --now docker openvswitch-switch
```

### 1. Clone & Set Up Python Environment

Choose either `venv` (recommended for matching the reference testbed) or `conda`:

#### Option A: Python `venv`
```bash
git clone https://github.com/AliTavakkoli80/sdn-mtd-mbb-rl.git
cd sdn-mtd-mbb-rl

python3.9 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

#### Option B: Conda / Mamba
```bash
git clone https://github.com/AliTavakkoli80/sdn-mtd-mbb-rl.git
cd sdn-mtd-mbb-rl

conda env create -f environment.yml
conda activate sdn-mtd
```

### 2. Install Containernet & Build Host Docker Image (Required for Stage 2)

Install Containernet (`mininet==3.0`) into your active virtual environment and build the Alpine container image (`alpine-mn`) used by `testbed/containernet_topos/finetune_topo.py`:

```bash
# Install Containernet Python package into the active environment
git clone https://github.com/containernet/containernet.git /tmp/containernet
pip install /tmp/containernet

# Build the lightweight Alpine host image (dnsmasq, iperf3, curl, python3)
sudo docker build -t alpine-mn testbed/containernet_topos/host-docker/
```

---

### Stage 1: Offline PPO Pre-Training & Analytical Simulation

Stage 1 trains both the **3-action MOMDP-PPO agent** (`mtd_ppo_agent.zip`) and the **2-action Binary DRL baseline** (`mtd_ppo_binary_baseline.zip`) for 300,000 timesteps on CPU:

```bash
source .venv/bin/activate

# Train Stage 1 policies (outputs saved under rl_agent/runs/run_<timestamp>/ and rl_agent/)
python rl_agent/train_agent.py

# Evaluate policies across analytical threat/load regimes
python rl_agent/evaluate_agent.py
```

Optional verification scripts:
```bash
python rl_agent/verify_continuous_reward.py
python rl_agent/test_reconvergence.py
```

---

### Stage 2: Containernet Online Fine-Tuning & $2 \times 5$ Factorial Benchmarks

Stage 2 launches the Ryu SDN controller (`mtd_ip_shuffling.app` on OpenFlow port `6653` and REST port `8088`) alongside the 2-Spine / 4-Leaf Containernet fabric (`finetune_topo.py` with command socket on port `9999`).

> **Note:** Containernet requires `sudo` privileges to create OVS bridges, veth pairs, and Docker network namespaces.

#### A. Online Sim-to-Real Fine-Tuning
Fine-tunes `rl_agent/mtd_ppo_agent.zip` on the live Containernet testbed (saving `rl_agent/mtd_ppo_agent_real.zip`), then runs the MBB throughput benchmark, canonical evaluation, and figure generation:
```bash
./finetune_pipeline.sh --steps 5000 --step_duration 0.06 --lr 0.0001
```
Audit parameter divergence between the Stage 1 simulation checkpoint and Stage 2 fine-tuned checkpoint:
```bash
python rl_agent/verify_divergence.py
```

#### B. Live $2 \times 5$ Factorial Benchmark (10 Policy $\times$ Dataplane Cells)
Evaluates 5 control policies (`Static`, `Periodic`, `IDS-Triggered`, `Binary DRL`, `Proposed DRL`) across both data-plane modes (`Stateless Hard Flush` vs. `Stateful Table-1 MBB`) and regenerates plots:
```bash
# Usage: ./run_factorial_benchmark.sh [EPISODES] [STEPS] [STEP_DURATION]
./run_factorial_benchmark.sh 15 42 0.6
```

#### C. Live Data-Plane Make-Before-Break Throughput Benchmark
Measures live `iperf3` TCP throughput and retransmissions across IP shuffles at $t = 8, 16, 24\,\mathrm{s}$ (Stateful MBB vs. Stateless Hard Flush):
```bash
./rl_agent/run_dataplane_benchmark.sh
```

#### D. Full Benchmark Suite & Plot Regeneration
```bash
# Run MBB data-plane benchmark + 5-policy canonical evaluation + figure generation
./run_all_benchmarks.sh

# Or regenerate publication figures from recorded CSV artifacts
python rl_agent/visualize_results.py
```

All generated CSVs, model checkpoints (`.zip`), and figures (`.pdf`/`.png`) are saved to `rl_agent/runs/run_<timestamp>/` and mirrored under `rl_agent/`.

---

## Authors

- **Ali Tavakkoli** — [![ORCID](https://img.shields.io/badge/ORCID-0009--0002--9036--730X-A6CE39?logo=orcid&logoColor=white)](https://orcid.org/0009-0002-9036-730X)  
  *Department of Computer Engineering, Shahed University, Tehran, Iran*
- **Hamid H.S. Javadi** *(Corresponding Author)* — [![ORCID](https://img.shields.io/badge/ORCID-0000--0003--0082--036X-A6CE39?logo=orcid&logoColor=white)](https://orcid.org/0000-0003-0082-036X)  
  *Department of Computer Engineering, Shahed University, Tehran, Iran*
- **M.K. Dadsetani** — [![ORCID](https://img.shields.io/badge/ORCID-0009--0002--9540--7593-A6CE39?logo=orcid&logoColor=white)](https://orcid.org/0009-0002-9540-7593)  
  *Department of Computer Engineering, Shahed University, Tehran, Iran*
- **Mohsen Niknezhad Someh** — [![ORCID](https://img.shields.io/badge/ORCID-0009--0002--8657--367X-A6CE39?logo=orcid&logoColor=white)](https://orcid.org/0009-0002-8657-367X)  
  *Department of Computer Engineering, Shahed University, Tehran, Iran*

---

## Citation

If you use this software or benchmark suite in your research, please cite our Elsevier *Array* paper and software archive:

```bibtex
@article{tavakkoli2026zerodowntime,
  title     = {Zero-Downtime Moving Target Defense in Software-Defined Networks: Stateful Make-Before-Break Mutation via Multi-Objective Reinforcement Learning},
  author    = {Tavakkoli, Ali and Javadi, Hamid H.S. and Dadsetani, M.K. and Niknezhad Someh, Mohsen},
  journal   = {Array},
  publisher = {Elsevier},
  year      = {2026},
  note      = {Submitted for publication}
}

@software{tavakkoli2026mtd_software,
  author  = {Tavakkoli, Ali and Javadi, Hamid H.S. and Dadsetani, M.K. and Niknezhad Someh, Mohsen},
  title   = {{sdn-mtd-mbb-rl}: Zero-Downtime Stateful SDN Moving Target Defense Framework},
  version = {v1.0.0},
  year    = {2026},
  url     = {https://github.com/AliTavakkoli80/sdn-mtd-mbb-rl},
  license = {MIT}
}
```

---

## License

This project is released under the [MIT License](LICENSE) for academic research and reproducibility. Moving Target Defense increases reconnaissance complexity and should be deployed as part of a defense-in-depth architecture alongside standard perimeter security controls.
