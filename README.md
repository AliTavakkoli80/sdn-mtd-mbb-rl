# Moving Target Defense (MTD) IP Shuffling for SDN

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue?logo=python)](https://www.python.org/)
[![Ryu](https://img.shields.io/badge/Ryu-4.34-0078D7?logo=linux)](https://ryu-sdn.org/)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![SDN](https://img.shields.io/badge/SDN-OpenFlow_1.3-green)](https://www.opennetworking.org/)

A transparent, **Cost-Aware Moving Target Defense (MTD)** framework for Software-Defined Networks. It dynamically shuffles IP addresses to protect critical servers from L3/L4 reconnaissance and targeted attacks. Clients interact only with virtual IPs while the controller transparently translates traffic to real server IPs at network edges. The shuffling frequency is governed by a **Deep Reinforcement Learning (PPO)** agent that balances security gains against Quality of Service (QoS) degradation.

## 🌐 Architecture Overview

```text
+----------------+     +-------------------------------------+     +------------------+
|   Client       |     |          SDN Network                |     |  Protected Host  |
|                |     |                                     |     |                  |
| 10.0.0.5       |     |  +--------+     +--------+          |     | Real IP: 10.0.0.1|
|                |---->|->| Edge   |---->| Core   |----+     |---->| Virtual:10.0.0.11|
| Sees ONLY      | ARP |  | Switch |     | Switch |    | DNS | UDP |                  |
| 10.0.0.11      |<----|<-| (S1)   |<----| (S2)   |<---+     |<----|                  |
+----------------+     |  +--------+     +--------+          |     +------------------+
                       |        ↑                            |
                       |        | Ryu Controller             |
                       |        | • DNS Payload Patching     |
                       |        | • L3/L4 Threat Detection   |
                       |        | • PPO RL Inference Engine  |
                       +-------------------------------------+
```

> **Core Security Principle**: Attackers see only virtual IPs that are dynamically rotated by an RL agent. Real server IPs remain hidden. Translation occurs ONLY at edge switches to minimize performance impact and maintain core network hardware forwarding efficiency.

## ✨ Key Features

- **Transparent IP Translation**: Real IPs hidden behind virtual IPs; clients never see actual server addresses.
- **Bulletproof DNS Payload Patching**: Surgically modifies raw DNS bytes and recalculates RFC 1071 checksums to ensure strict Linux kernels (like Alpine/musl) accept translated DNS responses without dropping them.
- **Information-Theoretic L3/L4 Threat Detection**: Monitors IPv4/TCP/UDP traffic using **Shannon Entropy**, **EWMA Rate Smoothing**, and **Inter-Arrival Time (IAT) Fingerprinting** to detect Nmap SYN scans and IP sweeps in real-time.
- **Cost-Aware Deep Reinforcement Learning**: A Proximal Policy Optimization (PPO) agent decides *when* to shuffle IPs, penalizing unnecessary shuffles that would break active TCP flows (QoS preservation).
- **Edge-Only Translation**: IP translation occurs ONLY at host-facing edge switches.
- **Bidirectional Flow Handling**: Installs flows for both client→server and server→client paths with proper translation.
- **Topology-Aware**: Discovers network topology and accurately identifies edge vs. core switches using LLDP.

---

## 🧠 AI & Reinforcement Learning (DRL) Integration

This project features a dual-mode MTD engine: **Heuristic Fallback** and **AI-Driven Inference**.

### 1. Training the PPO Agent
The RL agent is trained in a simulated Gymnasium environment (`mtd_env.py`) using Stable-Baselines3. The agent learns a policy $\pi(a|s)$ that maps the network state $s$ (threat intensity, active flows, time since last shuffle) to an action $a \in \{HOLD, SHUFFLE\}$.

To train the agent from scratch:
```bash
# Activate virtual environment
source venv/bin/activate

# Run the training script (Uses mock objects for standalone training)
python train_agent.py
```
*This will generate `mtd_ppo_agent.zip` in the project root.*

### 2. Deploying AI Inference
When the Ryu controller starts, `mtd_engine.py` automatically checks for `mtd_ppo_agent.zip`. 
- **If found**: The controller loads the PPO model and queries it every 2 seconds for rapid, intelligent shuffling decisions.
- **If not found**: The controller falls back to the hardcoded heuristic logic (shuffling based on simple threshold triggers).

---

## ⚙️ Installation & Setup

### Prerequisites
```bash
# System dependencies (Ubuntu/Debian)
sudo apt update
sudo apt install -y python3 python3-pip python3-venv openvswitch-switch git
```

### Project Setup with Virtual Environment
```bash
cd /path/to/mtd-ip-shuffling
python3 -m venv venv
source venv/bin/activate

pip install --upgrade pip
pip install -r requirements.txt # Includes: ryu, gymnasium, stable-baselines3, dnslib, numpy
```

---

## 🚀 Controller Execution

### Start the Controller
```bash
# Ensure virtual environment is activated!
source venv/bin/activate

# Start Ryu with topology discovery
PYTHONPATH=. ryu-manager mtd_ip_shuffling.app ./flowmanager/flowmanager.py --observe-links
```

---

## 🌐 GNS3 Deployment Guide

To properly test MTD and Threat Detection, we use **Netshoot** (a lightweight Linux Docker container with full networking tools like `nmap`, `arping`, and `tcpdump`) instead of basic VPCS nodes. We also use a custom **dnsmasq** Docker image configured to handle IPv6 (`AAAA`) queries gracefully.

### 1. Client Configuration (Netshoot Docker Containers)
In GNS3, drag two **Netshoot** Docker containers into your topology. Go to **Configure > Docker > Start command** and paste the following:

**For PC1 (Attacker/Scanner Node):**
```bash
sh -c 'ip link set eth0 down ; ip link set dev eth0 address 00:50:79:66:68:00 ; ip addr add 10.0.0.1/8 dev eth0 ; ip link set eth0 up ; sysctl -w net.ipv6.conf.eth0.disable_ipv6=1 ; sysctl -w net.ipv6.conf.all.disable_ipv6=1 ; echo "nameserver 10.0.0.10" > /etc/resolv.conf ; echo "options single-request" >> /etc/resolv.conf ; exec sh'
```

**For PC2 (Victim Node):**
```bash
sh -c 'ip link set eth0 down ; ip link set dev eth0 address 00:50:79:66:68:01 ; ip addr add 10.0.0.2/8 dev eth0 ; ip link set eth0 up ; sysctl -w net.ipv6.conf.eth0.disable_ipv6=1 ; sysctl -w net.ipv6.conf.all.disable_ipv6=1 ; echo "nameserver 10.0.0.10" > /etc/resolv.conf ; echo "options single-request" >> /etc/resolv.conf ; exec sh'
```

### 2. DNS Server Configuration (Dnsmasq Docker Container)
Use this **Start command** in your dnsmasq Docker node settings to prevent `REFUSED` errors on IPv6 queries:
```bash
sh -c 'printf "interface=eth0\nno-resolv\nlocal=/com/\naddress=/host1.com/10.0.0.1\naddress=/host2.com/10.0.0.2\n" > /etc/dnsmasq.conf ; dnsmasq ; exec sh'
```

---

## 🔬 Testing & Verification

### Test 1: Transparent Communication & DNS Interception
```bash
# On PC1 (Netshoot):
ping host2.com
# EXPECTED: Resolves to a Virtual IP (e.g., 10.0.100.XX). Ping succeeds.
# Controller logs will show DNS byte-patching and flow installation.
```

### Test 2: L3/L4 Threat Detection & AI Shuffling
Simulate an attacker performing an Nmap SYN scan to trigger the Information-Theoretic Threat Detector.
```bash
# On PC1 (Netshoot), run an Nmap SYN scan across the subnet:
nmap -sS -p 80 10.0.0.1-50
```
**EXPECTED CONTROLLER LOGS:**
```text
🚨 [THREAT] Intelligent scan signature detected from 10.0.0.1 (Score: 0.842)
🧠 [AI DECISION] SHUFFLE | Obs: [1.0  0.8  0.1  0.0]
🎲 [MTD] Executing IP Shuffle...
✅ [MTD] New mapping applied:
   10.0.0.1 ⇄ 10.0.100.44
   10.0.0.2 ⇄ 10.0.100.32
```
*The entropy and IAT metrics detect the automated scanner. The PPO agent observes the high threat score and triggers an immediate shuffle, invalidating the attacker's scan results.*

---

## 📊 Research & Experimental Methodology (For Q1 Publication)

To evaluate the framework for academic publication, the following methodology is used to generate the performance graphs:

1. **Testbed Setup**: A Mininet/GNS3 topology with 4 Open vSwitches and 8 hosts.
2. **Traffic Generation**: 
   - **Legitimate Traffic**: `iperf3` generates continuous TCP streams between hosts to measure QoS degradation.
   - **Attack Traffic**: A Python/Scapy script generates L3/L4 SYN sweeps at varying intensities.
3. **Baselines for Comparison**:
   - **Static SDN**: No MTD applied.
   - **Periodic MTD**: Shuffles IPs exactly every 10 seconds.
   - **Random MTD**: Shuffles IPs based on a Poisson distribution.
   - **Proposed DRL-MTD**: The PPO agent.
4. **Key Metrics Evaluated**:
   - **Reconnaissance Failure Rate**: Percentage of attacker's mapped topology that becomes obsolete.
   - **TCP Throughput Degradation**: Measured via `iperf3` to prove the RL agent avoids shuffling during heavy TCP flows.
   - **Control Plane Overhead**: Number of `FLOW_MOD` messages sent by Ryu.

---

## 📝 Citation

If you use this framework or its underlying concepts in your research, please cite:

```bibtex
@mastersthesis{tavakkoli2026dynamic,
  title={A Dynamic Framework for Intelligent Mitigation of Network Reconnaissance and Scanning using Reinforcement Learning in Software-Defined Networks},
  author={Tavakkoli, Ali},
  year={2026},
  school={University Name}
}
```

---

## 🔒 Security Considerations

| Threat Vector | Mitigation Implemented | Limitation |
|---------------|------------------------|------------|
| **L3/L4 IP Scanning** | Real IPs never exposed; RL-driven shuffling breaks scan maps | Requires DNS interception |
| **Automated Scanners** | IAT Coefficient of Variation fingerprinting detects low-variance tool traffic | N/A |
| **Flow Table Exhaustion** | Translation flows limited to edge switches + idle timeouts (300s) | Core switches unaffected |
| **DNS Cache Poisoning** | Controller intercepts ALL DNS responses & patches bytes securely | Only protects DNS passing through controller |

> ⚠️ **Critical Warning**: MTD increases attack surface complexity but is **NOT a replacement** for firewalls, IDS/IPS, patching, or other security controls. Use as a defense-in-depth layer only.

---

## 📜 License

```text
Copyright 2026 Ali Tavakkoli

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
```

> ⚠️ **Disclaimer**: This project is provided for **educational and research purposes** (Master's Thesis / Q1 Journal Submission). Not recommended for production environments without extensive security hardening.