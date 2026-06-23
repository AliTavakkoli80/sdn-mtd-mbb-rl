Here is the fully updated `README.md`. It accurately reflects all the massive architectural upgrades we've built (Information-Theoretic Detection, Exponential QoS Rewards, and Stateful Make-Before-Break Table Chaining) while explicitly leaving out the Targeted IP Shuffling feature, as that is our next step.

***

# Moving Target Defense (MTD) IP Shuffling for SDN

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue?logo=python)](https://www.python.org/)
[![Ryu](https://img.shields.io/badge/Ryu-4.34-0078D7?logo=linux)](https://ryu-sdn.org/)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![SDN](https://img.shields.io/badge/SDN-OpenFlow_1.3-green)](https://www.opennetworking.org/)

A transparent, **Stateful Moving Target Defense (MTD)** framework for Software-Defined Networks. It dynamically shuffles IP addresses to protect critical servers from L2/L3/L4 reconnaissance and targeted attacks. Clients interact only with virtual IPs while the controller transparently translates traffic to real server IPs at network edges. The shuffling frequency is governed by a **Cost-Aware Deep Reinforcement Learning (PPO)** agent that balances security gains against Quality of Service (QoS) degradation, utilizing **OpenFlow 1.3 Table Chaining** to ensure zero-downtime for active TCP sessions.

## 🌐 Architecture Overview

```text
+----------------+     +-------------------------------------+     +------------------+
|   Client       |     |          SDN Network                |     |  Protected Host  |
|                |     |                                     |     |                  |
| 10.0.0.1       |     |  +--------+     +--------+          |     | Real IP: 10.0.0.2|
|                |---->|->| Edge   |---->| Core   |----+     |---->| Virtual:10.0.0.12|
| Sees ONLY      | ARP |  | Switch |     | Switch |    | DNS | UDP |                  |
| 10.0.0.12      |<----|<-| (S1)   |<----| (S2)   |<---+     |<----|                  |
+----------------+     |  +--------+     +--------+          |     +------------------+
                       |        ↑                            |
                       |        | Ryu Controller             |
                       |        | • DNS Payload Patching     |
                       |        | • Info-Theoretic Detection |
                       |        | • PPO RL Inference Engine  |
                       |        | • Make-Before-Break Tables |
                       +-------------------------------------+
```

> **Core Security Principle**: Attackers see only virtual IPs that are dynamically rotated by an RL agent. Real server IPs remain hidden. Translation occurs ONLY at edge switches to minimize performance impact and maintain core network hardware forwarding efficiency.

## ✨ Key Features

- **Stateful Zero-Downtime MTD (Make-Before-Break)**: Utilizes OpenFlow 1.3 Table Chaining. When a shuffle occurs, old mappings are moved to a "Grace Table" (Table 1) with a 15-second hard timeout, while new mappings are installed in the "Active Table" (Table 0). This guarantees active TCP sessions survive the IP change without triggering TCP Global Synchronization.
- **Information-Theoretic L2/L3/L4 Threat Detection**: Monitors traffic using **Shannon Entropy**, **EWMA Rate Smoothing**, and **Inter-Arrival Time (IAT) Coefficient of Variation** to mathematically fingerprint automated scanners (like Nmap/arping) vs. legitimate human traffic.
- **Cost-Aware Deep Reinforcement Learning**: A Proximal Policy Optimization (PPO) agent decides *when* to shuffle IPs. It uses an **Exponential TCP Collapse Penalty** to avoid shuffling during high network load, and a **Staleness Penalty** to force proactive shuffling before attackers can map the network.
- **Transparent IP Translation & Bulletproof DNS**: Real IPs hidden behind virtual IPs. Surgically modifies raw DNS bytes and recalculates RFC 1071 checksums to ensure strict Linux kernels accept translated DNS responses.
- **Zero-Overhead Flow Tracking**: Tracks active OpenFlow flows via asynchronous `OFPFF_SEND_FLOW_REM` events to measure real-time QoS cost without polling the switches.
- **Topology-Aware Edge Translation**: Discovers network topology via LLDP and accurately identifies edge vs. core switches, ensuring IP translation only happens at the network perimeter.

---

## 🧠 AI & Reinforcement Learning (DRL) Integration

This project features a dual-mode MTD engine: **Heuristic Fallback** and **AI-Driven Inference**.

### 1. The 7D State Space & Multi-Objective Reward
The RL agent observes a 7-dimensional state vector: `[IP_Entropy, Port_Entropy, EWMA_Rate, IAT_CV, Threat_Flag, Time_Since_Shuffle, Active_Flows]`. 

The reward function mathematically models the trade-off between Security and QoS:
* **Exponential QoS Penalty**: Shuffling during high TCP load incurs an exponential penalty $-2.0 \times (e^{3 \cdot f_t} - 1)$ to model TCP Global Synchronization.
* **Staleness Penalty**: Holding too long incurs a penalty proportional to the time since the last shuffle, forcing the agent to proactively randomize the network.

### 2. Training and Deployment
```bash
# Activate virtual environment
source venv/bin/activate

# Train the PPO agent (Generates mtd_ppo_agent.zip)
python train_agent.py
```
When the Ryu controller starts, `mtd_engine.py` automatically loads `mtd_ppo_agent.zip`. If found, it queries the AI every 2 seconds for intelligent shuffling decisions. If not found, it falls back to hardcoded heuristic logic.

---

## ⚙️ Installation & Setup

### Prerequisites
```bash
sudo apt update
sudo apt install -y python3 python3-pip python3-venv openvswitch-switch git
```

### Project Setup
```bash
cd /path/to/mtd-ip-shuffling
python3 -m venv venv
source venv/bin/activate

pip install --upgrade pip
pip install -r requirements.txt # Includes: ryu, gymnasium, stable-baselines3, dnslib, numpy
```

---

## 🚀 Controller Execution

```bash
# Ensure virtual environment is activated!
source venv/bin/activate

# Start Ryu with topology discovery and log redirection
PYTHONPATH=. ryu-manager mtd_ip_shuffling.app ./flowmanager/flowmanager.py --observe-links > ryu_controller.log 2>&1
```

---

## 🌐 GNS3 Deployment Guide

To properly test MTD and Threat Detection, we use **Netshoot** (a lightweight Linux Docker container with full networking tools like `nmap`, `arping`, and `tcpdump`) instead of basic VPCS nodes. 

### 1. Client Configuration (Netshoot Docker Containers)
In GNS3, drag two **Netshoot** Docker containers into your topology. Go to **Configure > Docker > Start command** and paste the following to disable IPv6 (prevents DNS AAAA timeout issues):

**For PC1 (Attacker/Client Node):**
```bash
sh -c 'ip link set eth0 down ; ip link set dev eth0 address 00:50:79:66:68:00 ; ip addr add 10.0.0.1/8 dev eth0 ; ip link set eth0 up ; sysctl -w net.ipv6.conf.eth0.disable_ipv6=1 ; sysctl -w net.ipv6.conf.all.disable_ipv6=1 ; echo "nameserver 10.0.0.10" > /etc/resolv.conf ; exec sh'
```

**For PC2 (Victim/Server Node):**
```bash
sh -c 'ip link set eth0 down ; ip link set dev eth0 address 00:50:79:66:68:01 ; ip addr add 10.0.0.2/8 dev eth0 ; ip link set eth0 up ; sysctl -w net.ipv6.conf.eth0.disable_ipv6=1 ; sysctl -w net.ipv6.conf.all.disable_ipv6=1 ; echo "nameserver 10.0.0.10" > /etc/resolv.conf ; exec sh'
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
# EXPECTED: Resolves to a Virtual IP (e.g., 10.0.0.12). Ping succeeds.
# Controller logs will show DNS byte-patching and flow installation in Table 0.
```

### Test 2: Stateful Zero-Downtime MTD (The Make-Before-Break Proof)
This test proves that active TCP sessions survive an IP shuffle without dropping.

**1. Start the server on PC2:**
```bash
iperf3 -s
```

**2. Run the client and trigger a sequential attack on PC1:**
```bash
# Start a 60-second TCP stream using the domain name
iperf3 -c host2.com -t 60 -i 2 > /tmp/iperf_results.txt &

# Wait 10 seconds for the stream to stabilize
sleep 10

# Trigger a sequential ARP sweep to force the AI to shuffle
echo "--- Triggering Surgical Sequential Sweep ---"
for i in $(seq 50 70); do arping -c 1 -w 1 10.0.0.$i; done

# Wait for iperf3 to finish and show results
wait
cat /tmp/iperf_results.txt
```

**EXPECTED BEHAVIOR:**
1. The `arping` sweep triggers the Information-Theoretic Threat Detector.
2. The PPO agent observes the threat and triggers a **SHUFFLE**.
3. The controller moves the old flows to **Table 1 (Grace)** and installs new flows in **Table 0 (Active)**.
4. The `iperf3` output will show **continuous high throughput** for 15 seconds after the shuffle, proving the TCP session survived via the Grace Period, before cleanly terminating when the 15s hard timeout expires.

---

## 🔒 Security Considerations

| Threat Vector | Mitigation Implemented | Limitation |
|---------------|------------------------|------------|
| **L2/L3/L4 Scanning** | Real IPs never exposed; RL-driven shuffling breaks scan maps | Requires DNS interception |
| **Automated Scanners** | IAT Coefficient of Variation fingerprinting detects low-variance tool traffic | N/A |
| **TCP Session Drops** | OpenFlow Table Chaining (Make-Before-Break) preserves active flows | 15s grace period limit |
| **Flow Table Exhaustion** | Translation flows limited to edge switches + idle timeouts | Core switches unaffected |

> ⚠️ **Critical Warning**: MTD increases attack surface complexity but is **NOT a replacement** for firewalls, IDS/IPS, patching, or other security controls. Use as a defense-in-depth layer only.

---


> ⚠️ **Disclaimer**: This project is provided for **educational and research purposes** (Master's Thesis / Q1 Journal Submission). Not recommended for production environments without extensive security hardening.