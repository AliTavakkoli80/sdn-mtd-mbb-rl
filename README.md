
# Moving Target Defense (MTD) IP Shuffling for SDN

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue?logo=python)](https://www.python.org/)
[![Ryu](https://img.shields.io/badge/Ryu-4.34-0078D7?logo=linux)](https://ryu-sdn.org/)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![SDN](https://img.shields.io/badge/SDN-OpenFlow_1.3-green)](https://www.opennetworking.org/)

A transparent **Moving Target Defense (MTD)** implementation for Software-Defined Networks that dynamically shuffles IP addresses to protect critical servers from reconnaissance and targeted attacks. Clients interact only with virtual IPs while the controller transparently translates traffic to real server IPs at network edges.

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
                       |        | • Dynamic IP Shuffling     |
                       |        | • ARP Threat Detection     |
                       +-------------------------------------+
```

> **Core Security Principle**: Attackers see only virtual IPs that can be periodically rotated, while real server IPs remain hidden. Translation occurs ONLY at edge switches to minimize performance impact and maintain core network efficiency.

## ✨ Key Features

- **Transparent IP Translation**: Real IPs hidden behind virtual IPs; clients never see actual server addresses.
- **Bulletproof DNS Payload Patching**: Surgically modifies raw DNS bytes and recalculates RFC 1071 checksums to ensure strict Linux kernels (like Alpine/musl) accept translated DNS responses without dropping them.
- **Dynamic IP Shuffling Engine**: Periodically rotates Virtual-to-Real IP mappings from a predefined pool, invalidating attacker reconnaissance and breaking active scan maps.
- **ARP Threat Detection System**: Monitors ARP traffic using a sliding time window to detect network scanning attacks (e.g., `arping`, `nmap` sweeps).
- **Edge-Only Translation**: IP translation occurs ONLY at host-facing edge switches (core switches use hardware forwarding).
- **Bidirectional Flow Handling**: Installs flows for both client→server and server→client paths with proper translation.
- **Topology-Aware**: Discovers network topology and accurately identifies edge vs. core switches using LLDP.
- **Zero Host Modification**: No changes required on protected hosts or clients.

## ⚙️ Installation & Setup

### Prerequisites
```bash
# System dependencies (Ubuntu/Debian)
sudo apt update
sudo apt install -y python3 python3-pip python3-venv openvswitch-switch git
```

### Project Setup with Virtual Environment
```bash
# Clone or navigate to project directory
cd /path/to/mtd-ip-shuffling

# Create virtual environment
python3 -m venv venv

# Activate virtual environment (CRITICAL STEP)
source venv/bin/activate

# Install dependencies from requirements.txt
pip install --upgrade pip
pip install -r requirements.txt

# Verify installation
ryu-manager --version
# Expected output: ryu-manager 4.34
```

### Project Structure
```text
mtd-ip-shuffling/
├── app.py                 # Main Ryu application (modular version)
├── config.py              # IP mappings & parameters
├── constants.py           # Protocol constants
├── topology.py            # Topology discovery manager
├── flow_manager.py        # Flow installation & flushing logic
├── mtd_engine.py          # Dynamic IP shuffling & mapping rotation
├── threat_detector.py     # ARP scan detection & state monitoring
├── packet_handler.py      # Packet-in dispatcher
├── arp_handler.py         # ARP handling with MTD awareness
├── ipv4_handler.py        # IPv4/DNS translation & byte-patching logic
├── utils.py               # Logging & helpers
├── requirements.txt       # Project dependencies (dnslib, ryu, ovs, etc.)
├── venv/                  # Python virtual environment (gitignored)
└── README.md
```

## 🔧 Configuration Guide

Edit `config.py` to define your protected hosts:

```python
# config.py

# MTD mappings: Real IP → Virtual IP (Initial State)
REAL_TO_VIRTUAL = {
    '10.0.0.1': '10.0.0.11',   # Web server (protected)
    '10.0.0.2': '10.0.0.12'    # Database server (protected)
}

# DNS server IP (excluded from MTD translation)
DNS_SERVER_IP = '10.0.0.10'

# Topology discovery parameters
TOPOLOGY_DISCOVERY_INTERVAL = 15  # Seconds between partial scans
TOPOLOGY_FULL_SCAN_CYCLES = 2     # Full topology scan every N intervals
```

> 💡 **Best Practice**: The `MTDEngine` will automatically draw from a larger pool of virtual IPs (e.g., `10.0.100.0/24`) to shuffle mappings dynamically during runtime.

## 🚀 Controller Execution

### Critical: Always activate virtual environment first!
```bash
cd /path/to/mtd-ip-shuffling
source venv/bin/activate
```

### Start the Controller
```bash
PYTHONPATH=. ryu-manager mtd_ip_shuffling.app ./flowmanager/flowmanager.py --observe-links
```

> ⚠️ **Required Flags**:
> - `--observe-links`: Enables LLDP-based topology discovery (MANDATORY)
> - `PYTHONPATH=.`: Required for modular version to resolve package imports

## 🌐 GNS3 Deployment Guide

To properly test MTD and Threat Detection, we use **Netshoot** (a lightweight Linux Docker container with full networking tools like `nmap`, `arping`, and `tcpdump`) instead of basic VPCS nodes. We also use a custom **dnsmasq** Docker image configured to handle IPv6 (`AAAA`) queries gracefully.

### 1. Client Configuration (Netshoot Docker Containers)
VPCS cannot generate attack traffic or handle strict Linux kernel DNS validations. Netshoot solves this. 

In GNS3, drag two **Netshoot** Docker containers into your topology. To make the network configs permanent and disable IPv6 (which prevents DNS `AAAA` timeout issues), go to **Configure > Docker > Start command** and paste the following:

**For PC1 (Attacker/Scanner Node):**
```bash
sh -c 'ip link set eth0 down ; ip link set dev eth0 address 00:50:79:66:68:00 ; ip addr add 10.0.0.1/8 dev eth0 ; ip link set eth0 up ; sysctl -w net.ipv6.conf.eth0.disable_ipv6=1 ; sysctl -w net.ipv6.conf.all.disable_ipv6=1 ; echo "nameserver 10.0.0.10" > /etc/resolv.conf ; echo "options single-request" >> /etc/resolv.conf ; exec sh'
```

**For PC2 (Victim Node):**
```bash
sh -c 'ip link set eth0 down ; ip link set dev eth0 address 00:50:79:66:68:01 ; ip addr add 10.0.0.2/8 dev eth0 ; ip link set eth0 up ; sysctl -w net.ipv6.conf.eth0.disable_ipv6=1 ; sysctl -w net.ipv6.conf.all.disable_ipv6=1 ; echo "nameserver 10.0.0.10" > /etc/resolv.conf ; echo "options single-request" >> /etc/resolv.conf ; exec sh'
```
*(Note: Ensure the Docker container is set to **Privileged** mode in GNS3 settings so `sysctl` can disable IPv6).*

### 2. DNS Server Configuration (Dnsmasq Docker Container)
Standard dnsmasq Docker images often reject IPv6 (`AAAA`) queries with a `REFUSED` error if they lack upstream resolvers, causing Linux clients to drop the valid IPv4 response. 

To fix this and make the config persistent, use this **Start command** in your dnsmasq Docker node settings:

```bash
sh -c 'printf "interface=eth0\nno-resolv\nlocal=/com/\naddress=/host1.com/10.0.0.1\naddress=/host2.com/10.0.0.2\n" > /etc/dnsmasq.conf ; dnsmasq ; exec sh'
```
*This overwrites the config cleanly on every boot, asserts authority over `.com` to return polite `NOERROR` for AAAA queries, and hands control back to the shell.*

### 3. Open vSwitch Configuration (All Switches)
```bash
# Create bridge
sudo ovs-vsctl add-br br0

# Configure management interface
sudo ip addr add 172.16.1.20/24 dev br0  # Use unique IP per switch
sudo ip link set br0 up

# Connect to controller
sudo ovs-vsctl set-controller br0 tcp:172.16.1.100:6653
sudo ovs-vsctl set bridge br0 protocols=OpenFlow13
```

## 🔬 Testing & Verification

### Test 1: Transparent Communication & DNS Interception
```bash
# On PC1 (Netshoot):
ping host2.com

# EXPECTED BEHAVIOR:
# - Resolves to a Virtual IP (e.g., 10.0.100.XX)
# - Ping succeeds seamlessly.
# - Controller logs show DNS byte-patching and flow installation.
```

### Test 2: Verify Real IP Remains Hidden
```bash
# On PC1:
tcpdump -i eth0 -n icmp
# You will see ICMP packets arriving from the REAL IP (10.0.0.1), 
# proving the controller is translating the traffic transparently.
```

### Test 3: Threat Detection & Dynamic Shuffling
Simulate an attacker scanning the network to trigger the `ThreatDetector`.
```bash
# On PC1 (Netshoot), run an ARP sweep:
for i in {50..70}; do arping -c 1 -w 1 10.0.0.$i; done
```
**EXPECTED CONTROLLER LOGS:**
```text
🚨 [THREAT] ARP Scan detected from 10.0.0.1! Targeted 15 unique IPs in 10.0s
🎲 [MTD] Triggering IP Shuffle...
✅ [MTD] New mapping applied:
   10.0.0.1 ⇄ 10.0.100.44
   10.0.0.2 ⇄ 10.0.100.32
```
*The controller detects the scan and instantly flushes old OpenFlow flows, rotating the Virtual IPs to break the attacker's network map.*

## 🧪 Troubleshooting Guide

| Symptom | Likely Cause | Solution |
|---------|--------------|----------|
| DNS returns `REFUSED` for AAAA | Dnsmasq lacks authority for `.com` | Use the custom `printf ... local=/com/` start command in GNS3. |
| Ping fails / DNS timeout on Netshoot | IPv6 `AAAA` query timing out | Ensure `sysctl -w net.ipv6.conf.eth0.disable_ipv6=1` runs *after* `ip link set eth0 up`. |
| GNS3 Console window closes instantly | Docker main process crashing | Ensure you use `exec sh` or `dnsmasq -d` at the end of your start commands. |
| `ModuleNotFoundError: No module named 'ryu'` | Virtual environment not activated | Run `source venv/bin/activate` BEFORE starting controller. |
| Switches not connecting | Firewall blocking port 6653 | `sudo ufw allow 6653/tcp` on controller. |
| Connectivity fails after DNS lookup | Missing reverse translation flow | Check if egress switch correctly identified; verify `host_table` population. |

## 🔒 Security Considerations

| Threat Vector | Mitigation Implemented | Limitation |
|---------------|------------------------|------------|
| **IP Scanning** | Real IPs never exposed; Dynamic Shuffling breaks scan maps | Requires DNS interception |
| **ARP Spoofing** | Controller-managed ARP with virtual IP translation | Requires topology awareness |
| **Flow Table Exhaustion** | Translation flows limited to edge switches + idle timeouts (300s) | Core switches unaffected |
| **DNS Cache Poisoning** | Controller intercepts ALL DNS responses & patches bytes securely | Only protects DNS responses passing through controller |
| **Controller Compromise** | N/A (critical vulnerability) | **Must secure controller separately** (TLS, auth, isolation) |

> ⚠️ **Critical Warning**: MTD increases attack surface complexity but is **NOT a replacement** for firewalls, IDS/IPS, patching, or other security controls. Use as a defense-in-depth layer only.

## 📜 License

```text
Copyright 2026 Ali Tavakkoli

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```

> ⚠️ **Disclaimer**: This project is provided for **educational and research purposes only** (Master's Thesis). Not recommended for production environments without extensive security hardening and testing.

---

*Ali Tavakkoli © 2026*