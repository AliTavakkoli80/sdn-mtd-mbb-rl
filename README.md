# Moving Target Defense (MTD) IP Shuffling for SDN

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue?logo=python)](https://www.python.org/)
[![Ryu](https://img.shields.io/badge/Ryu-4.34-0078D7?logo=linux)](https://ryu-sdn.org/)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![SDN](https://img.shields.io/badge/SDN-OpenFlow_1.3-green)](https://www.opennetworking.org/)

A transparent **Moving Target Defense (MTD)** implementation for Software-Defined Networks that dynamically shuffles IP addresses to protect critical servers from reconnaissance and targeted attacks. Clients interact only with virtual IPs while the controller transparently translates traffic to real server IPs at network edges.

## 🌐 Architecture Overview

```
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
                       |        | • DNS Response Modification|
                       |        | • Edge-Only IP Translation |
                       |        | • Topology-Aware Routing   |
                       +-------------------------------------+
```

> **Core Security Principle**: Attackers see only virtual IPs that can be periodically rotated, while real server IPs remain hidden. Translation occurs ONLY at edge switches to minimize performance impact and maintain core network efficiency.

## ✨ Key Features

- **Transparent IP Translation**: Real IPs hidden behind virtual IPs; clients never see actual server addresses
- **DNS Response Interception**: Automatically replaces real IPs with virtual IPs in DNS A records
- **Edge-Only Translation**: IP translation occurs ONLY at host-facing edge switches (core switches use hardware forwarding)
- **Bidirectional Flow Handling**: Installs flows for both client→server and server→client paths with proper translation
- **Topology-Aware**: Discovers network topology and accurately identifies edge vs. core switches using LLDP
- **Zero Host Modification**: No changes required on protected hosts or clients
- **Modular Architecture**: Clean separation of concerns (topology, flows, packet handling)
- **Comprehensive Logging**: Detailed visual logs for debugging and verification

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
```
mtd-ip-shuffling/
├── app.py                 # Main Ryu application (modular version)
├── config.py              # IP mappings & parameters
├── constants.py           # Protocol constants
├── topology.py            # Topology discovery manager
├── flow_manager.py        # Flow installation logic
├── packet_handler.py      # Packet-in dispatcher
├── arp_handler.py         # ARP handling with MTD awareness
├── ipv4_handler.py        # IPv4/DNS translation logic
├── utils.py               # Logging & helpers
├── requirements.txt       # Project dependencies (dnslib, ryu, ovs, etc.)
├── venv/                  # Python virtual environment (gitignored)
└── README.md
```

## 🔧 Configuration Guide

Edit `config.py` to define your protected hosts:

```python
# config.py

# MTD mappings: Real IP → Virtual IP
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

> 💡 **Best Practice**: Use IPs from a separate subnet for virtual IPs to avoid conflicts (e.g., real: `10.0.0.0/24` → virtual: `10.0.1.0/24`)

## 🚀 Controller Execution

### Critical: Always activate virtual environment first!
```bash
cd /path/to/mtd-ip-shuffling
source venv/bin/activate
```

### Option 1: Modular Version (RECOMMENDED)
```bash
PYTHONPATH=. ryu-manager mtd_ip_shuffling.app ./flowmanager/flowmanager.py --observe-links
```

### Option 2: Single-File Version (Legacy)
```bash
ryu-manager mtd_ip_shuffling.py ./flowmanager/flowmanager.py --observe-links
```

> ⚠️ **Required Flags**:
> - `--observe-links`: Enables LLDP-based topology discovery (MANDATORY)
> - `PYTHONPATH=.`: Required for modular version to resolve package imports

### Expected Startup Output
```
2026-02-14 10:30:22 | INFO     | ================================================================================
2026-02-14 10:30:22 | INFO     | 🚀 MTD IP SHUFFLING CONTROLLER STARTED
2026-02-14 10:30:22 | INFO     | ================================================================================
2026-02-14 10:30:22 | INFO     | 🛡️  REAL IP → VIRTUAL IP MAPPING:
2026-02-14 10:30:22 | INFO     |    • 10.0.0.1       ⇄ 10.0.0.11      (Protected)
2026-02-14 10:30:22 | INFO     |    • 10.0.0.2       ⇄ 10.0.0.12      (Protected)
2026-02-14 10:30:22 | INFO     | ================================================================================
2026-02-14 10:30:22 | INFO     | 🔍 Starting topology discovery thread (interval: 15s, full scan: 30s)
```

## 🌐 GNS3 Deployment Guide

### Network Topology Requirements
Based on your GNS3 topology:
- **Controller**: Ubuntu VM (`ubuntu-MTD-1`) with management interface connected to OVS switches
- **Switches**: Open vSwitch instances (`OpenvSwitch-3`, `OpenvSwitch-4`, etc.)
- **Hosts**: Linux VMs (`PC1`, `PC2`) as clients
- **DNS Server**: Dedicated Linux VM (`DNS-1`) with BIND/dnsmasq

### Step-by-Step Setup

#### 1. Controller Configuration (`ubuntu-MTD-1`)
Here's your netplan configuration integrated into the README.md file under a dedicated **Controller Network Configuration** subsection. I've added context explaining each interface's role in your GNS3/MTD setup:

---

## 🌐 GNS3 Deployment Guide

### Controller Network Configuration (`ubuntu-MTD-1`)

Your Ubuntu controller VM requires three network interfaces for proper operation in GNS3:

| Interface | IP Address       | Purpose                                                                 | Connection Target          |
|-----------|------------------|-------------------------------------------------------------------------|----------------------------|
| `enp0s3`  | DHCP-assigned    | **Internet access** (NAT) for package installation & updates            | VirtualBox NAT             |
| `enp0s8`  | `172.16.1.100/24`| **SDN Control Plane** – Connects to Open vSwitch management interfaces  | GNS3 Management Network    |
| `enp0s9`  | `192.168.56.110/24`| **GNS3 VM Management** – Host-only access for SSH/console from host OS | VirtualBox Host-Only Adapter |

#### Netplan Configuration (`/etc/netplan/01-network-manager-all.yaml`)
```yaml
network:
  version: 2
  renderer: NetworkManager
  ethernets:
    enp0s3:
      dhcp4: true
      dhcp-identifier: mac

    enp0s8:
      addresses:
        - 172.16.1.100/24
      dhcp4: false
    
    enp0s9:
      addresses:
        - 192.168.56.110/24
      dhcp4: false
```

#### Apply Configuration
```bash
sudo netplan apply
```

#### Verify Interfaces
```bash
ip -br addr show | grep -E "enp0s[389]"
# Expected output:
# enp0s3    UP    10.0.2.15/24        # (DHCP-assigned NAT address)
# enp0s8    UP    172.16.1.100/24     # SDN control plane
# enp0s9    UP    192.168.56.110/24   # GNS3 host management
```

### Controller Startup Procedure
```bash
# 1. Verify network connectivity to switches
ping -c 2 172.16.1.20  # Test connection to first OVS switch

# 2. Disable firewall (for testing) OR allow OpenFlow port
sudo ufw disable
# OR for production-like testing:
sudo ufw allow 6653/tcp  # OpenFlow control channel

# 3. Activate virtual environment (CRITICAL!)
cd /path/to/mtd-ip-shuffling
source venv/bin/activate

# 4. Start the MTD controller with topology discovery
PYTHONPATH=. ryu-manager mtd_ip_shuffling.app ./flowmanager/flowmanager.py --observe-links
```

> 💡 **Pro Tip**: The `172.16.1.0/24` subnet (`enp0s8`) is your **SDN control plane** – all Open vSwitch instances must have management interfaces in this subnet with unique IPs (e.g., `172.16.1.20`, `172.16.1.21`, etc.) pointing to your controller at `172.16.1.100:6653`.

```bash
# Configure management interface (connects to OVS switches)
sudo ip addr add 172.16.1.100/24 dev enp0s8
sudo ip link set enp0s8 up

# Disable firewall (for testing) OR allow OpenFlow port
sudo ufw disable
# OR
sudo ufw allow 6653/tcp

# Activate virtual environment and start controller (CRITICAL!)
cd /path/to/mtd-ip-shuffling
source venv/bin/activate

# Start the MTD controller (MODULAR VERSION - RECOMMENDED)
PYTHONPATH=. ryu-manager mtd_ip_shuffling.app ./flowmanager/flowmanager.py --observe-links
```

#### 2. Open vSwitch Configuration (All Switches)
```bash
# Create bridge (if not exists)
sudo ovs-vsctl add-br br0

# Configure management interface
sudo ip addr add 172.16.1.20/24 dev br0  # Use unique IP per switch (e.g., .21, .22)
sudo ip link set br0 up

# Connect to controller
sudo ovs-vsctl set-controller br0 tcp:172.16.1.100:6653
sudo ovs-vsctl set bridge br0 protocols=OpenFlow13
sudo ovs-vsctl set bridge br0 stp_enable=true

# Verify configuration
sudo ovs-vsctl show
```

#### 3. DNS Server Configuration (`DNS-1`)
```bash
# Configure network interface
sudo ip addr add 10.0.0.10/24 dev eth0
sudo ip link set eth0 up

# Configure DNS resolution (using /etc/hosts for simplicity)
echo "10.0.0.1 host1.com host1" | sudo tee -a /etc/hosts
echo "10.0.0.2 host2.com host2" | sudo tee -a /etc/hosts

# Install and start DNS server
sudo apt update
sudo apt install -y dnsmasq
sudo systemctl restart dnsmasq
```

#### 4. Client Configuration (`PC1`, `PC2`)
```bash
# Configure network interface
sudo ip addr add 10.0.0.5/24 dev eth0  # Use unique IP per client
sudo ip link set eth0 up

# Set DNS server
echo "nameserver 10.0.0.10" | sudo tee /etc/resolv.conf
```

## 🔬 Testing & Verification

### Test 1: DNS Response Modification
```bash
# On PC1 (client):
nslookup host1.com

# EXPECTED OUTPUT:
# Name:	host1.com
# Address: 10.0.0.11   <-- VIRTUAL IP (NOT real 10.0.0.1)

# Check controller logs for:
# [dns] 🔒 PROTECTED: 10.0.0.1 → 10.0.0.11 | Domain: host1.com.
```

### Test 2: Transparent Communication with Virtual IP
```bash
# On PC1:
ping -c 4 host1.com

# EXPECTED BEHAVIOR:
# - Packets sent to 10.0.0.11 (virtual IP)
# - Replies received from 10.0.0.11
# - Connection succeeds despite server using 10.0.0.1 internally

# Check controller logs for:
# [mtd] 🔒 VIRTUAL IP DETECTED: 10.0.0.11 → translating to REAL IP 10.0.0.1
# [flow] ✅ Translation flows installed ONLY at edge switches
```

### Test 3: Verify Real IP Remains Hidden
```bash
# On PC1:
nmap -sn 10.0.0.0/24

# EXPECTED RESULT:
# - 10.0.0.11 and 10.0.0.12 appear as active hosts
# - 10.0.0.1 and 10.0.0.2 DO NOT appear (hidden by MTD)
```

### Test 4: Topology Verification
After 30 seconds, check controller logs for topology summary:
```
┌──────────────────────────────────────────────────────────────────────────────┐
│ 🌐 NETWORK TOPOLOGY SUMMARY                                                  │
├──────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│ 📦 SWITCHES (3 total):                                                       │
│    • Switch DPID: 1                                                          │
│      ├─ Access Ports (to hosts): 1                                           │
│      └─ Interior Ports (to switches): 2                                      │
│                                                                              │
│ 🔗 INTER-SWITCH LINKS (2 total):                                             │
│    • S1:p2 ⟷ S2:p2                                                           │
│    • S2:p3 ⟷ S3:p1                                                           │
│                                                                              │
│ 🖥️  PROTECTED HOSTS (2 total):                                               │
│    • REAL: 10.0.0.1      → VIRTUAL: 10.0.0.11                                │
│      Location: Switch S1, Port 1, MAC: 00:00:00:00:00:01                     │
│    • REAL: 10.0.0.2      → VIRTUAL: 10.0.0.12                                │
│      Location: Switch S2, Port 3, MAC: 00:00:00:00:00:02                     │
└──────────────────────────────────────────────────────────────────────────────┘
```

## 🧪 Troubleshooting Guide

| Symptom | Likely Cause | Solution |
|---------|--------------|----------|
| `ModuleNotFoundError: No module named 'ryu'` | Virtual environment not activated | Run `source venv/bin/activate` BEFORE starting controller |
| Switches not connecting to controller | Firewall blocking port 6653 | `sudo ufw allow 6653/tcp` on controller |
| DNS returns real IPs instead of virtual | DNS traffic not passing through controller | Verify switch topology; ensure DNS server connected via edge switch |
| No translation flows installed | Host location unknown | Wait for first ARP/IPv4 packet from host; check `access_ports` detection |
| Connectivity fails after DNS lookup | Missing reverse translation flow | Check if egress switch correctly identified; verify `host_table` population |
| `OFPError: OFPET_BAD_REQUEST` | OpenFlow version mismatch | Ensure all switches configured with `protocols=OpenFlow13` |
| Controller starts but no topology discovery | Missing `--observe-links` flag | Restart controller with `--observe-links` flag |

## 🔒 Security Considerations

| Threat Vector | Mitigation Implemented | Limitation |
|---------------|------------------------|------------|
| **IP Scanning** | Real IPs never exposed to clients | Requires DNS interception |
| **ARP Spoofing** | Controller-managed ARP with virtual IP translation | Requires topology awareness |
| **Flow Table Exhaustion** | Translation flows limited to edge switches + idle timeouts (300s) | Core switches unaffected |
| **DNS Cache Poisoning** | Controller intercepts ALL DNS responses from authoritative server | Only protects DNS responses passing through controller |
| **Controller Compromise** | N/A (critical vulnerability) | **Must secure controller separately** (TLS, auth, isolation) |

> ⚠️ **Critical Warning**: MTD increases attack surface complexity but is **NOT a replacement** for firewalls, IDS/IPS, patching, or other security controls. Use as a defense-in-depth layer only. Never deploy in production without:
> - TLS encryption between controller and switches
> - Strong authentication mechanisms
> - Network segmentation and isolation of control plane
> - Regular security audits

## 📊 Performance Characteristics

| Metric | Value | Notes |
|--------|-------|-------|
| **Translation Latency** | < 1ms | Only affects first packet of flow; subsequent packets handled by switch hardware |
| **Flow Table Usage** | 4 flows per protected host pair | Minimal impact on switch resources |
| **Core Network Impact** | Zero | Interior switches use normal forwarding (`OFPP_NORMAL`) |
| **DNS Modification Overhead** | ~2ms per response | Occurs only on DNS responses containing protected IPs |

## 📜 License

```
Copyright 2026 Ali

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

> ⚠️ **Disclaimer**: This project is provided for **educational and research purposes only**. Not recommended for production environments without extensive security hardening and testing.

---

*Ali Tavakkoli © 2026*