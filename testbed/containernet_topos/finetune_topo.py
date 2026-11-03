#!/usr/bin/env python3
"""
finetune_topo.py - Large topology for RL fine-tuning with robust initialization.

Handles large networks (10+ hosts, 4+ switches) with:
- Retry logic for ping/DNS tests
- Gradual host registration
- DNS-based connectivity (not direct IP)
- Health checks before proceeding
"""

import sys
import os
import shutil
import time
import socket
import threading
import json
import signal
import re
import requests
from mininet.net import Containernet
from mininet.node import RemoteController, OVSSwitch
from mininet.link import Link
from mininet.cli import CLI
from mininet.log import setLogLevel, info

# Global references
net = None
cmd_socket = None
running = True

# Configuration
NUM_HOSTS = 16
DNS_IP = '10.0.0.254'
COMMAND_PORT = 9999

def signal_handler(signum, frame):
    global running
    info("\n*** Received shutdown signal\n")
    running = False
    if net:
        try:
            net.stop()
        except Exception:
            pass
    sys.exit(0)

# ============================================================================
# PHASE 1: Basic Topology Creation (Enterprise 2-Spine 4-Leaf Fabric)
# ============================================================================

def create_basic_topology():
    """Create the enterprise 2-Spine 4-Leaf fabric with 16 Docker hosts."""
    global net
    
    info("*** PHASE 1: Creating Enterprise 2-Spine 4-Leaf Topology\n")
    
    net = Containernet()
    
    # Controller
    info("*** Adding Controller\n")
    c0 = net.addController('c0', controller=RemoteController, ip='127.0.0.1', port=6653)
    
    # 2 Spine Switches (OpenFlow 1.3, stp=False)
    info("*** Adding 2 Spine Switches (s_sp1, s_sp2)\n")
    s_sp1 = net.addSwitch('s_sp1', cls=OVSSwitch, protocols='OpenFlow13', dpid='0000000000000011', stp=False)
    s_sp2 = net.addSwitch('s_sp2', cls=OVSSwitch, protocols='OpenFlow13', dpid='0000000000000012', stp=False)
    
    # 4 Leaf Switches (OpenFlow 1.3, stp=False)
    info("*** Adding 4 Leaf Switches (s_lf1, s_lf2, s_lf3, s_lf4)\n")
    s_lf1 = net.addSwitch('s_lf1', cls=OVSSwitch, protocols='OpenFlow13', dpid='0000000000000001', stp=False)
    s_lf2 = net.addSwitch('s_lf2', cls=OVSSwitch, protocols='OpenFlow13', dpid='0000000000000002', stp=False)
    s_lf3 = net.addSwitch('s_lf3', cls=OVSSwitch, protocols='OpenFlow13', dpid='0000000000000003', stp=False)
    s_lf4 = net.addSwitch('s_lf4', cls=OVSSwitch, protocols='OpenFlow13', dpid='0000000000000004', stp=False)
    
    # Protected hosts (h1-h16)
    info(f"*** Adding {NUM_HOSTS} Docker Hosts (4 hosts per Leaf)\n")
    hosts = []
    for i in range(1, NUM_HOSTS + 1):
        host_name = f'h{i}'
        ip = f'10.0.0.{i}/24'
        host = net.addDocker(host_name, ip=ip, dimage='alpine-mn', volumes=['/tmp:/tmp:rw'])
        hosts.append(host)
        info(f"    Added {host_name} ({ip})\n")
    
    # Dedicated DNS server
    info("*** Adding DNS Server\n")
    dns = net.addDocker('dns', ip=f'{DNS_IP}/24', dimage='alpine-mn')
    
    # Create bipartite mesh trunk links (every Leaf connected to both Spines)
    info("*** Creating 8 Bipartite Spine-Leaf Trunk Links\n")
    net.addLink(s_lf1, s_sp1)
    net.addLink(s_lf1, s_sp2)
    net.addLink(s_lf2, s_sp1)
    net.addLink(s_lf2, s_sp2)
    net.addLink(s_lf3, s_sp1)
    net.addLink(s_lf3, s_sp2)
    net.addLink(s_lf4, s_sp1)
    net.addLink(s_lf4, s_sp2)
    
    # Host distribution: 4 hosts per Leaf switch
    # h1-h4 on Leaf 1
    for h in hosts[0:4]:
        net.addLink(h, s_lf1)
    # h5-h8 on Leaf 2
    for h in hosts[4:8]:
        net.addLink(h, s_lf2)
    # h9-h12 on Leaf 3
    for h in hosts[8:12]:
        net.addLink(h, s_lf3)
    # h13-h16 on Leaf 4
    for h in hosts[12:16]:
        net.addLink(h, s_lf4)
    
    # DNS connection (connected to Leaf 1)
    net.addLink(dns, s_lf1)
    
    # Start network
    info("*** Starting Network\n")
    net.start()
    
    # Wait for switches to connect to controller
    info("*** Waiting for switches to connect to controller...\n")
    time.sleep(5)
    
    info("✅ Phase 1 complete: 2-Spine 4-Leaf fabric created\n")
    return net

# ============================================================================
# PHASE 2: DNS Configuration
# ============================================================================

def configure_dns():
    """Configure DNS server with records for all hosts."""
    info("*** PHASE 2: Configuring DNS server\n")
    
    dns = net.get('dns')
    
    # Create DNS records for all hosts
    info("*** Creating DNS records\n")
    for i in range(1, NUM_HOSTS + 1):
        dns.cmd(f'echo "10.0.0.{i} host{i}.com" >> /etc/hosts')
    
    dns.cmd('echo "10.0.0.254 dns" >> /etc/hosts')
    
    # Start dnsmasq
    info("*** Starting dnsmasq\n")
    dns.cmd('dnsmasq')
    time.sleep(2)
    
    # Point all hosts to the DNS server
    info("*** Configuring DNS clients\n")
    for i in range(1, NUM_HOSTS + 1):
        host = net.get(f'h{i}')
        host.cmd(f'echo "nameserver {DNS_IP}" > /etc/resolv.conf')
        host.cmd('echo "options single-request" >> /etc/resolv.conf')
    
    info("✅ Phase 2 complete: DNS configured\n")

# ============================================================================
# PHASE 3: Host Registration via DNS (Gradual)
# ============================================================================

def register_hosts_via_dns():
    """Force hosts to register with Ryu GENTLY to avoid CPU starvation."""
    info("*** PHASE 3: Registering hosts gently via DNS...\n")
    
    # Wait for Ryu to discover topology
    info("*** Waiting for Ryu to discover topology (5s)...\n")
    time.sleep(5)
    
    # 1. Register DNS server FIRST so Ryu knows where 10.0.0.254 lives
    dns = net.get('dns')
    dns.cmd('ping -c 1 -W 2 10.0.0.1 > /dev/null 2>&1 || true')
    time.sleep(0.5)
    info("    Registered dns server\n")

    # 2. GENTLE APPROACH: Have each host ping the DNS server once.
    info("*** Registering hosts one by one...\n")
    for i in range(1, NUM_HOSTS + 1):
        host = net.get(f'h{i}')
        # Ping the DNS server to establish L2/L3 paths
        host.cmd(f'ping -c 1 -W 2 {DNS_IP} > /dev/null 2>&1 || true')
        info(f"    Registered h{i}\n")
        
        # Allow Ryu to process the Packet-In before the next one
        time.sleep(0.5) 
    
    info("✅ Phase 3 complete: Hosts registered gently\n")

# ============================================================================
# PHASE 4: Testing with Retry Logic
# ============================================================================

def ping_with_retry(src_host, dst_domain, max_attempts=3, timeout=3):
    """Ping a domain name with retry logic."""
    for attempt in range(1, max_attempts + 1):
        info(f"    Attempt {attempt}/{max_attempts}: {src_host.name} -> {dst_domain}\n")
        result = src_host.cmd(f'ping -c 1 -W {timeout} {dst_domain} 2>&1')
        
        if '0% packet loss' in result or '1 packets transmitted, 1 received' in result:
            return True, result
        
        if attempt < max_attempts:
            info(f"    Failed, retrying in 2s...\n")
            time.sleep(2)
    
    return False, result

def test_dns_resolution():
    """Test DNS resolution with retry logic across all 4 leaves."""
    info("\n" + "="*60 + "\n")
    info("*** PHASE 4: Testing DNS resolution across leaves (with retries)\n")
    info("="*60 + "\n")
    
    h1 = net.get('h1')
    h5 = net.get('h5')
    h9 = net.get('h9')
    h13 = net.get('h13')
    
    tests = [
        (h1, 'host5.com'),   # Leaf 1 -> Leaf 2
        (h1, 'host9.com'),   # Leaf 1 -> Leaf 3
        (h1, 'host13.com'),  # Leaf 1 -> Leaf 4
        (h5, 'host1.com'),   # Leaf 2 -> Leaf 1
        (h9, 'host14.com'),  # Leaf 3 -> Leaf 4
        (h13, 'host3.com'),  # Leaf 4 -> Leaf 1
    ]
    
    success_count = 0
    for src, dst in tests:
        success, result = ping_with_retry(src, dst, max_attempts=3)
        if success:
            info(f"    ✅ {src.name} -> {dst} PASSED\n")
            success_count += 1
        else:
            info(f"    ❌ {src.name} -> {dst} FAILED\n")
    
    info(f"\n*** DNS Resolution Results: {success_count}/{len(tests)} passed\n")
    return success_count == len(tests)

def test_all_hosts_via_dns():
    """Test that all hosts can be reached via DNS from h1."""
    info("\n" + "="*60 + "\n")
    info("*** PHASE 4: Testing all hosts via DNS from h1\n")
    info("="*60 + "\n")
    
    h1 = net.get('h1')
    success_count = 0
    
    for i in range(2, NUM_HOSTS + 1):
        domain = f'host{i}.com'
        success, _ = ping_with_retry(h1, domain, max_attempts=2, timeout=2)
        
        if success:
            info(f"    ✅ {domain} reachable\n")
            success_count += 1
        else:
            info(f"    ❌ {domain} unreachable\n")
    
    info(f"\n*** Results: {success_count}/{NUM_HOSTS-1} hosts reachable\n")
    return success_count == (NUM_HOSTS - 1)

def run_all_tests():
    """Run all tests with retry logic."""
    info("\n" + "="*60 + "\n")
    info("*** RUNNING ALL TESTS (with retry logic)\n")
    info("="*60 + "\n")
    
    results = {
        'dns_resolution': test_dns_resolution(),
        'all_hosts': test_all_hosts_via_dns()
    }
    
    info("\n" + "="*60 + "\n")
    info("*** TEST SUMMARY\n")
    info("="*60 + "\n")
    
    for test_name, passed in results.items():
        status = "✅ PASSED" if passed else "❌ FAILED"
        info(f"{test_name}: {status}\n")
    
    all_passed = all(results.values())
    
    if all_passed:
        info("\n✅ ALL TESTS PASSED\n")
    else:
        info("\n⚠️  SOME TESTS FAILED (may still work for finetuning)\n")
    
    return all_passed

# ============================================================================
# PHASE 5: Finetuning Services
# ============================================================================

def command_listener(port=COMMAND_PORT):
    """Listen for commands from the RL environment."""
    global net, cmd_socket, running
    
    cmd_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    cmd_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    cmd_socket.bind(('127.0.0.1', port))
    cmd_socket.listen(5)
    cmd_socket.settimeout(1.0)
    
    info(f"*** Command listener ready on port {port}\n")
    
    while running:
        try:
            conn, addr = cmd_socket.accept()
            conn.settimeout(10.0)
            try:
                data = conn.recv(4096).decode()
                cmd = json.loads(data)
                response = handle_command(cmd)
                conn.sendall(json.dumps(response).encode())
            except socket.timeout:
                conn.sendall(json.dumps({'status': 'timeout', 'message': 'Command timed out'}).encode())
            except json.JSONDecodeError as e:
                conn.sendall(json.dumps({'status': 'error', 'message': f'Invalid JSON: {e}'}).encode())
            except Exception as e:
                conn.sendall(json.dumps({'status': 'error', 'message': str(e)}).encode())
            finally:
                conn.close()
        except socket.timeout:
            continue
        except Exception as e:
            if running:
                info(f"*** Command listener error: {e}\n")

def resolve_target_vip(h, target_id, dns_ip="10.0.0.254"):
    """
    Dynamically resolve target domain via Ryu REST API or DNS server to obtain its active Virtual IP.
    """
    target_str = str(target_id).strip()
    real_ip = target_str
    if 'host' in target_str:
        num = re.findall(r'\d+', target_str)
        if num:
            real_ip = f"10.0.0.{num[0]}"

    # 1. Query Ryu controller REST API directly (instant 0ms lookup)
    try:
        ryu_api = os.getenv("RYU_API_URL", "http://127.0.0.1:8088")
        r = requests.get(f"{ryu_api}/mtd/state", timeout=0.5)
        if r.status_code == 200:
            mapping = r.json().get('current_mapping', {})
            if real_ip in mapping:
                return mapping[real_ip]
    except Exception:
        pass

    # 2. Fast container query with strict timeout
    try:
        domain = f"host{real_ip.split('.')[-1]}.com" if real_ip.startswith('10.0.0.') else target_str
        out = h.cmd(f"timeout 0.3 nslookup {domain} {dns_ip} 2>&1")
        ips = re.findall(r'\b10\.0\.0\.\d+\b', out)
        valid_ips = [ip for ip in ips if ip != dns_ip]
        if valid_ips:
            return valid_ips[-1]
    except Exception:
        pass

    return real_ip


def handle_command(cmd):
    """Execute a command on the network with retry logic."""
    global net
    if not net:
        return {'status': 'error', 'message': 'Network not initialized'}
    
    action = cmd.get('action')
    
    try:
        if action == 'ping':
            h1 = net.get('h1')
            h2 = net.get('h2')
            result = net.ping([h1, h2], timeout=2)
            return {'status': 'ok', 'loss': result}
        
        elif action == 'ping_dns':
            # Test DNS resolution with retries
            h1 = net.get('h1')
            h5 = net.get('h5')
            
            success1, result1 = ping_with_retry(h1, 'host2.com', max_attempts=3)
            success2, result2 = ping_with_retry(h5, 'host1.com', max_attempts=3)
            
            return {
                'status': 'ok',
                'h1_to_host2': success1,
                'h5_to_host1': success2,
                'output_h1': result1,
                'output_h5': result2
            }
        
        elif action == 'attack_arp':
            h1 = net.get('h1')
            h1.cmd('pkill -9 -f "scan_worker" > /dev/null 2>&1 || true')
            h1.cmd('pkill -9 -f "arping" > /dev/null 2>&1 || true')
            h1.cmd('pkill -9 -f "dev/tcp" > /dev/null 2>&1 || true')
            h1.cmd('pkill -9 -f "nc" > /dev/null 2>&1 || true')

            # Dynamically resolve protected hosts host2.com - host10.com to active VIPs
            resolved_vips = []
            for i in range(2, NUM_HOSTS + 1):
                vip = resolve_target_vip(h1, f"host{i}.com", DNS_IP)
                if vip:
                    resolved_vips.append(vip)
            if not resolved_vips:
                resolved_vips = [f"10.0.0.{i}" for i in range(2, NUM_HOSTS + 1)]
            vips_str = " ".join(resolved_vips)

            # Continuous high-rate empirical probe tracking writing to /tmp/attacker_scan_results.json
            h1.cmd(f"sh -c 'python3 /tmp/scan_worker.py --vips {vips_str} --ports 80 </dev/null >/tmp/scan_worker.log 2>&1 &'")
            return {'status': 'ok', 'message': f'GLOBAL scan active across VIPs: {vips_str}', 'vips': resolved_vips}

        elif action == 'attack_syn':
            h1 = net.get('h1')
            h1.cmd('pkill -9 -f "scan_worker" > /dev/null 2>&1 || true')
            h1.cmd('pkill -9 -f "dev/tcp" > /dev/null 2>&1 || true')
            # Attack across all 16 hosts
            h1.cmd('nohup bash -c "'
                '  exec -a scan_worker bash -c \''
                '    while true; do '
                '      for i in $(seq 2 16); do '
                '        for port in 22 80 443; do '
                '          (timeout 0.1 bash -c \\"echo > /dev/tcp/10.0.0.$i/$port\\" 2>/dev/null || true) & '
                '        done ; '
                '      done ; '
                '      wait ; '
                '      sleep 0.2 ; '
                '    done \''
                '" > /dev/null 2>&1 &')
            return {'status': 'ok', 'message': 'GLOBAL SYN scan (all hosts)'}

        elif action == 'attack_targeted':
            h1 = net.get('h1')
            raw_targets = cmd.get('targets', ['10.0.0.2', '10.0.0.3'])
            ports = cmd.get('ports', [80, 22, 443, 8080, 21])
            h1.cmd('pkill -9 -f "scan_worker" > /dev/null 2>&1 || true')
            h1.cmd('pkill -9 -f "arping" > /dev/null 2>&1 || true')
            h1.cmd('pkill -9 -f "dev/tcp" > /dev/null 2>&1 || true')
            h1.cmd('pkill -9 -f "nc" > /dev/null 2>&1 || true')

            # Dynamically resolve hostnames via DNS server 10.0.0.254 to get active VIPs
            resolved_vips = []
            for t in raw_targets:
                vip = resolve_target_vip(h1, t, DNS_IP)
                if vip:
                    resolved_vips.append(vip)
            if not resolved_vips:
                resolved_vips = ['10.0.0.2', '10.0.0.3']
            vips_str = " ".join(resolved_vips)
            ports_str = " ".join(str(p) for p in ports)

            # Continuous high-rate probe tracking writing to /tmp/attacker_scan_results.json
            h1.cmd(f"sh -c 'python3 /tmp/scan_worker.py --vips {vips_str} --ports {ports_str} </dev/null >/tmp/scan_worker.log 2>&1 &'")
            return {'status': 'ok', 'message': f'TARGETED scan active on VIPs: {vips_str} across ports: {ports_str}', 'vips': resolved_vips, 'ports': ports}

        elif action == 'attack_ports':
            h1 = net.get('h1')
            raw_targets = cmd.get('targets', ['10.0.0.2'])
            ports = cmd.get('ports', [21, 22, 80, 443, 8080])
            h1.cmd('pkill -9 -f "scan_worker" > /dev/null 2>&1 || true')
            h1.cmd('pkill -9 -f "arping" > /dev/null 2>&1 || true')
            h1.cmd('pkill -9 -f "dev/tcp" > /dev/null 2>&1 || true')
            h1.cmd('pkill -9 -f "nc" > /dev/null 2>&1 || true')

            resolved_vips = []
            for t in raw_targets:
                vip = resolve_target_vip(h1, t, DNS_IP)
                if vip:
                    resolved_vips.append(vip)
            if not resolved_vips:
                resolved_vips = ['10.0.0.2']
            vips_str = " ".join(resolved_vips)
            ports_str = " ".join(str(p) for p in ports)

            h1.cmd(f"sh -c 'python3 /tmp/scan_worker.py --vips {vips_str} --ports {ports_str} </dev/null >/tmp/scan_worker.log 2>&1 &'")
            return {'status': 'ok', 'message': f'PORT scan active on VIPs: {vips_str} across ports: {ports_str}', 'vips': resolved_vips, 'ports': ports}

        elif action == 'stop_attacks':
            h1 = net.get('h1')
            h1.cmd('pkill -9 -f "scan_worker" > /dev/null 2>&1 || true')
            h1.cmd('pkill -9 -f "arping" > /dev/null 2>&1 || true')
            h1.cmd('pkill -9 -f "nslookup" > /dev/null 2>&1 || true')
            h1.cmd('pkill -9 -f "dev/tcp" > /dev/null 2>&1 || true')
            h1.cmd('pkill -9 -f "nc" > /dev/null 2>&1 || true')
            h1.cmd('echo "[]" > /tmp/attacker_scan_results.json')
            return {'status': 'ok', 'message': 'All attacks stopped'}

        elif action == 'get_scan_results':
            h1 = net.get('h1')
            out = h1.cmd('cat /tmp/attacker_scan_results.json 2>/dev/null || echo "[]"')
            try:
                data = json.loads(out)
                return {'status': 'ok', 'results': data}
            except Exception:
                return {'status': 'ok', 'results': []}

        elif action == 'set_traffic_load':
            level = cmd.get('level', 'high')
            h3 = net.get('h3')
            h4 = net.get('h4')
            h7 = net.get('h7')
            h8 = net.get('h8')
            h7.cmd('pkill -9 -f iperf3 > /dev/null 2>&1 || true')
            h8.cmd('pkill -9 -f iperf3 > /dev/null 2>&1 || true')
            h3.cmd('pkill -9 -f iperf3 > /dev/null 2>&1 || true')
            h4.cmd('pkill -9 -f iperf3 > /dev/null 2>&1 || true')
            h3.cmd('pkill -9 -f carrier_worker > /dev/null 2>&1 || true')
            h4.cmd('pkill -9 -f carrier_worker > /dev/null 2>&1 || true')
            time.sleep(0.1)
            h7.cmd('iperf3 -s -D > /dev/null 2>&1 || true')
            h8.cmd('iperf3 -s -p 5202 -D > /dev/null 2>&1 || true')
            time.sleep(0.1)
            if level == 'high':
                h3.cmd("sh -c 'python3 /tmp/carrier_worker.py --target host7.com --port 5201 --bandwidth 10M </dev/null >/tmp/carrier3.log 2>&1 &'")
                h4.cmd("sh -c 'python3 /tmp/carrier_worker.py --target host8.com --port 5202 --bandwidth 10M </dev/null >/tmp/carrier4.log 2>&1 &'")
                return {'status': 'ok', 'message': 'High traffic load active across fabric (h3->host7.com, h4->host8.com)'}
            else:
                h3.cmd("sh -c 'python3 /tmp/carrier_worker.py --target host7.com --port 5201 --bandwidth 2M </dev/null >/tmp/carrier3.log 2>&1 &'")
                return {'status': 'ok', 'message': 'Low traffic load active (h3->host7.com)'}

        elif action == 'attack_dns':
            h1 = net.get('h1')
            # Attack for 10 seconds
            h1.cmd('nohup bash -c "'
                '  for i in $(seq 1 100); do '
                '    nslookup host1.com 10.0.0.254 > /dev/null 2>&1 '
                '    sleep 0.1 '
                '  done '
                '" > /dev/null 2>&1 &')
            return {'status': 'ok', 'message': 'INTERMITTENT DNS flood (10s burst)'}
                
        elif action == 'start_iperf':
            h2 = net.get('h2')
            h1 = net.get('h1')
            h2.cmd('pkill -f iperf3 > /dev/null 2>&1')
            h1.cmd('pkill -f iperf3 > /dev/null 2>&1')
            time.sleep(0.5)
            
            h2.cmd('iperf3 -s -D > /dev/null 2>&1')
            time.sleep(0.5)
            # Use domain name for iperf
            h1.cmd('nohup iperf3 -c host2.com -t 300 -i 5 -b 8M > /tmp/iperf.log 2>&1 &')
            return {'status': 'ok', 'message': 'iperf3 traffic started (300s)'}
        
        elif action == 'get_iperf':
            h1 = net.get('h1')
            output = h1.cmd('tail -20 /tmp/iperf.log 2>/dev/null || echo "no data"')
            return {'status': 'ok', 'output': output}
        
        elif action == 'get_status':
            h1 = net.get('h1')
            h2 = net.get('h2')
            ping_result = net.ping([h1, h2], timeout=2)
            return {
                'status': 'ok',
                'total_hosts': len([h for h in net.hosts if h.name.startswith('h')]),
                'ping_loss': ping_result
            }
        
        elif action == 'stop':
            info("*** Stopping network by command\n")
            if net: net.stop()
            sys.exit(0)
        
        else:
            return {'status': 'error', 'message': f'Unknown action: {action}'}
    
    except Exception as e:
        return {'status': 'error', 'message': f'Command failed: {str(e)}'}

def start_backend_services():
    """Start persistent lightweight TCP services on backend hosts h2-h16."""
    info(f"*** Starting persistent TCP backend services on h2-h{NUM_HOSTS} (port 80)...\n")
    for i in range(2, NUM_HOSTS + 1):
        h = net.get(f'h{i}')
        h.cmd('pkill -9 -f "nc -lk" > /dev/null 2>&1 || true')
        h.cmd("nohup sh -c 'while true; do nc -lk -p 80 -e /bin/true; sleep 0.1; done' > /dev/null 2>&1 &")

def start_finetuning_services():
    """Start command listener and background traffic for finetuning."""
    info("\n" + "="*60 + "\n")
    info("*** PHASE 5: Starting finetuning services\n")
    info("="*60 + "\n")
    
    # Deploy scan_worker.py to shared volume /tmp
    src_worker = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'scan_worker.py')
    if os.path.exists(src_worker):
        try:
            if os.path.exists('/tmp/scan_worker.py'):
                try:
                    os.remove('/tmp/scan_worker.py')
                except Exception:
                    pass
            shutil.copy(src_worker, '/tmp/scan_worker.py')
            os.chmod('/tmp/scan_worker.py', 0o777)
            info("    Deployed scan_worker.py to /tmp/scan_worker.py\n")
        except Exception as e:
            info(f"    Notice: scan_worker.py deployment: {e}\n")

    # Deploy carrier_worker.py to shared volume /tmp
    src_carrier = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'carrier_worker.py')
    if os.path.exists(src_carrier):
        try:
            if os.path.exists('/tmp/carrier_worker.py'):
                try:
                    os.remove('/tmp/carrier_worker.py')
                except Exception:
                    pass
            shutil.copy(src_carrier, '/tmp/carrier_worker.py')
            os.chmod('/tmp/carrier_worker.py', 0o777)
            info("    Deployed carrier_worker.py to /tmp/carrier_worker.py\n")
        except Exception as e:
            info(f"    Notice: carrier_worker.py deployment: {e}\n")

    # Start persistent backend TCP services on protected targets
    start_backend_services()

    # Start command listener
    info(f"*** Starting command listener on port {COMMAND_PORT}\n")
    listener_thread = threading.Thread(target=command_listener, daemon=True)
    listener_thread.start()
    
    # Background traffic ready on command
    info("*** Command listener ready on port 9999 (background services idle)\n")
    
    info("✅ Phase 5 complete: Finetuning services started\n")

# ============================================================================
# Main Execution
# ============================================================================

def main():
    global net
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    info("\n" + "="*60 + "\n")
    info("*** MTD FINE-TUNING TOPOLOGY SETUP (Large Network)\n")
    info("="*60 + "\n")
    
    # Parse command line arguments
    run_tests = '--test' in sys.argv
    use_cli = '--cli' in sys.argv
    skip_finetuning = '--no-finetune' in sys.argv
    
    try:
        # Phase 1: Basic topology
        create_basic_topology()
        
        # Phase 2: DNS configuration
        configure_dns()
        
        # Phase 3: Host registration via DNS (gradual)
        register_hosts_via_dns()
        
        # Phase 4: Testing (optional)
        if run_tests:
            all_passed = run_all_tests()
            if not all_passed and not use_cli:
                info("⚠️  Tests failed. Use --cli to enter CLI for manual debugging.\n")
                return
        
        # Drop into CLI if requested
        if use_cli:
            info("\n" + "="*60 + "\n")
            info("*** DROPPING INTO CONTAINERNET CLI\n")
            info("Type 'exit' to continue or quit.\n")
            info("="*60 + "\n")
            CLI(net)
            info("*** Exiting CLI\n")
        
        # Phase 5: Finetuning services (unless skipped)
        if not skip_finetuning and not use_cli:
            start_finetuning_services()
        
        # Print summary
        info("\n" + "="*60 + "\n")
        info("✅ TOPOLOGY READY\n")
        info("="*60 + "\n")
        info(f"   Protected Hosts: h1-h{NUM_HOSTS} (10.0.0.1 to 10.0.0.{NUM_HOSTS})\n")
        info(f"   DNS Server: dns ({DNS_IP})\n")
        info("   DNS Records:\n")
        for i in range(1, NUM_HOSTS + 1):
            info(f"     host{i}.com -> 10.0.0.{i}\n")
        if not skip_finetuning and not use_cli:
            info(f"   Command interface: 127.0.0.1:{COMMAND_PORT}\n")
            info("   Background traffic: iperf3 (h1 -> host2.com)\n")
        info("="*60 + "\n")
        
        # Keep running (unless in CLI mode)
        if not use_cli:
            while running:
                time.sleep(1)
            
    except KeyboardInterrupt:
        info("\n*** Shutting down\n")
    finally:
        if net:
            try:
                net.stop()
            except Exception:
                pass

if __name__ == '__main__':
    setLogLevel('info')
    main()