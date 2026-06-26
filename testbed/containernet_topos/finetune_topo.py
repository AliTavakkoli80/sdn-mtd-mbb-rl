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
import time
import socket
import threading
import json
import signal
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
NUM_HOSTS = 10
DNS_IP = '10.0.0.254'
COMMAND_PORT = 9999

def signal_handler(signum, frame):
    global running
    info("\n*** Received shutdown signal\n")
    running = False
    if net:
        net.stop()
    sys.exit(0)

# ============================================================================
# PHASE 1: Basic Topology Creation
# ============================================================================

def create_basic_topology():
    """Create the basic network topology with retry logic."""
    global net
    
    info("*** PHASE 1: Creating basic topology\n")
    
    net = Containernet()
    
    # Controller
    info("*** Adding Controller\n")
    c0 = net.addController('c0', controller=RemoteController, ip='127.0.0.1', port=6653)
    
    # Switches
    info("*** Adding 4 OVS Switches (OpenFlow 1.3)\n")
    s1 = net.addSwitch('s1', cls=OVSSwitch, protocols='OpenFlow13')
    s2 = net.addSwitch('s2', cls=OVSSwitch, protocols='OpenFlow13')
    s3 = net.addSwitch('s3', cls=OVSSwitch, protocols='OpenFlow13')
    s4 = net.addSwitch('s4', cls=OVSSwitch, protocols='OpenFlow13')
    
    # Protected hosts (h1-h10)
    info(f"*** Adding {NUM_HOSTS} Docker Hosts\n")
    hosts = []
    for i in range(1, NUM_HOSTS + 1):
        host_name = f'h{i}'
        ip = f'10.0.0.{i}/24'
        host = net.addDocker(host_name, ip=ip, dimage='alpine-mn')
        hosts.append(host)
        info(f"    Added {host_name} ({ip})\n")
    
    # DNS server
    info("*** Adding DNS Server\n")
    dns = net.addDocker('dns', ip=f'{DNS_IP}/24', dimage='alpine-mn')
    
    # Create links
    info("*** Creating links (mesh topology)\n")
    # Core links
    net.addLink(s1, s2)
    net.addLink(s2, s3)
    net.addLink(s3, s4)
    net.addLink(s1, s4)
    
    # Host connections (distributed across switches)
    net.addLink(hosts[0], s1)   # h1 -> s1
    net.addLink(hosts[1], s1)   # h2 -> s1
    net.addLink(hosts[2], s2)   # h3 -> s2
    net.addLink(hosts[3], s2)   # h4 -> s2
    net.addLink(hosts[4], s3)   # h5 -> s3
    net.addLink(hosts[5], s3)   # h6 -> s3
    net.addLink(hosts[6], s4)   # h7 -> s4
    net.addLink(hosts[7], s4)   # h8 -> s4
    net.addLink(hosts[8], s1)   # h9 -> s1
    net.addLink(hosts[9], s3)   # h10 -> s3
    
    # DNS connection
    net.addLink(dns, s2)
    
    # Start network
    info("*** Starting Network\n")
    net.start()
    
    # Wait for switches to connect to controller
    info("*** Waiting for switches to connect to controller...\n")
    time.sleep(5)
    
    info("✅ Phase 1 complete: Basic topology created\n")
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
    
    # GENTLE APPROACH: Just have each host ping the DNS server once.
    # This generates exactly 10 Packet-In messages total, keeping Ryu happy.
    info("*** Registering hosts one by one...\n")
    for i in range(1, NUM_HOSTS + 1):
        host = net.get(f'h{i}')
        # Ping the DNS server to establish L2/L3 paths
        host.cmd(f'ping -c 1 -W 2 {DNS_IP} > /dev/null 2>&1')
        info(f"    Registered h{i}\n")
        
        # CRITICAL: Sleep to let Ryu process the Packet-In before the next one
        time.sleep(1.5) 
    
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
    """Test DNS resolution with retry logic."""
    info("\n" + "="*60 + "\n")
    info("*** PHASE 4: Testing DNS resolution (with retries)\n")
    info("="*60 + "\n")
    
    h1 = net.get('h1')
    h5 = net.get('h5')
    h10 = net.get('h10')
    
    tests = [
        (h1, 'host2.com'),
        (h1, 'host5.com'),
        (h5, 'host1.com'),
        (h5, 'host10.com'),
        (h10, 'host3.com'),
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
            conn.settimeout(2.0)
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
            # Scan using domain names (DNS will resolve to IPs)
            h1.cmd('nohup bash -c "for i in $(seq 1 10); do arping -c 1 -w 1 host$i.com > /dev/null 2>&1; done" &')
            return {'status': 'ok', 'message': 'ARP scan attack launched (background)'}
        
        elif action == 'attack_syn':
            h1 = net.get('h1')
            h1.cmd('nohup bash -c "for i in $(seq 1 10); do timeout 2 bash -c \'echo > /dev/tcp/host$i.com/22\' 2>/dev/null; done" &')
            return {'status': 'ok', 'message': 'SYN scan attack launched (background)'}
        
        elif action == 'attack_dns':
            h1 = net.get('h1')
            h1.cmd(f'nohup bash -c "for i in $(seq 1 50); do nslookup host1.com {DNS_IP} > /dev/null 2>&1; done" &')
            return {'status': 'ok', 'message': 'DNS flood attack launched (background)'}
        
        elif action == 'start_iperf':
            h2 = net.get('h2')
            h1 = net.get('h1')
            h2.cmd('pkill -f iperf3 > /dev/null 2>&1')
            h1.cmd('pkill -f iperf3 > /dev/null 2>&1')
            time.sleep(0.5)
            
            h2.cmd('iperf3 -s -D > /dev/null 2>&1')
            time.sleep(0.5)
            # Use domain name for iperf
            h1.cmd('nohup iperf3 -c host2.com -t 300 -i 5 > /tmp/iperf.log 2>&1 &')
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

def start_finetuning_services():
    """Start command listener and background traffic for finetuning."""
    info("\n" + "="*60 + "\n")
    info("*** PHASE 5: Starting finetuning services\n")
    info("="*60 + "\n")
    
    # Start command listener
    info(f"*** Starting command listener on port {COMMAND_PORT}\n")
    listener_thread = threading.Thread(target=command_listener, daemon=True)
    listener_thread.start()
    
    # Start background traffic
    info("*** Starting background iperf3 traffic (using DNS)...\n")
    handle_command({'action': 'start_iperf'})
    time.sleep(2)
    
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
            net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    main()