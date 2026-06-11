#!/usr/bin/env python3
import time
import re
from mininet.net import Containernet
from mininet.node import Controller, RemoteController, Host
from mininet.cli import CLI
from mininet.log import setLogLevel, info

def mtd_experiment():
    info("*** Creating Containernet with native Mininet hosts\n")
    
    # 1. Start network, connecting to your running Ryu controller
    net = Containernet(controller=RemoteController)
    
    info("*** Adding Hosts (Native Mininet namespaces)\n")
    # Using default cls=Host. This creates lightweight Linux network namespaces.
    # They share the Ubuntu filesystem, so iperf3 and scapy are automatically available!
    h1 = net.addHost('h1', ip='10.0.0.1/24') 
    h2 = net.addHost('h2', ip='10.0.0.2/24')
    dns = net.addHost('dns', ip='10.0.0.10/24')

    info("*** Adding Open vSwitches\n")
    s1 = net.addSwitch('s1') 
    s2 = net.addSwitch('s2') 
    s3 = net.addSwitch('s3') 

    info("*** Creating Links\n")
    net.addLink(h1, s1)
    net.addLink(s1, s2)
    net.addLink(s2, s3)
    net.addLink(h2, s3)
    net.addLink(dns, s3)

    info("*** Starting Network\n")
    c0 = net.addController('c0', controller=RemoteController, ip='127.0.0.1', port=6653)
    net.start()

    info("*** Disabling IPv6 and Reverse Path Filtering (Crucial for clean logs)\n")
    # This stops the 0x86dd IPv6 spam in your Ryu logs and prevents Linux from dropping packets
    for host in [h1, h2, dns]:
        host.cmd('sysctl -w net.ipv6.conf.all.disable_ipv6=1 > /dev/null')
        host.cmd('sysctl -w net.ipv6.conf.default.disable_ipv6=1 > /dev/null')
        host.cmd('sysctl -w net.ipv4.conf.all.rp_filter=0 > /dev/null')
        host.cmd('sysctl -w net.ipv4.conf.default.rp_filter=0 > /dev/null')

    info("*** Starting Dummy DNS Server on 'dns' host\n")
    # Uses your existing dnslib package to answer host1.com and host2.com
    venv_python = "/home/ubuntu/Project/MTD/venv/bin/python3"
    dns_server_script = """
from dnslib import DNSRecord, RR, A, QTYPE
from dnslib.server import DNSServer, BaseResolver
class SimpleResolver(BaseResolver):
    def resolve(self, request, handler):
        reply = request.reply()
        qname = str(request.q.qname).rstrip('.')
        if 'host1' in qname:
            reply.add_answer(RR(qname, QTYPE.A, rdata=A('10.0.0.1'), ttl=60))
        elif 'host2' in qname:
            reply.add_answer(RR(qname, QTYPE.A, rdata=A('10.0.0.2'), ttl=60))
        return reply
DNSServer(SimpleResolver(), port=53, address='0.0.0.0').start_thread()
import time; time.sleep(9999)
"""
    dns.cmd(f'{venv_python} -c "{dns_server_script}" > /dev/null 2>&1 &')
    time.sleep(2) # Wait for DNS to start

    info("*** Testing basic connectivity (Ping h1 -> h2)...\n")
    net.ping([h1, h2])

    info("*** Configuring DNS on h1 and h2\n")
    h1.cmd('echo "nameserver 10.0.0.10" > /etc/resolv.conf')
    h2.cmd('echo "nameserver 10.0.0.10" > /etc/resolv.conf')

    info("*** Waiting for Ryu to discover topology (5 seconds)...\n")
    time.sleep(5)

    info("*** Starting Legitimate Background Traffic (iperf3)\n")
    h2.cmd('iperf3 -s -D')
    time.sleep(1)
    
    h1.cmd('iperf3 -c 10.0.0.2 -t 60 -i 5 > /tmp/iperf_results.txt &')

    info("*** Waiting 10 seconds before launching attack...\n")
    time.sleep(10)

    info("*** 🚨 LAUNCHING L3/L4 SYN SCAN ATTACK 🚨\n")
    attack_script = """
from scapy.all import *
print("Starting SYN sweep...")
send(IP(dst="10.0.0.1-30")/TCP(dport=[22, 80, 443, 8080], flags="S"), verbose=False, inter=0.01)
print("Attack complete.")
"""
    # Use the venv Python to ensure scapy is found
    h1.cmd(f'{venv_python} -c "{attack_script}"')

    info("*** Waiting for iperf3 to finish...\n")
    time.sleep(50) # Wait for the remaining time of the 60s iperf test

    info("*** Extracting Results...\n")
    iperf_out = h1.cmd('cat /tmp/iperf_results.txt')
    
    print("--- iperf3 Raw Output ---")
    print(iperf_out)
    print("-------------------------")
    
    match = re.search(r'(\d+\.?\d*)\s+Mbits/sec\s+sender', iperf_out)
    if match:
        info(f"✅ Average Throughput: {match.group(1)} Mbps\n")
    else:
        info("⚠️ Could not parse iperf throughput. Check raw output above.\n")

    info("*** Stopping Network\n")
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    mtd_experiment()