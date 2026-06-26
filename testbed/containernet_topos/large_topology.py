#!/usr/bin/env python3
###############################################################################
# MTD mappings (real IP -> initial virtual IP)
# All 10 hosts are protected by MTD
# REAL_TO_VIRTUAL = {
#     '10.0.0.1': '10.0.100.1',   # h1
#     '10.0.0.2': '10.0.100.2',   # h2
#     '10.0.0.3': '10.0.100.3',   # h3
#     '10.0.0.4': '10.0.100.4',   # h4
#     '10.0.0.5': '10.0.100.5',   # h5
#     '10.0.0.6': '10.0.100.6',   # h6
#     '10.0.0.7': '10.0.100.7',   # h7
#     '10.0.0.8': '10.0.100.8',   # h8
#     '10.0.0.9': '10.0.100.9',   # h9
#     '10.0.0.10': '10.0.100.10', # h10
# }

# # DNS Server IP (NOT protected by MTD)
# DNS_SERVER_IP = '10.0.0.254'

# # Hosts that should NOT be shuffled (infrastructure)
# EXCLUDED_HOSTS = [DNS_SERVER_IP]

# # Topology discovery interval (seconds)
# TOPOLOGY_DISCOVERY_INTERVAL = 15
# TOPOLOGY_FULL_SCAN_CYCLES = 2   # every 2 intervals do a full scan
###############################################################################

from mininet.net import Containernet
from mininet.node import RemoteController, OVSSwitch
from mininet.cli import CLI
from mininet.log import info, setLogLevel

def create_topology():
    setLogLevel('info')

    info('*** Initializing Containernet\n')
    net = Containernet()

    info('*** Adding the remote controller\n')
    c0 = net.addController('c0', controller=RemoteController, ip='127.0.0.1', port=6653)

    info('*** Adding Docker containers (10 Hosts + 1 DNS)\n')
    # Protected hosts (h1-h10)
    h1 = net.addDocker('h1', ip='10.0.0.1/24', dimage="alpine-mn")
    h2 = net.addDocker('h2', ip='10.0.0.2/24', dimage="alpine-mn")
    h3 = net.addDocker('h3', ip='10.0.0.3/24', dimage="alpine-mn")
    h4 = net.addDocker('h4', ip='10.0.0.4/24', dimage="alpine-mn")
    h5 = net.addDocker('h5', ip='10.0.0.5/24', dimage="alpine-mn")
    h6 = net.addDocker('h6', ip='10.0.0.6/24', dimage="alpine-mn")
    h7 = net.addDocker('h7', ip='10.0.0.7/24', dimage="alpine-mn")
    h8 = net.addDocker('h8', ip='10.0.0.8/24', dimage="alpine-mn")
    h9 = net.addDocker('h9', ip='10.0.0.9/24', dimage="alpine-mn")
    h10 = net.addDocker('h10', ip='10.0.0.10/24', dimage="alpine-mn")
    
    # DNS Server
    dns = net.addDocker('dns', ip='10.0.0.254/24', dimage="alpine-mn")

    info('*** Adding OVS switches with OpenFlow 1.3 support\n')
    s1 = net.addSwitch('s1', cls=OVSSwitch, protocols='OpenFlow13')
    s2 = net.addSwitch('s2', cls=OVSSwitch, protocols='OpenFlow13')
    s3 = net.addSwitch('s3', cls=OVSSwitch, protocols='OpenFlow13')
    s4 = net.addSwitch('s4', cls=OVSSwitch, protocols='OpenFlow13')

    info('*** Creating links\n')
    # Core links (switch-to-switch)
    net.addLink(s1, s2)
    net.addLink(s2, s3)
    net.addLink(s3, s4)
    net.addLink(s1, s4)  # Redundant link for mesh topology
    
    # Host connections (distributed across switches)
    net.addLink(h1, s1)
    net.addLink(h2, s1)
    net.addLink(h3, s2)
    net.addLink(h4, s2)
    net.addLink(h5, s3)
    net.addLink(h6, s3)
    net.addLink(h7, s4)
    net.addLink(h8, s4)
    net.addLink(h9, s1)
    net.addLink(h10, s3)
    
    # DNS connection
    net.addLink(dns, s2)

    info('*** Starting network\n')
    net.start()

    info('*** Configuring DNS server and Host resolutions\n')
    # Add DNS records for all hosts
    dns.cmd('echo "10.0.0.1 host1.com" > /etc/hosts')
    dns.cmd('echo "10.0.0.2 host2.com" >> /etc/hosts')
    dns.cmd('echo "10.0.0.3 host3.com" >> /etc/hosts')
    dns.cmd('echo "10.0.0.4 host4.com" >> /etc/hosts')
    dns.cmd('echo "10.0.0.5 host5.com" >> /etc/hosts')
    dns.cmd('echo "10.0.0.6 host6.com" >> /etc/hosts')
    dns.cmd('echo "10.0.0.7 host7.com" >> /etc/hosts')
    dns.cmd('echo "10.0.0.8 host8.com" >> /etc/hosts')
    dns.cmd('echo "10.0.0.9 host9.com" >> /etc/hosts')
    dns.cmd('echo "10.0.0.10 host10.com" >> /etc/hosts')
    dns.cmd('echo "10.0.0.254 dns" >> /etc/hosts')
    dns.cmd('dnsmasq')

    # Configure all hosts to use DNS server
    for i in range(1, 11):
        host = net.get(f'h{i}')
        host.cmd('echo "nameserver 10.0.0.254" > /etc/resolv.conf')

    info('*** Disabling IPv6 on all hosts\n')
    for host in net.hosts:
        host.cmd('sysctl -w net.ipv6.conf.all.disable_ipv6=1 > /dev/null 2>&1')
        host.cmd('sysctl -w net.ipv6.conf.default.disable_ipv6=1 > /dev/null 2>&1')

    info('*** Dropping into Mininet CLI\n')
    info('*** Test commands:\n')
    info('    h1 ping host2.com\n')
    info('    h5 ping host10.com\n')
    info('    h1 nslookup host3.com 10.0.0.254\n')
    CLI(net)

    info('*** Stopping network\n')
    net.stop()

if __name__ == '__main__':
    create_topology()