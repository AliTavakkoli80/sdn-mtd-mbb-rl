#!/usr/bin/env python3
"""
Master's Thesis Evaluation Testbed (Containernet)
Phase 1: Functional Validation of MTD DNS Interception & Transparent Routing
"""
import docker
import os
import time
import tempfile
from mininet.net import Containernet
from mininet.node import RemoteController, OVSSwitch
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import info, setLogLevel

def ensure_docker_image(image_name):
    client = docker.from_env()
    try:
        client.images.get(image_name)
        info(f'✅ Image {image_name} is already cached locally.\n')
    except docker.errors.ImageNotFound:
        info(f'⏳ Image {image_name} not found. Pulling from Docker Hub...\n')
        client.images.pull(image_name)
        info(f'✅ Successfully pulled {image_name}\n')

def ensure_dns_image():
    client = docker.from_env()
    try:
        client.images.get('mtd-dns:latest')
        info('✅ Custom DNS image (mtd-dns:latest) is cached.\n')
    except docker.errors.ImageNotFound:
        info('⏳ Building custom DNS image (Alpine + dnsmasq + bash)...\n')
        with tempfile.TemporaryDirectory() as tmpdir:
            dockerfile_path = os.path.join(tmpdir, 'Dockerfile')
            with open(dockerfile_path, 'w') as f:
                f.write("FROM alpine:latest\n")
                f.write("RUN apk add --no-cache dnsmasq bash\n")
                f.write("ENTRYPOINT [\"dnsmasq\"]\n")
            client.images.build(path=tmpdir, tag='mtd-dns:latest', rm=True)
        info('✅ Successfully built mtd-dns:latest\n')

def run_evaluation():
    info('*** Ensuring required Docker images are available...\n')
    ensure_docker_image('nicolaka/netshoot')
    ensure_dns_image()

    net = Containernet(controller=RemoteController, link=TCLink)

    try:
        info('*** Adding Ryu SDN Controller (Ensure Ryu is running on host!)\n')
        c0 = net.addController('c0', controller=RemoteController, ip='127.0.0.1', port=6653)

        info('*** Adding OpenFlow 1.3 Switches\n')
        s1 = net.addSwitch('s1', cls=OVSSwitch, protocols='OpenFlow13')
        s2 = net.addSwitch('s2', cls=OVSSwitch, protocols='OpenFlow13')
        net.addLink(s1, s2, cls=TCLink, delay='5ms', bw=100)

        info('*** Adding Docker Hosts (Netshoot)\n')
        pc1 = net.addDocker('pc1', ip='10.0.0.1/8', mac='00:50:79:66:68:00', dimage='nicolaka/netshoot', cmd=['sleep', 'infinity'])
        net.addLink(pc1, s1)
        
        pc2 = net.addDocker('pc2', ip='10.0.0.2/8', mac='00:50:79:66:68:01', dimage='nicolaka/netshoot', cmd=['sleep', 'infinity'])
        net.addLink(pc2, s2)
        
        info('*** Adding DNS Server (Custom mtd-dns Image)\n')
        # We use sleep infinity so Containernet can configure the IP, then start dnsmasq manually
        dns = net.addDocker('dns', ip='10.0.0.10/8', dimage='mtd-dns:latest', cmd=['sleep', 'infinity'])
        net.addLink(dns, s1)

        info('*** Starting Network\n')
        net.start()

        info('*** Configuring Hosts (Fixing Docker Bridge Overrides)\n')
        # Flush Docker's default 172.17.x.x IPs and force the MTD IPs/MACs
        for host, ip, mac in [(pc1, '10.0.0.1/8', '00:50:79:66:68:00'), (pc2, '10.0.0.2/8', '00:50:79:66:68:01')]:
            host.cmd('ip addr flush dev eth0')
            host.cmd(f'ip addr add {ip} dev eth0')
            host.cmd(f'ip link set dev eth0 address {mac}')
            host.cmd('ip link set eth0 up')
            host.cmd('sysctl -w net.ipv6.conf.all.disable_ipv6=1 > /dev/null 2>&1')
            host.cmd('sysctl -w net.ipv6.conf.default.disable_ipv6=1 > /dev/null 2>&1')
            host.cmd('sysctl -w net.ipv6.conf.eth0.disable_ipv6=1 > /dev/null 2>&1')
            host.cmd('echo "nameserver 10.0.0.10" > /etc/resolv.conf')
            host.cmd('echo "options single-request" >> /etc/resolv.conf')

        # Fix DNS IP and start dnsmasq manually (Containernet overrides ENTRYPOINT with bash)
        dns.cmd('ip addr flush dev eth0')
        dns.cmd('ip addr add 10.0.0.10/8 dev eth0')
        dns.cmd('ip link set eth0 up')
        info('*** Starting dnsmasq daemon inside DNS container...\n')
        dns.cmd('dnsmasq --log-queries --interface=eth0 --no-resolv --local=/com/ --address=/host1.com/10.0.0.1 --address=/host2.com/10.0.0.2')

        time.sleep(2)

        # info('\n' + '='*70 + '\n')
        # info('*** PHASE 1: FUNCTIONAL VALIDATION (DNS & Transparent Routing)\n')
        # info('='*70 + '\n')
        
        # info('\n--- Step 1: Querying DNS for host2.com ---\n')
        # info('Expected: The Ryu controller intercepts this and returns a Virtual IP (e.g., 10.0.100.XX)\n')
        # dns_result = pc1.cmd('nslookup host2.com 10.0.0.10')
        # info(dns_result)

        # info('\n--- Step 2: Pinging host2.com ---\n')
        # info('Expected: Ping succeeds. Ryu translates Virtual IP -> Real IP (10.0.0.2)\n')
        # ping_result = pc1.cmd('ping -c 3 host2.com')
        # info(ping_result)

        # info('\n--- Step 3: Verifying Transparent Translation via tcpdump ---\n')
        # info('Expected: PC2 sees ICMP packets from the REAL IP (10.0.0.1), proving MTD is invisible to the host.\n')
        # pc2.cmd('tcpdump -i eth0 -n icmp -c 3 -w /tmp/pc2_capture.pcap &')
        # time.sleep(1)
        # pc1.cmd('ping -c 3 host2.com > /dev/null 2>&1')
        # time.sleep(2)
        # capture_result = pc2.cmd('tcpdump -r /tmp/pc2_capture.pcap -n')
        # info(capture_result)

        # info('\n' + '='*70 + '\n')
        # info('✅ Phase 1 Complete! Dropping to Containernet CLI.\n')
        # info('Type "exit" to cleanly tear down the network.\n')
        # info('='*70 + '\n')
        
        CLI(net)

    except Exception as e:
        info(f"❌ Error during evaluation: {e}\n")
        import traceback
        traceback.print_exc()
    finally:
        info('\n*** Stopping Network and Cleaning up Docker/OVS resources\n')
        net.stop()

if __name__ == '__main__':
    if os.geteuid() != 0:
        exit("⚠️ You need to run this script with sudo: sudo python3 eval_topology.py")
        
    setLogLevel('info')
    run_evaluation()