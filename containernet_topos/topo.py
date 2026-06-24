#!/usr/bin/env python3

from mininet.net import Containernet
from mininet.node import RemoteController, OVSSwitch
from mininet.cli import CLI
from mininet.log import info, setLogLevel

def create_topology():
    setLogLevel('info')

    info('*** Initializing Containernet\n')
    # We remove the default controller argument here
    net = Containernet()

    info('*** Adding the remote controller\n')
    # UPDATE THE IP ADDRESS BELOW TO MATCH YOUR CONTROLLER'S IP
    # Common OpenFlow ports are 6633 or 6653. 
    # If the controller is running on the same host machine as this script, keep it '127.0.0.1'
    c0 = net.addController('c0', controller=RemoteController, ip='127.0.0.1', port=6653)

    info('*** Adding Docker containers (Hosts and DNS)\n')
    # Use the new image that contains bash
    h1 = net.addDocker('h1', ip='10.0.0.1/24', dimage="alpine-mn")
    h2 = net.addDocker('h2', ip='10.0.0.2/24', dimage="alpine-mn")
    
    # Use the exact same image for DNS, as it also has dnsmasq installed
    dns = net.addDocker('dns', ip='10.0.0.10/24', dimage="alpine-mn")

    info('*** Adding OVS switches with OpenFlow 1.3 support\n')
    s1 = net.addSwitch('s1', cls=OVSSwitch, protocols='OpenFlow13')
    s2 = net.addSwitch('s2', cls=OVSSwitch, protocols='OpenFlow13')
    s3 = net.addSwitch('s3', cls=OVSSwitch, protocols='OpenFlow13')

    info('*** Creating links\n')
    net.addLink(s1, s2)
    net.addLink(s2, s3)
    net.addLink(h1, s1)
    net.addLink(h2, s3)
    net.addLink(dns, s1)

    info('*** Starting network\n')
    # When net.start() runs, the switches will actively attempt to connect to the remote controller
    net.start()

    info('*** Configuring DNS server and Host resolutions\n')
    dns.cmd('echo "10.0.0.1 host1.com" > /etc/hosts')
    dns.cmd('echo "10.0.0.2 host2.com" >> /etc/hosts')
    dns.cmd('echo "10.0.0.10 dns" >> /etc/hosts')
    dns.cmd('dnsmasq')

    h1.cmd('echo "nameserver 10.0.0.10" > /etc/resolv.conf')
    h2.cmd('echo "nameserver 10.0.0.10" > /etc/resolv.conf')

    info('*** Dropping into Mininet CLI\n')
    CLI(net)

    info('*** Stopping network\n')
    net.stop()

if __name__ == '__main__':
    create_topology()