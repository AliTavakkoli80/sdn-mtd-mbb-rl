#!/usr/bin/env python3
"""
Simple Containernet Topology for MTD IP Shuffling Testing
         
         Controller (Ryu)
              |
        +-----+-----+
        |           |
       S1 --------- S2
       / \         / \
      /   \       /   \
    h1     h2   h3     h4
    
h1, h2: Protected hosts (10.0.0.1, 10.0.0.2)
h3: DNS Server (10.0.0.10)
h4: Client/Attacker simulator
"""

from mininet.net import Containernet
from containernet.node import DockerSta
from mininet.node import Controller, OVSKernelSwitch
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel, info
import time
import subprocess
import sys
import os

def setup_mtd_topology():
    """Create the emulation network."""
    net = Containernet(
        controller=Controller,
        switch=OVSKernelSwitch,
        link=TCLink,
        autoSetMacs=True,
        autoStaticArp=False  # We'll manage ARP manually
    )
    
    info("*** Adding Controller\n")
    c0 = net.addController(
        'c0',
        controller=Controller,
        ip='127.0.0.1',
        port=6633
    )
    
    info("*** Adding Switches\n")
    s1 = net.addSwitch('s1', cls=OVSKernelSwitch, protocols='OpenFlow13')
    s2 = net.addSwitch('s2', cls=OVSKernelSwitch, protocols='OpenFlow13')
    
    info("*** Adding Hosts (Docker Containers)\n")
    # Protected hosts
    h1 = net.addDockerSta(
        'h1',
        ip='10.0.0.1/24',
        dimage='mtd-host:latest',
        dcmd='/bin/bash'
    )
    h2 = net.addDockerSta(
        'h2',
        ip='10.0.0.2/24',
        dimage='mtd-host:latest',
        dcmd='/bin/bash'
    )
    
    # DNS Server
    h3 = net.addDockerSta(
        'h3',
        ip='10.0.0.10/24',
        dimage='mtd-host:latest',
        dcmd='/bin/bash'
    )
    
    # Client/Attacker simulator
    h4 = net.addDockerSta(
        'h4',
        ip='10.0.0.100/24',
        dimage='mtd-host:latest',
        dcmd='/bin/bash'
    )
    
    info("*** Adding Links (S1-S2 core, hosts to edge)\n")
    # Access links (hosts to switches)
    net.addLink(h1, s1, bw=100, delay='1ms')
    net.addLink(h2, s1, bw=100, delay='1ms')
    net.addLink(h3, s1, bw=100, delay='1ms')
    net.addLink(h4, s2, bw=100, delay='1ms')
    
    # Core link (switch to switch)
    net.addLink(s1, s2, bw=1000, delay='0.5ms')
    
    info("*** Starting Network\n")
    net.start()
    
    info("*** Configuring OpenFlow\n")
    for s in [s1, s2]:
        s.cmd(f'ovs-vsctl set-controller {s} tcp:127.0.0.1:6633')
        s.cmd('ovs-vsctl set bridge {} fail_mode=secure'.format(s))
    
    return net

def main():
    setLogLevel('info')
    net = setup_mtd_topology()
    
    info("\n*** Network is running!\n")
    info("*** Run your Ryu controller in another terminal:\n")
    info("    cd mtd_controller && ryu-manager app.py\n\n")
    
    CLI(net)
    
    info("*** Stopping network\n")
    net.stop()

if __name__ == '__main__':
    main()