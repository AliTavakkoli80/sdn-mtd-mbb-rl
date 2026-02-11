# mtd_ip_shuffling.py
"""
Ryu application for Moving Target Defense (MTD) with IP shuffling in SDN.
Fully integrated with topology awareness for accurate host/switch port detection.
Implements virtual IP mapping, DNS response modification (real IP -> virtual IP),
intelligent ARP handling with network-wide flooding ONLY for host discovery,
and transparent IPv4 packet translation ONLY at edge switches.
"""

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, arp, ipv4, udp, tcp, icmp
from ryu.lib.packet import ether_types
from ryu.topology import event
from ryu.topology.api import get_switch, get_link
from ryu.lib import hub
import logging
import struct
import socket
from dnslib import DNSRecord, QTYPE, A

# Configure detailed logging with custom format
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s | %(levelname)-8s | %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
LOG = logging.getLogger('ryu.app.mtd_ip_shuffling')


class MTDMovingTargetDefense(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    # Topology discovery events to listen for
    events = [
        event.EventSwitchEnter,
        event.EventSwitchLeave,
        event.EventPortAdd,
        event.EventPortDelete,
        event.EventPortModify,
        event.EventLinkAdd,
        event.EventLinkDelete
    ]

    def __init__(self, *args, **kwargs):
        super(MTDMovingTargetDefense, self).__init__(*args, **kwargs)

        self.dns_ip = '10.0.0.10'
        
        # ===== MTD-Specific Mappings =====
        self.real_to_virtual = {
            '10.0.0.1': '10.0.0.11',
            '10.0.0.2': '10.0.0.12'
        }
        self.virtual_to_real = {v: k for k, v in self.real_to_virtual.items()}
        
        # ===== Topology Awareness Structures =====
        self.link_to_port = {}      # {(src_dpid,dst_dpid):(src_port,dst_port),}
        self.access_table = {}      # {(sw, port):(ip, mac),}
        self.switch_port_table = {} # {dpid:set(port_num,),}
        self.access_ports = {}      # {dpid:set(port_num,),} - Ports to hosts ONLY
        self.interior_ports = {}    # {dpid:set(port_num,),} - Ports to switches ONLY
        self.switches = []          # [dpid,]
        self.host_table = {}        # {real_ip: {'mac': mac, 'dpid': dpid, 'port': port}}
        self.mac_to_port = {}       # For fallback L2 switching: {dpid: {mac: port}}
        self.datapath_list = {}     # {dpid: datapath}
        
        # Flow priority levels
        self.FLOW_PRIORITY_ARP = 100
        self.FLOW_PRIORITY_TRANSLATION = 50
        self.FLOW_PRIORITY_NORMAL = 10
        
        # Start topology discovery thread
        self.discover_thread = hub.spawn(self._discover_topo)
        
        LOG.info("="*80)
        LOG.info("🚀 MTD IP SHUFFLING CONTROLLER STARTED")
        LOG.info("="*80)
        LOG.info("🛡️  REAL IP → VIRTUAL IP MAPPING:")
        for real, virt in sorted(self.real_to_virtual.items()):
            LOG.info(f"   • {real:15s} ⇄ {virt:15s} (Protected)")
        LOG.info("="*80)

    # ===== TOPOLOGY DISCOVERY WITH ACCURATE PORT CLASSIFICATION =====
    
    def _discover_topo(self):
        """Periodic topology discovery with comprehensive logging"""
        LOG.info("🔍 Starting topology discovery thread (interval: 15s, full scan: 30s)")
        i = 0
        while True:
            if i == 2:
                LOG.info("\n" + "="*80)
                LOG.info("🔄 FULL TOPOLOGY DISCOVERY CYCLE")
                LOG.info("="*80)
                self.get_topology(None)
                self._log_topology_summary()
                i = 0
            hub.sleep(15)
            i += 1

    def _log_topology_summary(self):
        """Log comprehensive topology summary with visual structure"""
        LOG.info("\n" + "─"*80)
        LOG.info("🌐 NETWORK TOPOLOGY SUMMARY")
        LOG.info("─"*80)
        
        # Log switches
        LOG.info(f"\n📦 SWITCHES ({len(self.switches)} total):")
        for dpid in sorted(self.switches):
            LOG.info(f"   • Switch DPID: {dpid}")
            
            # Log access ports (to hosts)
            access = sorted(self.access_ports.get(dpid, set()))
            if access:
                LOG.info(f"     ├─ Access Ports (to hosts): {', '.join(map(str, access))}")
            else:
                LOG.info(f"     ├─ Access Ports (to hosts): (none)")
            
            # Log interior ports (to switches)
            interior = sorted(self.interior_ports.get(dpid, set()))
            if interior:
                LOG.info(f"     └─ Interior Ports (to switches): {', '.join(map(str, interior))}")
            else:
                LOG.info(f"     └─ Interior Ports (to switches): (none)")
        
        # Log inter-switch links
        LOG.info(f"\n🔗 INTER-SWITCH LINKS ({len(self.link_to_port)} total):")
        if self.link_to_port:
            for (src_dpid, dst_dpid), (src_port, dst_port) in sorted(self.link_to_port.items()):
                LOG.info(f"   • S{src_dpid}:p{src_port:2d} ⟷ S{dst_dpid}:p{dst_port:2d}")
        else:
            LOG.info("   (no inter-switch links detected)")
        
        # Log hosts with virtual IPs
        LOG.info(f"\n🖥️  PROTECTED HOSTS ({len(self.host_table)} total):")
        if self.host_table:
            for real_ip, info in sorted(self.host_table.items()):
                virt_ip = self.real_to_virtual.get(real_ip, 'N/A')
                mac = info['mac']
                dpid = info['dpid']
                port = info['port']
                LOG.info(f"   • REAL: {real_ip:15s} → VIRTUAL: {virt_ip:15s}")
                LOG.info(f"     Location: Switch S{dpid}, Port {port}, MAC: {mac}")
        else:
            LOG.info("   (no hosts discovered yet - wait for ARP/IPv4 traffic)")
        
        LOG.info("─"*80)

    @set_ev_cls(events)
    def get_topology(self, ev):
        """Get topology information and update port classifications"""
        LOG.info("\n[topology] Discovering network topology...")
        
        switch_list = get_switch(self, None)
        link_list = get_link(self, None)
        
        self.create_port_map(switch_list)
        self.switches = [sw.dp.id for sw in switch_list]
        self.create_interior_links(link_list)
        self.create_access_ports()
        
        LOG.info(f"[topology] ✓ Discovered {len(self.switches)} switches, {len(self.link_to_port)} inter-switch links")

    def create_port_map(self, switch_list):
        """Create switch_port_table from switch list"""
        for sw in switch_list:
            dpid = sw.dp.id
            self.switch_port_table.setdefault(dpid, set())
            self.interior_ports.setdefault(dpid, set())
            self.access_ports.setdefault(dpid, set())
            
            for port in sw.ports:
                if port.port_no in [ofproto_v1_3.OFPP_LOCAL, ofproto_v1_3.OFPP_CONTROLLER]:
                    continue
                self.switch_port_table[dpid].add(port.port_no)

    def create_interior_links(self, link_list):
        """Identify ports connected to other switches (interior ports)"""
        self.link_to_port.clear()
        
        for link in link_list:
            src = link.src
            dst = link.dst
            
            if src.port_no in [ofproto_v1_3.OFPP_LOCAL, ofproto_v1_3.OFPP_CONTROLLER] or \
               dst.port_no in [ofproto_v1_3.OFPP_LOCAL, ofproto_v1_3.OFPP_CONTROLLER]:
                continue
            
            self.link_to_port[(src.dpid, dst.dpid)] = (src.port_no, dst.port_no)
            
            if src.dpid in self.switches:
                self.interior_ports[src.dpid].add(src.port_no)
            if dst.dpid in self.switches:
                self.interior_ports[dst.dpid].add(dst.port_no)

    def create_access_ports(self):
        """Identify ports connected to hosts (access ports) = all ports - interior ports"""
        for sw in self.switch_port_table:
            all_ports = self.switch_port_table[sw]
            interior = self.interior_ports.get(sw, set())
            # Access ports = all non-reserved ports that are NOT interior ports
            self.access_ports[sw] = all_ports - interior - {ofproto_v1_3.OFPP_LOCAL, ofproto_v1_3.OFPP_CONTROLLER}

    def register_access_info(self, dpid, in_port, ip, mac):
        """Register host information when ARP/IPv4 packet is received"""
        # Only register if port is an access port (connected to host)
        if dpid in self.access_ports and in_port in self.access_ports[dpid]:
            virt_ip = self.real_to_virtual.get(ip, 'N/A')
            
            # Update MTD host table for translation
            if ip in self.real_to_virtual:
                self.host_table[ip] = {'mac': mac, 'dpid': dpid, 'port': in_port}
                LOG.info(f"\n[host] ✓ NEW HOST DISCOVERED: {ip} → VIRTUAL: {virt_ip}")
                LOG.info(f"      Location: Switch S{dpid}, Port {in_port}, MAC: {mac}")
            
            # Update topology access table
            prev = self.access_table.get((dpid, in_port))
            self.access_table[(dpid, in_port)] = (ip, mac)
            
            if prev != (ip, mac):
                if prev:
                    LOG.info(f"[host]   ⚠️  IP/MAC changed on S{dpid}:p{in_port}: {prev} → ({ip}, {mac})")
                else:
                    LOG.info(f"[host]   ➤ Registered in topology table: ({dpid}, {in_port}) → ({ip}, {mac})")

    # ===== PACKET HANDLING WITH CORRECT FLOODING LOGIC =====

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        LOG.info(f"\n[switch] ✓ Switch connected: DPID={datapath.id} | Table-miss flow installed")

    def add_flow(self, datapath, priority, match, actions, buffer_id=None, 
                 idle_timeout=0, hard_timeout=0, table_id=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        if buffer_id and buffer_id != ofproto.OFP_NO_BUFFER:
            mod = parser.OFPFlowMod(
                datapath=datapath, buffer_id=buffer_id, priority=priority,
                match=match, instructions=inst, table_id=table_id,
                idle_timeout=idle_timeout, hard_timeout=hard_timeout)
        else:
            mod = parser.OFPFlowMod(
                datapath=datapath, priority=priority, match=match,
                instructions=inst, table_id=table_id,
                idle_timeout=idle_timeout, hard_timeout=hard_timeout)
        datapath.send_msg(mod)
        LOG.debug(f"[flow] Installed on S{datapath.id}: priority={priority}, match={match}")

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        pkt_type = "UNKNOWN"
        if pkt.get_protocol(arp.arp):
            pkt_type = "ARP"
        elif pkt.get_protocol(ipv4.ipv4):
            pkt_type = "IPv4"
        elif pkt.get_protocol(udp.udp):
            pkt_type = "UDP"
        elif pkt.get_protocol(tcp.tcp):
            pkt_type = "TCP"
        elif pkt.get_protocol(icmp.icmp):
            pkt_type = "ICMP"

        LOG.info(f"\n{'='*80}")
        LOG.info(f"📥 PACKET_IN | Switch: S{datapath.id} | Port: {in_port} | Type: {pkt_type}")
        LOG.info(f"   Src MAC: {eth.src} → Dst MAC: {eth.dst} | EtherType: {hex(eth.ethertype)}")

        arp_pkt = pkt.get_protocol(arp.arp)
        if arp_pkt:
            self.register_access_info(datapath.id, in_port, arp_pkt.src_ip, arp_pkt.src_mac)
            self._handle_arp(datapath, in_port, pkt, eth, arp_pkt, msg.buffer_id)
            return

        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
        if ipv4_pkt:
            eth_pkt = pkt.get_protocol(ethernet.ethernet)
            if eth_pkt:
                self.register_access_info(datapath.id, in_port, ipv4_pkt.src, eth_pkt.src)
            self._handle_ipv4(datapath, in_port, pkt, eth, ipv4_pkt, msg.buffer_id, msg.data)
            return

        LOG.warning(f"[packet] ⚠️  Unknown packet type {hex(eth.ethertype)} - flooding locally")
        self._flood_packet_locally(datapath, in_port, msg.buffer_id, msg.data)
    
    def _handle_ipv4(self, datapath, in_port, pkt, eth, ipv4_pkt, buffer_id, raw_data):
        src_ip = ipv4_pkt.src
        dst_ip = ipv4_pkt.dst
        proto = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}.get(ipv4_pkt.proto, str(ipv4_pkt.proto))
        
        LOG.info(f"[ipv4] {src_ip} → {dst_ip} | Proto: {proto} | TTL: {ipv4_pkt.ttl}")

        # Handle DNS responses (UDP src_port=53)
        if ipv4_pkt.proto == 17:  # UDP
            udp_pkt = pkt.get_protocol(udp.udp)
            if udp_pkt and udp_pkt.src_port == 53:  # DNS response FROM server
                LOG.info(f"[dns]  📡 DNS RESPONSE: {src_ip}:{udp_pkt.src_port} → {dst_ip}:{udp_pkt.dst_port}")
                self._handle_dns_response(datapath, in_port, pkt, eth, ipv4_pkt, udp_pkt, buffer_id, raw_data)
                return
        
        # Check if destination is a virtual IP we manage
        if dst_ip in self.virtual_to_real:
            real_dst_ip = self.virtual_to_real[dst_ip]
            LOG.info(f"[mtd]  🔒 VIRTUAL IP DETECTED: {dst_ip} → translating to REAL IP {real_dst_ip}")
            LOG.info(f"[mtd]  ➤ Installing bidirectional translation flows...")
            self._install_translation_flows(datapath, in_port, eth, ipv4_pkt, src_ip, dst_ip, real_dst_ip)
            self._translate_and_forward_packet(datapath, in_port, pkt, eth, ipv4_pkt, src_ip, dst_ip, real_dst_ip, buffer_id)
        else:
            LOG.info(f"[ipv4] ➤ Normal IPv4 packet to {dst_ip} - L2 forwarding")
            self._handle_normal_ipv4(datapath, in_port, eth, ipv4_pkt, buffer_id, raw_data)

    def _handle_arp(self, datapath, in_port, pkt, eth, arp_pkt, buffer_id):
        arp_type = "REQUEST" if arp_pkt.opcode == arp.ARP_REQUEST else "REPLY"
        LOG.info(f"[arp] {arp_type}: {arp_pkt.src_ip} ({arp_pkt.src_mac}) → {arp_pkt.dst_ip}")

        if arp_pkt.opcode == arp.ARP_REQUEST:
            self._handle_arp_request(datapath, in_port, pkt, eth, arp_pkt, buffer_id)
        else:
            self._handle_arp_reply(datapath, in_port, pkt, eth, arp_pkt, buffer_id)

    def _handle_arp_request(self, datapath, in_port, pkt, eth, arp_pkt, buffer_id):
        target_ip = arp_pkt.dst_ip
        sender_ip = arp_pkt.src_ip
        sender_mac = arp_pkt.src_mac
        
        # 🔑 CRITICAL: Special handling for DNS server - NO translation, NO virtual IP
        if target_ip == self.dns_ip or sender_ip == self.dns_ip:
            LOG.info(f"[arp]   📡 ARP request for DNS SERVER ({sender_ip} -> {target_ip}) - forwarding WITHOUT translation")
            # Flood original ARP request to ALL host ports in network (DNS server could be anywhere)
            self._flood_arp_to_all_hosts(pkt.data, datapath.id, in_port)
            return
        
        # Check if target is a virtual IP we manage (for protected hosts ONLY)
        if target_ip in self.virtual_to_real:
            real_target_ip = self.virtual_to_real[target_ip]
            LOG.info(f"[arp]   ➤ VIRTUAL IP request: {target_ip} → translating to REAL IP {real_target_ip}")
            
            # Create modified ARP request with real target IP
            new_arp_pkt = arp.arp(
                opcode=arp.ARP_REQUEST,
                src_mac=sender_mac,
                src_ip=sender_ip,
                dst_mac='ff:ff:ff:ff:ff:ff',
                dst_ip=real_target_ip  # Translated to real IP
            )
            new_eth = ethernet.ethernet(
                dst='ff:ff:ff:ff:ff:ff',
                src=sender_mac,
                ethertype=ether_types.ETH_TYPE_ARP
            )
            new_pkt = packet.Packet()
            new_pkt.add_protocol(new_eth)
            new_pkt.add_protocol(new_arp_pkt)
            new_pkt.serialize()
            
            # 🔑 CRITICAL LOGIC: Flood ONLY to host ports across ENTIRE NETWORK if target unknown
            if real_target_ip not in self.host_table:
                LOG.info(f"[arp]   📡 Target host location UNKNOWN - flooding to ALL host ports in network")
                self._flood_arp_to_all_hosts(new_pkt.data, datapath.id, in_port)
            else:
                # Target known - send directly to its switch/port
                host_info = self.host_table[real_target_ip]
                LOG.info(f"[arp]   📍 Target known at S{host_info['dpid']}:p{host_info['port']} - sending directly")
                self._send_packet_to_host(new_pkt.data, host_info['dpid'], host_info['port'], buffer_id)
            return
        
        # Standard ARP request (non-MTD, non-DNS) - flood locally to host ports on this switch only
        LOG.info(f"[arp]   ➤ Standard ARP request for {target_ip} - flooding locally to host ports")
        self._flood_packet_locally(datapath, in_port, buffer_id, pkt.data)

    def _handle_arp_reply(self, datapath, in_port, pkt, eth, arp_pkt, buffer_id):
        sender_ip = arp_pkt.src_ip
        sender_mac = arp_pkt.src_mac
        target_ip = arp_pkt.dst_ip
        
        LOG.info(f"[arp] REPLY: {sender_ip} ({sender_mac}) → {target_ip}")
        
        if sender_ip == self.dns_ip or target_ip == self.dns_ip:
            LOG.info(f"[arp]   📡 ARP reply FROM DNS SERVER ({sender_ip} -> {target_ip}) - forwarding WITHOUT translation")
            # Register DNS server location for topology awareness (but NOT for MTD translation)
            if datapath.id in self.access_ports and in_port in self.access_ports[datapath.id]:
                # Store in access_table for topology, but skip host_table (no MTD translation)
                self.access_table[(datapath.id, in_port)] = (sender_ip, sender_mac)
                LOG.info(f"[arp]   ➤ DNS server registered in topology: S{datapath.id}:p{in_port} = {sender_ip}")
                if target_ip in self.host_table:
                    host_info = self.host_table[target_ip]
                    LOG.info(f"[arp]   📍 Direct delivery to requester at S{host_info['dpid']}:p{host_info['port']}")
                    self._send_packet_to_host(pkt.data, host_info['dpid'], host_info['port'], buffer_id)
                    return
            # Forward original ARP reply locally (to the requester on this switch)
            self._flood_packet_locally(datapath, in_port, buffer_id, pkt.data)
            return
        
        # Check if original requester used a virtual IP (for protected hosts ONLY)
        if target_ip in self.real_to_virtual:
            virtual_target_ip = self.real_to_virtual[target_ip]
            LOG.info(f"[arp]   ➤ TRANSLATING ARP REPLY (MTD host):")
            LOG.info(f"        Real Src: {sender_ip} → Virtual Src: {self.real_to_virtual.get(sender_ip, sender_ip)}")
            LOG.info(f"        Real Dst: {target_ip} → Virtual Dst: {virtual_target_ip}")
            
            # Translate sender IP to virtual IP (if it's a protected host)
            reply_sender_ip = self.real_to_virtual.get(sender_ip, sender_ip)
            
            # Create modified ARP reply with virtual IPs
            new_arp_pkt = arp.arp(
                opcode=arp.ARP_REPLY,
                src_mac=sender_mac,
                src_ip=reply_sender_ip,  # Virtual IP (or real if not protected)
                dst_mac=arp_pkt.dst_mac,
                dst_ip=virtual_target_ip  # Virtual IP of requester
            )
            new_eth = ethernet.ethernet(
                dst=arp_pkt.dst_mac,
                src=sender_mac,
                ethertype=ether_types.ETH_TYPE_ARP
            )
            new_pkt = packet.Packet()
            new_pkt.add_protocol(new_eth)
            new_pkt.add_protocol(new_arp_pkt)
            new_pkt.serialize()
            
            # Send DIRECTLY to requester if location known
            if virtual_target_ip in self.virtual_to_real:
                real_requester_ip = self.virtual_to_real[virtual_target_ip]
                if real_requester_ip in self.host_table:
                    host_info = self.host_table[real_requester_ip]
                    LOG.info(f"[arp]   📍 Direct delivery to requester at S{host_info['dpid']}:p{host_info['port']}")
                    self._send_packet_to_host(new_pkt.data, host_info['dpid'], host_info['port'],buffer_id)
                    return
            
            LOG.warning(f"[arp]   ⚠️  Requester location unknown - flooding reply locally")
            self._flood_packet_locally(datapath, in_port, datapath.ofproto.OFP_NO_BUFFER, new_pkt.data)
            return
        
        # Normal ARP reply (non-MTD) - flood locally
        LOG.info("[arp]   ➤ Normal ARP reply - flooding locally")
        self._flood_packet_locally(datapath, in_port, buffer_id, pkt.data)

    def _handle_dns_response(self, datapath, in_port, pkt, eth, ipv4_pkt, udp_pkt, buffer_id, raw_data):
        """Intercept DNS responses and replace real IPs with virtual IPs in A records with detailed logging"""
        src_ip = ipv4_pkt.src  # DNS server IP
        dst_ip = ipv4_pkt.dst  # Client IP
        
        try:
            # Extract DNS payload (after Ethernet + IPv4 + UDP headers)
            ip_header_len = ipv4_pkt.header_length * 4
            udp_start = 14 + ip_header_len
            dns_start = udp_start + 8
            
            if len(raw_data) < dns_start + 12:
                LOG.warning("[dns]  ⚠️  DNS packet too short - forwarding unchanged")
                self._forward_packet(datapath, in_port, buffer_id, raw_data)
                return
            
            dns_payload = raw_data[dns_start:]
            dns_resp = DNSRecord.parse(dns_payload)
            
            # Log original DNS response structure BEFORE modification
            LOG.info(f"\n[dns]  📡 ORIGINAL DNS RESPONSE (Server: {src_ip} → Client: {dst_ip})")
            LOG.info(f"       ID: 0x{dns_resp.header.id:04x} | QR: {dns_resp.header.qr} | OPCODE: {dns_resp.header.opcode}")
            LOG.info(f"       AA: {dns_resp.header.aa} | TC: {dns_resp.header.tc} | RD: {dns_resp.header.rd} | RA: {dns_resp.header.ra}")
            LOG.info(f"       QDCOUNT: {dns_resp.header.q}")
            LOG.info(f"       ANCOUNT: {dns_resp.header.a} | NSCOUNT: {dns_resp.header.auth} | ARCOUNT: {dns_resp.header.ar}")
            
            # Log questions
            if dns_resp.questions:
                LOG.info(f"\n       ❓ QUESTIONS ({len(dns_resp.questions)}):")
                for i, q in enumerate(dns_resp.questions, 1):
                    LOG.info(f"          {i}. {q.get_qname()} | TYPE: {QTYPE[q.qtype]} ({q.qtype}) | CLASS: {q.qclass}")
            
            # Log answers (before modification)
            if dns_resp.rr:
                LOG.info(f"\n       ✅ ANSWERS ({len(dns_resp.rr)}):")
                for i, rr in enumerate(dns_resp.rr, 1):
                    if rr.rtype == QTYPE.A and isinstance(rr.rdata, A):
                        ip_str = str(rr.rdata)
                        status = "🛡️ PROTECTED" if ip_str in self.real_to_virtual else "🔓 PUBLIC"
                        LOG.info(f"          {i}. {rr.rname} | TTL: {rr.ttl} | TYPE: A | VALUE: {ip_str:15s} | {status}")
                    elif rr.rtype == QTYPE.CNAME:
                        LOG.info(f"          {i}. {rr.rname} | TTL: {rr.ttl} | TYPE: CNAME | VALUE: {rr.rdata}")
                    else:
                        LOG.info(f"          {i}. {rr.rname} | TTL: {rr.ttl} | TYPE: {QTYPE[rr.rtype]} ({rr.rtype})")
            
            # Log authorities
            if dns_resp.auth:
                LOG.info(f"\n       📚 AUTHORITIES ({len(dns_resp.auth)}):")
                for i, rr in enumerate(dns_resp.auth, 1):
                    LOG.info(f"          {i}. {rr.rname} | TTL: {rr.ttl} | TYPE: {QTYPE[rr.rtype]} | VALUE: {rr.rdata}")
            
            # Log additional records
            if dns_resp.ar:
                LOG.info(f"\n       ➕ ADDITIONAL ({len(dns_resp.ar)}):")
                for i, rr in enumerate(dns_resp.ar, 1):
                    LOG.info(f"          {i}. {rr.rname} | TTL: {rr.ttl} | TYPE: {QTYPE[rr.rtype]} | VALUE: {rr.rdata}")
            
            # Only process actual responses with answers
            if not (dns_resp.header.qr == 1 and dns_resp.rr):
                LOG.info("[dns]  ➤ Not a DNS response or no answers - forwarding unchanged")
                self._forward_packet(datapath, in_port, buffer_id, raw_data)
                return
            
            # Modify A records (type=1) in answer section
            modified_records = []
            protected_count = 0
            for rr in dns_resp.rr:
                if rr.rtype == QTYPE.A and isinstance(rr.rdata, A):
                    real_ip = str(rr.rdata)
                    if real_ip in self.real_to_virtual:
                        virtual_ip = self.real_to_virtual[real_ip]
                        old_rdata = str(rr.rdata)
                        rr.rdata = A(virtual_ip)
                        modified_records.append((real_ip, virtual_ip))
                        protected_count += 1
                        LOG.info(f"[dns]  🔒 PROTECTED: {real_ip:15s} → {virtual_ip:15s} | Domain: {rr.rname}")
            
            if not modified_records:
                LOG.info("[dns]  ➤ No protected IPs in DNS response - forwarding unchanged")
                self._forward_packet(datapath, in_port, buffer_id, raw_data)
                return
            
            # Log modifications summary
            LOG.info(f"\n[dns]  ✅ DNS MODIFICATION SUMMARY:")
            LOG.info(f"       Total A records: {len([rr for rr in dns_resp.rr if rr.rtype == QTYPE.A])}")
            LOG.info(f"       Protected hosts modified: {protected_count}")
            for real, virt in modified_records:
                LOG.info(f"        • {real:15s} → {virt:15s} (Virtual IP substitution)")
            
            # Rebuild DNS payload
            new_dns_data = dns_resp.pack()
            
            # Log modified DNS response structure AFTER modification
            LOG.info(f"\n[dns]  📤 MODIFIED DNS RESPONSE (Ready to send to client {dst_ip}):")
            modified_resp = DNSRecord.parse(new_dns_data)
            
            if modified_resp.rr:
                LOG.info(f"       ✅ ANSWERS ({len(modified_resp.rr)}):")
                for i, rr in enumerate(modified_resp.rr, 1):
                    if rr.rtype == QTYPE.A and isinstance(rr.rdata, A):
                        ip_str = str(rr.rdata)
                        status = "🛡️ VIRTUAL" if ip_str in self.virtual_to_real else "🔓 PUBLIC"
                        LOG.info(f"          {i}. {rr.rname} | TTL: {rr.ttl} | TYPE: A | VALUE: {ip_str:15s} | {status}")
                    else:
                        LOG.info(f"          {i}. {rr.rname} | TTL: {rr.ttl} | TYPE: {QTYPE[rr.rtype]}")
            
            # Build complete packet using packet.Packet() for automatic checksum calculation
            new_pkt = packet.Packet()
            
            new_eth_pkt = ethernet.ethernet(
                dst=eth.dst,
                src=eth.src,
                ethertype=eth.ethertype
            )

            # 1. Ethernet layer (unchanged)
            new_pkt.add_protocol(new_eth_pkt)

            new_ipv4_pkt = ipv4.ipv4(
                version=ipv4_pkt.version,
                header_length=ipv4_pkt.header_length,
                tos=ipv4_pkt.tos,
                total_length=20 + 8 + len(new_dns_data),
                identification=ipv4_pkt.identification,
                flags=ipv4_pkt.flags,
                offset=ipv4_pkt.offset,
                ttl=ipv4_pkt.ttl,
                proto=ipv4_pkt.proto,
                csum=0,
                src=ipv4_pkt.src,
                dst=ipv4_pkt.dst,
                option=ipv4_pkt.option  # Correct singular form
            )
            
            # 2. IPv4 layer (with updated total_length)
            new_pkt.add_protocol(new_ipv4_pkt)
            
            # 3. UDP layer
            new_pkt.add_protocol(udp.udp(
                src_port=udp_pkt.src_port,
                dst_port=udp_pkt.dst_port,
                total_length=8 + len(new_dns_data),
                csum=0
            ))
            
            # 4. DNS payload (modified)
            new_pkt.add_protocol(new_dns_data)
            
            # Serialize the entire packet (automatically recalculates all checksums)
            new_pkt.serialize()
            
            # The DNS response has dst_ip = client IP (the original requester)
            client_dpid, client_port = self.get_host_location_by_ip(dst_ip)

            if client_dpid is not None and client_port is not None:
                # Get datapath for client's switch
                client_dp = self._get_datapath(client_dpid)
                
                if client_dp:
                    # Build PacketOut to send directly to client's port
                    parser = client_dp.ofproto_parser
                    ofproto = client_dp.ofproto
                    
                    actions = [parser.OFPActionOutput(client_port)]
                    out = parser.OFPPacketOut(
                        datapath=client_dp,
                        buffer_id=ofproto.OFP_NO_BUFFER,  # Always NO_BUFFER for raw packet data
                        in_port=ofproto.OFPP_CONTROLLER,   # Coming from controller
                        actions=actions,
                        data=new_pkt.data
                    )
                    client_dp.send_msg(out)
                    
                    # Log successful direct delivery
                    LOG.info(f"\n[dns]  📤 DIRECT DELIVERY to client {dst_ip}")
                    LOG.info(f"       Path: Controller → Switch S{client_dpid} → Port {client_port}")
                    LOG.info(f"       Packet size: {len(new_pkt.data)} bytes | Protected IPs substituted: {protected_count}")
                else:
                    # Fallback: Client switch not registered (should not happen in normal operation)
                    LOG.warning(f"[dns]  ⚠️  Client switch S{client_dpid} not found - falling back to normal forwarding")
                    self._forward_packet(datapath, in_port, datapath.ofproto.OFP_NO_BUFFER, new_pkt.data)
                    LOG.info(f"\n[dns]  ➤ Modified DNS response forwarded via OFPP_NORMAL (client location unknown)")
            else:
                # Fallback: Client location unknown (should not happen after ARP resolution)
                LOG.warning(f"[dns]  ⚠️  Client location UNKNOWN for IP {dst_ip} - falling back to normal forwarding")
                self._forward_packet(datapath, in_port, datapath.ofproto.OFP_NO_BUFFER, new_pkt.data)
                LOG.info(f"\n[dns]  ➤ Modified DNS response forwarded via OFPP_NORMAL (client location unknown)")
            
        except Exception as e:
            LOG.error(f"[dns]  ❌ Error modifying DNS response: {e}", exc_info=True)
            # On error, forward original packet to avoid breaking connectivity
            self._forward_packet(datapath, in_port, buffer_id, raw_data)

    def _calc_ipv4_checksum(self, ipv4_header):
        """Calculate IPv4 header checksum (RFC 791)"""
        if isinstance(ipv4_header, bytearray):
            ipv4_header = bytes(ipv4_header)
        
        if len(ipv4_header) % 2 != 0:
            ipv4_header += b'\x00'
        
        checksum = 0
        for i in range(0, len(ipv4_header), 2):
            word = (ipv4_header[i] << 8) + ipv4_header[i+1]
            checksum += word
            checksum = (checksum & 0xffff) + (checksum >> 16)
        
        return ~checksum & 0xffff

    def _calc_udp_checksum(self, src_ip, dst_ip, proto, udp_packet):
        """Calculate UDP checksum including pseudo-header (RFC 768)"""
        # Pseudo-header: src IP (4) + dst IP (4) + zero (1) + proto (1) + UDP length (2)
        pseudo_header = struct.pack('!4s4sBBH', 
            struct.pack('!I', src_ip),
            struct.pack('!I', dst_ip),
            0,
            proto,
            len(udp_packet)
        )
        
        data = pseudo_header + udp_packet
        
        if len(data) % 2 != 0:
            data += b'\x00'
        
        checksum = 0
        for i in range(0, len(data), 2):
            word = (data[i] << 8) + data[i+1]
            checksum += word
            checksum = (checksum & 0xffff) + (checksum >> 16)
        
        result = ~checksum & 0xffff
        return result if result != 0 else 0xffff

    def _ip_to_int(self, ip_str):
        """Convert IP string to integer"""
        return struct.unpack("!I", socket.inet_aton(ip_str))[0]

    def _int_to_ip(self, ip_int):
        """Convert integer to IP string"""
        return socket.inet_ntoa(struct.pack("!I", ip_int))

    # ===== CRITICAL: CORRECT FLOW INSTALLATION AT EDGE SWITCHES ONLY =====
    
    def _install_translation_flows(self, ingress_datapath, in_port, eth, ipv4_pkt, src_ip, virtual_dst_ip, real_dst_ip):
        """
        Install bidirectional translation flows ONLY at edge switches.
        Interior switches use normal forwarding (OFPP_NORMAL) without translation.
        """
        LOG.info(f"\n[flow] 🔄 INSTALLING BIDIRECTIONAL TRANSLATION FLOWS")
        LOG.info(f"       Flow: {src_ip} (real) ⇄ {virtual_dst_ip} (virtual) | Real Dst: {real_dst_ip}")
        
        if real_dst_ip not in self.host_table:
            LOG.error(f"[flow] ❌ Destination host {real_dst_ip} location unknown - ABORTING flow installation")
            return
        
        dst_info = self.host_table[real_dst_ip]
        egress_dpid = dst_info['dpid']
        egress_port = dst_info['port']
        virtual_src_ip = self.real_to_virtual.get(src_ip, src_ip)
        
        parser = ingress_datapath.ofproto_parser
        ofproto = ingress_datapath.ofproto
        
        # 1. INGRESS EDGE SWITCH: Virtual → Real translation + NORMAL forwarding
        #    Only install if this is an edge switch (has access ports)
        if ingress_datapath.id in self.access_ports:
            LOG.info(f"\n[flow] ➤ EDGE SWITCH (S{ingress_datapath.id}): Virtual → Real translation")
            LOG.info(f"       Match: IPv4 Dst = {virtual_dst_ip}")
            LOG.info(f"       Action: Set IPv4 Dst = {real_dst_ip} → Output NORMAL (to interior switches)")
            match = parser.OFPMatch(
                eth_type=0x0800,
                ipv4_dst=virtual_dst_ip
            )
            actions = [
                parser.OFPActionSetField(ipv4_dst=real_dst_ip),
                parser.OFPActionOutput(ofproto.OFPP_NORMAL)  # ⚠️ Critical: Forward normally to interior switches
            ]
            self.add_flow(ingress_datapath, self.FLOW_PRIORITY_TRANSLATION, match, actions, idle_timeout=300)
        else:
            LOG.warning(f"[flow] ⚠️  Ingress switch S{ingress_datapath.id} is NOT an edge switch - skipping translation flow")
            # Still forward the packet normally without translation
            self._forward_packet(ingress_datapath, in_port, ofproto.OFP_NO_BUFFER, 
                               self._build_translated_packet(eth, ipv4_pkt, src_ip, virtual_dst_ip, real_dst_ip).data)
            return
        
        # 2. EGRESS EDGE SWITCH (if different): Real → Virtual translation + direct host output
        if egress_dpid != ingress_datapath.id:
            egress_dp = self._get_datapath(egress_dpid)
            if egress_dp and egress_dpid in self.access_ports:
                LOG.info(f"\n[flow] ➤ EDGE SWITCH (S{egress_dpid}): Real → Virtual translation BEFORE host")
                LOG.info(f"       Match: IPv4 Src={src_ip}, Dst={real_dst_ip}")
                LOG.info(f"       Action: Set IPv4 Src = {virtual_src_ip} → Output Port {egress_port} (direct to host)")
                match = parser.OFPMatch(
                    eth_type=0x0800,
                    ipv4_src=src_ip,
                    ipv4_dst=real_dst_ip
                )
                actions = [
                    parser.OFPActionSetField(ipv4_src=virtual_src_ip),
                    parser.OFPActionOutput(egress_port)  # ⚠️ Critical: Direct output to host port (NOT NORMAL)
                ]
                self.add_flow(egress_dp, self.FLOW_PRIORITY_TRANSLATION, match, actions, idle_timeout=300)
        
        # 3. REVERSE PATH: EGRESS EDGE SWITCH → INGRESS EDGE SWITCH
        if egress_dpid != ingress_datapath.id:
            egress_dp = self._get_datapath(egress_dpid)
            if egress_dp and egress_dpid in self.access_ports:
                LOG.info(f"\n[flow] ➤ REVERSE PATH - EDGE SWITCH (S{egress_dpid}): Virtual → Real translation")
                LOG.info(f"       Match: IPv4 Dst = {virtual_src_ip}")
                LOG.info(f"       Action: Set IPv4 Dst = {src_ip} → Output NORMAL")
                match = parser.OFPMatch(
                    eth_type=0x0800,
                    ipv4_dst=virtual_src_ip
                )
                actions = [
                    parser.OFPActionSetField(ipv4_dst=src_ip),
                    parser.OFPActionOutput(ofproto.OFPP_NORMAL)
                ]
                self.add_flow(egress_dp, self.FLOW_PRIORITY_TRANSLATION, match, actions, idle_timeout=300)
        
        # 4. REVERSE PATH: INGRESS EDGE SWITCH before host
        if ingress_datapath.id in self.access_ports:
            LOG.info(f"\n[flow] ➤ REVERSE PATH - EDGE SWITCH (S{ingress_datapath.id}): Real → Virtual translation BEFORE host")
            LOG.info(f"       Match: IPv4 Src={real_dst_ip}, Dst={src_ip}")
            LOG.info(f"       Action: Set IPv4 Src = {virtual_dst_ip} → Output Port {in_port} (direct to host)")
            match = parser.OFPMatch(
                eth_type=0x0800,
                ipv4_src=real_dst_ip,
                ipv4_dst=src_ip
            )
            actions = [
                parser.OFPActionSetField(ipv4_src=virtual_dst_ip),
                parser.OFPActionOutput(in_port)  # ⚠️ Critical: Direct output to host port
            ]
            self.add_flow(ingress_datapath, self.FLOW_PRIORITY_TRANSLATION, match, actions, idle_timeout=300)
        
        # 🔑 KEY POINT: Interior switches have NO translation flows installed
        # They will use table-miss flow (OFPP_NORMAL) for standard L2/L3 forwarding
        LOG.info(f"\n[flow] ✅ Translation flows installed ONLY at edge switches")
        LOG.info(f"       ⚠️  Interior switches use normal forwarding (OFPP_NORMAL) without translation")

    def _build_translated_packet(self, eth, ipv4_pkt, src_ip, virtual_dst_ip, real_dst_ip):
        """Helper to build translated packet for first packet forwarding"""
        pkt_new = packet.Packet()
        pkt_new.add_protocol(ethernet.ethernet(ethertype=eth.ethertype, dst=eth.dst, src=eth.src))
        pkt_new.add_protocol(ipv4.ipv4(
            src=ipv4_pkt.src,
            dst=real_dst_ip,  # Translated to real IP
            proto=ipv4_pkt.proto,
            ttl=max(0, ipv4_pkt.ttl - 1),
            identification=ipv4_pkt.identification,
            flags=ipv4_pkt.flags,
            offset=ipv4_pkt.offset,
            option=ipv4_pkt.option
        ))
        
        # Add transport layer
        if ipv4_pkt.proto == 1:  # ICMP
            icmp_pkt = packet.Packet(ipv4_pkt.data).get_protocol(icmp.icmp)
            if icmp_pkt:
                pkt_new.add_protocol(icmp_pkt)
        elif ipv4_pkt.proto == 6:  # TCP
            tcp_pkt = packet.Packet(ipv4_pkt.data).get_protocol(tcp.tcp)
            if tcp_pkt:
                pkt_new.add_protocol(tcp_pkt)
        elif ipv4_pkt.proto == 17:  # UDP
            udp_pkt = packet.Packet(ipv4_pkt.data).get_protocol(udp.udp)
            if udp_pkt:
                pkt_new.add_protocol(udp.udp(
                    src_port=udp_pkt.src_port,
                    dst_port=udp_pkt.dst_port,
                    total_length=udp_pkt.total_length,
                    csum=0
                ))
                # Add payload if exists
                if len(ipv4_pkt.data) > 8:
                    pkt_new.add_protocol(ipv4_pkt.data[8:])
        
        pkt_new.serialize()
        return pkt_new

    def _translate_and_forward_packet(self, datapath, in_port, pkt, eth, ipv4_pkt, src_ip, virtual_dst_ip, real_dst_ip, buffer_id):
        """
        Translate first packet's destination IP using OpenFlow actions (no manual packet rebuilding).
        This avoids checksum issues and AttributeError related to ipv4_pkt.data.
        """
        LOG.info(f"[mtd]  ➤ Translating first packet: Dst {virtual_dst_ip} → {real_dst_ip}")
        
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        
        # 🔑 CRITICAL FIX: Use OFPActionSetField instead of manual packet rebuilding
        # This leverages switch hardware for IP translation and automatic checksum recalculation
        actions = [
            parser.OFPActionSetField(ipv4_dst=real_dst_ip),  # Translate virtual → real IP
            parser.OFPActionOutput(ofproto.OFPP_NORMAL)      # Forward through normal pipeline
        ]
        
        # Send packet-out with translation actions
        # Note: If packet is buffered (buffer_id != NO_BUFFER), we don't need to send data
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=buffer_id,
            in_port=in_port,
            actions=actions,
            data=pkt.data if buffer_id == ofproto.OFP_NO_BUFFER else None
        )
        datapath.send_msg(out)
        
        LOG.info(f"[mtd]  ✅ First packet translated via OFPActionSetField and forwarded")
        LOG.info(f"       Switch hardware will handle TTL decrement and checksum recalculation")

    def _handle_normal_ipv4(self, datapath, in_port, eth, ipv4_pkt, buffer_id, raw_data):
        """
        Handle non-MTD IPv4 packets using standard L2/L3 forwarding via OFPP_NORMAL.
        Leverages switch's built-in forwarding logic - NO manual MAC learning required.
        Uses topology awareness to avoid unnecessary flooding to interior ports.
        """
        dst_ip = ipv4_pkt.dst
        src_ip = ipv4_pkt.src
        
        LOG.debug(f"[normal] Non-MTD traffic: {src_ip} → {dst_ip} | Using OFPP_NORMAL forwarding")
        
        # First packet: forward via controller using OFPP_NORMAL
        parser = datapath.ofproto_parser
        actions = [parser.OFPActionOutput(datapath.ofproto.OFPP_NORMAL)]
        
        # Install a simple flow to avoid future packet-ins for this flow
        # Match on IP addresses only (no MAC needed - handled by switch's L2 logic)
        match = parser.OFPMatch(
            eth_type=0x0800,  # IPv4
            ipv4_src=src_ip,
            ipv4_dst=dst_ip
        )
        self.add_flow(
            datapath, 
            self.FLOW_PRIORITY_NORMAL, 
            match, 
            actions,
            idle_timeout=60,   # Shorter timeout for non-critical traffic
            hard_timeout=300
        )
        
        # Forward the current packet
        if buffer_id != datapath.ofproto.OFP_NO_BUFFER:
            out = parser.OFPPacketOut(
                datapath=datapath,
                buffer_id=buffer_id,
                in_port=in_port,
                actions=actions
            )
        else:
            out = parser.OFPPacketOut(
                datapath=datapath,
                buffer_id=datapath.ofproto.OFP_NO_BUFFER,
                in_port=in_port,
                actions=actions,
                data=raw_data
            )
        datapath.send_msg(out)
        LOG.debug(f"[normal] ✓ Flow installed for {src_ip} → {dst_ip} | Forwarded via OFPP_NORMAL")

    # ===== CORRECT FLOODING LOGIC: SEPARATE LOCAL VS NETWORK-WIDE =====
    
    def _flood_packet_locally(self, datapath, in_port, buffer_id, data):
        """
        Flood packet ONLY to access ports on the LOCAL switch (for non-MTD traffic).
        This prevents unnecessary flooding across the entire network.
        """
        if datapath.id not in self.access_ports:
            LOG.warning(f"[flood] ⚠️  No access ports known for S{datapath.id} - dropping packet")
            return
            
        ports = [p for p in self.access_ports[datapath.id] if p != in_port]
        if not ports:
            LOG.debug(f"[flood] No access ports to flood on S{datapath.id} (excluding port {in_port})")
            return
            
        LOG.debug(f"[flood] Flooding locally to {len(ports)} host ports on S{datapath.id}: {sorted(ports)}")
        
        for port in ports:
            actions = [datapath.ofproto_parser.OFPActionOutput(port)]
            out = datapath.ofproto_parser.OFPPacketOut(
                datapath=datapath,
                buffer_id=buffer_id if buffer_id != datapath.ofproto.OFP_NO_BUFFER else datapath.ofproto.OFP_NO_BUFFER,
                in_port=in_port,
                actions=actions,
                data=data if buffer_id == datapath.ofproto.OFP_NO_BUFFER else None
            )
            datapath.send_msg(out)

    def _flood_arp_to_all_hosts(self, pkt_data, exclude_dpid, exclude_port):
        """
        Flood ARP request to ALL host ports across the ENTIRE NETWORK.
        Used ONLY when target host location is unknown during ARP resolution.
        Critical: Does NOT flood to interior ports (switch-to-switch links).
        """
        LOG.info(f"[arp]   📡 Flooding ARP to ALL host ports in network (excluding S{exclude_dpid}:p{exclude_port})")
        total_ports = 0
        total_switches = 0
        
        for dpid, ports in self.access_ports.items():
            dp = self._get_datapath(dpid)
            if not dp:
                continue
                
            total_switches += 1
            for port in ports:
                # Skip the input port to prevent loops
                if dpid == exclude_dpid and port == exclude_port:
                    continue
                    
                actions = [dp.ofproto_parser.OFPActionOutput(port)]
                out = dp.ofproto_parser.OFPPacketOut(
                    datapath=dp,
                    buffer_id=dp.ofproto.OFP_NO_BUFFER,
                    in_port=dp.ofproto.OFPP_CONTROLLER,
                    actions=actions,
                    data=pkt_data
                )
                dp.send_msg(out)
                total_ports += 1
        
        LOG.info(f"[arp]   ✅ Flooded to {total_ports} host ports across {total_switches} switches")

    def _send_packet_to_host(self, pkt_data, dpid, port, buffer_id):
        """Send packet directly to a specific host port on a specific switch"""
        dp = self._get_datapath(dpid)
        if dp:
            actions = [dp.ofproto_parser.OFPActionOutput(port)]
            out = dp.ofproto_parser.OFPPacketOut(
                datapath=dp,
                buffer_id=buffer_id,
                in_port=dp.ofproto.OFPP_CONTROLLER,
                actions=actions,
                data=pkt_data
            )
            dp.send_msg(out)
            LOG.info(f"[packet] Direct delivery to host at S{dpid}:p{port}")
        else:
            LOG.warning(f"[packet] ⚠️  Datapath S{dpid} not found - cannot deliver packet")

    def _forward_packet(self, datapath, in_port, buffer_id, data):
        """Forward packet using normal pipeline (OFPP_NORMAL)"""
        parser = datapath.ofproto_parser
        actions = [parser.OFPActionOutput(datapath.ofproto.OFPP_NORMAL)]
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=buffer_id if buffer_id != datapath.ofproto.OFP_NO_BUFFER else datapath.ofproto.OFP_NO_BUFFER,
            in_port=in_port,
            actions=actions,
            data=data if buffer_id == datapath.ofproto.OFP_NO_BUFFER else None
        )
        datapath.send_msg(out)

    def _get_datapath(self, dpid):
        """Helper to get datapath object by DPID"""
        return self.datapath_list.get(dpid)

    @set_ev_cls(ofp_event.EventOFPStateChange, MAIN_DISPATCHER)
    def _state_change_handler(self, ev):
        """Track datapaths for later access"""
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            self.datapath_list[datapath.id] = datapath
            LOG.info(f"[switch] 🔌 Switch S{datapath.id} connected and registered")
        elif ev.state == 'DEAD_DISPATCHER':
            if datapath.id in self.datapath_list:
                del self.datapath_list[datapath.id]
                LOG.info(f"[switch] 💔 Switch S{datapath.id} disconnected and unregistered")

# ===== HELPER METHODS FOR HOST LOCATION DISCOVERY =====

    def get_host_location_by_ip(self, ip_address):
        """
        Find host location (dpid, port) by IP address.
        Supports both real IPs (10.0.0.1) and virtual IPs (10.0.0.11).
        
        Args:
            ip_address (str): IP address to search for
            
        Returns:
            tuple: (dpid, port) if found, else (None, None)
        """
        # Case 1: Check if it's a VIRTUAL IP (e.g., 10.0.0.11)
        if ip_address in self.virtual_to_real:
            real_ip = self.virtual_to_real[ip_address]
            LOG.debug(f"[lookup] IP {ip_address} is VIRTUAL → mapped to REAL IP {real_ip}")
            return self._get_host_location_by_real_ip(real_ip)
        
        # Case 2: Check if it's a REAL IP (e.g., 10.0.0.1)
        return self._get_host_location_by_real_ip(ip_address)

    def _get_host_location_by_real_ip(self, real_ip):
        """
        Internal helper: Find host location by REAL IP address only.
        
        Args:
            real_ip (str): Real IP address
            
        Returns:
            tuple: (dpid, port) if found, else (None, None)
        """
        # Primary lookup: MTD host table (protected hosts)
        if real_ip in self.host_table:
            info = self.host_table[real_ip]
            dpid = info['dpid']
            port = info['port']
            mac = info['mac']
            LOG.debug(f"[lookup] ✓ Found REAL IP {real_ip} in host_table: S{dpid}:p{port} (MAC: {mac})")
            return (dpid, port)
        
        # Secondary lookup: Topology access table (all hosts)
        for (dpid, port), (ip, mac) in self.access_table.items():
            if ip == real_ip:
                LOG.debug(f"[lookup] ✓ Found REAL IP {real_ip} in access_table: S{dpid}:p{port} (MAC: {mac})")
                return (dpid, port)
        
        # Not found
        LOG.debug(f"[lookup] ✗ REAL IP {real_ip} NOT FOUND in any table")
        return (None, None)

    def get_host_location_by_mac(self, mac_address):
        """
        Find host location (dpid, port) by MAC address.
        
        Args:
            mac_address (str): MAC address to search for (e.g., '00:00:00:00:00:01')
            
        Returns:
            tuple: (dpid, port) if found, else (None, None)
        """
        mac_address = mac_address.lower()
        
        # Case 1: Check MTD host table (protected hosts)
        for real_ip, info in self.host_table.items():
            if info['mac'].lower() == mac_address:
                dpid = info['dpid']
                port = info['port']
                virt_ip = self.real_to_virtual.get(real_ip, 'N/A')
                LOG.debug(f"[lookup] ✓ Found MAC {mac_address} in host_table: S{dpid}:p{port} (REAL: {real_ip}, VIRT: {virt_ip})")
                return (dpid, port)
        
        # Case 2: Check topology access table (all hosts)
        for (dpid, port), (ip, mac) in self.access_table.items():
            if mac.lower() == mac_address:
                LOG.debug(f"[lookup] ✓ Found MAC {mac_address} in access_table: S{dpid}:p{port} (IP: {ip})")
                return (dpid, port)
        
        # Case 3: Check fallback L2 MAC table (non-MTD traffic)
        for dpid, mac_table in self.mac_to_port.items():
            if mac_address in mac_table:
                port = mac_table[mac_address]
                LOG.debug(f"[lookup] ✓ Found MAC {mac_address} in mac_to_port: S{dpid}:p{port} (L2 fallback)")
                return (dpid, port)
        
        # Not found
        LOG.debug(f"[lookup] ✗ MAC {mac_address} NOT FOUND in any table")
        return (None, None)

    def get_host_info_by_ip(self, ip_address):
        """
        Get complete host information by IP address (real or virtual).
        
        Args:
            ip_address (str): IP address to search for
            
        Returns:
            dict: Host info with keys: 'ip_type', 'real_ip', 'virtual_ip', 'mac', 'dpid', 'port'
                or None if not found
        """
        # Determine IP type and get real IP
        if ip_address in self.virtual_to_real:
            ip_type = 'virtual'
            real_ip = self.virtual_to_real[ip_address]
            virtual_ip = ip_address
        elif ip_address in self.real_to_virtual:
            ip_type = 'real'
            real_ip = ip_address
            virtual_ip = self.real_to_virtual[ip_address]
        else:
            # Not a protected IP - check access_table
            for (dpid, port), (ip, mac) in self.access_table.items():
                if ip == ip_address:
                    return {
                        'ip_type': 'public',
                        'real_ip': ip_address,
                        'virtual_ip': None,
                        'mac': mac,
                        'dpid': dpid,
                        'port': port
                    }
            return None
        
        # Get location from host_table
        if real_ip in self.host_table:
            info = self.host_table[real_ip]
            return {
                'ip_type': ip_type,
                'real_ip': real_ip,
                'virtual_ip': virtual_ip,
                'mac': info['mac'],
                'dpid': info['dpid'],
                'port': info['port']
            }
        
        return None

    def show_network_hosts(self):
        """
        Display comprehensive host information for debugging and monitoring.
        Shows protected hosts (MTD), DNS server, and all discovered hosts.
        """
        LOG.info("\n" + "="*80)
        LOG.info("🖥️  NETWORK HOST INVENTORY")
        LOG.info("="*80)
        
        # Protected hosts (MTD)
        LOG.info("\n🛡️  PROTECTED HOSTS (MTD Enabled):")
        if self.host_table:
            LOG.info("   {:<15s} {:<15s} {:<17s} {:<8s} {:<6s}".format(
                "REAL IP", "VIRTUAL IP", "MAC", "SWITCH", "PORT"
            ))
            LOG.info("   " + "-"*65)
            for real_ip, info in sorted(self.host_table.items()):
                virt_ip = self.real_to_virtual.get(real_ip, 'N/A')
                mac = info['mac']
                dpid = info['dpid']
                port = info['port']
                LOG.info(f"   {real_ip:<15s} {virt_ip:<15s} {mac:<17s} S{dpid:<6d} {port:<6d}")
        else:
            LOG.info("   (no protected hosts discovered)")
        
        # DNS server (if registered)
        LOG.info("\n📡 DNS SERVER:")
        dns_found = False
        for (dpid, port), (ip, mac) in self.access_table.items():
            if ip == self.dns_ip:
                LOG.info(f"   IP: {ip} | MAC: {mac} | Location: Switch S{dpid}, Port {port}")
                dns_found = True
                break
        if not dns_found:
            LOG.info(f"   IP: {self.dns_ip} | Status: NOT YET DISCOVERED (waiting for ARP/DNS traffic)")
        
        # All discovered hosts (including non-protected)
        LOG.info("\n🔍 ALL DISCOVERED HOSTS (Topology View):")
        if self.access_table:
            LOG.info("   {:<15s} {:<17s} {:<8s} {:<6s} {:<15s}".format(
                "IP", "MAC", "SWITCH", "PORT", "STATUS"
            ))
            LOG.info("   " + "-"*70)
            for (dpid, port), (ip, mac) in sorted(self.access_table.items()):
                status = "🛡️ PROTECTED" if ip in self.real_to_virtual else "🔓 PUBLIC"
                LOG.info(f"   {ip:<15s} {mac:<17s} S{dpid:<6d} {port:<6d} {status:<15s}")
        else:
            LOG.info("   (no hosts discovered yet - wait for ARP/IPv4 traffic)")
        
        # Hosts with unknown location (in host_table but not in access_table)
        unknown_hosts = []
        for real_ip in self.real_to_virtual.keys():
            if real_ip not in [ip for (_, _), (ip, _) in self.access_table.items()]:
                unknown_hosts.append(real_ip)
        
        if unknown_hosts:
            LOG.info("\n⚠️  HOSTS WITH UNKNOWN LOCATION (Waiting for first packet):")
            for ip in unknown_hosts:
                virt_ip = self.real_to_virtual[ip]
                LOG.info(f"   REAL: {ip:<15s} → VIRTUAL: {virt_ip:<15s}")
        
        LOG.info("\n" + "="*80)