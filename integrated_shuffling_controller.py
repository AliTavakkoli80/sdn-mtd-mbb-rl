from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, arp, ipv4, udp
from dnslib import DNSRecord, DNSHeader, RR, QTYPE, A
import logging
import ipaddress

class IntegratedShufflingController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(IntegratedShufflingController, self).__init__(*args, **kwargs)
        self.logger.setLevel(logging.INFO)
        
        # MAC learning table for Layer 2 switching {dpid: {mac: port}}
        self.mac_to_port = {}
        
        # Define IP ranges clearly to avoid confusion
        self.real_ip_range_start = ipaddress.IPv4Address("10.0.0.1")
        self.real_ip_range_end = ipaddress.IPv4Address("10.0.0.50")
        
        self.virtual_ip_range_start = ipaddress.IPv4Address("10.0.0.100")
        self.virtual_ip_range_end = ipaddress.IPv4Address("10.0.0.150")
        
        # Pre-defined pool of virtual IPs available for assignment
        self.virtual_ip_pool = [
            "10.0.0.100", "10.0.0.101", "10.0.0.102", "10.0.0.103",
            "10.0.0.104", "10.0.0.105", "10.0.0.106", "10.0.0.107"
        ]
        
        # Mappings between real IPs and their assigned virtual IPs
        self.real_to_virtual = {}  # real_ip -> virtual_ip
        self.virtual_to_real = {}  # virtual_ip -> real_ip
        
        # Track already installed flow rules to avoid duplicates
        self.installed_flow_rules = set()
        
        self.logger.info(f"Controller initialized with virtual IP pool: {self.virtual_ip_pool}")

    def _is_in_real_ip_range(self, ip_str):
        """Check if an IP is in the real IP range (not virtual)."""
        try:
            ip = ipaddress.IPv4Address(ip_str)
            return self.real_ip_range_start <= ip <= self.real_ip_range_end
        except:
            return False

    def _is_in_virtual_ip_range(self, ip_str):
        """Check if an IP is in the virtual IP range."""
        try:
            ip = ipaddress.IPv4Address(ip_str)
            return self.virtual_ip_range_start <= ip <= self.virtual_ip_range_end
        except:
            return False

    def _is_ip_already_virtual(self, ip_str):
        """Check if an IP is already a virtual IP we've assigned."""
        return ip_str in self.virtual_to_real

    def _should_assign_virtual_ip(self, ip_str):
        """
        Determine if we should assign a virtual IP to this real IP.
        Only assign to real IPs that are not already virtualized.
        """
        if not self._is_in_real_ip_range(ip_str):
            return False
        
        if ip_str in self.real_to_virtual:
            return False
        
        return True

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """Install a default table-miss flow entry when a switch connects."""
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        # Table-miss flow entry: send all unmatched packets to controller
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                        ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        self.logger.info(f"Switch {datapath.id} connected. Installed table-miss flow.")

    def add_flow(self, datapath, priority, match, actions, idle_timeout=0, hard_timeout=0):
        """Install a flow rule on the switch."""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=datapath, 
            priority=priority,
            match=match, 
            instructions=inst,
            idle_timeout=idle_timeout,
            hard_timeout=hard_timeout
        )
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        """Main packet handler - processes all incoming packets."""
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        dpid = datapath.id
        pkt = packet.Packet(msg.data)

        # 1. First process DNS (highest priority)
        if self._handle_dns(pkt, datapath, in_port, msg):
            self.logger.debug("Packet handled by DNS handler")
            return  # Packet processed by DNS handler

        # 2. Then process ARP
        if self._handle_arp(pkt, datapath, in_port, msg):
            self.logger.debug("Packet handled by ARP handler")
            return  # Packet processed by ARP handler

        # 3. Finally handle regular data packets (Layer 2 switching)
        self._do_layer2_switching(pkt, datapath, in_port, msg)

    def _handle_dns(self, pkt, datapath, in_port, msg):
        """
        Handle DNS packets:
        - Allow DNS queries to pass through to real DNS server
        - Intercept DNS responses and replace real IPs with virtual IPs
        Returns: True if packet was DNS and was handled, False otherwise
        """
        eth = pkt.get_protocol(ethernet.ethernet)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        udp_pkt = pkt.get_protocol(udp.udp)
        
        # Check if this is a DNS packet (port 53)
        if not (eth and ip_pkt and udp_pkt):
            return False
        
        # DNS Query (client to server) - let it pass through
        if udp_pkt.dst_port == 53:
            self.logger.debug(f"DNS Query from {ip_pkt.src}:{udp_pkt.src_port} to {ip_pkt.dst}:53")
            # Forward the query to the real DNS server
            self._forward_packet_normal(datapath, in_port, msg)
            return True
        
        # DNS Response (server to client) - intercept and modify
        elif udp_pkt.src_port == 53:
            return self._handle_dns_response(pkt, datapath, in_port, msg, eth, ip_pkt, udp_pkt)
        
        return False

    def _handle_dns_response(self, pkt, datapath, in_port, msg, eth, ip_pkt, udp_pkt):
        """Handle DNS responses from real DNS server."""
        try:
            # Get DNS payload
            protocols = pkt.protocols
            udp_index = protocols.index(udp_pkt)
            if udp_index + 1 >= len(protocols):
                return False
                
            dns_payload = protocols[udp_index + 1]
            if not isinstance(dns_payload, bytes) or len(dns_payload) < 12:
                return False
            
            # Parse DNS response
            dns_record = DNSRecord.parse(dns_payload)
            
            # Check if this is a response and has answers
            if dns_record.header.qr != 1 or not dns_record.rr:
                return False
            
            modified = False
            
            # Process each answer in the DNS response
            for rr in dns_record.rr:
                if rr.rtype == QTYPE.A:  # IPv4 address record
                    domain_name = str(rr.rname).rstrip('.')
                    real_ip = str(rr.rdata)
                    
                    # FIXED: Check if this IP is already a virtual IP we created
                    if self._is_ip_already_virtual(real_ip):
                        self.logger.debug(f"Ignoring our own virtual IP: {real_ip}")
                        continue  # Skip - this is our own virtual IP!
                    
                    # Check if we should assign a virtual IP to this real IP
                    if self._should_assign_virtual_ip(real_ip):
                        if self.virtual_ip_pool:
                            # Assign a virtual IP from pool
                            virtual_ip = self.virtual_ip_pool.pop(0)
                            
                            # Store the mapping
                            self.real_to_virtual[real_ip] = virtual_ip
                            self.virtual_to_real[virtual_ip] = real_ip
                            
                            self.logger.info(f"✅ Assigned virtual IP {virtual_ip} to REAL IP {real_ip} (domain: {domain_name})")
                        else:
                            self.logger.warning(f"No virtual IPs available for {real_ip}")
                            continue
                    
                    # Now check if we should translate this IP
                    if real_ip in self.real_to_virtual:
                        virtual_ip = self.real_to_virtual[real_ip]
                        
                        # Replace real IP with virtual IP in the DNS answer
                        rr.rdata = A(virtual_ip)
                        
                        self.logger.info(f"✅ DNS IP Translation: {domain_name} | {real_ip} -> {virtual_ip}")
                        modified = True
            
            # If we modified the DNS response, send it to the client
            if modified:
                # Rebuild the packet with modified DNS response
                reply_pkt = packet.Packet()
                reply_pkt.add_protocol(ethernet.ethernet(
                    ethertype=eth.ethertype,
                    dst=eth.dst,
                    src=eth.src
                ))
                reply_pkt.add_protocol(ipv4.ipv4(
                    src=ip_pkt.src,  # DNS server IP
                    dst=ip_pkt.dst,  # Client IP
                    proto=ip_pkt.proto
                ))
                reply_pkt.add_protocol(udp.udp(
                    src_port=udp_pkt.src_port,
                    dst_port=udp_pkt.dst_port
                ))
                reply_pkt.add_protocol(dns_record.pack())
                reply_pkt.serialize()
                
                # Send modified response back to client
                parser = datapath.ofproto_parser
                ofproto = datapath.ofproto
                out = parser.OFPPacketOut(
                    datapath=datapath,
                    buffer_id=datapath.ofproto.OFP_NO_BUFFER,
                    in_port=in_port,
                    actions=[parser.OFPActionOutput(ofproto.OFPP_NORMAL)],
                    data=reply_pkt.data
                )
                datapath.send_msg(out)
                
                # Install translation rules for the client-server communication
                client_ip = ip_pkt.dst
                for real_ip, virtual_ip in self.real_to_virtual.items():
                    # Only install rules for IPs that were actually translated in this response
                    rule_key = f"{client_ip}<->{virtual_ip}"
                    if rule_key not in self.installed_flow_rules:
                        self._install_translation_rules(datapath, client_ip, real_ip)
                        self.installed_flow_rules.add(rule_key)
                
                return True
            
        except Exception as e:
            self.logger.error(f"Error handling DNS response: {e}")
        
        return False

    def _handle_arp(self, pkt, datapath, in_port, msg):
        """
        Handle ARP packets:
        - For ARP requests to virtual IPs: translate to real IP
        - For ARP replies from real IPs: translate to virtual IP
        """
        eth = pkt.get_protocol(ethernet.ethernet)
        arp_pkt = pkt.get_protocol(arp.arp)
        
        if not (eth and arp_pkt):
            return False
            
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        
        # Handle ARP REQUEST
        if arp_pkt.opcode == arp.ARP_REQUEST:
            target_ip = arp_pkt.dst_ip
            
            # If request is for a virtual IP, translate to real IP
            if target_ip in self.virtual_to_real:
                real_ip = self.virtual_to_real[target_ip]
                
                # Modify the ARP packet: change dst_ip from virtual to real
                modified_arp = arp.arp(
                    opcode=arp.ARP_REQUEST,
                    src_mac=arp_pkt.src_mac,
                    src_ip=arp_pkt.src_ip,
                    dst_mac=arp_pkt.dst_mac,
                    dst_ip=real_ip  # Translated to real IP
                )
                
                # Rebuild the packet with modified ARP
                modified_pkt = packet.Packet()
                modified_pkt.add_protocol(ethernet.ethernet(
                    ethertype=eth.ethertype,
                    dst=eth.dst,
                    src=eth.src
                ))
                modified_pkt.add_protocol(modified_arp)
                modified_pkt.serialize()
                
                # Send modified packet for normal processing
                out = parser.OFPPacketOut(
                    datapath=datapath,
                    buffer_id=ofproto.OFP_NO_BUFFER,
                    in_port=in_port,
                    actions=[parser.OFPActionOutput(ofproto.OFPP_NORMAL)],
                    data=modified_pkt.data
                )
                datapath.send_msg(out)
                
                self.logger.info(f"✅ ARP Request Translation: {target_ip} -> {real_ip}")
                return True
        
        # Handle ARP REPLY
        elif arp_pkt.opcode == arp.ARP_REPLY:
            src_ip = arp_pkt.src_ip
            
            # If reply is from a real IP that has a virtual mapping
            if src_ip in self.real_to_virtual:
                virtual_ip = self.real_to_virtual[src_ip]
                
                # Modify the ARP reply: change src_ip from real to virtual
                modified_arp = arp.arp(
                    opcode=arp.ARP_REPLY,
                    src_mac=arp_pkt.src_mac,
                    src_ip=virtual_ip,  # Translated to virtual IP
                    dst_mac=arp_pkt.dst_mac,
                    dst_ip=arp_pkt.dst_ip
                )
                
                # Rebuild the packet
                modified_pkt = packet.Packet()
                modified_pkt.add_protocol(ethernet.ethernet(
                    ethertype=eth.ethertype,
                    dst=eth.dst,
                    src=eth.src
                ))
                modified_pkt.add_protocol(modified_arp)
                modified_pkt.serialize()
                
                # Send modified packet back to requester
                out = parser.OFPPacketOut(
                    datapath=datapath,
                    buffer_id=ofproto.OFP_NO_BUFFER,
                    in_port=in_port,
                    actions=[parser.OFPActionOutput(ofproto.OFPP_NORMAL)],
                    data=modified_pkt.data
                )
                datapath.send_msg(out)
                
                self.logger.info(f"✅ ARP Reply Translation: {src_ip} -> {virtual_ip}")
                return True
        
        return False

    def _install_translation_rules(self, datapath, client_ip, server_real_ip):
        """
        Install bidirectional flow rules for IP translation between client and server.
        """
        if server_real_ip not in self.real_to_virtual:
            self.logger.error(f"No virtual IP mapping for real IP {server_real_ip}")
            return
        
        server_virtual_ip = self.real_to_virtual[server_real_ip]
        
        # Check if client also has a virtual IP
        client_virtual_ip = None
        if client_ip in self.real_to_virtual:
            client_virtual_ip = self.real_to_virtual[client_ip]
        
        parser = datapath.ofproto_parser
        
        # Rule 1: Outbound traffic (client to virtual server)
        # Match: client to virtual IP, Action: translate to real IP
        match_out = parser.OFPMatch(
            eth_type=0x0800,
            ipv4_src=client_ip,
            ipv4_dst=server_virtual_ip
        )
        actions_out = [
            parser.OFPActionSetField(ipv4_dst=server_real_ip),
            parser.OFPActionOutput(datapath.ofproto.OFPP_NORMAL)
        ]
        self.add_flow(datapath, 100, match_out, actions_out, idle_timeout=300)
        
        # Rule 2: Inbound traffic (server to client)
        # Match: server real IP to client, Action: translate to virtual IP
        match_in = parser.OFPMatch(
            eth_type=0x0800,
            ipv4_src=server_real_ip,
            ipv4_dst=client_ip
        )
        
        actions_in = [parser.OFPActionSetField(ipv4_src=server_virtual_ip)]
        
        # If client has a virtual IP, translate destination too
        if client_virtual_ip:
            actions_in.append(parser.OFPActionSetField(ipv4_dst=client_virtual_ip))
        
        actions_in.append(parser.OFPActionOutput(datapath.ofproto.OFPP_NORMAL))
        
        self.add_flow(datapath, 100, match_in, actions_in, idle_timeout=300)
        
        self.logger.info(f"✅ Installed translation rules: {client_ip} <-> {server_virtual_ip} ({server_real_ip})")

    def _forward_packet_normal(self, datapath, in_port, msg):
        """Forward a packet through normal processing (not through controller)."""
        parser = datapath.ofproto_parser
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=datapath.ofproto.OFP_NO_BUFFER,
            in_port=in_port,
            actions=[parser.OFPActionOutput(datapath.ofproto.OFPP_NORMAL)],
            data=msg.data
        )
        datapath.send_msg(out)

    def _do_layer2_switching(self, pkt, datapath, in_port, msg):
        """
        Perform basic Layer 2 switching with MAC learning.
        """
        eth = pkt.get_protocol(ethernet.ethernet)
        if not eth:
            return
            
        dpid = datapath.id
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        
        # Learn MAC address
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][eth.src] = in_port
        
        # Check if destination MAC is known
        if eth.dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][eth.dst]
        else:
            out_port = ofproto.OFPP_FLOOD
        
        # For data packets, check if translation rules are needed
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if ip_pkt:
            # If destination is a virtual IP, ensure translation rule exists
            if ip_pkt.dst in self.virtual_to_real:
                real_ip = self.virtual_to_real[ip_pkt.dst]
                rule_key = f"{ip_pkt.src}<->{ip_pkt.dst}"
                if rule_key not in self.installed_flow_rules:
                    self._install_translation_rules(datapath, ip_pkt.src, real_ip)
                    self.installed_flow_rules.add(rule_key)
                    self.logger.debug(f"✅ Data packet to virtual IP {ip_pkt.dst}, installed translation rules")
        
        # Install flow rule to avoid controller for future packets
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(
                in_port=in_port,
                eth_dst=eth.dst,
                eth_src=eth.src
            )
            actions = [parser.OFPActionOutput(out_port)]
            
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 10, match, actions, msg.buffer_id)
                return
        
        # Send packet out
        actions = [parser.OFPActionOutput(out_port)]
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
            
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=data
        )
        datapath.send_msg(out)
        
        self.logger.debug(f"L2 switching: {eth.src[:8]}... -> {eth.dst[:8]}... via port {out_port}")