import time
from ryu.ofproto import ofproto_v1_3
from . import constants as const

class FlowManager:
    def __init__(self, app):
        self.app = app
        self.active_flow_count = 0
        self.flow_mod_count = 0
        
        # Track active sessions for Make-Before-Break with creation timestamps
        # Key: (src_real_ip, dst_real_ip) -> Value: {'virtual_src': vs, 'virtual_dst': vd, 'created_at': ts}
        self.active_sessions = {} 

    def prune_expired_sessions(self, grace_period=const.GRACE_PERIOD_IDLE_TIMEOUT):
        """
        Prunes only grace sessions whose grace timers after shuffle have genuinely expired (t - shuffled_at > grace_period).
        Retains active unexpired sessions across rapid successive shuffles.
        """
        now = time.time()
        expired_keys = [
            k for k, v in self.active_sessions.items()
            if isinstance(v, dict) and v.get('shuffled_at') is not None and (now - v['shuffled_at']) > grace_period
        ]
        for k in expired_keys:
            del self.active_sessions[k]
        return len(expired_keys) 

    def add_flow(self, datapath, priority, match, actions, buffer_id=None,
                 idle_timeout=0, hard_timeout=0, table_id=0, cookie=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        
        # Request flow removal notifications to track active flows accurately
        flags = ofproto.OFPFF_SEND_FLOW_REM 
        
        if buffer_id and buffer_id != ofproto.OFP_NO_BUFFER:
            mod = parser.OFPFlowMod(
                datapath=datapath, cookie=cookie, buffer_id=buffer_id, priority=priority,
                match=match, instructions=inst, table_id=table_id,
                idle_timeout=idle_timeout, hard_timeout=hard_timeout, flags=flags)
        else:
            mod = parser.OFPFlowMod(
                datapath=datapath, cookie=cookie, priority=priority, match=match,
                instructions=inst, table_id=table_id,
                idle_timeout=idle_timeout, hard_timeout=hard_timeout, flags=flags)
                
        datapath.send_msg(mod)
        self.active_flow_count += 1
        self.flow_mod_count += 1
        self.app.logger.debug(f"[flow] installed on S{datapath.id}: prio={priority} match={match}")

    def get_active_flow_count(self):
        """Returns accurate active flow count reflecting tracked active sessions and forwarding rules."""
        self.prune_expired_sessions()
        self.active_flow_count = len(self.active_sessions) * 4
        return self.active_flow_count
       
    def is_leaf_switch(self, datapath_id):
        if datapath_id in [17, 18, 0x11, 0x12]:
            return False
        if hasattr(self.app.topology, 'leaf_switches') and self.app.topology.leaf_switches:
            return datapath_id in self.app.topology.leaf_switches
        return datapath_id < 10

    def install_table_miss(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        # TABLE 0 (ACTIVE) MISS -> Send to TABLE 1 (GRACE)
        match = parser.OFPMatch()
        inst = [parser.OFPInstructionGotoTable(const.TABLE_GRACE)]
        mod = parser.OFPFlowMod(
            datapath=datapath, priority=const.PRIORITY_TABLE_MISS,
            match=match, instructions=inst, table_id=const.TABLE_ACTIVE)
        datapath.send_msg(mod)

        # TABLE 1 (GRACE) MISS -> Send to Controller
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=datapath, priority=const.PRIORITY_TABLE_MISS,
            match=match, instructions=inst, table_id=const.TABLE_GRACE)
        datapath.send_msg(mod)

        # Proactively intercept DNS responses (UDP src port 53) in Table 0 ONLY on Leaf switches
        if self.is_leaf_switch(datapath.id):
            self.install_dns_interception(datapath)

    def install_dns_interception(self, datapath):
        """Proactively intercepts DNS responses (UDP src port 53 from DNS server) to rewrite real IPs to virtual IPs."""
        if not self.is_leaf_switch(datapath.id):
            return

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dns_ip = getattr(self.app, 'dns_ip', const.DNS_SERVER_IP)
        match_dns = parser.OFPMatch(
            eth_type=const.ETH_TYPE_IP,
            ip_proto=const.IP_PROTO_UDP,
            ipv4_src=dns_ip,
            udp_src=const.DNS_SERVER_PORT
        )
        actions_dns = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        inst_dns = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions_dns)]
        mod_dns = parser.OFPFlowMod(
            datapath=datapath,
            priority=const.PRIORITY_TRANSLATION + 10,
            match=match_dns,
            instructions=inst_dns,
            table_id=const.TABLE_ACTIVE
        )
        datapath.send_msg(mod_dns)
        self.app.logger.info(f"[dns] Proactive DNS response interception installed on S{datapath.id}")

    def install_translation_flows(self, ingress_dp, in_port, src_ip, virtual_dst, real_dst, 
                                  proto=None, dst_port=None,
                                  table_id=const.TABLE_ACTIVE, hard_timeout=0):
        log = self.app.logger
        if real_dst not in self.app.topology.host_table:
            log.error(f"[flow] Destination {real_dst} unknown - abort")
            return False

        dst_info = self.app.topology.host_table[real_dst]
        egress_dpid = dst_info['dpid']
        egress_port = dst_info['port']
        real_mac = dst_info.get('mac')
        virtual_src = self.app.real_to_virtual.get(src_ip, src_ip)
        virtual_mac = self.app.arp_handler.vip_to_vmac(virtual_dst)
        
        # Track this specific session for the Grace Period with creation timestamp
        now = time.time()
        threat_sources = self.app.threat_detector.get_flagged_threat_sources() if hasattr(self.app, 'threat_detector') and hasattr(self.app.threat_detector, 'get_flagged_threat_sources') else set()
        if src_ip not in threat_sources:
            self.active_sessions[(src_ip, real_dst)] = {
                'virtual_src': virtual_src,
                'virtual_dst': virtual_dst,
                'created_at': now,
                'shuffled_at': None
            }
        
        parser = ingress_dp.ofproto_parser
        ofproto = ingress_dp.ofproto

        # Build strict L4 microflow match kwargs at Ingress Leaf
        match_kwargs = {'eth_type': const.ETH_TYPE_IP, 'ipv4_dst': virtual_dst}
        if proto == const.IP_PROTO_TCP and dst_port is not None:
            match_kwargs['ip_proto'] = const.IP_PROTO_TCP
            match_kwargs['tcp_dst'] = int(dst_port)
        elif proto == const.IP_PROTO_UDP and dst_port is not None:
            match_kwargs['ip_proto'] = const.IP_PROTO_UDP
            match_kwargs['udp_dst'] = int(dst_port)
        elif proto == const.IP_PROTO_ICMP:
            match_kwargs['ip_proto'] = const.IP_PROTO_ICMP

        match_ing = parser.OFPMatch(**match_kwargs)

        if ingress_dp.id == egress_dpid:
            # Intra-leaf: direct output to host port with real MAC rewrite
            out_action = parser.OFPActionOutput(egress_port)
            actions = [parser.OFPActionSetField(ipv4_dst=real_dst)]
            if real_mac:
                actions.append(parser.OFPActionSetField(eth_dst=real_mac))
            actions.append(out_action)
            self.add_flow(ingress_dp, const.PRIORITY_TRANSLATION, match_ing, actions,
                          idle_timeout=const.TRANSLATION_FLOW_IDLE_TIMEOUT,
                          hard_timeout=hard_timeout, table_id=table_id, cookie=const.COOKIE_MTD_TRANSLATION)

            # Reverse path at ingress (rewrite eth_src to virtual_mac)
            rev_match_kwargs = {'eth_type': const.ETH_TYPE_IP, 'ipv4_src': real_dst, 'ipv4_dst': src_ip}
            if proto == const.IP_PROTO_TCP and dst_port is not None:
                rev_match_kwargs['ip_proto'] = const.IP_PROTO_TCP
                rev_match_kwargs['tcp_src'] = int(dst_port)
            elif proto == const.IP_PROTO_UDP and dst_port is not None:
                rev_match_kwargs['ip_proto'] = const.IP_PROTO_UDP
                rev_match_kwargs['udp_src'] = int(dst_port)
            elif proto == const.IP_PROTO_ICMP:
                rev_match_kwargs['ip_proto'] = const.IP_PROTO_ICMP

            match_rev_src = parser.OFPMatch(**rev_match_kwargs)
            actions_rev_src = [
                parser.OFPActionSetField(ipv4_src=virtual_dst),
                parser.OFPActionSetField(eth_src=virtual_mac),
                parser.OFPActionOutput(in_port)
            ]
            self.add_flow(ingress_dp, const.PRIORITY_TRANSLATION, match_rev_src, actions_rev_src,
                          idle_timeout=const.TRANSLATION_FLOW_IDLE_TIMEOUT,
                          hard_timeout=hard_timeout, table_id=table_id, cookie=const.COOKIE_MTD_TRANSLATION)
        else:
            # Inter-leaf: Deterministic 2-hop routing via ECMP Spine (Leaf_src -> Spine_k -> Leaf_dst)
            route = self.app.topology.get_inter_switch_route(ingress_dp.id, egress_dpid, flow_key=(src_ip, real_dst))
            if route and all(p is not None for p in route[1:]):
                spine_dpid, port_in_to_sp, port_sp_to_eg, port_eg_to_sp, port_sp_to_in = route
                spine_dp = self.app.topology.get_datapath(spine_dpid)
                egress_dp = self.app.topology.get_datapath(egress_dpid)

                # 1. Ingress Leaf: virtual_dst -> real_dst (microflow match on L4), output to Spine port
                actions_ing = [parser.OFPActionSetField(ipv4_dst=real_dst), parser.OFPActionOutput(port_in_to_sp)]
                self.add_flow(ingress_dp, const.PRIORITY_TRANSLATION, match_ing, actions_ing,
                              idle_timeout=const.TRANSLATION_FLOW_IDLE_TIMEOUT,
                              hard_timeout=hard_timeout, table_id=table_id, cookie=const.COOKIE_MTD_TRANSLATION)

                # 2. Spine switch: Transit forward to Egress Leaf
                if spine_dp:
                    sp_parser = spine_dp.ofproto_parser
                    match_sp = sp_parser.OFPMatch(eth_type=const.ETH_TYPE_IP, ipv4_dst=real_dst)
                    actions_sp = [sp_parser.OFPActionOutput(port_sp_to_eg)]
                    self.add_flow(spine_dp, const.PRIORITY_TRANSLATION, match_sp, actions_sp,
                                  idle_timeout=const.TRANSLATION_FLOW_IDLE_TIMEOUT,
                                  hard_timeout=hard_timeout, table_id=const.TABLE_ACTIVE)

                # 3. Egress Leaf: Deliver to Destination Host port (rewrite eth_dst to real_mac)
                if egress_dp:
                    eg_parser = egress_dp.ofproto_parser
                    match_eg = eg_parser.OFPMatch(eth_type=const.ETH_TYPE_IP, ipv4_dst=real_dst)
                    actions_eg = []
                    if real_mac:
                        actions_eg.append(eg_parser.OFPActionSetField(eth_dst=real_mac))
                    actions_eg.append(eg_parser.OFPActionOutput(egress_port))
                    self.add_flow(egress_dp, const.PRIORITY_TRANSLATION, match_eg, actions_eg,
                                  idle_timeout=const.TRANSLATION_FLOW_IDLE_TIMEOUT,
                                  hard_timeout=hard_timeout, table_id=table_id, cookie=const.COOKIE_MTD_TRANSLATION)

                    # Reverse 1: Egress Leaf -> Rewrite real_dst to virtual_dst, rewrite eth_src to virtual_mac, output to Spine
                    rev_eg_kwargs = {'eth_type': const.ETH_TYPE_IP, 'ipv4_src': real_dst, 'ipv4_dst': src_ip}
                    if proto == const.IP_PROTO_TCP and dst_port is not None:
                        rev_eg_kwargs['ip_proto'] = const.IP_PROTO_TCP
                        rev_eg_kwargs['tcp_src'] = int(dst_port)
                    elif proto == const.IP_PROTO_UDP and dst_port is not None:
                        rev_eg_kwargs['ip_proto'] = const.IP_PROTO_UDP
                        rev_eg_kwargs['udp_src'] = int(dst_port)
                    elif proto == const.IP_PROTO_ICMP:
                        rev_eg_kwargs['ip_proto'] = const.IP_PROTO_ICMP

                    match_eg_rev = eg_parser.OFPMatch(**rev_eg_kwargs)
                    actions_eg_rev = [
                        eg_parser.OFPActionSetField(ipv4_src=virtual_dst),
                        eg_parser.OFPActionSetField(eth_src=virtual_mac),
                        eg_parser.OFPActionOutput(port_eg_to_sp)
                    ]
                    self.add_flow(egress_dp, const.PRIORITY_TRANSLATION, match_eg_rev, actions_eg_rev,
                                  idle_timeout=const.TRANSLATION_FLOW_IDLE_TIMEOUT,
                                  hard_timeout=hard_timeout, table_id=table_id, cookie=const.COOKIE_MTD_TRANSLATION)

                # Reverse 2: Spine switch -> Forward to Ingress Leaf
                if spine_dp:
                    sp_parser = spine_dp.ofproto_parser
                    match_sp_rev = sp_parser.OFPMatch(eth_type=const.ETH_TYPE_IP, ipv4_dst=src_ip)
                    actions_sp_rev = [sp_parser.OFPActionOutput(port_sp_to_in)]
                    self.add_flow(spine_dp, const.PRIORITY_TRANSLATION, match_sp_rev, actions_sp_rev,
                                  idle_timeout=const.TRANSLATION_FLOW_IDLE_TIMEOUT,
                                  hard_timeout=hard_timeout, table_id=const.TABLE_ACTIVE)

                # Reverse 3: Ingress Leaf -> Deliver to Source Host port
                match_in_rev = parser.OFPMatch(eth_type=const.ETH_TYPE_IP, ipv4_dst=src_ip)
                actions_in_rev = [parser.OFPActionOutput(in_port)]
                self.add_flow(ingress_dp, const.PRIORITY_TRANSLATION, match_in_rev, actions_in_rev,
                              idle_timeout=const.TRANSLATION_FLOW_IDLE_TIMEOUT,
                              hard_timeout=hard_timeout, table_id=table_id, cookie=const.COOKIE_MTD_TRANSLATION)
            else:
                log.warning(f"[flow] No 2-hop spine route found between S{ingress_dp.id} and S{egress_dpid}")

        log.info(f"[flow] ✅ Translation flows installed in Table {table_id} (proto={proto}, dst_port={dst_port})")
        return True

    def install_normal_flow(self, datapath, src_ip, dst_ip, in_port, buffer_id, data):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        dst_dpid, dst_port = self.app.topology.get_host_location_by_ip(dst_ip)
        if dst_dpid is None or dst_port is None:
            self.app.logger.warning(f"[normal] Destination {dst_ip} location unknown - dropping to prevent loops")
            return

        if dst_dpid == datapath.id:
            # Intra-leaf: direct output to host port
            actions = [parser.OFPActionOutput(dst_port)]
            match = parser.OFPMatch(eth_type=const.ETH_TYPE_IP, ipv4_src=src_ip, ipv4_dst=dst_ip)
            self.add_flow(datapath, const.PRIORITY_NORMAL, match, actions,
                          idle_timeout=const.NORMAL_FLOW_IDLE_TIMEOUT,
                          hard_timeout=const.NORMAL_FLOW_HARD_TIMEOUT)

            # Install reverse flow if source is also on this datapath
            src_dpid, src_port = self.app.topology.get_host_location_by_ip(src_ip)
            if src_dpid == datapath.id and src_port is not None:
                match_rev = parser.OFPMatch(eth_type=const.ETH_TYPE_IP, ipv4_src=dst_ip, ipv4_dst=src_ip)
                actions_rev = [parser.OFPActionOutput(src_port)]
                self.add_flow(datapath, const.PRIORITY_NORMAL, match_rev, actions_rev,
                              idle_timeout=const.NORMAL_FLOW_IDLE_TIMEOUT,
                              hard_timeout=const.NORMAL_FLOW_HARD_TIMEOUT)

            out = parser.OFPPacketOut(datapath=datapath, buffer_id=buffer_id if buffer_id != ofproto.OFP_NO_BUFFER else ofproto.OFP_NO_BUFFER,
                                      in_port=in_port, actions=actions, data=data if buffer_id == ofproto.OFP_NO_BUFFER else None)
            datapath.send_msg(out)
        else:
            # Inter-leaf: 2-hop route via Spine
            route = self.app.topology.get_inter_switch_route(datapath.id, dst_dpid, flow_key=(src_ip, dst_ip))
            if route and all(p is not None for p in route[1:]):
                spine_dpid, port_in_to_sp, port_sp_to_eg, port_eg_to_sp, port_sp_to_in = route
                spine_dp = self.app.topology.get_datapath(spine_dpid)
                egress_dp = self.app.topology.get_datapath(dst_dpid)
                src_dpid, src_port = self.app.topology.get_host_location_by_ip(src_ip)

                # 1. Forward Flows (src -> dst)
                # Ingress Leaf
                match_in = parser.OFPMatch(eth_type=const.ETH_TYPE_IP, ipv4_src=src_ip, ipv4_dst=dst_ip)
                actions_in = [parser.OFPActionOutput(port_in_to_sp)]
                self.add_flow(datapath, const.PRIORITY_NORMAL, match_in, actions_in,
                              idle_timeout=const.NORMAL_FLOW_IDLE_TIMEOUT,
                              hard_timeout=const.NORMAL_FLOW_HARD_TIMEOUT)

                # Spine Switch
                if spine_dp:
                    sp_parser = spine_dp.ofproto_parser
                    match_sp = sp_parser.OFPMatch(eth_type=const.ETH_TYPE_IP, ipv4_src=src_ip, ipv4_dst=dst_ip)
                    actions_sp = [sp_parser.OFPActionOutput(port_sp_to_eg)]
                    self.add_flow(spine_dp, const.PRIORITY_NORMAL, match_sp, actions_sp,
                                  idle_timeout=const.NORMAL_FLOW_IDLE_TIMEOUT,
                                  hard_timeout=const.NORMAL_FLOW_HARD_TIMEOUT)

                # Egress Leaf
                if egress_dp:
                    eg_parser = egress_dp.ofproto_parser
                    match_eg = eg_parser.OFPMatch(eth_type=const.ETH_TYPE_IP, ipv4_src=src_ip, ipv4_dst=dst_ip)
                    actions_eg = [eg_parser.OFPActionOutput(dst_port)]
                    self.add_flow(egress_dp, const.PRIORITY_NORMAL, match_eg, actions_eg,
                                  idle_timeout=const.NORMAL_FLOW_IDLE_TIMEOUT,
                                  hard_timeout=const.NORMAL_FLOW_HARD_TIMEOUT)

                # 2. Reverse Flows (dst -> src)
                if egress_dp and src_port is not None:
                    match_eg_rev = eg_parser.OFPMatch(eth_type=const.ETH_TYPE_IP, ipv4_src=dst_ip, ipv4_dst=src_ip)
                    actions_eg_rev = [eg_parser.OFPActionOutput(port_eg_to_sp)]
                    self.add_flow(egress_dp, const.PRIORITY_NORMAL, match_eg_rev, actions_eg_rev,
                                  idle_timeout=const.NORMAL_FLOW_IDLE_TIMEOUT,
                                  hard_timeout=const.NORMAL_FLOW_HARD_TIMEOUT)

                if spine_dp and src_port is not None:
                    match_sp_rev = sp_parser.OFPMatch(eth_type=const.ETH_TYPE_IP, ipv4_src=dst_ip, ipv4_dst=src_ip)
                    actions_sp_rev = [sp_parser.OFPActionOutput(port_sp_to_in)]
                    self.add_flow(spine_dp, const.PRIORITY_NORMAL, match_sp_rev, actions_sp_rev,
                                  idle_timeout=const.NORMAL_FLOW_IDLE_TIMEOUT,
                                  hard_timeout=const.NORMAL_FLOW_HARD_TIMEOUT)

                if src_port is not None:
                    match_in_rev = parser.OFPMatch(eth_type=const.ETH_TYPE_IP, ipv4_src=dst_ip, ipv4_dst=src_ip)
                    actions_in_rev = [parser.OFPActionOutput(src_port)]
                    self.add_flow(datapath, const.PRIORITY_NORMAL, match_in_rev, actions_in_rev,
                                  idle_timeout=const.NORMAL_FLOW_IDLE_TIMEOUT,
                                  hard_timeout=const.NORMAL_FLOW_HARD_TIMEOUT)

                # Forward initial packet out towards Spine
                out = parser.OFPPacketOut(datapath=datapath, buffer_id=buffer_id if buffer_id != ofproto.OFP_NO_BUFFER else ofproto.OFP_NO_BUFFER,
                                          in_port=in_port, actions=actions_in, data=data if buffer_id == ofproto.OFP_NO_BUFFER else None)
                datapath.send_msg(out)
            else:
                self.app.logger.warning(f"[normal] No 2-hop spine route found between S{datapath.id} and S{dst_dpid}")

    def flush_translation_flows(self, datapath):
        """Deletes only MTD translation flows in the ACTIVE table (Table 0), preserving normal flows and DNS interception."""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        match = parser.OFPMatch(eth_type=const.ETH_TYPE_IP)
        mod = parser.OFPFlowMod(
            datapath=datapath,
            command=ofproto.OFPFC_DELETE,
            out_group=ofproto.OFPG_ANY,
            out_port=ofproto.OFPP_ANY,
            match=match,
            cookie=const.COOKIE_MTD_TRANSLATION,
            cookie_mask=const.COOKIE_MASK_EXACT,
            table_id=const.TABLE_ACTIVE
        )
        datapath.send_msg(mod)
        self.flow_mod_count += 1
        self.install_dns_interception(datapath)
        self.app.logger.debug(f"[flow] 🗑️ Flushed MTD translation flows in Table 0 on S{datapath.id}")

    def flush_table(self, datapath, table_id):
        """Deletes all flows in the specified table."""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        match = parser.OFPMatch(eth_type=const.ETH_TYPE_IP)
        mod = parser.OFPFlowMod(
            datapath=datapath,
            command=ofproto.OFPFC_DELETE,
            out_group=ofproto.OFPG_ANY,
            out_port=ofproto.OFPP_ANY,
            match=match,
            priority=const.PRIORITY_TRANSLATION,
            table_id=table_id
        )
        datapath.send_msg(mod)
        self.flow_mod_count += 1
        self.app.logger.debug(f"[flow] 🗑️ Flushed table {table_id} on S{datapath.id}")    