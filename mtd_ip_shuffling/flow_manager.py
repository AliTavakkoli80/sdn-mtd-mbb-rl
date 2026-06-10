from ryu.ofproto import ofproto_v1_3
from . import constants as const

class FlowManager:
    def __init__(self, app):
        self.app = app
        self.active_flow_count = 0 # 🌟 Q1 UPGRADE: Track active flows for RL cost metric

    def add_flow(self, datapath, priority, match, actions, buffer_id=None,
                 idle_timeout=0, hard_timeout=0, table_id=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        
        # 🌟 Q1 UPGRADE: Request flow removal notifications to track active flows accurately
        flags = ofproto.OFPFF_SEND_FLOW_REM 
        
        if buffer_id and buffer_id != ofproto.OFP_NO_BUFFER:
            mod = parser.OFPFlowMod(
                datapath=datapath, buffer_id=buffer_id, priority=priority,
                match=match, instructions=inst, table_id=table_id,
                idle_timeout=idle_timeout, hard_timeout=hard_timeout, flags=flags)
        else:
            mod = parser.OFPFlowMod(
                datapath=datapath, priority=priority, match=match,
                instructions=inst, table_id=table_id,
                idle_timeout=idle_timeout, hard_timeout=hard_timeout, flags=flags)
                
        datapath.send_msg(mod)
        self.active_flow_count += 1 # Increment counter
        self.app.logger.debug(f"[flow] installed on S{datapath.id}: prio={priority} match={match}")
       
    def install_table_miss(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, const.PRIORITY_TABLE_MISS, match, actions)

    def install_translation_flows(self, ingress_dp, in_port, src_ip, virtual_dst, real_dst):
        log = self.app.logger
        if real_dst not in self.app.topology.host_table:
            log.error(f"[flow] Destination {real_dst} unknown - abort")
            return False

        dst_info = self.app.topology.host_table[real_dst]
        egress_dpid = dst_info['dpid']
        egress_port = dst_info['port']
        virtual_src = self.app.real_to_virtual.get(src_ip, src_ip)
        parser = ingress_dp.ofproto_parser
        ofproto = ingress_dp.ofproto

        # Ingress: virtual→real + NORMAL
        if ingress_dp.id in self.app.topology.access_ports:
            match = parser.OFPMatch(eth_type=const.ETH_TYPE_IP, ipv4_dst=virtual_dst)
            actions = [parser.OFPActionSetField(ipv4_dst=real_dst),
                       parser.OFPActionOutput(ofproto.OFPP_NORMAL)]
            self.add_flow(ingress_dp, const.PRIORITY_TRANSLATION, match, actions,
                          idle_timeout=const.TRANSLATION_FLOW_IDLE_TIMEOUT)

        # Egress (if different): real→virtual + direct output
        if egress_dpid != ingress_dp.id:
            egress_dp = self.app.topology.get_datapath(egress_dpid)
            if egress_dp and egress_dpid in self.app.topology.access_ports:
                match = parser.OFPMatch(eth_type=const.ETH_TYPE_IP, ipv4_src=src_ip, ipv4_dst=real_dst)
                actions = [parser.OFPActionSetField(ipv4_src=virtual_src),
                           parser.OFPActionOutput(egress_port)]
                self.add_flow(egress_dp, const.PRIORITY_TRANSLATION, match, actions,
                              idle_timeout=const.TRANSLATION_FLOW_IDLE_TIMEOUT)

                # Reverse path: from egress to ingress
                match_rev = parser.OFPMatch(eth_type=const.ETH_TYPE_IP, ipv4_dst=virtual_src)
                actions_rev = [parser.OFPActionSetField(ipv4_dst=src_ip),
                               parser.OFPActionOutput(ofproto.OFPP_NORMAL)]
                self.add_flow(egress_dp, const.PRIORITY_TRANSLATION, match_rev, actions_rev,
                              idle_timeout=const.TRANSLATION_FLOW_IDLE_TIMEOUT)

        # Reverse path at ingress: from dest to source
        if ingress_dp.id in self.app.topology.access_ports:
            match_rev_src = parser.OFPMatch(eth_type=const.ETH_TYPE_IP, ipv4_src=real_dst, ipv4_dst=src_ip)
            actions_rev_src = [parser.OFPActionSetField(ipv4_src=virtual_dst),
                               parser.OFPActionOutput(in_port)]
            self.add_flow(ingress_dp, const.PRIORITY_TRANSLATION, match_rev_src, actions_rev_src,
                          idle_timeout=const.TRANSLATION_FLOW_IDLE_TIMEOUT)

        log.info("[flow] ✅ Translation flows installed")
        return True

    def install_normal_flow(self, datapath, src_ip, dst_ip, in_port, buffer_id, data):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        actions = [parser.OFPActionOutput(ofproto.OFPP_NORMAL)]
        match = parser.OFPMatch(eth_type=const.ETH_TYPE_IP, ipv4_src=src_ip, ipv4_dst=dst_ip)
        self.add_flow(datapath, const.PRIORITY_NORMAL, match, actions,
                      idle_timeout=const.NORMAL_FLOW_IDLE_TIMEOUT,
                      hard_timeout=const.NORMAL_FLOW_HARD_TIMEOUT)
        if buffer_id != ofproto.OFP_NO_BUFFER:
            out = parser.OFPPacketOut(datapath=datapath, buffer_id=buffer_id,
                                      in_port=in_port, actions=actions)
        else:
            out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                                      in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
        self.app.logger.debug(f"[normal] flow for {src_ip}→{dst_ip}")

    def flush_translation_flows(self, datapath):
        """Deletes all flows with PRIORITY_TRANSLATION on a specific datapath."""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        # Match any IPv4 packet (eth_type=0x0800) to target our translation flows
        match = parser.OFPMatch(eth_type=const.ETH_TYPE_IP)
        
        mod = parser.OFPFlowMod(
            datapath=datapath,
            command=ofproto.OFPFC_DELETE,
            out_group=ofproto.OFPG_ANY,
            out_port=ofproto.OFPP_ANY,
            match=match,
            priority=const.PRIORITY_TRANSLATION
        )
        datapath.send_msg(mod)
        self.app.logger.debug(f"[flow] 🗑️ Flushed translation flows on S{datapath.id}")    