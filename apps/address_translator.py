from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4
import logging

class AddressTranslator(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(AddressTranslator, self).__init__(*args, **kwargs)
        self.logger.setLevel(logging.INFO)
        self.logger.info("=" * 60)
        self.logger.info("Address Translator started - translating virtual ↔ real IPs")
        self.logger.info("=" * 60)
        
        # Mapping from virtual IP to real IP
        self.virtual_to_real = {
            "10.0.0.100": "10.0.0.2",  # host2.com
        }
        # Mapping from real IP to virtual IP
        self.real_to_virtual = {
            "10.0.0.2": "10.0.0.100",
        }
        
        # Statistics
        self.flow_rules_installed = 0

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ip_pkt = packet.Packet(msg.data).get_protocol(ipv4.ipv4)

        if not ip_pkt:
            return

        dst_ip = ip_pkt.dst

        # Install bidirectional rules only for virtual destination IPs
        if dst_ip in self.virtual_to_real:
            real_dst = self.virtual_to_real[dst_ip]
            self._install_bidirectional_rules(datapath, dst_ip, real_dst)
            self.logger.info(f"✓ BIDIRECTIONAL RULES FOR: {dst_ip} ↔ {real_dst}")

    def _install_bidirectional_rules(self, datapath, virtual_ip, real_ip):
        """Install both outbound and inbound flow rules together"""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Rule 1: Outbound (virtual IP → real IP)
        match_out = parser.OFPMatch(eth_type=0x0800, ipv4_dst=virtual_ip)
        actions_out = [
            parser.OFPActionSetField(ipv4_dst=real_ip),
            parser.OFPActionOutput(ofproto.OFPP_NORMAL)
        ]
        inst_out = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions_out)]
        mod_out = parser.OFPFlowMod(
            datapath=datapath,
            priority=100,
            match=match_out,
            instructions=inst_out,
            idle_timeout=300,
            hard_timeout=3600
        )
        datapath.send_msg(mod_out)

        # Rule 2: Inbound (real IP → virtual IP)
        match_in = parser.OFPMatch(eth_type=0x0800, ipv4_src=real_ip)
        actions_in = [
            parser.OFPActionSetField(ipv4_src=virtual_ip),
            parser.OFPActionOutput(ofproto.OFPP_NORMAL)
        ]
        inst_in = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions_in)]
        mod_in = parser.OFPFlowMod(
            datapath=datapath,
            priority=100,
            match=match_in,
            instructions=inst_in,
            idle_timeout=300,
            hard_timeout=3600
        )
        datapath.send_msg(mod_in)

        self.flow_rules_installed += 2
        self.logger.info(f"✓ INSTALLED 2 FLOWS: {virtual_ip} ↔ {real_ip} on switch {datapath.id}")