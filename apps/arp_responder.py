from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, arp
import logging

class ARPResponder(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(ARPResponder, self).__init__(*args, **kwargs)
        self.logger.setLevel(logging.INFO)
        self.logger.info("ARP Responder started")

        # List of virtual IPs that should respond to ARP requests
        self.virtual_ips = ["10.0.0.100"]

        # Fake MAC address for ARP replies
        self.virtual_mac = "aa:bb:cc:dd:ee:ff"

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)  # Get Ethernet header
        arp_pkt = pkt.get_protocol(arp.arp)        # Get ARP header

        if eth and arp_pkt and arp_pkt.opcode == arp.ARP_REQUEST:
            target_ip = arp_pkt.dst_ip
            if target_ip in self.virtual_ips:
                self._send_arp_reply(datapath, in_port, eth, arp_pkt)
                self.logger.info(f"Sent ARP reply for virtual IP: {target_ip}")

    def _send_arp_reply(self, datapath, in_port, eth, arp_request):
        """Send ARP reply for virtual IP address"""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Build ARP reply packet
        arp_reply = packet.Packet()
        arp_reply.add_protocol(ethernet.ethernet(
            ethertype=eth.ethertype,  # Use Ethernet's ethertype (0x0806 for ARP)
            dst=arp_request.src_mac,  # Request sender's MAC
            src=self.virtual_mac      # Fake MAC
        ))
        arp_reply.add_protocol(arp.arp(
            opcode=arp.ARP_REPLY,
            src_mac=self.virtual_mac,
            src_ip=arp_request.dst_ip,  # Virtual IP
            dst_mac=arp_request.src_mac,
            dst_ip=arp_request.src_ip
        ))
        arp_reply.serialize()

        # Send reply back to the requesting port
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=ofproto.OFP_NO_BUFFER,
            in_port=ofproto.OFPP_CONTROLLER,
            actions=[parser.OFPActionOutput(in_port)],
            data=arp_reply.data
        )
        datapath.send_msg(out)