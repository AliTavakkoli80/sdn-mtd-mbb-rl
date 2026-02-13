from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, set_ev_cls
from ryu.lib.packet import packet, ethernet, arp, ipv4
from . import constants as const

class PacketInHandler:
    def __init__(self, app):
        self.app = app

    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if eth.ethertype == const.ETH_TYPE_LLDP:
            return

        pkt_type = self._packet_type(pkt)
        self.app.logger.info(f"\n{'='*80}")
        self.app.logger.info(f"📥 PACKET_IN | S{datapath.id}:{in_port} | {pkt_type}")
        self.app.logger.info(f"   {eth.src} → {eth.dst} | EtherType={hex(eth.ethertype)}")

        arp_pkt = pkt.get_protocol(arp.arp)
        if arp_pkt:
            self.app.arp_handler.handle_arp(datapath, in_port, pkt, eth, arp_pkt, msg.buffer_id)
            return

        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
        if ipv4_pkt:
            self.app.ipv4_handler.handle_ipv4(datapath, in_port, pkt, eth, ipv4_pkt, msg.buffer_id, msg.data)
            return

        self.app.logger.warning(f"[packet] unknown type {hex(eth.ethertype)} - flood locally")
        self._flood_locally(datapath, in_port, msg.buffer_id, msg.data)

    def _packet_type(self, pkt):
        if pkt.get_protocol(arp.arp):
            return "ARP"
        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
        if ipv4_pkt:
            proto = {1:'ICMP',6:'TCP',17:'UDP'}.get(ipv4_pkt.proto, str(ipv4_pkt.proto))
            return f"IPv4/{proto}"
        return "UNKNOWN"

    def _flood_locally(self, datapath, in_port, buffer_id, data):
        if datapath.id not in self.app.topology.access_ports:
            return
        ports = [p for p in self.app.topology.access_ports[datapath.id] if p != in_port]
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