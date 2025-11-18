from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, udp
from dnslib import DNSRecord, DNSHeader, RR, QTYPE, A
import logging

class DNSInterceptor(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(DNSInterceptor, self).__init__(*args, **kwargs)
        self.logger.setLevel(logging.INFO)
        self.logger.info("DNS Interceptor started - will reply with virtual IPs")

        # Define a simple mapping: domain name → virtual IP
        self.domain_to_virtual_ip = {
            "host2.com": "10.0.0.100"
        }

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        pkt = packet.Packet(msg.data)

        # Extract protocols
        eth = pkt.get_protocol(ethernet.ethernet)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        udp_pkt = pkt.get_protocol(udp.udp)

        # Process only DNS packets (requests to port 53)
        if not (eth and ip_pkt and udp_pkt and udp_pkt.dst_port == 53):
            return

        try:
            # Locate DNS payload
            protocols = pkt.protocols
            udp_index = protocols.index(udp_pkt)
            if udp_index + 1 >= len(protocols):
                return
            dns_payload = protocols[udp_index + 1]
            if not isinstance(dns_payload, bytes) or len(dns_payload) < 12:
                return

            # Parse DNS request
            dns_req = DNSRecord.parse(dns_payload)
            if not dns_req.questions:
                return

            # Extract requested domain name
            q = dns_req.questions[0]
            qname = str(q.get_qname())
            domain = qname.rstrip('.')  # Remove trailing dot

            # Check if this domain is in our protected list
            if domain not in self.domain_to_virtual_ip:
                self.logger.info(f"Ignoring DNS query for non-protected domain: {domain}")
                return

            # Get virtual IP
            virtual_ip = self.domain_to_virtual_ip[domain]
            self.logger.info(f"Intercepting DNS query for {domain} → replying with {virtual_ip}")

            # Construct DNS reply
            dns_reply = DNSRecord(
                header=DNSHeader(id=dns_req.header.id, qr=1, aa=1, ra=1),
                q=dns_req.q
            )
            dns_reply.add_answer(RR(qname, QTYPE.A, rdata=A(virtual_ip), ttl=0))

            # Build reply packet
            reply_pkt = packet.Packet()
            reply_pkt.add_protocol(ethernet.ethernet(
                ethertype=eth.ethertype,
                dst=eth.src,
                src=eth.dst
            ))
            reply_pkt.add_protocol(ipv4.ipv4(
                src=ip_pkt.dst,  # DNS server (e.g., 10.0.0.10)
                dst=ip_pkt.src,  # Client (e.g., 10.0.0.1)
                proto=ip_pkt.proto
            ))
            reply_pkt.add_protocol(udp.udp(
                src_port=udp_pkt.dst_port,  # 53
                dst_port=udp_pkt.src_port   # Client port
            ))
            reply_pkt.add_protocol(dns_reply.pack())

            # Serialize and send reply
            reply_pkt.serialize()
            out = parser.OFPPacketOut(
                datapath=datapath,
                buffer_id=ofproto.OFP_NO_BUFFER,
                in_port=ofproto.OFPP_CONTROLLER,
                actions=[parser.OFPActionOutput(msg.match['in_port'])],
                data=reply_pkt.data
            )
            datapath.send_msg(out)

            # BLOCK FUTURE DNS RESPONSES FROM REAL DNS SERVER
            # Install a high-priority flow rule to DROP any future DNS response from the real DNS server
            match = parser.OFPMatch(
                eth_type=0x0800,           # IPv4
                ip_proto=17,               # UDP
                ipv4_src="10.0.0.10",      # Real DNS server IP
                ipv4_dst=ip_pkt.src,       # Client IP
                udp_src=53,                # DNS port
                udp_dst=udp_pkt.src_port   # Client's DNS query port
            )
            # No actions = DROP
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, [])]
            mod = parser.OFPFlowMod(
                datapath=datapath,
                priority=200,              # Higher than normal flows
                match=match,
                instructions=inst,
                hard_timeout=10            # Block for 10 seconds (enough for DNS resolution)
            )
            datapath.send_msg(mod)
            self.logger.info(f"Blocked future DNS responses from 10.0.0.10 to {ip_pkt.src}:{udp_pkt.src_port}")

        except Exception as e:
            self.logger.error(f"Error handling DNS query: {e}")