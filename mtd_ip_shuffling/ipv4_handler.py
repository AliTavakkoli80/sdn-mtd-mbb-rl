from ryu.lib.packet import packet, ethernet, ipv4, udp
from . import constants as const
from dnslib import DNSRecord, QTYPE, A

class IPv4Handler:
    def __init__(self, app):
        self.app = app

    def handle_ipv4(self, datapath, in_port, pkt, eth, ipv4_pkt, buffer_id, raw_data):
        src, dst = ipv4_pkt.src, ipv4_pkt.dst
        proto = {1:'ICMP',6:'TCP',17:'UDP'}.get(ipv4_pkt.proto, str(ipv4_pkt.proto))
        self.app.logger.info(f"[ipv4] {src} → {dst} | {proto} | TTL={ipv4_pkt.ttl}")
        self.app.topology.register_host(datapath.id, in_port, src, eth.src)

        # DNS response
        if ipv4_pkt.proto == const.IP_PROTO_UDP:
            udp_pkt = pkt.get_protocol(udp.udp)
            if udp_pkt and udp_pkt.src_port == const.DNS_SERVER_PORT:
                self.app.logger.info("[dns] DNS response intercepted")
                self._handle_dns_response(datapath, in_port, pkt, eth, ipv4_pkt, udp_pkt, buffer_id, raw_data)
                return

        # MTD translation
        if dst in self.app.virtual_to_real:
            real_dst = self.app.virtual_to_real[dst]
            self.app.logger.info(f"[mtd] virtual {dst} → real {real_dst}")
            self.app.flow_manager.install_translation_flows(datapath, in_port, src, dst, real_dst)
            self._translate_and_forward(datapath, in_port, dst, real_dst, buffer_id, raw_data)
        else:
            self.app.logger.info("[ipv4] normal traffic")
            self.app.flow_manager.install_normal_flow(datapath, src, dst, in_port, buffer_id, raw_data)

    def _translate_and_forward(self, datapath, in_port, virtual_dst, real_dst, buffer_id, raw_data):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        actions = [
            parser.OFPActionSetField(ipv4_dst=real_dst),
            parser.OFPActionOutput(ofproto.OFPP_NORMAL)
        ]
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=buffer_id,
            in_port=in_port,
            actions=actions,
            data=raw_data if buffer_id == ofproto.OFP_NO_BUFFER else None
        )
        datapath.send_msg(out)
        self.app.logger.info("[mtd] first packet translated")

    def _handle_dns_response(self, datapath, in_port, pkt, eth, ipv4_pkt, udp_pkt, buffer_id, raw_data):
        try:
            ip_hdr_len = ipv4_pkt.header_length * 4
            dns_start = 14 + ip_hdr_len + 8
            if len(raw_data) < dns_start + 12:
                self._forward_original(datapath, in_port, buffer_id, raw_data)
                return

            dns_payload = raw_data[dns_start:]
            dns_resp = DNSRecord.parse(dns_payload)

            if not (dns_resp.header.qr == 1 and dns_resp.rr):
                self._forward_original(datapath, in_port, buffer_id, raw_data)
                return

            modified = False
            for rr in dns_resp.rr:
                if rr.rtype == QTYPE.A and isinstance(rr.rdata, A):
                    real_ip = str(rr.rdata)
                    if real_ip in self.app.real_to_virtual:
                        virt_ip = self.app.real_to_virtual[real_ip]
                        rr.rdata = A(virt_ip)
                        modified = True
                        self.app.logger.info(f"[dns] {real_ip} → {virt_ip}")

            if not modified:
                self._forward_original(datapath, in_port, buffer_id, raw_data)
                return

            new_dns_data = dns_resp.pack()
            new_pkt = self._build_packet(eth, ipv4_pkt, udp_pkt, new_dns_data)
            new_pkt.serialize()

            client_ip = ipv4_pkt.dst
            dpid, port = self.app.topology.get_host_location_by_ip(client_ip)
            if dpid and port:
                dp = self.app.topology.get_datapath(dpid)
                if dp:
                    actions = [dp.ofproto_parser.OFPActionOutput(port)]
                    out = dp.ofproto_parser.OFPPacketOut(
                        datapath=dp,
                        buffer_id=dp.ofproto.OFP_NO_BUFFER,
                        in_port=dp.ofproto.OFPP_CONTROLLER,
                        actions=actions,
                        data=new_pkt.data
                    )
                    dp.send_msg(out)
                    self.app.logger.info(f"[dns] direct to client {client_ip}")
                    return

            self.app.logger.warning("[dns] client unknown - fallback")
            self._forward_original(datapath, in_port, buffer_id, new_pkt.data)

        except Exception as e:
            self.app.logger.error(f"[dns] error: {e}")
            self._forward_original(datapath, in_port, buffer_id, raw_data)

    def _build_packet(self, eth, ipv4_pkt, udp_pkt, dns_data):
        p = packet.Packet()
        p.add_protocol(ethernet.ethernet(dst=eth.dst, src=eth.src, ethertype=eth.ethertype))
        p.add_protocol(ipv4.ipv4(
            version=ipv4_pkt.version,
            header_length=ipv4_pkt.header_length,
            tos=ipv4_pkt.tos,
            total_length=20 + 8 + len(dns_data),
            identification=ipv4_pkt.identification,
            flags=ipv4_pkt.flags,
            offset=ipv4_pkt.offset,
            ttl=ipv4_pkt.ttl,
            proto=ipv4_pkt.proto,
            csum=0,
            src=ipv4_pkt.src,
            dst=ipv4_pkt.dst,
            option=ipv4_pkt.option
        ))
        p.add_protocol(udp.udp(
            src_port=udp_pkt.src_port,
            dst_port=udp_pkt.dst_port,
            total_length=8 + len(dns_data),
            csum=0
        ))
        p.add_protocol(dns_data)
        return p

    def _forward_original(self, datapath, in_port, buffer_id, data):
        actions = [datapath.ofproto_parser.OFPActionOutput(datapath.ofproto.OFPP_NORMAL)]
        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=buffer_id if buffer_id != datapath.ofproto.OFP_NO_BUFFER else datapath.ofproto.OFP_NO_BUFFER,
            in_port=in_port,
            actions=actions,
            data=data if buffer_id == datapath.ofproto.OFP_NO_BUFFER else None
        )
        datapath.send_msg(out)