from ryu.lib.packet import packet, ethernet, ipv4, tcp, udp
from . import constants as const
from dnslib import DNSRecord, QTYPE, A
import socket

class IPv4Handler:
    def __init__(self, app):
        self.app = app

    def handle_ipv4(self, datapath, in_port, pkt, eth, ipv4_pkt, buffer_id, raw_data):
        src, dst = ipv4_pkt.src, ipv4_pkt.dst
        proto = ipv4_pkt.proto
        proto_name = {1:'ICMP',6:'TCP',17:'UDP'}.get(proto, str(proto))
        self.app.logger.info(f"[ipv4] {src} → {dst} | {proto_name} | TTL={ipv4_pkt.ttl}")
        self.app.topology.register_host(datapath.id, in_port, src, eth.src)

        dst_port = None
        if proto == 6:  # TCP
            tcp_pkt = pkt.get_protocol(tcp.tcp)
            if tcp_pkt:
                dst_port = tcp_pkt.dst_port
        elif proto == 17:  # UDP
            udp_pkt = pkt.get_protocol(udp.udp)
            if udp_pkt:
                dst_port = udp_pkt.dst_port

        # Feed all incoming IPv4 packets to threat detector without host exemptions
        self.app.threat_detector.process_packet(
            src_ip=src,
            dst_ip=dst,
            dst_port=dst_port,
            proto=proto
        )

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
            self.app.logger.info(f"[mtd] virtual {dst} → real {real_dst} (proto={proto_name}, port={dst_port})")
            self.app.flow_manager.install_translation_flows(
                datapath, in_port, src, dst, real_dst, proto=proto, dst_port=dst_port
            )
            self._translate_and_forward(datapath, in_port, dst, real_dst, buffer_id, raw_data)
        else:
            self.app.logger.info("[ipv4] normal traffic")
            self.app.flow_manager.install_normal_flow(datapath, src, dst, in_port, buffer_id, raw_data)

    def _translate_and_forward(self, datapath, in_port, virtual_dst, real_dst, buffer_id, raw_data):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        dpid, out_port = self.app.topology.get_host_location_by_ip(real_dst)
        if dpid == datapath.id and out_port is not None:
            out_action = parser.OFPActionOutput(out_port)
        else:
            route = self.app.topology.get_inter_switch_route(datapath.id, dpid, flow_key=real_dst)
            if route and route[1] is not None:
                out_action = parser.OFPActionOutput(route[1])
            else:
                self.app.logger.warning(f"[mtd] No inter-switch route found from S{datapath.id} to S{dpid} for {real_dst}")
                return
        actions = [
            parser.OFPActionSetField(ipv4_dst=real_dst),
            out_action
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
        client_ip = ipv4_pkt.dst
        try:
            # 1. Dynamically find the start of the IP header (Handles VLAN tags safely)
            ip_start = 14
            if len(raw_data) >= 18 and raw_data[12:14] == b'\x81\x00':
                ip_start = 18 # 802.1Q VLAN tag present
                
            ip_hdr_len = ipv4_pkt.header_length * 4
            udp_start = ip_start + ip_hdr_len
            dns_start = udp_start + 8
            
            if len(raw_data) < dns_start + 12:
                self._send_dns_packet(datapath, in_port, client_ip, bytes(raw_data))
                return

            # 2. Parse the DNS payload
            dns_payload = bytearray(raw_data[dns_start:])
            dns_resp = DNSRecord.parse(bytes(dns_payload))

            if not (dns_resp.header.qr == 1 and dns_resp.rr):
                self._send_dns_packet(datapath, in_port, client_ip, bytes(raw_data))
                return

            modified = False
            for rr in dns_resp.rr:
                if rr.rtype == QTYPE.A and isinstance(rr.rdata, A):
                    real_ip = str(rr.rdata)
                    if real_ip in self.app.real_to_virtual:
                        virt_ip = self.app.real_to_virtual[real_ip]
                        
                        # Find and replace the exact 4 bytes in the payload
                        real_bytes = socket.inet_aton(real_ip)
                        virt_bytes = socket.inet_aton(virt_ip)
                        
                        idx = dns_payload.find(real_bytes)
                        if idx != -1:
                            dns_payload[idx:idx+4] = virt_bytes
                            modified = True
                            self.app.logger.info(f"[dns] {real_ip} → {virt_ip}")

            if not modified:
                self._send_dns_packet(datapath, in_port, client_ip, bytes(raw_data))
                return

            # 3. Splice the modified DNS payload back into the original raw packet
            patched_raw_data = bytearray(raw_data)
            patched_raw_data[dns_start:dns_start+len(dns_payload)] = dns_payload

            # 4. Recalculate the IP Header Checksum (RFC 1071)
            patched_raw_data[ip_start + 10] = 0  # Zero out old checksum
            patched_raw_data[ip_start + 11] = 0
            
            ip_header = patched_raw_data[ip_start:ip_start+ip_hdr_len]
            if len(ip_header) % 2 == 1:
                ip_header += b'\0' # Pad if odd length
                
            s = 0
            for i in range(0, len(ip_header), 2):
                w = (ip_header[i] << 8) + ip_header[i+1]
                s += w
            s = (s >> 16) + (s & 0xffff)
            s += (s >> 16)
            new_csum = (~s) & 0xffff
            
            patched_raw_data[ip_start + 10] = (new_csum >> 8) & 0xff
            patched_raw_data[ip_start + 11] = new_csum & 0xff

            # 5. Force UDP Checksum to 0 (Valid for IPv4, prevents Linux kernel from dropping)
            udp_csum_offset = udp_start + 6
            patched_raw_data[udp_csum_offset] = 0
            patched_raw_data[udp_csum_offset + 1] = 0

            # 6. Deliver the modified DNS packet directly to the destination client
            self._send_dns_packet(datapath, in_port, client_ip, bytes(patched_raw_data))

        except Exception as e:
            self.app.logger.error(f"[dns] error: {e}")
            self._send_dns_packet(datapath, in_port, client_ip, bytes(raw_data))

    def _send_dns_packet(self, datapath, in_port, client_ip, packet_data):
        client_dpid, client_port = self.app.topology.get_host_location_by_ip(client_ip)
        if client_dpid and client_port:
            dp = self.app.topology.get_datapath(client_dpid)
            if dp and client_dpid == datapath.id:
                # Intra-leaf: direct output to host port
                actions = [dp.ofproto_parser.OFPActionOutput(client_port)]
                out = dp.ofproto_parser.OFPPacketOut(
                    datapath=dp, buffer_id=dp.ofproto.OFP_NO_BUFFER,
                    in_port=dp.ofproto.OFPP_CONTROLLER, actions=actions, data=packet_data
                )
                dp.send_msg(out)
                self.app.logger.info(f"[dns] Delivered directly to client {client_ip} on S{client_dpid}:p{client_port}")
                return
            elif dp:
                # Inter-leaf: route through spine to egress leaf
                route = self.app.topology.get_inter_switch_route(datapath.id, client_dpid, flow_key=client_ip)
                if route and route[1] is not None:
                    port_to_sp = route[1]
                    actions = [datapath.ofproto_parser.OFPActionOutput(port_to_sp)]
                    out = datapath.ofproto_parser.OFPPacketOut(
                        datapath=datapath, buffer_id=datapath.ofproto.OFP_NO_BUFFER,
                        in_port=datapath.ofproto.OFPP_CONTROLLER, actions=actions, data=packet_data
                    )
                    datapath.send_msg(out)
                    self.app.logger.info(f"[dns] Forwarded via Spine to client {client_ip} (S{client_dpid}:p{client_port})")
                    return

        self.app.logger.warning(f"[dns] Client {client_ip} location unknown - dropping packet to prevent loop")