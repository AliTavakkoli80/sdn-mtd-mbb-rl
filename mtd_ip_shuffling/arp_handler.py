from ryu.lib.packet import packet, ethernet, arp
from . import constants as const

class ARPHandler:
    def __init__(self, app):
        self.app = app
        self.pending_virtual_arp = {}  # (requester_real_ip, target_real_ip) -> virtual_requested_ip

    @staticmethod
    def vip_to_vmac(vip_str: str) -> str:
        """
        Synthesizes a deterministic IEEE 802 locally administered unicast MAC address from a VIP.
        Format: 02:00:0a:00:00:xx where xx is the host/last octet in hex (matching 02:00:a:b:c:d).
        Sets IEEE 802 LAA bit (bit 1 of 1st octet is 1, bit 0 is 0 -> 0x02).
        """
        try:
            octets = [int(x) for x in str(vip_str).split('.')]
            if len(octets) == 4:
                return f"02:00:{octets[0]:02x}:{octets[1]:02x}:{octets[2]:02x}:{octets[3]:02x}"
        except Exception:
            pass
        return "02:00:0a:00:00:01"

    def handle_arp(self, datapath, in_port, pkt, eth, arp_pkt, buffer_id):
        op = "REQUEST" if arp_pkt.opcode == arp.ARP_REQUEST else "REPLY"
        self.app.logger.info(f"[arp] {op}: {arp_pkt.src_ip} ({arp_pkt.src_mac}) → {arp_pkt.dst_ip}")
        self.app.topology.register_host(datapath.id, in_port, arp_pkt.src_ip, arp_pkt.src_mac)

        if arp_pkt.opcode == arp.ARP_REQUEST:
            # Uniform L2 Sweep Detection across all source hosts without IP restrictions
            self.app.threat_detector.process_arp_request(arp_pkt.src_ip, arp_pkt.dst_ip)
            self._handle_request(datapath, in_port, pkt, eth, arp_pkt, buffer_id)
        else:
            self._handle_reply(datapath, in_port, pkt, eth, arp_pkt, buffer_id)

    def _handle_request(self, datapath, in_port, pkt, eth, arp_pkt, buffer_id):
        target = arp_pkt.dst_ip
        sender_ip = arp_pkt.src_ip
        sender_mac = arp_pkt.src_mac

        # 1. DNS Server Queries (target == dns_ip)
        if target == self.app.dns_ip:
            loc = self.app.topology.host_table.get(self.app.dns_ip)
            if loc and loc.get('mac'):
                reply_pkt = self._build_reply(loc['mac'], self.app.dns_ip, sender_mac, sender_ip)
                actions = [datapath.ofproto_parser.OFPActionOutput(in_port)]
                out = datapath.ofproto_parser.OFPPacketOut(
                    datapath=datapath, buffer_id=datapath.ofproto.OFP_NO_BUFFER,
                    in_port=datapath.ofproto.OFPP_CONTROLLER, actions=actions, data=reply_pkt.data
                )
                datapath.send_msg(out)
                self.app.logger.info(f"[arp] Direct Proxy ARP for DNS {self.app.dns_ip} -> {loc['mac']} sent to {sender_ip}")
                return
            elif loc:
                self.app.logger.info(f"[arp] DNS known at S{loc['dpid']}:{loc['port']} - direct request")
                self._send_to_host(pkt.data, loc['dpid'], loc['port'])
                return
            else:
                self.app.logger.info("[arp] DNS location unknown - flood all hosts")
                self._flood_to_all_hosts(pkt.data, datapath.id, in_port)
                return

        # 2. DNS Server asking for client MAC
        if sender_ip == self.app.dns_ip:
            loc = self.app.topology.host_table.get(target)
            if loc and loc.get('mac'):
                reply_pkt = self._build_reply(loc['mac'], target, sender_mac, sender_ip)
                actions = [datapath.ofproto_parser.OFPActionOutput(in_port)]
                out = datapath.ofproto_parser.OFPPacketOut(
                    datapath=datapath, buffer_id=datapath.ofproto.OFP_NO_BUFFER,
                    in_port=datapath.ofproto.OFPP_CONTROLLER, actions=actions, data=reply_pkt.data
                )
                datapath.send_msg(out)
                self.app.logger.info(f"[arp] Direct Proxy ARP for client {target} -> {loc['mac']} sent to DNS {sender_ip}")
                return
            elif loc:
                self._send_to_host(pkt.data, loc['dpid'], loc['port'])
                return
            else:
                self._flood_to_all_hosts(pkt.data, datapath.id, in_port)
                return

        # 3. Virtual IP request: Proxy ARP with synthesized Virtual MAC (Zero Real MAC Exposure)
        if target in self.app.virtual_to_real:
            real_target = self.app.virtual_to_real[target]
            vmac = self.vip_to_vmac(target)
            loc = self.app.topology.host_table.get(real_target)
            if loc and loc.get('mac'):
                reply_pkt = self._build_reply(vmac, target, sender_mac, sender_ip)
                actions = [datapath.ofproto_parser.OFPActionOutput(in_port)]
                out = datapath.ofproto_parser.OFPPacketOut(
                    datapath=datapath, buffer_id=datapath.ofproto.OFP_NO_BUFFER,
                    in_port=datapath.ofproto.OFPP_CONTROLLER, actions=actions, data=reply_pkt.data
                )
                datapath.send_msg(out)
                self.app.logger.info(f"[arp] Proxy ARP: Virtual {target} ({real_target}) -> VMAC {vmac} to {sender_ip}")
                return

            self.pending_virtual_arp[(sender_ip, real_target)] = target
            self.app.logger.info(f"[arp] virtual {target} → {real_target}")
            new_pkt = self._build_request(sender_mac, sender_ip, real_target)
            if real_target not in self.app.topology.host_table:
                self.app.logger.info("[arp] target unknown - flood all hosts")
                self._flood_to_all_hosts(new_pkt.data, datapath.id, in_port)
            else:
                loc = self.app.topology.host_table[real_target]
                self.app.logger.info(f"[arp] target known at S{loc['dpid']}:{loc['port']} - direct")
                self._send_to_host(new_pkt.data, loc['dpid'], loc['port'])
            return

        # 4. Normal ARP for known real host: Proxy ARP
        loc = self.app.topology.host_table.get(target)
        if loc and loc.get('mac'):
            reply_pkt = self._build_reply(loc['mac'], target, sender_mac, sender_ip)
            actions = [datapath.ofproto_parser.OFPActionOutput(in_port)]
            out = datapath.ofproto_parser.OFPPacketOut(
                datapath=datapath, buffer_id=datapath.ofproto.OFP_NO_BUFFER,
                in_port=datapath.ofproto.OFPP_CONTROLLER, actions=actions, data=reply_pkt.data
            )
            datapath.send_msg(out)
            self.app.logger.info(f"[arp] Proxy ARP: Real host {target} -> {loc['mac']} to {sender_ip}")
            return
        elif loc:
            self._send_to_host(pkt.data, loc['dpid'], loc['port'])
            return

        # Normal ARP: flood locally
        self.app.logger.info("[arp] normal ARP - flood locally")
        self._flood_locally(datapath, in_port, buffer_id, pkt.data)

    def _handle_reply(self, datapath, in_port, pkt, eth, arp_pkt, buffer_id):
        sender_ip = arp_pkt.src_ip
        sender_mac = arp_pkt.src_mac
        target_ip = arp_pkt.dst_ip

        if sender_ip == self.app.dns_ip or target_ip == self.app.dns_ip:
            self.app.logger.info("[arp] DNS reply")
            self.app.topology.register_host(datapath.id, in_port, sender_ip, sender_mac)

            # Find the location of the target (the other party)
            loc_dpid, loc_port = self.app.topology.get_host_location_by_ip(target_ip)
            if loc_dpid and loc_port:
                self.app.logger.info(f"[arp] Direct delivery to {target_ip} at S{loc_dpid}:p{loc_port}")
                self._send_to_host(pkt.data, loc_dpid, loc_port)
            else:
                self.app.logger.info("[arp] Target location unknown - flood locally")
                self._flood_locally(datapath, in_port, buffer_id, pkt.data)
            return

        # Check if this reply answers a pending virtual IP ARP request
        if (target_ip, sender_ip) in self.pending_virtual_arp:
            virtual_requested = self.pending_virtual_arp.pop((target_ip, sender_ip))
            # Synthesize virtual MAC for the requested virtual IP to keep real MAC hidden!
            vmac = self.vip_to_vmac(virtual_requested)
            new_pkt = self._build_reply(vmac, virtual_requested, arp_pkt.dst_mac, target_ip)
            loc = self.app.topology.get_host_location_by_ip(target_ip)
            if loc[0] and loc[1]:
                self.app.logger.info(f"[arp] Delivering virtual ARP reply for {virtual_requested} (VMAC: {vmac}) to {target_ip} at S{loc[0]}:p{loc[1]}")
                self._send_to_host(new_pkt.data, loc[0], loc[1])
                return
            self._flood_locally(datapath, in_port, datapath.ofproto.OFP_NO_BUFFER, new_pkt.data)
            return

        # Normal ARP reply (between real hosts): deliver directly to target if known, else flood locally
        loc = self.app.topology.get_host_location_by_ip(target_ip)
        if loc[0] and loc[1]:
            self.app.logger.info(f"[arp] Direct delivery of normal ARP reply to {target_ip} at S{loc[0]}:p{loc[1]}")
            self._send_to_host(pkt.data, loc[0], loc[1])
            return

        self.app.logger.info("[arp] normal reply - flood locally")
        self._flood_locally(datapath, in_port, buffer_id, pkt.data)

    # Helper methods
    def _build_request(self, src_mac, src_ip, target_ip):
        p = packet.Packet()
        p.add_protocol(ethernet.ethernet(dst='ff:ff:ff:ff:ff:ff', src=src_mac, ethertype=const.ETH_TYPE_ARP))
        p.add_protocol(arp.arp(opcode=arp.ARP_REQUEST, src_mac=src_mac, src_ip=src_ip,
                                dst_mac='ff:ff:ff:ff:ff:ff', dst_ip=target_ip))
        p.serialize()
        return p

    def _build_reply(self, src_mac, src_ip, dst_mac, dst_ip):
        p = packet.Packet()
        p.add_protocol(ethernet.ethernet(dst=dst_mac, src=src_mac, ethertype=const.ETH_TYPE_ARP))
        p.add_protocol(arp.arp(opcode=arp.ARP_REPLY, src_mac=src_mac, src_ip=src_ip,
                                dst_mac=dst_mac, dst_ip=dst_ip))
        p.serialize()
        return p

    def _flood_locally(self, datapath, in_port, buffer_id, data):
        ports = self.app.topology.access_ports.get(datapath.id, [])
        for p in ports:
            if p == in_port: continue
            actions = [datapath.ofproto_parser.OFPActionOutput(p)]
            out = datapath.ofproto_parser.OFPPacketOut(
                datapath=datapath,
                buffer_id=buffer_id if buffer_id != datapath.ofproto.OFP_NO_BUFFER else datapath.ofproto.OFP_NO_BUFFER,
                in_port=in_port,
                actions=actions,
                data=data if buffer_id == datapath.ofproto.OFP_NO_BUFFER else None
            )
            datapath.send_msg(out)

    def _flood_to_all_hosts(self, data, exclude_dpid, exclude_port):
        for dpid, ports in self.app.topology.access_ports.items():
            dp = self.app.topology.get_datapath(dpid)
            if not dp: continue
            for port in ports:
                if dpid == exclude_dpid and port == exclude_port: continue
                actions = [dp.ofproto_parser.OFPActionOutput(port)]
                out = dp.ofproto_parser.OFPPacketOut(
                    datapath=dp,
                    buffer_id=dp.ofproto.OFP_NO_BUFFER,
                    in_port=dp.ofproto.OFPP_CONTROLLER,
                    actions=actions,
                    data=data
                )
                dp.send_msg(out)

    def _send_to_host(self, data, dpid, port):
        dp = self.app.topology.get_datapath(dpid)
        if dp:
            actions = [dp.ofproto_parser.OFPActionOutput(port)]
            out = dp.ofproto_parser.OFPPacketOut(
                datapath=dp,
                buffer_id=dp.ofproto.OFP_NO_BUFFER,
                in_port=dp.ofproto.OFPP_CONTROLLER,
                actions=actions,
                data=data
            )
            dp.send_msg(out)