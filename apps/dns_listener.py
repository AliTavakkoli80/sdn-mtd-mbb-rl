from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import udp
from dnslib import DNSRecord, QTYPE
import logging
import binascii

class DNSListener(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(DNSListener, self).__init__(*args, **kwargs)
        self.logger.setLevel(logging.INFO)
        self.logger.info("Enhanced DNS Listener started (with proper QTYPE support)")

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        
        pkt = packet.Packet(msg.data)
        
        # Extract protocols
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        udp_pkt = pkt.get_protocol(udp.udp)
        
        # Check DNS packets
        if udp_pkt and ip_pkt and (udp_pkt.dst_port == 53 or udp_pkt.src_port == 53):
            try:
                # Find DNS payload after UDP header
                protocols = pkt.protocols
                udp_index = protocols.index(udp_pkt)
                if udp_index + 1 < len(protocols):
                    dns_payload = protocols[udp_index + 1]
                    
                    if isinstance(dns_payload, bytes) and len(dns_payload) > 0:
                        # Parse DNS packet and print complete information
                        dns_record = DNSRecord.parse(dns_payload)
                        self.logger.info('DNS Request: {}'.format(dns_record))
                
                # Process DNS packet
                self._handle_dns_packet(pkt, ip_pkt, udp_pkt, dpid)
            except Exception as e:
                self.logger.error(f"Error processing DNS packet: {str(e)}")
                # Debug: Show hex dump of packet in case of error
                try:
                    self.logger.debug(f"Packet data (first 64 bytes): {binascii.hexlify(msg.data[:64]).decode()}")
                except:
                    pass

    def _handle_dns_packet(self, pkt, ip_pkt, udp_pkt, dpid):
        """Process DNS packets with detailed information"""
        # Determine packet type based on destination port
        packet_type = "QUERY" if udp_pkt.dst_port == 53 else "RESPONSE"
        
        self.logger.info("=" * 50)
        self.logger.info(f"DNS {packet_type} DETECTED")
        self.logger.info(f"Received from Switch DPID: {dpid}")
        self.logger.info("=" * 50)
        self.logger.info(f"Source: {ip_pkt.src}:{udp_pkt.src_port}")
        self.logger.info(f"Destination: {ip_pkt.dst}:{udp_pkt.dst_port}")
        
        try:
            # Get DNS payload
            protocols = pkt.protocols
            udp_index = protocols.index(udp_pkt)
            if udp_index + 1 < len(protocols):
                dns_payload = protocols[udp_index + 1]
                
                if isinstance(dns_payload, bytes) and len(dns_payload) >= 12:
                    dns_record = DNSRecord.parse(dns_payload)
                    
                    # Display DNS questions
                    if dns_record.questions:
                        self.logger.info(f"\nDNS Questions ({len(dns_record.questions)}):")
                        for q in dns_record.questions:
                            qname = str(q.get_qname())
                            # Remove trailing dot from domain name
                            domain_name = qname[:-1] if qname.endswith('.') else qname
                            self.logger.info(f"  - {domain_name} (Type: {QTYPE[q.qtype]})")
                    
                    # Display answers if available
                    if dns_record.rr:
                        self.logger.info(f"\nDNS Answers ({len(dns_record.rr)}):")
                        for rr in dns_record.rr:
                            rname = str(rr.rname)
                            domain_name = rname[:-1] if rname.endswith('.') else rname
                            record_type = QTYPE[rr.rtype]
                            
                            # Display specific information based on record type
                            if record_type == "A":  # IPv4 address
                                self.logger.info(f"  - {domain_name} -> {rr.rdata} (Type: {record_type}, TTL: {rr.ttl})")
                            elif record_type == "AAAA":  # IPv6 address
                                self.logger.info(f"  - {domain_name} -> {rr.rdata} (Type: {record_type}, TTL: {rr.ttl})")
                            elif record_type in ["CNAME", "MX", "TXT", "NS"]:
                                self.logger.info(f"  - {domain_name} = {rr.rdata} (Type: {record_type}, TTL: {rr.ttl})")
                            else:
                                self.logger.info(f"  - {domain_name} (Type: {record_type}, TTL: {rr.ttl})")
        except Exception as e:
            self.logger.error(f"Could not parse DNS content: {str(e)}")
        
        self.logger.info("=" * 50)