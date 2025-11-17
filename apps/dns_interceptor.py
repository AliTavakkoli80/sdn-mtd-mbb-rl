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

        # تعریف نگاشت ساده: نام دامنه → آدرس مجازی
        self.domain_to_virtual_ip = {
            "host2.com": "192.168.1.2"
        }

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        pkt = packet.Packet(msg.data)

        # استخراج پروتکل‌ها
        eth = pkt.get_protocol(ethernet.ethernet)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        udp_pkt = pkt.get_protocol(udp.udp)

        # پردازش فقط بسته‌های DNS (درخواست به پورت 53)
        if not (eth and ip_pkt and udp_pkt and udp_pkt.dst_port == 53):
            return

        try:
            # پیدا کردن پیلود DNS
            protocols = pkt.protocols
            udp_index = protocols.index(udp_pkt)
            if udp_index + 1 >= len(protocols):
                return
            dns_payload = protocols[udp_index + 1]
            if not isinstance(dns_payload, bytes) or len(dns_payload) < 12:
                return

            # تحلیل درخواست DNS
            dns_req = DNSRecord.parse(dns_payload)
            if not dns_req.questions:
                return

            # دریافت نام دامنه درخواست شده
            q = dns_req.questions[0]
            qname = str(q.get_qname())
            domain = qname.rstrip('.')  # حذف نقطه پایانی

            # بررسی اینکه آیا این دامنه در لیست ما است
            if domain not in self.domain_to_virtual_ip:
                self.logger.info(f"Ignoring DNS query for non-protected domain: {domain}")
                return

            # دریافت آدرس مجازی
            virtual_ip = self.domain_to_virtual_ip[domain]
            self.logger.info(f"Intercepting DNS query for {domain} → replying with {virtual_ip}")

            # ساخت پاسخ DNS
            dns_reply = DNSRecord(
                header=DNSHeader(id=dns_req.header.id, qr=1, aa=1, ra=1),
                q=dns_req.q
            )
            dns_reply.add_answer(RR(qname, QTYPE.A, rdata=A(virtual_ip), ttl=0))

            # ساخت بسته پاسخ
            reply_pkt = packet.Packet()
            reply_pkt.add_protocol(ethernet.ethernet(
                ethertype=eth.ethertype,
                dst=eth.src,
                src=eth.dst
            ))
            reply_pkt.add_protocol(ipv4.ipv4(
                src=ip_pkt.dst,  # سرور DNS (مثلاً 10.0.0.10)
                dst=ip_pkt.src,  # کلاینت (مثلاً 10.0.0.1)
                proto=ip_pkt.proto
            ))
            reply_pkt.add_protocol(udp.udp(
                src_port=udp_pkt.dst_port,  # 53
                dst_port=udp_pkt.src_port   # پورت کلاینت
            ))
            reply_pkt.add_protocol(dns_reply.pack())

            # نوشتن و ارسال پاسخ
            reply_pkt.serialize()
            out = parser.OFPPacketOut(
                datapath=datapath,
                buffer_id=ofproto.OFP_NO_BUFFER,
                in_port=ofproto.OFPP_CONTROLLER,
                actions=[parser.OFPActionOutput(msg.match['in_port'])],
                data=reply_pkt.data
            )
            datapath.send_msg(out)

        except Exception as e:
            self.logger.error(f"Error handling DNS query: {e}")