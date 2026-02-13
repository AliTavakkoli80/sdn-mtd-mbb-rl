from ryu.topology.api import get_switch, get_link
from . import constants as const

class TopologyManager:
    """Manages network topology discovery and host tracking."""

    def __init__(self, app):
        self.app = app
        self.link_to_port = {}      # {(src_dpid,dst_dpid):(src_port,dst_port)}
        self.access_table = {}       # {(sw, port): (ip, mac)}
        self.switch_port_table = {}  # {dpid: set(port_num)}
        self.access_ports = {}       # {dpid: set(port_num)} ports to hosts
        self.interior_ports = {}     # {dpid: set(port_num)} ports to switches
        self.switches = []            # list of dpids
        self.host_table = {}          # {real_ip: {'mac': mac, 'dpid': dpid, 'port': port}}
        self.mac_to_port = {}         # fallback L2: {dpid: {mac: port}}
        self.datapath_list = {}       # {dpid: datapath}

    def register_datapath(self, dpid, datapath):
        self.datapath_list[dpid] = datapath

    def unregister_datapath(self, dpid):
        self.datapath_list.pop(dpid, None)

    def get_datapath(self, dpid):
        return self.datapath_list.get(dpid)

    def discover(self):
        """Discover topology and update port classifications."""
        self.app.logger.info("[topology] Discovering network topology...")
        switch_list = get_switch(self.app, None)
        link_list = get_link(self.app, None)

        self._create_port_map(switch_list)
        self.switches = [sw.dp.id for sw in switch_list]
        self._create_interior_links(link_list)
        self._create_access_ports()
        self.app.logger.info(f"[topology] ✓ Discovered {len(self.switches)} switches, {len(self.link_to_port)} links")

    def _create_port_map(self, switch_list):
        for sw in switch_list:
            dpid = sw.dp.id
            self.switch_port_table.setdefault(dpid, set())
            self.interior_ports.setdefault(dpid, set())
            self.access_ports.setdefault(dpid, set())
            for port in sw.ports:
                if port.port_no in [const.OFPP_LOCAL, const.OFPP_CONTROLLER]:
                    continue
                self.switch_port_table[dpid].add(port.port_no)

    def _create_interior_links(self, link_list):
        self.link_to_port.clear()
        for link in link_list:
            src, dst = link.src, link.dst
            if src.port_no in [const.OFPP_LOCAL, const.OFPP_CONTROLLER] or \
               dst.port_no in [const.OFPP_LOCAL, const.OFPP_CONTROLLER]:
                continue
            self.link_to_port[(src.dpid, dst.dpid)] = (src.port_no, dst.port_no)
            if src.dpid in self.switches:
                self.interior_ports[src.dpid].add(src.port_no)
            if dst.dpid in self.switches:
                self.interior_ports[dst.dpid].add(dst.port_no)

    def _create_access_ports(self):
        for sw in self.switch_port_table:
            all_ports = self.switch_port_table[sw]
            interior = self.interior_ports.get(sw, set())
            self.access_ports[sw] = all_ports - interior - {const.OFPP_LOCAL, const.OFPP_CONTROLLER}

    def register_host(self, dpid, in_port, ip, mac):
        """Register host if port is an access port."""
        if dpid in self.access_ports and in_port in self.access_ports[dpid]:
            if ip in self.app.real_to_virtual:
                self.host_table[ip] = {'mac': mac, 'dpid': dpid, 'port': in_port}
                virt = self.app.real_to_virtual.get(ip, 'N/A')
                self.app.logger.info(f"\n[host] ✓ NEW HOST: {ip} → VIRTUAL: {virt} at S{dpid}:p{in_port} MAC:{mac}")

            prev = self.access_table.get((dpid, in_port))
            self.access_table[(dpid, in_port)] = (ip, mac)
            if prev != (ip, mac):
                if prev:
                    self.app.logger.info(f"[host] ⚠️ Changed on S{dpid}:p{in_port}: {prev} → ({ip},{mac})")
                else:
                    self.app.logger.info(f"[host] ➤ Registered: ({dpid},{in_port}) → ({ip},{mac})")

    def get_host_location_by_ip(self, ip_address):
        """Return (dpid, port) for given IP (real or virtual)."""
        if ip_address in self.app.virtual_to_real:
            real_ip = self.app.virtual_to_real[ip_address]
            return self._get_host_location_by_real_ip(real_ip)
        return self._get_host_location_by_real_ip(ip_address)

    def _get_host_location_by_real_ip(self, real_ip):
        if real_ip in self.host_table:
            info = self.host_table[real_ip]
            return info['dpid'], info['port']
        for (dpid, port), (ip, _) in self.access_table.items():
            if ip == real_ip:
                return dpid, port
        return None, None

    def get_host_location_by_mac(self, mac):
        mac = mac.lower()
        for info in self.host_table.values():
            if info['mac'].lower() == mac:
                return info['dpid'], info['port']
        for (dpid, port), (_, m) in self.access_table.items():
            if m.lower() == mac:
                return dpid, port
        for dpid, mac_table in self.mac_to_port.items():
            if mac in mac_table:
                return dpid, mac_table[mac]
        return None, None

    def log_summary(self):
        self.app.logger.info("\n" + "─"*80)
        self.app.logger.info("🌐 TOPOLOGY SUMMARY")
        self.app.logger.info("─"*80)
        # Switches
        self.app.logger.info(f"\n📦 SWITCHES ({len(self.switches)}):")
        for dpid in sorted(self.switches):
            self.app.logger.info(f"   • S{dpid}: access={sorted(self.access_ports.get(dpid,[]))}, interior={sorted(self.interior_ports.get(dpid,[]))}")
        # Links
        self.app.logger.info(f"\n🔗 LINKS ({len(self.link_to_port)}):")
        for (s,d),(sp,dp) in sorted(self.link_to_port.items()):
            self.app.logger.info(f"   • S{s}:p{sp} ↔ S{d}:p{dp}")
        # Protected hosts
        self.app.logger.info(f"\n🖥️ PROTECTED HOSTS ({len(self.host_table)}):")
        for real,info in sorted(self.host_table.items()):
            virt = self.app.real_to_virtual.get(real,'N/A')
            self.app.logger.info(f"   • {real:15s} → {virt:15s} at S{info['dpid']}:p{info['port']} MAC:{info['mac']}")
        self.app.logger.info("─"*80)