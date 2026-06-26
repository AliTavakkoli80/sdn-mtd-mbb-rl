from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib import hub
from ryu.topology import event

from . import config
from . import constants as const
from .utils import setup_logging
from .topology import TopologyManager
from .flow_manager import FlowManager
from .packet_handler import PacketInHandler
from .arp_handler import ARPHandler
from .ipv4_handler import IPv4Handler
from .mtd_engine import MTDEngine
from .threat_detector import ThreatDetector
from ryu.app.wsgi import ControllerBase, WSGIApplication, route
import json
from webob import Response


LOG = setup_logging()

class MTDStateAPI(ControllerBase):
    """
    REST API for Sim-to-Real fine-tuning.
    Exposes the controller's internal state to the RL environment.
    """
    
    def __init__(self, req, link, data, **config):
        super(MTDStateAPI, self).__init__(req, link, data, **config)
        self.mtd_app = data['app']

    @route('mtd', '/mtd/finetune_mode', methods=['POST'])
    def set_fine_tune_mode(self, req, **kwargs):
        """Enable or disable fine-tuning mode."""
        try:
            data = json.loads(req.body or '{}')
            enabled = bool(data.get('enabled', False))
            
            self.mtd_app.mtd_engine.set_fine_tune_mode(enabled)
            
            mode_str = "ENABLED" if enabled else "DISABLED"
            return Response(
                content_type='application/json',
                body=json.dumps({
                    'status': 'ok',
                    'message': f'Fine-tuning mode {mode_str}',
                    'fine_tune_mode': enabled
                }).encode('utf-8')
            )
        except Exception as e:
            return Response(
                status=500,
                content_type='application/json',
                body=json.dumps({'error': str(e)}).encode('utf-8')
            )    

    @route('mtd', '/mtd/state', methods=['GET'])
    def get_state(self, req, **kwargs):
        """Returns the 7D observation vector + metadata."""
        try:
            threat_state = self.mtd_app.threat_detector.get_state().tolist()
            intensity = self.mtd_app.threat_detector.get_max_intensity()
            flows = self.mtd_app.flow_manager.active_flow_count
            scanned = self.mtd_app.threat_detector.get_scanned_targets()
            is_attack = bool(self.mtd_app.threat_detector.is_under_attack)
            
            response_data = {
                'threat_state': threat_state,
                'intensity': float(intensity),
                'active_flows': int(flows),
                'scanned_targets': scanned,
                'is_under_attack': is_attack
            }
            
            # Use .encode('utf-8') to convert string to bytes
            return Response(
                content_type='application/json',
                body=json.dumps(response_data).encode('utf-8')
            )
        except Exception as e:
            return Response(
                status=500,
                content_type='application/json',
                body=json.dumps({'error': str(e)}).encode('utf-8')
            )

    @route('mtd', '/mtd/action', methods=['POST'])
    def execute_action(self, req, **kwargs):
        """Executes an MTD action (GLOBAL=1, TARGETED=2)."""
        try:
            data = json.loads(req.body or '{}')
            action = int(data.get('action', 0))
            
            if action == 1:
                self.mtd_app.mtd_engine.step(action=1)
                msg = "GLOBAL shuffle executed"
            elif action == 2:
                self.mtd_app.mtd_engine.step(action=2)
                msg = "TARGETED shuffle executed"
            elif action == 0:
                msg = "HOLD (no action)"
            else:
                return Response(
                    status=400,
                    content_type='application/json',
                    body=json.dumps({'error': 'Invalid action'}).encode('utf-8')
                )
            
            # Use .encode('utf-8') to convert string to bytes
            return Response(
                content_type='application/json',
                body=json.dumps({'status': 'ok', 'message': msg}).encode('utf-8')
            )
        except Exception as e:
            return Response(
                status=500,
                content_type='application/json',
                body=json.dumps({'error': str(e)}).encode('utf-8')
            )

class MTDMovingTargetDefense(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    
    # Register WSGI as a context
    _CONTEXTS = {
        'wsgi': WSGIApplication
    }

    _EVENTS = [
        event.EventSwitchEnter,
        event.EventSwitchLeave,
        event.EventPortAdd,
        event.EventPortDelete,
        event.EventPortModify,
        event.EventLinkAdd,
        event.EventLinkDelete
    ]

    def __init__(self, *args, **kwargs):
        super(MTDMovingTargetDefense, self).__init__(*args, **kwargs)
        
        # Register the REST API with the app reference
        self.wsgi = kwargs['wsgi']
        self.wsgi.register(MTDStateAPI, {'app': self})

        self.dns_ip = config.DNS_SERVER_IP
        self.real_to_virtual = config.REAL_TO_VIRTUAL
        self.virtual_to_real = {v: k for k, v in self.real_to_virtual.items()}

        # Initialize managers
        self.topology = TopologyManager(self)
        self.flow_manager = FlowManager(self)
        self.packet_handler = PacketInHandler(self)
        self.arp_handler = ARPHandler(self)
        self.ipv4_handler = IPv4Handler(self)

        self.threat_detector = ThreatDetector(self)

        self.mtd_engine = MTDEngine(self, normal_interval=300, attack_interval=5)

        # Start periodic discovery
        self.discover_thread = hub.spawn(self._discovery_loop)

        # Start MTD Shuffling Engine
        self.mtd_engine.start()

        LOG.info("="*80)
        LOG.info("🚀 MTD IP SHUFFLING CONTROLLER STARTED")
        for real, virt in sorted(self.real_to_virtual.items()):
            LOG.info(f"   • {real:15s} ⇄ {virt:15s}")
        LOG.info("="*80)

    def _discovery_loop(self):
        interval = config.TOPOLOGY_DISCOVERY_INTERVAL
        cycles = config.TOPOLOGY_FULL_SCAN_CYCLES
        i = 0
        while True:
            if i == cycles:
                self.topology.discover()
                self.topology.log_summary()
                i = 0
            hub.sleep(interval)
            i += 1

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        self.flow_manager.install_table_miss(datapath)
        LOG.info(f"[switch] ✓ Switch connected: DPID={datapath.id}")

    @set_ev_cls(ofp_event.EventOFPStateChange, MAIN_DISPATCHER)
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            self.topology.register_datapath(datapath.id, datapath)
            LOG.info(f"[switch] 🔌 Switch S{datapath.id} registered")
        elif ev.state == 'DEAD_DISPATCHER':
            self.topology.unregister_datapath(datapath.id)
            LOG.info(f"[switch] 💔 Switch S{datapath.id} unregistered")

    @set_ev_cls(_EVENTS)
    def _topology_event_handler(self, ev):
        # Trigger rediscovery on topology changes
        self.topology.discover()

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        self.packet_handler.packet_in_handler(ev)    

    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
    def flow_removed_handler(self, ev):
        """Tracks active flows for the RL agent's QoS cost metric with ZERO polling overhead."""
        self.flow_manager.active_flow_count = max(0, self.flow_manager.active_flow_count - 1)    