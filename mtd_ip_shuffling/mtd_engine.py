import random
import time
import os
import numpy as np
import ipaddress
from ryu.lib import hub
from . import constants as const
from . import config

# Import PPO for inference
try:
    from stable_baselines3 import PPO
    RL_AVAILABLE = True
except ImportError:
    RL_AVAILABLE = False


class MTDEngine:
    """
    Manages Moving Target Defense IP Shuffling.
    Supports AI-driven decision making via a trained PPO model.
    
    🌟 NEW: Fine-tuning mode disables internal AI loop for external control.
    """
    
    def __init__(self, app, normal_interval=300, attack_interval=5):
        self.app = app
        self.real_ips = list(app.real_to_virtual.keys())
        
        # Dynamic pool generation based on real IP subnet
        self.virtual_pool = self._generate_virtual_pool()
        
        # Timing configuration
        self.normal_interval = normal_interval
        self.attack_interval = attack_interval
        self.current_interval = normal_interval
        self.max_shuffle_interval = float(normal_interval)
        
        # State tracking
        self.current_mapping = app.real_to_virtual.copy()
        self.last_shuffle_time = time.time()
        self.is_accelerated = False
        
        # 🌟 NEW: Fine-tuning mode flag
        self.fine_tune_mode = False
        
        # AI model initialization
        self.use_ai = False
        self.model = None
        self._load_ai_model()
        
        self.app.logger.info(
            f"[MTD Engine] Initialized | Normal: {normal_interval}s | "
            f"Attack: {attack_interval}s | AI: {self.use_ai} | Fine-tune: {self.fine_tune_mode}"
        )

    def set_fine_tune_mode(self, enabled: bool):
        """
        Enable or disable fine-tuning mode.
        When enabled, the internal AI loop is paused and only external REST API commands are executed.
        """
        self.fine_tune_mode = enabled
        if enabled:
            self.app.logger.info("🎓 [MTD Engine] Fine-tuning mode ENABLED - Internal AI loop paused")
        else:
            self.app.logger.info("✅ [MTD Engine] Fine-tuning mode DISABLED - Internal AI loop resumed")

    def _load_ai_model(self):
        """Load the trained PPO model from the runs directory."""
        if not RL_AVAILABLE:
            self.app.logger.warning("⚠️ [MTD Engine] Stable-Baselines3 not installed. Using heuristic logic.")
            return
        
        # Look for model in project rl_agent directory or latest run
        project_root = os.path.dirname(os.path.dirname(__file__))
        candidate_paths = [
            os.path.join(project_root, "rl_agent", "mtd_ppo_agent_real.zip"),
            os.path.join(project_root, "rl_agent", "mtd_ppo_agent.zip"),
            os.path.join(os.getcwd(), "mtd_ppo_agent.zip")
        ]
        
        runs_dir = os.path.join(project_root, "rl_agent", "runs")
        if os.path.exists(runs_dir):
            run_folders = [f for f in os.listdir(runs_dir) if f.startswith('run_')]
            if run_folders:
                run_folders.sort(reverse=True)
                for rf in run_folders:
                    cand = os.path.join(runs_dir, rf, "mtd_ppo_agent_real.zip")
                    if os.path.exists(cand):
                        candidate_paths.insert(0, cand)
                        break
                    cand_base = os.path.join(runs_dir, rf, "mtd_ppo_agent.zip")
                    if os.path.exists(cand_base):
                        candidate_paths.insert(0, cand_base)
                        break

        model_path = None
        for cp in candidate_paths:
            if os.path.exists(cp):
                model_path = cp
                break
        
        if model_path:
            try:
                self.model = PPO.load(model_path, device="cpu")
                self.use_ai = True
                self.app.logger.info(f"🧠 [MTD Engine] AI Model loaded from: {model_path}")
            except Exception as e:
                self.app.logger.error(f"❌ [MTD Engine] Failed to load AI model: {e}. Falling back to heuristics.")
        else:
            self.app.logger.warning("⚠️ [MTD Engine] No trained model found. Falling back to heuristic logic.")

    def _generate_virtual_pool(self):
        """
        Dynamically generates a pool of virtual IPs based on the subnet of the real IPs.
        Finds the smallest common network containing all real IPs, ensuring the virtual 
        pool stays in the same local subnet for smoother ARP/L2 handling.
        """
        if not self.real_ips:
            self.app.logger.warning("[MTD Engine] No real IPs found. Virtual pool is empty.")
            return []
            
        try:
            # Calculate the common subnet using bitwise XOR
            ip_ints = [int(ipaddress.IPv4Address(ip)) for ip in self.real_ips]
            xor_sum = 0
            for i in range(1, len(ip_ints)):
                xor_sum |= (ip_ints[0] ^ ip_ints[i])
                
            if xor_sum == 0:
                prefix_len = 32
            else:
                prefix_len = 32 - xor_sum.bit_length()
                
            # Cap at /24 to ensure a sufficiently large pool (254 IPs)
            prefix_len = min(prefix_len, 24)
            
            # Create the network object
            network = ipaddress.IPv4Network(f"{self.real_ips[0]}/{prefix_len}", strict=False)
            
            # Build the pool, excluding real IPs and infrastructure hosts (DNS)
            excluded_ips = set(self.real_ips)
            excluded_ips.add(config.DNS_SERVER_IP)
            
            pool = []
            for ip in network.hosts(): 
                ip_str = str(ip)
                if ip_str not in excluded_ips:
                    pool.append(ip_str)
                    
            self.app.logger.info(f"[MTD Engine] 🌐 Virtual pool: {network} ({len(pool)} IPs)")
            return pool
            
        except Exception as e:
            self.app.logger.error(f"[MTD Engine] Failed to generate virtual pool: {e}")
            return [f"10.0.0.{i}" for i in range(10, 60)]

    def start(self):
        """Starts the adaptive shuffling loop."""
        hub.spawn(self._adaptive_shuffle_loop)

    def _adaptive_shuffle_loop(self):
        """Main control loop. Routes to AI or Heuristic based on model availability."""
        self.app.logger.info("[MTD Engine] Control loop started")
        
        while True:
            # 🌟 NEW: Skip internal AI loop if in fine-tuning mode
            if self.fine_tune_mode:
                hub.sleep(1)  # Just sleep, wait for external commands
                continue
            
            if self.use_ai:
                self._ai_inference_step()
                hub.sleep(2)  # Poll AI every 2 seconds
            else:
                self._heuristic_step()
                # Sleep in 1-second intervals, checking for state changes
                for _ in range(self.current_interval):
                    hub.sleep(1)
                    # Fixed: Use direct attribute access instead of .get()
                    if self.app.threat_detector.is_under_attack != self.is_accelerated:
                        break

    def _ai_inference_step(self):
        """Query the AI model and execute its decision."""
        obs = self._get_live_obs()

        # SIM-TO-REAL SAFETY GUARD
        # Prevents "Control Plane Thrashing" in edge cases.
        # If there is no threat (intensity < 0.1) and no active flows (flows < 0.05),
        # shuffling provides zero security benefit and only wastes control-plane overhead.
        threat_intensity = obs[4]
        active_flows_norm = obs[6]
        
        if threat_intensity < 0.1 and active_flows_norm < 0.05:
            # Network is completely idle. Force HOLD.
            return

        action, _states = self.model.predict(obs, deterministic=True)
        
        if action > 0: 
            action_name = "GLOBAL" if action == 1 else "TARGETED"
            self.app.logger.info(
                f"🧠 [AI] SHUFFLE ({action_name}) | "
                f"Intensity: {obs[4]:.2f} | Flows: {obs[6]:.2f}"
            )
            self.step(action=action) 
            self.last_shuffle_time = time.time()

    def _heuristic_step(self):
        """Hardcoded fallback logic when AI model is not available."""
        # Fixed: Use direct attribute access
        under_attack = self.app.threat_detector.is_under_attack
        
        if under_attack and not self.is_accelerated:
            self.current_interval = self.attack_interval
            self.is_accelerated = True
            self.app.logger.warning(f"⚡ [Heuristic] ATTACK DETECTED - Accelerating to {self.attack_interval}s")
            self.step()
            self.last_shuffle_time = time.time()
            
        elif not under_attack and self.is_accelerated:
            self.current_interval = self.normal_interval
            self.is_accelerated = False
            self.app.logger.info(f"✅ [Heuristic] Threat cleared - Returning to {self.normal_interval}s")
            self.step()
            self.last_shuffle_time = time.time()
            
        else:
            # Regular interval shuffle
            self.step()
            self.last_shuffle_time = time.time()

    def _get_live_obs(self):
        """Builds the 8D State Vector used during training."""
        threat_state = self.app.threat_detector.get_state()
        threat_intensity = threat_state[4]
        
        time_since = time.time() - self.last_shuffle_time
        time_norm = min(time_since / self.max_shuffle_interval, 1.0)
        
        active_flows = getattr(self.app.flow_manager, 'active_flow_count', 0)
        active_flows_norm = min(active_flows / 100.0, 1.0)
        
        # 8D: Target Cardinality (normalized)
        scanned_targets = self.app.threat_detector.get_scanned_targets()
        n_scanned = len(scanned_targets) if scanned_targets else 0
        total_hosts = float(len(self.real_ips)) if self.real_ips else 16.0
        target_cardinality = min(n_scanned / total_hosts, 1.0)
        
        return np.array([
            threat_state[0],   # ent_ip
            threat_state[1],   # ent_port
            threat_state[2],   # ewma_rate
            threat_state[3],   # cv
            threat_intensity,  # continuous intensity (index 4)
            time_norm,         # time staleness
            active_flows_norm, # active flows
            target_cardinality # target cardinality (index 7)
        ], dtype=np.float32)

    def step(self, action=1, enable_mbb=True):
        """Executes the network shuffle based on the chosen action."""
        if action == 2:
            self.app.logger.info("🎯 [MTD] Executing TARGETED IP Shuffle...")
            new_mapping = self._generate_targeted_mapping()
            # Control plane flow modification cost for targeted MTD (2 hosts * 4 rules = 8 flowmods)
            self.app.flow_manager.flow_mod_count += 8
        elif action == 1:
            self.app.logger.info("🎲 [MTD] Executing GLOBAL IP Shuffle...")
            new_mapping = self._generate_random_mapping()
            # Control plane flow modification cost for global MTD (10 hosts * 4 rules = 40 flowmods)
            self.app.flow_manager.flow_mod_count += 40
            
        self.apply_mapping(new_mapping, enable_mbb=enable_mbb)

    def _generate_targeted_mapping(self):
        """Generates a new mapping, changing only IPs currently being scanned."""
        targets = self.app.threat_detector.get_scanned_targets()
        new_mapping = self.current_mapping.copy()
        
        # Find which Real IPs correspond to the targeted Virtual IPs OR Real IPs
        # Check both current and previous mappings to resolve recently shuffled VIPs
        all_known_mappings = dict(getattr(self, 'previous_mapping', {}))
        all_known_mappings.update(new_mapping)
        targeted_real_ips = [
            real_ip for real_ip, virt_ip in all_known_mappings.items() 
            if (virt_ip in targets or real_ip in targets)
        ]
        targeted_real_ips = [r for r in self.real_ips if r in targeted_real_ips]
                
        if not targeted_real_ips:
            # Fallback must NEVER call _generate_random_mapping() for targeted actions!
            self.app.logger.warning("🎯 [MTD] Targeted shuffle: no target matched, mutating default 2 targets")
            threat_sources = self.app.threat_detector.get_flagged_threat_sources() if hasattr(self.app, 'threat_detector') and hasattr(self.app.threat_detector, 'get_flagged_threat_sources') else set()
            targeted_real_ips = [r for r in self.real_ips if r not in threat_sources][:2]

        # Get available IPs from the pool
        used_vips = set(new_mapping.values())
        available = [ip for ip in self.virtual_pool if ip not in used_vips]
        random.shuffle(available)
        
        # Only shuffle the targeted Real IPs
        for real_ip in targeted_real_ips:
            if available:
                new_mapping[real_ip] = available.pop()
                
        self.app.logger.info(f"🎯 [MTD] Targeted shuffle: {len(targeted_real_ips)} hosts ({targeted_real_ips})")
        return new_mapping    
        
    def _generate_random_mapping(self):
        """Generates a completely new random mapping."""
        available = self.virtual_pool.copy()
        random.shuffle(available)
        mapping = {}
        for real_ip in self.real_ips:
            if not available: 
                break
            mapping[real_ip] = available.pop()
        return mapping

    def apply_mapping(self, new_mapping, enable_mbb=True):
        """Applies new mapping with Make-Before-Break grace period (if enable_mbb=True)."""
        if enable_mbb:
            now = time.time()
            # 1. Prune expired sessions, retain active unexpired sessions across rapid shuffles
            self.app.flow_manager.prune_expired_sessions(const.GRACE_PERIOD_IDLE_TIMEOUT)
            # Exclude detected threat sources from MBB grace sessions
            threat_sources = self.app.threat_detector.get_flagged_threat_sources() if hasattr(self.app, 'threat_detector') and hasattr(self.app.threat_detector, 'get_flagged_threat_sources') else set()
            for src, dst in list(self.app.flow_manager.active_sessions.keys()):
                if src in threat_sources:
                    del self.app.flow_manager.active_sessions[(src, dst)]

            active_sessions = self.app.flow_manager.active_sessions.copy()
            # Mark the start of the grace period for sessions moving to Table 1
            for k, v in self.app.flow_manager.active_sessions.items():
                if isinstance(v, dict) and v.get('shuffled_at') is None:
                    v['shuffled_at'] = now

            self.app.logger.info(f"🔄 [MTD] Make-Before-Break retaining {len(active_sessions)} active sessions in Table 1...")
            # Install grace flows in Table 1
            self._install_session_grace_flows(active_sessions)
        else:
            self.app.logger.info(f"⚡ [MTD] Stateless Shuffle (Make-Before-Break DISABLED) - flushing Table 1...")
            for dpid, dp in self.app.topology.datapath_list.items():
                self.app.flow_manager.flush_table(dp, table_id=const.TABLE_GRACE)
            self.app.flow_manager.active_sessions.clear()
        
        # 2. Flush Table 0 (Active) translation flows on edge (leaf) switches only
        self._flush_old_flows()
        
        # 3. Update internal state
        self.previous_mapping = self.current_mapping.copy()
        self.current_mapping = new_mapping
        self.app.real_to_virtual = new_mapping
        self.app.virtual_to_real = {v: k for k, v in new_mapping.items()}
        
        # 4. In MBB mode, do NOT wipe active_sessions immediately with .clear()!
        # Sessions are retained with per-session created_at timestamps until their grace timer expires.
        if not enable_mbb:
            self.app.flow_manager.active_sessions.clear()
        
        mode_str = "120s grace period (15s idle)" if enable_mbb else "Stateless Hard Drop"
        self.app.logger.info(f"✅ [MTD] Shuffle complete ({mode_str}).")
        for r, v in sorted(new_mapping.items()):
            self.app.logger.info(f"   {r} ⇄ {v}")

    def _flush_old_flows(self):
        """Deletes translation flows in the ACTIVE table (Table 0) across edge (leaf) switches, preserving core transit rules."""
        leaf_dpids = self.app.topology.leaf_switches
        for dpid in leaf_dpids:
            dp = self.app.topology.get_datapath(dpid)
            if dp:
                self.app.flow_manager.flush_translation_flows(dp)

    def _install_session_grace_flows(self, sessions):
        """Installs 4-way flows for active sessions into Table 1 (Grace)."""
        now = time.time()
        threat_sources = self.app.threat_detector.get_flagged_threat_sources() if hasattr(self.app, 'threat_detector') and hasattr(self.app.threat_detector, 'get_flagged_threat_sources') else set()
        for (src_real, dst_real), s_data in sessions.items():
            if src_real in threat_sources:
                continue
            if (src_real not in self.app.topology.host_table or 
                dst_real not in self.app.topology.host_table):
                continue
                
            src_info = self.app.topology.host_table[src_real]
            dst_info = self.app.topology.host_table[dst_real]
            
            ingress_dp = self.app.topology.get_datapath(src_info['dpid'])
            egress_dp = self.app.topology.get_datapath(dst_info['dpid'])
            
            if not ingress_dp or not egress_dp:
                continue

            # Extract virtual IPs and compute remaining grace timeout
            if isinstance(s_data, dict):
                src_virt = s_data['virtual_src']
                dst_virt = s_data['virtual_dst']
                created_at = s_data.get('created_at', now)
            else:
                src_virt, dst_virt = s_data[:2]
                created_at = s_data[2] if len(s_data) > 2 else now

            parser = ingress_dp.ofproto_parser
            ofproto = ingress_dp.ofproto
            
            # 1. Ingress Forward: Old Virtual Dst -> Real Dst (Bound to authorized client src_real)
            if ingress_dp.id == egress_dp.id:
                # Intra-leaf
                out_fwd = parser.OFPActionOutput(dst_info['port'])
                match = parser.OFPMatch(eth_type=const.ETH_TYPE_IP, ipv4_src=src_real, ipv4_dst=dst_virt)
                actions = [parser.OFPActionSetField(ipv4_dst=dst_real), out_fwd]
                self.app.flow_manager.add_flow(ingress_dp, const.PRIORITY_TRANSLATION, match, actions,
                                              idle_timeout=15, hard_timeout=120, table_id=const.TABLE_GRACE,
                                              cookie=const.COOKIE_MTD_GRACE)

                match_rev = parser.OFPMatch(eth_type=const.ETH_TYPE_IP, ipv4_src=dst_real, ipv4_dst=src_real)
                actions_rev = [parser.OFPActionSetField(ipv4_src=dst_virt), parser.OFPActionOutput(src_info['port'])]
                self.app.flow_manager.add_flow(ingress_dp, const.PRIORITY_TRANSLATION, match_rev, actions_rev,
                                              idle_timeout=15, hard_timeout=120, table_id=const.TABLE_GRACE,
                                              cookie=const.COOKIE_MTD_GRACE)
            else:
                # Inter-leaf 2-hop route via Spine
                route = self.app.topology.get_inter_switch_route(ingress_dp.id, egress_dp.id, flow_key=(src_real, dst_real))
                if route and all(p is not None for p in route[1:]):
                    spine_dpid, port_in_to_sp, port_sp_to_eg, port_eg_to_sp, port_sp_to_in = route
                    spine_dp = self.app.topology.get_datapath(spine_dpid)

                    # 1. Ingress Leaf (Table 1 Grace): Output to Spine port
                    match_ing = parser.OFPMatch(eth_type=const.ETH_TYPE_IP, ipv4_src=src_real, ipv4_dst=dst_virt)
                    actions_ing = [parser.OFPActionSetField(ipv4_dst=dst_real), parser.OFPActionOutput(port_in_to_sp)]
                    self.app.flow_manager.add_flow(ingress_dp, const.PRIORITY_TRANSLATION, match_ing, actions_ing,
                                                  idle_timeout=15, hard_timeout=120, table_id=const.TABLE_GRACE,
                                                  cookie=const.COOKIE_MTD_GRACE)

                    # 2. Spine switch: Transit forward to Egress Leaf
                    if spine_dp:
                        sp_parser = spine_dp.ofproto_parser
                        match_sp = sp_parser.OFPMatch(eth_type=const.ETH_TYPE_IP, ipv4_src=src_real, ipv4_dst=dst_real)
                        actions_sp = [sp_parser.OFPActionOutput(port_sp_to_eg)]
                        self.app.flow_manager.add_flow(spine_dp, const.PRIORITY_TRANSLATION, match_sp, actions_sp,
                                                      idle_timeout=15, hard_timeout=120, table_id=const.TABLE_ACTIVE)

                    # 3. Egress Leaf (Table 1 Grace): Output to host port
                    e_parser = egress_dp.ofproto_parser
                    match_eg = e_parser.OFPMatch(eth_type=const.ETH_TYPE_IP, ipv4_src=src_real, ipv4_dst=dst_real)
                    actions_eg = [e_parser.OFPActionOutput(dst_info['port'])]
                    self.app.flow_manager.add_flow(egress_dp, const.PRIORITY_TRANSLATION, match_eg, actions_eg,
                                                  idle_timeout=15, hard_timeout=120, table_id=const.TABLE_GRACE,
                                                  cookie=const.COOKIE_MTD_GRACE)

                    # 4. Egress Leaf Reverse: Output to Spine port (match dst_real -> src_real)
                    match_eg_rev = e_parser.OFPMatch(eth_type=const.ETH_TYPE_IP, ipv4_src=dst_real, ipv4_dst=src_real)
                    actions_eg_rev = [e_parser.OFPActionSetField(ipv4_src=dst_virt), e_parser.OFPActionOutput(port_eg_to_sp)]
                    self.app.flow_manager.add_flow(egress_dp, const.PRIORITY_TRANSLATION, match_eg_rev, actions_eg_rev,
                                                  idle_timeout=15, hard_timeout=120, table_id=const.TABLE_GRACE,
                                                  cookie=const.COOKIE_MTD_GRACE)

                    # 5. Spine switch Reverse: Transit forward to Ingress Leaf
                    if spine_dp:
                        sp_parser = spine_dp.ofproto_parser
                        match_sp_rev = sp_parser.OFPMatch(eth_type=const.ETH_TYPE_IP, ipv4_dst=src_real)
                        actions_sp_rev = [sp_parser.OFPActionOutput(port_sp_to_in)]
                        self.app.flow_manager.add_flow(spine_dp, const.PRIORITY_TRANSLATION, match_sp_rev, actions_sp_rev,
                                                      idle_timeout=15, hard_timeout=120, table_id=const.TABLE_ACTIVE)

                    # 6. Ingress Leaf Reverse: Output to source host port
                    match_in_rev = parser.OFPMatch(eth_type=const.ETH_TYPE_IP, ipv4_dst=src_real)
                    actions_in_rev = [parser.OFPActionSetField(ipv4_src=dst_virt), parser.OFPActionOutput(src_info['port'])]
                    self.app.flow_manager.add_flow(ingress_dp, const.PRIORITY_TRANSLATION, match_in_rev, actions_in_rev,
                                                  idle_timeout=15, hard_timeout=120, table_id=const.TABLE_GRACE,
                                                  cookie=const.COOKIE_MTD_GRACE)
                else:
                    self.app.logger.warning(f"[mtd] No 2-hop spine route found for grace flow between S{ingress_dp.id} and S{egress_dp.id}")