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
        
        # AI model initialization
        self.use_ai = False
        self.model = None
        self._load_ai_model()
        
        self.app.logger.info(
            f"[MTD Engine] Initialized | Normal: {normal_interval}s | "
            f"Attack: {attack_interval}s | AI: {self.use_ai}"
        )

    def _load_ai_model(self):
        """Load the trained PPO model from the runs directory."""
        if not RL_AVAILABLE:
            self.app.logger.warning("⚠️ [MTD Engine] Stable-Baselines3 not installed. Using heuristic logic.")
            return
        
        # Look for the latest model in the runs directory
        runs_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "rl_agent", "runs")
        model_path = None
        
        if os.path.exists(runs_dir):
            # Find the most recent run folder
            run_folders = [f for f in os.listdir(runs_dir) if f.startswith('run_')]
            if run_folders:
                run_folders.sort(reverse=True)
                latest_model = os.path.join(runs_dir, run_folders[0], "mtd_ppo_agent.zip")
                if os.path.exists(latest_model):
                    model_path = latest_model
        
        # Fallback to current directory
        if not model_path:
            fallback_path = os.path.join(os.getcwd(), "mtd_ppo_agent.zip")
            if os.path.exists(fallback_path):
                model_path = fallback_path
        
        if model_path:
            try:
                self.model = PPO.load(model_path)
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

        # 🛡️ SIM-TO-REAL SAFETY GUARD
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
        """Builds the 7D State Vector used during training."""
        threat_state = self.app.threat_detector.get_state()
        threat_intensity = self.app.threat_detector.get_max_intensity()
        
        time_since = time.time() - self.last_shuffle_time
        time_norm = min(time_since / self.max_shuffle_interval, 1.0)
        
        active_flows = getattr(self.app.flow_manager, 'active_flow_count', 0)
        active_flows_norm = min(active_flows / 100.0, 1.0)
        
        return np.array([
            threat_state[0],  # ent_ip
            threat_state[1],  # ent_port
            threat_state[2],  # ewma_rate
            threat_state[3],  # cv
            threat_intensity, # continuous intensity (index 4)
            time_norm,        # time staleness
            active_flows_norm # active flows
        ], dtype=np.float32)

    def step(self, action=1):
        """Executes the network shuffle based on the chosen action."""
        if action == 2:
            self.app.logger.info("🎯 [MTD] Executing TARGETED IP Shuffle...")
            new_mapping = self._generate_targeted_mapping()
        else:
            self.app.logger.info("🎲 [MTD] Executing GLOBAL IP Shuffle...")
            new_mapping = self._generate_random_mapping()
            
        self.apply_mapping(new_mapping)

    def _generate_targeted_mapping(self):
        """Generates a new mapping, changing only IPs currently being scanned."""
        targets = self.app.threat_detector.get_scanned_targets()
        new_mapping = self.current_mapping.copy()
        
        # Find which Real IPs correspond to the targeted Virtual IPs
        targeted_real_ips = [
            real_ip for real_ip, virt_ip in new_mapping.items() 
            if virt_ip in targets
        ]
                
        if not targeted_real_ips:
            return self._generate_random_mapping()

        # Get available IPs from the pool
        used_vips = set(new_mapping.values())
        available = [ip for ip in self.virtual_pool if ip not in used_vips]
        random.shuffle(available)
        
        # Only shuffle the targeted Real IPs
        for real_ip in targeted_real_ips:
            if available:
                new_mapping[real_ip] = available.pop()
                
        self.app.logger.info(f"🎯 [MTD] Targeted shuffle: {len(targeted_real_ips)} hosts")
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

    def apply_mapping(self, new_mapping):
        """Applies new mapping with Make-Before-Break grace period."""
        active_sessions = self.app.flow_manager.active_sessions.copy()
        
        self.app.logger.info(f"🔄 [MTD] Make-Before-Break for {len(active_sessions)} sessions...")
        
        # 1. Install grace flows in Table 1
        self._install_session_grace_flows(active_sessions)
        
        # 2. Flush Table 0 (Active)
        self._flush_old_flows()
        
        # 3. Update internal state
        self.current_mapping = new_mapping
        self.app.real_to_virtual = new_mapping
        self.app.virtual_to_real = {v: k for k, v in new_mapping.items()}
        
        # 4. Clear session tracker
        self.app.flow_manager.active_sessions.clear()
        
        self.app.logger.info("✅ [MTD] Graceful shuffle complete. 15s grace period.")
        for r, v in sorted(new_mapping.items()):
            self.app.logger.info(f"   {r} ⇄ {v}")

    def _flush_old_flows(self):
        """Deletes all flows in the ACTIVE table (Table 0) across all switches."""
        for dpid, dp in self.app.topology.datapath_list.items():
            self.app.flow_manager.flush_translation_flows(dp)

    def _install_session_grace_flows(self, sessions):
        """Installs 4-way flows for active sessions into Table 1 (Grace)."""
        for (src_real, dst_real), (src_virt, dst_virt) in sessions.items():
            if (src_real not in self.app.topology.host_table or 
                dst_real not in self.app.topology.host_table):
                continue
                
            src_info = self.app.topology.host_table[src_real]
            dst_info = self.app.topology.host_table[dst_real]
            
            ingress_dp = self.app.topology.get_datapath(src_info['dpid'])
            egress_dp = self.app.topology.get_datapath(dst_info['dpid'])
            
            if not ingress_dp or not egress_dp:
                continue
                
            parser = ingress_dp.ofproto_parser
            ofproto = ingress_dp.ofproto
            
            # 1. Ingress Forward: Old Virtual Dst -> Real Dst
            match = parser.OFPMatch(eth_type=const.ETH_TYPE_IP, ipv4_dst=dst_virt)
            actions = [
                parser.OFPActionSetField(ipv4_dst=dst_real),
                parser.OFPActionOutput(ofproto.OFPP_NORMAL)
            ]
            self.app.flow_manager.add_flow(
                ingress_dp, const.PRIORITY_TRANSLATION, match, actions,
                hard_timeout=const.GRACE_PERIOD_TIMEOUT, table_id=const.TABLE_GRACE
            )

            # 2. Ingress Reverse: Real Src -> Old Virtual Src
            match_rev = parser.OFPMatch(
                eth_type=const.ETH_TYPE_IP, 
                ipv4_src=dst_real, 
                ipv4_dst=src_real
            )
            actions_rev = [
                parser.OFPActionSetField(ipv4_src=dst_virt),
                parser.OFPActionOutput(src_info['port'])
            ]
            self.app.flow_manager.add_flow(
                ingress_dp, const.PRIORITY_TRANSLATION, match_rev, actions_rev,
                hard_timeout=const.GRACE_PERIOD_TIMEOUT, table_id=const.TABLE_GRACE
            )

            # Egress flows (if different switch)
            if ingress_dp.id != egress_dp.id:
                e_parser = egress_dp.ofproto_parser
                e_ofproto = egress_dp.ofproto
                
                # 3. Egress Forward: Real Src/Dst -> Old Virtual Src
                match_eg = e_parser.OFPMatch(
                    eth_type=const.ETH_TYPE_IP, 
                    ipv4_src=src_real, 
                    ipv4_dst=dst_real
                )
                actions_eg = [
                    e_parser.OFPActionSetField(ipv4_src=src_virt),
                    e_parser.OFPActionOutput(dst_info['port'])
                ]
                self.app.flow_manager.add_flow(
                    egress_dp, const.PRIORITY_TRANSLATION, match_eg, actions_eg,
                    hard_timeout=const.GRACE_PERIOD_TIMEOUT, table_id=const.TABLE_GRACE
                )

                # 4. Egress Reverse: Old Virtual Dst -> Real Dst
                match_eg_rev = e_parser.OFPMatch(
                    eth_type=const.ETH_TYPE_IP, 
                    ipv4_dst=src_virt
                )
                actions_eg_rev = [
                    e_parser.OFPActionSetField(ipv4_dst=src_real),
                    e_parser.OFPActionOutput(e_ofproto.OFPP_NORMAL)
                ]
                self.app.flow_manager.add_flow(
                    egress_dp, const.PRIORITY_TRANSLATION, match_eg_rev, actions_eg_rev,
                    hard_timeout=const.GRACE_PERIOD_TIMEOUT, table_id=const.TABLE_GRACE
                )