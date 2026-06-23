import random
import time
import os
import numpy as np
import ipaddress # 🌟 Added for dynamic subnet calculation
from ryu.lib import hub
from . import constants as const

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
        
        # DYNAMIC POOL GENERATION: Calculates the subnet based on real IPs
        self.virtual_pool = self._generate_virtual_pool()
        
        self.normal_interval = normal_interval
        self.attack_interval = attack_interval
        self.current_interval = normal_interval
        self.max_shuffle_interval = float(normal_interval)
        
        self.current_mapping = app.real_to_virtual.copy()
        self.last_shuffle_time = time.time()
        self.is_accelerated = False
        
        # 🧠 AI MODEL LOADING
        self.use_ai = False
        self.model = None
        
        if RL_AVAILABLE:
            # Look for the model in the project root (where you run ryu-manager)
            model_path = os.path.join(os.getcwd(), "mtd_ppo_agent.zip")
            if os.path.exists(model_path):
                try:
                    self.model = PPO.load(model_path)
                    self.use_ai = True
                    self.app.logger.info("🧠 [MTD Engine] AI Model loaded successfully! Switching to DRL Inference.")
                except Exception as e:
                    self.app.logger.error(f"❌ [MTD Engine] Failed to load AI model: {e}. Falling back to heuristics.")
            else:
                self.app.logger.warning("⚠️ [MTD Engine] mtd_ppo_agent.zip not found. Falling back to heuristic logic.")
        else:
            self.app.logger.warning("⚠️ [MTD Engine] Stable-Baselines3 not installed. Using heuristic logic.")

        self.app.logger.info(
            f"[MTD Engine] Initialized | Normal: {normal_interval}s | Attack: {attack_interval}s | AI: {self.use_ai}"
        )

    def _generate_virtual_pool(self):
        """
         Dynamically generates a pool of virtual IPs based on the subnet of the real IPs.
        It finds the smallest common network that contains all real IPs, ensuring the 
        virtual pool stays in the same local subnet for smoother ARP/L2 handling.
        """
        if not self.real_ips:
            self.app.logger.warning("[MTD Engine] No real IPs found. Virtual pool is empty.")
            return []
            
        try:
            # 1. Calculate the common subnet for all real IPs using bitwise XOR
            ip_ints = [int(ipaddress.IPv4Address(ip)) for ip in self.real_ips]
            xor_sum = 0
            for i in range(1, len(ip_ints)):
                xor_sum |= (ip_ints[0] ^ ip_ints[i])
                
            if xor_sum == 0:
                prefix_len = 32
            else:
                prefix_len = 32 - xor_sum.bit_length()
                
            # 2. Cap the prefix length at /8 to ensure a sufficiently large pool (254 IPs)
            # If the hosts are on different /8 subnets, it will dynamically expand to cover them
            prefix_len = min(prefix_len, 8)
            
            # 3. Create the network object
            network = ipaddress.IPv4Network(f"{self.real_ips[0]}/{prefix_len}", strict=False)
            
            # 4. Build the pool, excluding the actual real IPs
            pool = []
            for ip in network.hosts(): # .hosts() automatically excludes network/broadcast addresses
                ip_str = str(ip)
                if ip_str not in self.real_ips:
                    pool.append(ip_str)
                    
            self.app.logger.info(f"[MTD Engine] 🌐 Dynamically generated virtual pool: {network} ({len(pool)} available IPs)")
            return pool
            
        except Exception as e:
            self.app.logger.error(f"[MTD Engine] Failed to generate virtual pool dynamically: {e}")
            # Fallback to a default pool if something goes wrong
            return [f"10.0.100.{i}" for i in range(10, 60)]

    def start(self):
        """Starts the adaptive shuffling loop."""
        hub.spawn(self._adaptive_shuffle_loop)

    def _adaptive_shuffle_loop(self):
        """The main control loop. Routes to AI or Heuristic based on model availability."""
        self.app.logger.info("[MTD Engine] Control loop started")
        
        while True:
            if self.use_ai:
                self._ai_inference_step()
                # Poll the AI every 2 seconds for rapid response
                hub.sleep(2) 
            else:
                self._heuristic_step()
                # Fallback sleep logic
                for _ in range(self.current_interval):
                    hub.sleep(1)
                    state = self.app.threat_detector.get_state()
                    if state.get('is_under_attack', False) != self.is_accelerated:
                        break

    def _ai_inference_step(self):
        """Queries the live network state and asks the AI what to do."""
        obs = self._get_live_obs()
        
        action, _states = self.model.predict(obs, deterministic=True)
        
        # SAFETY GUARD: The PPO model is currently undertrained and may output 
        # random actions due to the Sim2Real gap. We force it to only shuffle if 
        # the threat detector actually confirms an attack (obs[4] is the threat_flag).
        if action == 1 and obs[4] > 0.5: 
            self.app.logger.info(f"🧠 [AI DECISION] SHUFFLE | Obs: {np.round(obs, 2)}")
            self.step()
            self.last_shuffle_time = time.time()
        else:
            # HOLD - Do nothing, save network overhead
            pass 

    def _heuristic_step(self):
        """The original hardcoded logic (Fallback)."""
        state = self.app.threat_detector.get_state()
        under_attack = state.get('is_under_attack', False)
        
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
            self.step()
            self.last_shuffle_time = time.time()

    def _get_live_obs(self):
        """Builds the exact same 7D State Vector used during training."""
        # 1-5: Threat metrics
        threat_state = self.app.threat_detector.get_state()
        
        # 6: Time since last shuffle
        time_since = time.time() - self.last_shuffle_time
        time_norm = min(time_since / self.max_shuffle_interval, 1.0)
        
        # 7: Active flows (QoS Cost)
        active_flows = getattr(self.app.flow_manager, 'active_flow_count', 0)
        active_flows_norm = min(active_flows / 100.0, 1.0)
        
        return np.append(threat_state, [time_norm, active_flows_norm]).astype(np.float32)

    def step(self, action=None):
        """Executes the actual network shuffle."""
        self.app.logger.info("🎲 [MTD] Executing IP Shuffle...")
        new_mapping = self._generate_random_mapping()
        self.apply_mapping(new_mapping)
        
    def _generate_random_mapping(self):
        available = self.virtual_pool.copy()
        random.shuffle(available)
        mapping = {}
        for real_ip in self.real_ips:
            if not available: break
            mapping[real_ip] = available.pop()
        return mapping

    def apply_mapping(self, new_mapping):
        old_mapping = self.current_mapping.copy()
        # Grab a snapshot of all active TCP sessions before we flush
        active_sessions = self.app.flow_manager.active_sessions.copy()
        
        self.app.logger.info(f"🔄 [MTD] Executing Make-Before-Break for {len(active_sessions)} active sessions...")
        
        # 1. Install ALL 4 directions of the OLD flows into Table 1 (Grace)
        self._install_session_grace_flows(active_sessions)
        
        # 2. Flush Table 0 (Active)
        self._flush_old_flows()
        
        # 3. Update internal state
        self.current_mapping = new_mapping
        self.app.real_to_virtual = new_mapping
        self.app.virtual_to_real = {v: k for k, v in new_mapping.items()}
        
        # 4. Clear the session tracker (new connections will use the new mapping)
        self.app.flow_manager.active_sessions.clear()
        
        self.app.logger.info("✅ [MTD] Graceful shuffle complete. Old TCP sessions have 15s to finish.")
        for r, v in sorted(new_mapping.items()):
            self.app.logger.info(f"   {r} ⇄ {v}")

    def _flush_old_flows(self):
        """Deletes all flows ONLY in the ACTIVE table (Table 0) across all switches."""
        for dpid, dp in self.app.topology.datapath_list.items():
            self.app.flow_manager.flush_translation_flows(dp)   

    def flush_translation_flows(self, datapath):
        """Deletes all flows with PRIORITY_TRANSLATION on a specific datapath."""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        # Match any IPv4 packet (eth_type=0x0800) to target our translation flows
        match = parser.OFPMatch(eth_type=const.ETH_TYPE_IP)
        
        mod = parser.OFPFlowMod(
            datapath=datapath,
            command=ofproto.OFPFC_DELETE,
            out_group=ofproto.OFPG_ANY,
            out_port=ofproto.OFPP_ANY,
            match=match,
            priority=const.PRIORITY_TRANSLATION,
            table_id=const.TABLE_ACTIVE # Only delete from Table 0!
        )
        datapath.send_msg(mod)
        self.app.logger.debug(f"[flow] 🗑️ Flushed ACTIVE flows on S{datapath.id}")             

    def _install_session_grace_flows(self, sessions):
        """Installs the exact 4-way flows for active sessions into Table 1 (Grace)."""
        for (src_real, dst_real), (src_virt, dst_virt) in sessions.items():
            if src_real not in self.app.topology.host_table or dst_real not in self.app.topology.host_table:
                continue
                
            src_info = self.app.topology.host_table[src_real]
            dst_info = self.app.topology.host_table[dst_real]
            
            ingress_dp = self.app.topology.get_datapath(src_info['dpid'])
            egress_dp = self.app.topology.get_datapath(dst_info['dpid'])
            
            if not ingress_dp or not egress_dp:
                continue
                
            parser = ingress_dp.ofproto_parser
            ofproto = ingress_dp.ofproto
            
            # 1. Ingress Forward (Client Edge): Match Old Virtual Dst -> Set Real Dst
            match = parser.OFPMatch(eth_type=const.ETH_TYPE_IP, ipv4_dst=dst_virt)
            actions = [parser.OFPActionSetField(ipv4_dst=dst_real),
                    parser.OFPActionOutput(ofproto.OFPP_NORMAL)]
            self.app.flow_manager.add_flow(ingress_dp, const.PRIORITY_TRANSLATION, match, actions,
                                        hard_timeout=const.GRACE_PERIOD_TIMEOUT, table_id=const.TABLE_GRACE)

            # 2. Ingress Reverse (Client Edge): Match Real Src -> Set Old Virtual Src
            match_rev = parser.OFPMatch(eth_type=const.ETH_TYPE_IP, ipv4_src=dst_real, ipv4_dst=src_real)
            actions_rev = [parser.OFPActionSetField(ipv4_src=dst_virt),
                        parser.OFPActionOutput(src_info['port'])]
            self.app.flow_manager.add_flow(ingress_dp, const.PRIORITY_TRANSLATION, match_rev, actions_rev,
                                        hard_timeout=const.GRACE_PERIOD_TIMEOUT, table_id=const.TABLE_GRACE)

            if ingress_dp.id != egress_dp.id:
                e_parser = egress_dp.ofproto_parser
                e_ofproto = egress_dp.ofproto
                
                # 3. Egress Forward (Server Edge): Match Real Src/Dst -> Set Old Virtual Src
                match_eg = e_parser.OFPMatch(eth_type=const.ETH_TYPE_IP, ipv4_src=src_real, ipv4_dst=dst_real)
                actions_eg = [e_parser.OFPActionSetField(ipv4_src=src_virt),
                            e_parser.OFPActionOutput(dst_info['port'])]
                self.app.flow_manager.add_flow(egress_dp, const.PRIORITY_TRANSLATION, match_eg, actions_eg,
                                            hard_timeout=const.GRACE_PERIOD_TIMEOUT, table_id=const.TABLE_GRACE)

                # 4. Egress Reverse (Server Edge): Match Old Virtual Dst -> Set Real Dst
                match_eg_rev = e_parser.OFPMatch(eth_type=const.ETH_TYPE_IP, ipv4_dst=src_virt)
                actions_eg_rev = [e_parser.OFPActionSetField(ipv4_dst=src_real),
                                e_parser.OFPActionOutput(e_ofproto.OFPP_NORMAL)]
                self.app.flow_manager.add_flow(egress_dp, const.PRIORITY_TRANSLATION, match_eg_rev, actions_eg_rev,
                                            hard_timeout=const.GRACE_PERIOD_TIMEOUT, table_id=const.TABLE_GRACE)        