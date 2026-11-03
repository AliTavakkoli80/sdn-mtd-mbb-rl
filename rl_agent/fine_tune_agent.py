"""
fine_tune_agent.py - Fine-tune a pre-trained PPO agent on real Containernet.

This script implements the Sim-to-Real transfer methodology:
1. Load pre-trained model from mock environment
2. Fine-tune on real Containernet topology with reduced learning rate
3. Save fine-tuned model for evaluation

Usage:
    1. Start Ryu:       PYTHONPATH=. ryu-manager mtd_ip_shuffling.app
    2. Start topology:  sudo python3 containernet_topos/finetune_topo.py
    3. Run fine-tuning: python fine_tune_agent.py --model runs/run_XXX/mtd_ppo_agent.zip
"""

import os
import sys
import argparse
import numpy as np
from datetime import datetime
from stable_baselines3 import PPO
from stable_baselines3.common.callbacks import BaseCallback

# Add parent dir to path
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SCRIPT_DIR)
from containernet_env import ContainernetEnv


class FineTuneLogger(BaseCallback):
    """Logs fine-tuning progress to CSV with correct cumulative timesteps and loss."""
    
    def __init__(self, log_dir, base_timestep=300000, verbose=0):
        super().__init__(verbose)
        self.log_dir = log_dir
        self.log_file = None
        self.root_log_file = None
        self.base_timestep = base_timestep  # Where mock training ended
        self.last_loss = 0.0
        
    def _on_training_start(self):
        os.makedirs(self.log_dir, exist_ok=True)
        self.log_file = open(os.path.join(self.log_dir, "finetune_log.csv"), 'w')
        self.log_file.write("timestep,reward,action,threat_intensity,active_flows,loss\n")
        
        # Mirror directly to SCRIPT_DIR/finetune_log.csv
        root_path = os.path.join(SCRIPT_DIR, "finetune_log.csv")
        self.root_log_file = open(root_path, 'w')
        self.root_log_file.write("timestep,reward,action,threat_intensity,active_flows,loss\n")
        
    def _on_step(self):
        obs = self.locals['new_obs'][0]
        action = self.locals['actions'][0]
        reward = self.locals['rewards'][0]
        
        # Cumulative timestep across pre-training and fine-tuning
        timestep = self.num_timesteps
        if timestep < self.base_timestep:
            timestep += self.base_timestep
        
        # Extract training loss if available from SB3 logger
        loss_val = 0.0
        if hasattr(self, 'logger') and hasattr(self.logger, 'name_to_value'):
            loss_val = float(self.logger.name_to_value.get('train/loss',
                             self.logger.name_to_value.get('train/policy_gradient_loss', self.last_loss)))
            self.last_loss = loss_val
        
        line = f"{timestep},{reward:.4f},{action},{obs[4]:.4f},{obs[6]:.4f},{loss_val:.6f}\n"
        self.log_file.write(line)
        if self.root_log_file:
            self.root_log_file.write(line)
        
        if self.n_calls % 50 == 0 or self.n_calls == 1:
            self.log_file.flush()
            if self.root_log_file:
                self.root_log_file.flush()
            action_names = ["HOLD", "GLOBAL", "TARGETED"]
            act_name = action_names[action] if 0 <= action < 3 else str(action)
            print(f"  [FineTune] Step {self.n_calls:5d} (Cumul: {timestep:7d}) | Act: {act_name:8s} | "
                  f"R: {reward:+6.2f} | Threat: {obs[4]:.2f} | Flows: {obs[6]:.2f} | Loss: {loss_val:.4f}")
        
        return True
    
    def _on_training_end(self):
        if self.log_file:
            self.log_file.close()
        if self.root_log_file:
            self.root_log_file.close()


def get_latest_run_dir():
    """Find the most recent run directory."""
    runs_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "runs")
    if not os.path.exists(runs_dir):
        raise FileNotFoundError("No 'runs' directory found")
    
    runs = [d for d in os.listdir(runs_dir) if d.startswith('run_')]
    if not runs:
        raise FileNotFoundError("No experiment runs found")
    
    runs.sort(reverse=True)
    return os.path.join(runs_dir, runs[0])


def main():
    parser = argparse.ArgumentParser(description='Fine-tune PPO agent on Containernet')
    parser.add_argument('--model', type=str, default=None,
                       help='Path to pre-trained model (.zip). If not specified, uses rl_agent/mtd_ppo_agent.zip.')
    parser.add_argument('--steps', type=int, default=5000,
                       help='Number of fine-tuning steps (default: 5000)')
    parser.add_argument('--step_duration', type=float, default=0.06,
                       help='Step duration in seconds (default: 0.06)')
    parser.add_argument('--n_steps', type=int, default=64,
                       help='Rollout buffer size for live fine-tuning (default: 64)')
    parser.add_argument('--lr', type=float, default=0.0001,
                       help='Learning rate for fine-tuning (default: 0.0001, lower than training)')
    parser.add_argument('--verbose', action='store_true',
                       help='Enable verbose step printing')
    args = parser.parse_args()
    
    print("="*60)
    print("🎓 SIM-TO-REAL FINE-TUNING")
    print("="*60)
    
    # Determine model path: Prefer SCRIPT_DIR/mtd_ppo_agent.zip as the canonical simulation base checkpoint
    if args.model:
        model_path = args.model
        run_dir = os.path.dirname(model_path)
    else:
        cand = os.path.join(SCRIPT_DIR, "mtd_ppo_agent.zip")
        if os.path.exists(cand):
            model_path = cand
            run_dir = SCRIPT_DIR
        else:
            try:
                run_dir = get_latest_run_dir()
                model_path = os.path.join(run_dir, "mtd_ppo_agent.zip")
                print(f"📂 Using latest run: {os.path.basename(run_dir)}")
            except FileNotFoundError as e:
                print(f"❌ Error: {e}")
                sys.exit(1)
    
    if not os.path.exists(model_path):
        print(f"❌ Model not found: {model_path}")
        sys.exit(1)
    
    print(f"📦 Loading pre-trained simulation base model: {model_path}")
    
    # Load the pre-trained model
    model = PPO.load(model_path, device="cpu")
    
    # Determine output path: exclusively saves to mtd_ppo_agent_real.zip
    output_path = os.path.join(run_dir, "mtd_ppo_agent_real.zip")
    
    print(f"💾 Adapted real model will be saved to: {output_path}")
    print(f"📊 Live steps: {args.steps} (step_duration={args.step_duration}s)")
    print(f"🎯 Learning rate: {args.lr} | Buffer: n_steps={args.n_steps}")
    
    # Create the real environment
    print("\n🌐 Connecting to Containernet environment...")
    try:
        env = ContainernetEnv(step_duration=args.step_duration, render_mode="human" if args.verbose else None)
    except ConnectionError as e:
        print(f"❌ {e}")
        sys.exit(1)
    
    # Create logger
    logger = FineTuneLogger(run_dir, base_timestep=300000)
    
    print("\n" + "="*60)
    print("🚀 STARTING FINE-TUNING")
    print("="*60)
    print("The agent will now adapt to real network dynamics...")
    print("This may take several minutes. Press Ctrl+C to stop early.\n")
    
    # Fine-tune with a smaller learning rate to preserve learned behavior
    model.learning_rate = args.lr
    
    try:
        # Attach the environment to the loaded model BEFORE learning
        model.set_env(env)
        
        # Reallocate rollout buffer with live testbed n_steps
        from stable_baselines3.common.buffers import RolloutBuffer
        model.n_steps = args.n_steps
        model.rollout_buffer = RolloutBuffer(
            model.n_steps,
            model.observation_space,
            model.action_space,
            device=model.device,
            gamma=model.gamma,
            gae_lambda=model.gae_lambda,
            n_envs=model.n_envs
        )
        print(f"⚙️  Adjusted live rollout buffer size: n_steps={args.n_steps}")
        
        initial_steps = model.num_timesteps
        print(f"📊 Training for {args.steps} live steps from step {initial_steps}...")
        
        model.learn(
            total_timesteps=args.steps,
            callback=logger,
            reset_num_timesteps=False  # Continue from pre-trained
        )
    except KeyboardInterrupt:
        print("\n\n⚠️  Fine-tuning interrupted by user.")
    
    # Save the fine-tuned model
    print("\n" + "="*60)
    print("💾 SAVING FINE-TUNED MODEL")
    print("="*60)
    model.save(output_path.replace('.zip', ''))
    print(f"✅ Saved to: {output_path}")
    import shutil
    target_real_path = os.path.join(SCRIPT_DIR, "mtd_ppo_agent_real.zip")
    if os.path.abspath(output_path) != os.path.abspath(target_real_path):
        shutil.copy(output_path, target_real_path)
        print(f"✅ Copied to: {target_real_path}")
    
    # Close environment
    env.close()
    
    print("\n" + "="*60)
    print("🎉 FINE-TUNING COMPLETE!")
    print("="*60)
    print(f"📁 Run directory: {run_dir}")
    print(f"📦 Pre-trained model: {model_path}")
    print(f"📦 Fine-tuned model: {output_path}")
    print(f"📊 Fine-tuning log: {os.path.join(run_dir, 'finetune_log.csv')}")
    print("\nNext steps:")
    print("  1. Generate comparison plots (mock-only vs fine-tuned)")
    print("  2. Evaluate both models on real topology")
    print("  3. Document sim-to-real gap closure in thesis")


if __name__ == "__main__":
    main()