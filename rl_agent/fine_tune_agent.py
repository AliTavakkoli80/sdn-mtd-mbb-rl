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
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from containernet_env import ContainernetEnv


class FineTuneLogger(BaseCallback):
    """Logs fine-tuning progress to CSV with correct cumulative timesteps."""
    
    def __init__(self, log_dir, base_timestep=500000, verbose=0):
        super().__init__(verbose)
        self.log_dir = log_dir
        self.log_file = None
        self.base_timestep = base_timestep  # Where mock training ended
        
    def _on_training_start(self):
        os.makedirs(self.log_dir, exist_ok=True)
        self.log_file = open(os.path.join(self.log_dir, "finetune_log.csv"), 'w')
        self.log_file.write("timestep,reward,action,threat_intensity,active_flows\n")
        
    def _on_step(self):
        obs = self.locals['new_obs'][0]
        action = self.locals['actions'][0]
        reward = self.locals['rewards'][0]
        
        # 🌟 FIX: Add base_timestep to get cumulative timestep
        timestep = self.num_timesteps + self.base_timestep
        
        self.log_file.write(
            f"{timestep},{reward:.4f},{action},{obs[4]:.4f},{obs[6]:.4f}\n"
        )
        
        if timestep % 10 == 0:
            self.log_file.flush()
            action_names = ["HOLD", "GLOBAL", "TARGETED"]
            print(f"  Step {timestep:7d} | {action_names[action]:8s} | "
                  f"R={reward:+6.2f} | Threat={obs[4]:.2f} | Flows={obs[6]:.2f}")
        
        return True
    
    def _on_training_end(self):
        if self.log_file:
            self.log_file.close()


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
                       help='Path to pre-trained model (.zip). If not specified, uses latest run.')
    parser.add_argument('--steps', type=int, default=500,
                       help='Number of fine-tuning steps (default: 500)')
    parser.add_argument('--lr', type=float, default=0.0001,
                       help='Learning rate for fine-tuning (default: 0.0001, lower than training)')
    args = parser.parse_args()
    
    print("="*60)
    print("🎓 SIM-TO-REAL FINE-TUNING")
    print("="*60)
    
    # Determine model path
    if args.model:
        model_path = args.model
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
    
    print(f"📦 Loading pre-trained model: {model_path}")
    
    # Load the pre-trained model
    model = PPO.load(model_path)
    
    # Determine output path (same run directory)
    run_dir = os.path.dirname(model_path)
    output_path = os.path.join(run_dir, "mtd_ppo_agent_real.zip")
    
    print(f"💾 Fine-tuned model will be saved to: {output_path}")
    print(f"📊 Steps: {args.steps}")
    print(f"🎯 Learning rate: {args.lr}")
    
    # Create the real environment
    print("\n🌐 Connecting to Containernet environment...")
    try:
        env = ContainernetEnv(render_mode="human")
    except ConnectionError as e:
        print(f"❌ {e}")
        sys.exit(1)
    
    # Create logger
    logger = FineTuneLogger(run_dir, base_timestep=500000)
    
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