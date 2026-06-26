#!/bin/bash

# ==============================================================================
# Sim-to-Real Fine-Tuning Pipeline
# Orchestrates Ryu, Containernet, and the RL Fine-Tuning Agent.
# ==============================================================================

# 1. Setup Environment
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_DIR"

echo " Project Directory: $PROJECT_DIR"

# Activate virtual environment
if [ -d "venv" ]; then
    source venv/bin/activate
else
    echo "❌ Error: 'venv' directory not found. Please activate your environment manually."
    exit 1
fi

# 2. Define Cleanup Function (Runs on exit or Ctrl+C)
cleanup() {
    echo -e "\n🛑 Shutting down pipeline..."
    
    # Kill background processes
    if [ ! -z "$RYU_PID" ]; then
        echo "   Stopping Ryu Controller (PID: $RYU_PID)..."
        kill $RYU_PID 2>/dev/null
    fi
    if [ ! -z "$TOPO_PID" ]; then
        echo "   Stopping Containernet Topology (PID: $TOPO_PID)..."
        sudo kill $TOPO_PID 2>/dev/null
    fi
    
    # Clean up Containernet ghosts (Docker containers and OVS bridges)
    echo "   Cleaning up Containernet ghosts..."
    sudo docker rm -f $(sudo docker ps -a -q --filter name=mn.) 2>/dev/null
    sudo mn -c 2>/dev/null
    
    echo "✅ Pipeline shutdown complete."
}

# Register the cleanup function to run on script exit or interrupt
trap cleanup EXIT INT TERM

# 3. Helper function to wait for a port to open
wait_for_port() {
    local port=$1
    local name=$2
    local timeout=60
    local elapsed=0
    
    echo " Waiting for $name to be ready on port $port..."
    while ! (echo > /dev/tcp/127.0.0.1/$port) 2>/dev/null; do
        sleep 1
        elapsed=$((elapsed + 1))
        if [ $elapsed -ge $timeout ]; then
            echo "❌ Timeout waiting for $name. Check logs for errors."
            exit 1
        fi
    done
    echo "✅ $name is ready!"
}

# 4. Start Ryu Controller
echo -e "\n🧠 Starting Ryu Controller..."
PYTHONPATH=. ryu-manager mtd_ip_shuffling.app --observe-links > ryu_experiment.log &
RYU_PID=$!

# Wait for Ryu REST API (Port 8080)
wait_for_port 8080 "Ryu REST API"

# 5. Start Containernet Topology
echo -e "\n Starting Containernet Topology (Requires sudo)..."
# Note: sudo might prompt for a password here if not configured for passwordless sudo
sudo python3 testbed/containernet_topos/finetune_topo.py > topo_finetune.log 2>&1 &
TOPO_PID=$!

# Wait for Command Socket (Port 9999)
wait_for_port 9999 "Containernet Command Socket"

# 6. Run Fine-Tuning Agent
echo -e "\n🎓 Starting Sim-to-Real Fine-Tuning..."
echo "   (Passing arguments: $@)"
echo "   Logs will be saved to the respective run directory."
echo "   Press Ctrl+C to stop early."

# Run the fine-tuning script in the foreground
python rl_agent/fine_tune_agent.py "$@"
FINE_TUNE_EXIT_CODE=$?

# 7. Finish
if [ $FINE_TUNE_EXIT_CODE -eq 0 ]; then
    echo -e "\n🎉 Fine-tuning completed successfully!"
else
    echo -e "\n️  Fine-tuning exited with code $FINE_TUNE_EXIT_CODE."
fi

# The 'trap' will automatically handle the cleanup of Ryu and Topology
exit $FINE_TUNE_EXIT_CODE