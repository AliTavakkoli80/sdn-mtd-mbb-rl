#!/bin/bash
set -e

PROJECT_DIR="/home/ubuntu/Projects/MTD"
cd "$PROJECT_DIR"
export CUDA_VISIBLE_DEVICES=""

cleanup() {
    echo -e "\n🛑 Cleaning up background processes and Containernet testbed..."
    if [ ! -z "$RYU_PID" ]; then
        kill -9 $RYU_PID 2>/dev/null || true
    fi
    if [ ! -z "$TOPO_PID" ]; then
        sudo -E kill -9 $TOPO_PID 2>/dev/null || true
    fi
    sudo -E mn -c 2>/dev/null || true
    CONTAINERS=$(docker ps -a -q --filter name=mn.)
    if [ ! -z "$CONTAINERS" ]; then
        sudo -E docker rm -f $CONTAINERS 2>/dev/null || true
    fi
    echo "✅ Teardown complete."
}
trap cleanup EXIT INT TERM

# 0. Initial Clean
sudo -E mn -c 2>/dev/null || true
CONTAINERS=$(docker ps -a -q --filter name=mn.)
if [ ! -z "$CONTAINERS" ]; then
    sudo -E docker rm -f $CONTAINERS 2>/dev/null || true
fi
pkill -9 -f "ryu-manager" 2>/dev/null || true
sudo -E pkill -9 -f "finetune_topo\.py" 2>/dev/null || true

export RYU_API_URL="http://127.0.0.1:8088"

# 1. Start Ryu Controller
echo "🧠 Starting Ryu Controller..."
PYTHONPATH="$PROJECT_DIR" "$PROJECT_DIR/.venv/bin/ryu-manager" mtd_ip_shuffling.app --observe-links --ofp-tcp-listen-port 6653 --wsapi-port 8088 > ryu_experiment.log 2>&1 &
RYU_PID=$!

echo "Waiting for Ryu REST API on 127.0.0.1:8088..."
while ! "$PROJECT_DIR/.venv/bin/python" -c "import socket; s = socket.socket(); s.settimeout(1); s.connect(('127.0.0.1', 8088)); s.close()" 2>/dev/null; do
    sleep 1
done
echo "✅ Ryu ready on port 8088!"

# 2. Start Containernet Topology
echo "🌐 Starting Containernet Topology..."
sudo -E RYU_API_URL="http://127.0.0.1:8088" "$PROJECT_DIR/.venv/bin/python" testbed/containernet_topos/finetune_topo.py > topo_finetune.log 2>&1 &
TOPO_PID=$!

echo "Waiting for Containernet command socket on 127.0.0.1:9999..."
while ! "$PROJECT_DIR/.venv/bin/python" -c "import socket; s = socket.socket(); s.settimeout(1); s.connect(('127.0.0.1', 9999)); s.close()" 2>/dev/null; do
    sleep 1
done
echo "✅ Containernet Topology ready on port 9999!"

# Give Ryu and OVS a moment to establish full topology links and discover hosts
echo "⏳ Stabilizing network topology (10s)..."
sleep 10

# 3. Real Baseline Evaluation
echo -e "\n========================================================"
echo "📊 Running Live Containernet Baseline Evaluation (5 Policies, N=50)"
echo "========================================================"
"$PROJECT_DIR/.venv/bin/python" rl_agent/evaluate_real_agent.py --episodes 50 --steps 36 --step-duration 0.25

# 4. Plot Regeneration
echo -e "\n========================================================"
echo "📈 Regenerating Academic Visualizations"
echo "========================================================"
"$PROJECT_DIR/.venv/bin/python" rl_agent/visualize_results.py

# 5. Code Consolidation
echo -e "\n========================================================"
echo "📦 Consolidating Codebase"
echo "========================================================"
"$PROJECT_DIR/.venv/bin/python" consolidate_code.py

echo -e "\n🎉 EVALUATION AND PLOT REGENERATION COMPLETED SUCCESSFULLY!"
