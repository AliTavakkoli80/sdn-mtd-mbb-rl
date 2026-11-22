#!/bin/bash
set -e

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_DIR"
export CUDA_VISIBLE_DEVICES=""

if [ -x "$PROJECT_DIR/.venv/bin/python" ]; then
    PYTHON_BIN="$PROJECT_DIR/.venv/bin/python"
    RYU_BIN="$PROJECT_DIR/.venv/bin/ryu-manager"
elif [ -x "$PROJECT_DIR/venv/bin/python" ]; then
    PYTHON_BIN="$PROJECT_DIR/venv/bin/python"
    RYU_BIN="$PROJECT_DIR/venv/bin/ryu-manager"
else
    PYTHON_BIN="$(command -v python3)"
    RYU_BIN="$(command -v ryu-manager)"
fi

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
PYTHONPATH="$PROJECT_DIR" "$RYU_BIN" mtd_ip_shuffling.app --observe-links --ofp-tcp-listen-port 6653 --wsapi-port 8088 > ryu_experiment.log 2>&1 &
RYU_PID=$!

echo "Waiting for Ryu REST API on 127.0.0.1:8088..."
while ! "$PYTHON_BIN" -c "import socket; s = socket.socket(); s.settimeout(1); s.connect(('127.0.0.1', 8088)); s.close()" 2>/dev/null; do
    sleep 1
done
echo "✅ Ryu ready on port 8088!"

# 2. Start Containernet Topology
echo "🌐 Starting Containernet Topology..."
sudo -E RYU_API_URL="http://127.0.0.1:8088" "$PYTHON_BIN" testbed/containernet_topos/finetune_topo.py > topo_finetune.log 2>&1 &
TOPO_PID=$!

echo "Waiting for Containernet command socket on 127.0.0.1:9999..."
while ! "$PYTHON_BIN" -c "import socket; s = socket.socket(); s.settimeout(1); s.connect(('127.0.0.1', 9999)); s.close()" 2>/dev/null; do
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
"$PYTHON_BIN" rl_agent/evaluate_real_agent.py --episodes 50 --steps 36 --step-duration 0.25

# 4. Plot Regeneration
echo -e "\n========================================================"
echo "📈 Regenerating Academic Visualizations"
echo "========================================================"
"$PYTHON_BIN" rl_agent/visualize_results.py

# 5. Code Consolidation
echo -e "\n========================================================"
echo "📦 Consolidating Codebase"
echo "========================================================"
"$PYTHON_BIN" consolidate_code.py

echo -e "\n🎉 EVALUATION AND PLOT REGENERATION COMPLETED SUCCESSFULLY!"
