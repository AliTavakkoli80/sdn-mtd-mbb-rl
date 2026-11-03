#!/bin/bash
set -e

PROJECT_DIR="/home/ubuntu/Projects/MTD"
cd "$PROJECT_DIR"

cleanup() {
    echo -e "\n🛑 Cleaning up background processes and Containernet testbed..."
    if [ ! -z "$RYU_PID" ]; then
        kill -9 $RYU_PID 2>/dev/null || true
    fi
    if [ ! -z "$TOPO_PID" ]; then
        sudo -E kill -9 $TOPO_PID 2>/dev/null || true
    fi
    sudo -E mn -c 2>/dev/null || true
    sudo -E docker rm -f $(docker ps -a -q --filter name=mn.) 2>/dev/null || true
    echo "✅ Teardown complete."
}
trap cleanup EXIT INT TERM

# 0. Initial Clean
sudo -E mn -c 2>/dev/null || true
sudo -E docker rm -f $(docker ps -a -q --filter name=mn.) 2>/dev/null || true
pkill -9 -f "ryu-manager" 2>/dev/null || true
sudo -E pkill -9 -f "finetune_topo\.py" 2>/dev/null || true

export RYU_API_URL="http://127.0.0.1:8088"

# 1. Start Ryu Controller
echo "🧠 Starting Ryu Controller..."
PYTHONPATH="$PROJECT_DIR" "$PROJECT_DIR/.venv/bin/ryu-manager" mtd_ip_shuffling.app --observe-links --ofp-tcp-listen-port 6653 --wsapi-port 8088 > ryu_experiment.log 2>&1 &
RYU_PID=$!

for i in $(seq 1 15); do
    if "$PROJECT_DIR/.venv/bin/python" -c "import socket; s = socket.socket(); s.settimeout(1); s.connect(('127.0.0.1', 8088)); s.close()" 2>/dev/null; then
        echo "✅ Ryu ready on port 8088!"
        break
    fi
    if ! kill -0 $RYU_PID 2>/dev/null; then
        echo "❌ Ryu exited unexpectedly! Log output:"
        cat ryu_experiment.log
        exit 1
    fi
    sleep 1
done

# 2. Start Containernet Topology
echo "🌐 Starting Containernet Topology..."
sudo -E RYU_API_URL="http://127.0.0.1:8088" "$PROJECT_DIR/.venv/bin/python" testbed/containernet_topos/finetune_topo.py > topo_finetune.log 2>&1 &
TOPO_PID=$!

for i in $(seq 1 30); do
    if "$PROJECT_DIR/.venv/bin/python" -c "import socket; s = socket.socket(); s.settimeout(1); s.connect(('127.0.0.1', 9999)); s.close()" 2>/dev/null; then
        echo "✅ Containernet Topology ready on port 9999!"
        break
    fi
    if ! sudo kill -0 $TOPO_PID 2>/dev/null; then
        echo "❌ Containernet Topology exited unexpectedly! Log output:"
        cat topo_finetune.log
        exit 1
    fi
    sleep 1
done

# Give Ryu and OVS a moment to establish full topology links and discover hosts
sleep 15

# 3. Step 1: Live Data-Plane MBB Experiment
echo -e "\n========================================================"
echo "🔬 STEP 1: Live Data-Plane Make-Before-Break Benchmark"
echo "========================================================"
"$PROJECT_DIR/.venv/bin/python" rl_agent/benchmark_dataplane_mbb.py

# 4. Step 2: Real Baseline Evaluation
echo -e "\n========================================================"
echo "📊 STEP 2: Live Containernet Baseline Evaluation (5 Policies)"
echo "========================================================"
"$PROJECT_DIR/.venv/bin/python" rl_agent/evaluate_real_agent.py --episodes 30 --steps 36 --step-duration 0.25

# 5. Step 3: Plot Regeneration
echo -e "\n========================================================"
echo "📈 STEP 3: Academic Visualizations Regeneration"
echo "========================================================"
"$PROJECT_DIR/.venv/bin/python" rl_agent/visualize_results.py

# 6. Step 4: Refresh Consolidated Codebase
echo -e "\n========================================================"
echo "📦 STEP 4: Code Consolidation"
echo "========================================================"
"$PROJECT_DIR/.venv/bin/python" consolidate_code.py

echo -e "\n🎉 ALL BENCHMARKS AND VISUALIZATIONS COMPLETED SUCCESSFULLY!"
