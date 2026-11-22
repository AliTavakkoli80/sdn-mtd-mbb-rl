#!/bin/bash
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_DIR"

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
    echo "🛑 Stopping background processes and cleaning up..."
    if [ ! -z "$RYU_PID" ]; then
        kill $RYU_PID 2>/dev/null
    fi
    if [ ! -z "$TOPO_PID" ]; then
        sudo kill $TOPO_PID 2>/dev/null
    fi
    sudo docker rm -f $(sudo docker ps -a -q --filter name=mn.) 2>/dev/null
    sudo mn -c 2>/dev/null
    echo "✅ Cleaned up."
}
trap cleanup EXIT INT TERM

# Clean state first
sudo mn -c 2>/dev/null
sudo docker rm -f $(sudo docker ps -a -q --filter name=mn.) 2>/dev/null
sudo pkill -9 -f ryu-manager 2>/dev/null
sudo pkill -9 -f finetune_topo 2>/dev/null

echo "🧠 Starting Ryu Controller..."
export RYU_API_URL="http://127.0.0.1:8088"
PYTHONPATH="$PROJECT_DIR" "$RYU_BIN" mtd_ip_shuffling.app --observe-links --ofp-tcp-listen-port 6653 --wsapi-port 8088 > ryu_experiment.log 2>&1 &
RYU_PID=$!

while ! "$PYTHON_BIN" -c "import socket; s = socket.socket(); s.settimeout(1); s.connect(('127.0.0.1', 8088)); s.close()" 2>/dev/null; do
    sleep 1
done
echo "✅ Ryu ready on port 8088!"

echo "🌐 Starting Containernet Topology..."
sudo -E RYU_API_URL="http://127.0.0.1:8088" "$PYTHON_BIN" testbed/containernet_topos/finetune_topo.py > topo_finetune.log 2>&1 &
TOPO_PID=$!

while ! "$PYTHON_BIN" -c "import socket; s = socket.socket(); s.settimeout(1); s.connect(('127.0.0.1', 9999)); s.close()" 2>/dev/null; do
    sleep 1
done
echo "✅ Topology ready on port 9999!"
echo "⏳ Waiting 10s for topology link discovery to stabilize..."
sleep 10

echo "🔬 Running Data-Plane MBB Benchmark..."
"$PYTHON_BIN" rl_agent/benchmark_dataplane_mbb.py

echo "📈 Generating Plots..."
"$PYTHON_BIN" rl_agent/visualize_results.py

echo "🎉 Benchmark and visualizations completed successfully!"
