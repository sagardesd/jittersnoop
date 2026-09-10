#!/usr/bin/env bash
set -uo pipefail

CORE=${1:-27}
THRESHOLD=${2:-1000}
PORT=${3:-8080}
TOTAL_CORES=$(nproc)
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BINARY="$SCRIPT_DIR/target/debug/jittersnoop"

if (( CORE >= TOTAL_CORES )); then
    CORE=$((TOTAL_CORES-1))
fi

if [[ $EUID -ne 0 ]]; then
    echo "Usage: sudo bash demo.sh [core] [threshold_ns] [port]"
    echo "  e.g: sudo bash demo.sh 27 1000 8080"
    exit 1
fi

if [[ ! -f "$BINARY" ]]; then
    echo "ERROR: binary not found at $BINARY"
    echo "Run: cargo build -p jittersnoop"
    exit 1
fi

# Build the "all cores except target" mask
if (( CORE == 0 )); then
    SYSTEM_CPUS="1-$((TOTAL_CORES-1))"
elif (( CORE == TOTAL_CORES-1 )); then
    SYSTEM_CPUS="0-$((TOTAL_CORES-2))"
else
    SYSTEM_CPUS="0-$((CORE-1)),$((CORE+1))-$((TOTAL_CORES-1))"
fi

cleanup() {
    echo ""
    echo "  Cleaning up..."
    [[ -n "${VICTIM_PID:-}" ]]     && kill "$VICTIM_PID" 2>/dev/null
    [[ -n "${AGGRESSOR_PID:-}" ]]  && kill "$AGGRESSOR_PID" 2>/dev/null
    wait 2>/dev/null
    # Move everything back to root cgroup before removing
    for pid in $(cat /sys/fs/cgroup/isolated/cgroup.procs 2>/dev/null); do
        echo "$pid" > /sys/fs/cgroup/cgroup.procs 2>/dev/null || true
    done
    for pid in $(cat /sys/fs/cgroup/system/cgroup.procs 2>/dev/null); do
        echo "$pid" > /sys/fs/cgroup/cgroup.procs 2>/dev/null || true
    done
    rmdir /sys/fs/cgroup/isolated 2>/dev/null || true
    rmdir /sys/fs/cgroup/system 2>/dev/null || true
    echo "  Done."
}
trap cleanup EXIT

echo ""
echo "  +-------------------------------------------------------------------+"
echo "  |  JitterSnoop Full Demo                                            |"
echo "  +-------------------------------------------------------------------+"
echo ""
echo "  Core:       $CORE"
echo "  Threshold:  $THRESHOLD ns"
echo "  Dashboard:  http://localhost:$PORT"
echo ""

# ── Step 1: Create two cpusets ───────────────────────────────────────────
echo "  [1/5] Isolating core $CORE..."

# System cpuset: everything EXCEPT target core
mkdir -p /sys/fs/cgroup/system
echo "$SYSTEM_CPUS" > /sys/fs/cgroup/system/cpuset.cpus
echo "0" > /sys/fs/cgroup/system/cpuset.mems

# Isolated cpuset: ONLY target core
mkdir -p /sys/fs/cgroup/isolated
echo "$CORE" > /sys/fs/cgroup/isolated/cpuset.cpus
echo "0" > /sys/fs/cgroup/isolated/cpuset.mems

# Move all existing tasks to system cpuset (off the target core)
MOVED=0
for pid in $(ps -eo pid= | tr -d ' '); do
    echo "$pid" > /sys/fs/cgroup/system/cgroup.procs 2>/dev/null && MOVED=$((MOVED+1))
done
echo "        Moved $MOVED tasks off core $CORE"

# Move IRQs off the target core
IRQ_MOVED=0
for irq in /proc/irq/*/smp_affinity_list; do
    echo "$SYSTEM_CPUS" > "$irq" 2>/dev/null && IRQ_MOVED=$((IRQ_MOVED+1)) || true
done
echo "        Moved $IRQ_MOVED IRQs off core $CORE"

# ── Step 2: Spawn victim in the isolated cpuset ─────────────────────────
echo "  [2/5] Spawning victim on core $CORE..."
bash -c 'while true; do :; done' &
VICTIM_PID=$!
echo "$VICTIM_PID" > /sys/fs/cgroup/isolated/cgroup.procs
echo "        Victim PID: $VICTIM_PID (pinned to core $CORE)"
sleep 0.3

# ── Step 3: Spawn aggressor in the isolated cpuset ──────────────────────
echo "  [3/5] Spawning aggressor on core $CORE..."
bash -c 'while true; do dd if=/dev/urandom of=/dev/null bs=4096 count=1 2>/dev/null; done' &
AGGRESSOR_PID=$!
echo "$AGGRESSOR_PID" > /sys/fs/cgroup/isolated/cgroup.procs
echo "        Aggressor PID: $AGGRESSOR_PID (pinned to core $CORE)"
sleep 0.3

# ── Step 4: Show what's on the core ─────────────────────────────────────
echo "  [4/5] Processes on core $CORE:"
ps -eo pid,psr,comm | awk -v core="$CORE" '$2 == core { printf "        PID %-8s %s\n", $1, $3 }' | head -10

# ── Step 5: Launch JitterSnoop ───────────────────────────────────────────
echo "  [5/5] Starting JitterSnoop..."
echo ""
echo "        Open http://localhost:$PORT in your browser"
echo "        Press Ctrl-C to stop"
echo ""

"$BINARY" --cores "$CORE" --pid "$VICTIM_PID" --threshold-ns "$THRESHOLD" --port "$PORT"
