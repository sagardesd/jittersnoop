#!/usr/bin/env bash
set -euo pipefail

# ─── Configuration ───────────────────────────────────────────────────────────
TARGET_CORE=4
THRESHOLD_NS=1000
DURATION=10

EBPF_BIN="./target/bpfel-unknown-none/release/jittersnoop-ebpf"
USER_BIN="./target/release/jittersnoop"

# ─── Preflight ───────────────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    echo "ERROR: must run as root (eBPF requires CAP_BPF + CAP_TRACING)"
    echo "Usage: sudo bash test_jittersnoop.sh"
    exit 1
fi

NPROC=$(nproc)
if (( TARGET_CORE >= NPROC )); then
    TARGET_CORE=$((NPROC - 1))
    echo "Adjusted TARGET_CORE to $TARGET_CORE (system has $NPROC cores)"
fi

for f in "$EBPF_BIN" "$USER_BIN"; do
    if [[ ! -f "$f" ]]; then
        echo "ERROR: $f not found. Build first:"
        echo "  cargo +nightly build -p jittersnoop-ebpf --target bpfel-unknown-none -Z build-std=core --release"
        echo "  cargo build -p jittersnoop --release"
        exit 1
    fi
done

cleanup() {
    echo ""
    echo "── Cleaning up ─────────────────────────────────────────────────────"
    [[ -n "${VICTIM_PID:-}" ]] && kill "$VICTIM_PID" 2>/dev/null && echo "Stopped victim (PID $VICTIM_PID)"
    [[ -n "${AGGRESSOR_PID:-}" ]] && kill "$AGGRESSOR_PID" 2>/dev/null && echo "Stopped aggressor (PID $AGGRESSOR_PID)"
    wait 2>/dev/null
    echo "Done."
}
trap cleanup EXIT

echo "═══════════════════════════════════════════════════════════════════════"
echo "  JitterSnoop Test Harness"
echo "═══════════════════════════════════════════════════════════════════════"
echo ""
echo "  Target core:    $TARGET_CORE"
echo "  Threshold:      $THRESHOLD_NS ns"
echo "  Test duration:  ${DURATION}s"
echo ""

# ─── Step 1: Launch a "victim" — a pinned busy-loop on the target core ───────
echo "── Step 1: Launching victim process on core $TARGET_CORE ─────────────"
taskset -c "$TARGET_CORE" bash -c '
    while true; do
        : # tight busy-loop — simulates a latency-critical hot path
    done
' &
VICTIM_PID=$!
echo "Victim PID: $VICTIM_PID (busy-loop pinned to core $TARGET_CORE)"

sleep 0.5

# ─── Step 2: Launch an "aggressor" — forced onto the same core ───────────────
echo ""
echo "── Step 2: Launching aggressor process on core $TARGET_CORE ──────────"
taskset -c "$TARGET_CORE" bash -c '
    while true; do
        # Generate I/O and syscalls to force context switches
        dd if=/dev/urandom of=/dev/null bs=4096 count=1 2>/dev/null
    done
' &
AGGRESSOR_PID=$!
echo "Aggressor PID: $AGGRESSOR_PID (dd loop pinned to core $TARGET_CORE)"

sleep 0.5

# ─── Step 3: Run JitterSnoop ─────────────────────────────────────────────────
echo ""
echo "── Step 3: Running JitterSnoop for ${DURATION}s ──────────────────────"
echo ""

timeout --signal=INT "$DURATION" \
    "$USER_BIN" \
        --ebpf-path "$EBPF_BIN" \
        --cores "$TARGET_CORE" \
        --threshold-ns "$THRESHOLD_NS" \
        --watch \
    || true

echo ""
echo "═══════════════════════════════════════════════════════════════════════"
echo "  Test complete."
echo "═══════════════════════════════════════════════════════════════════════"
