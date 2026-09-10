#!/usr/bin/env bash
set -euo pipefail

CORE=${1:-27}
TOTAL_CORES=$(nproc)

if (( CORE >= TOTAL_CORES )); then
    echo "ERROR: core $CORE does not exist (system has $TOTAL_CORES cores: 0-$((TOTAL_CORES-1)))"
    exit 1
fi

if [[ $EUID -ne 0 ]]; then
    echo "ERROR: run as root"
    echo "Usage: sudo bash isolate_core.sh [core_id]"
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

echo ""
echo "  Isolating core $CORE (temporary — resets on reboot)"
echo "  System tasks will run on: $SYSTEM_CPUS"
echo ""

# ── Step 1: Create cpuset and move all tasks off the target core ─────────
echo "  [1/4] Creating system cpuset..."
mkdir -p /sys/fs/cgroup/system
echo "$SYSTEM_CPUS" > /sys/fs/cgroup/system/cpuset.cpus
echo "0" > /sys/fs/cgroup/system/cpuset.mems

echo "  [2/4] Moving all tasks off core $CORE..."
MOVED=0
FAILED=0
for pid in $(ps -eo pid= | tr -d ' '); do
    if echo "$pid" > /sys/fs/cgroup/system/cgroup.procs 2>/dev/null; then
        MOVED=$((MOVED+1))
    else
        FAILED=$((FAILED+1))
    fi
done
echo "        Moved $MOVED tasks ($FAILED kernel-bound tasks could not be moved)"

# ── Step 2: Move IRQs off the target core ────────────────────────────────
echo "  [3/4] Moving IRQs off core $CORE..."
IRQ_MOVED=0
for irq in /proc/irq/*/smp_affinity_list; do
    if echo "$SYSTEM_CPUS" > "$irq" 2>/dev/null; then
        IRQ_MOVED=$((IRQ_MOVED+1))
    fi
done
echo "        Moved $IRQ_MOVED IRQs"

# ── Step 3: Disable kernel timer tick on the core (best-effort) ──────────
echo "  [4/4] Tuning kernel timers..."
if [ -f /sys/devices/system/cpu/cpu${CORE}/nohz_full ]; then
    echo 1 > /sys/devices/system/cpu/cpu${CORE}/nohz_full 2>/dev/null && \
        echo "        nohz_full enabled for core $CORE" || \
        echo "        nohz_full not available at runtime (needs boot param)"
else
    echo "        nohz_full not available at runtime (needs boot param)"
fi

# ── Verify ───────────────────────────────────────────────────────────────
echo ""
echo "  Done. Core $CORE is now isolated."
echo ""
echo "  Verify — tasks still on core $CORE (should be only kernel-bound):"
ps -eo pid,psr,comm | awk -v core="$CORE" '$2 == core { printf "    PID %-8s %s\n", $1, $3 }' | head -10
REMAINING=$(ps -eo psr= | tr -d ' ' | grep -c "^${CORE}$" || true)
echo "  Total: $REMAINING tasks remaining on core $CORE"
echo ""
echo "  To undo:"
echo "    sudo rmdir /sys/fs/cgroup/system"
echo ""
echo "  To run JitterSnoop on this core:"
echo "    sudo ./target/debug/jittersnoop --cores $CORE --port 8080"
echo ""
