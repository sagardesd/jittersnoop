#!/usr/bin/env bash

if [[ $EUID -ne 0 ]]; then
    echo "Usage: sudo bash revert.sh"
    exit 1
fi

echo "  Killing demo processes..."
pkill -f "jsnoop-victim" 2>/dev/null || true
pkill -f "jsnoop-aggressor" 2>/dev/null || true
pkill -f "while true; do :; done" 2>/dev/null || true
pkill -f "jittersnoop" 2>/dev/null || true

echo "  Moving tasks back to root cgroup..."
for pid in $(cat /sys/fs/cgroup/isolated/cgroup.procs 2>/dev/null); do
    echo "$pid" > /sys/fs/cgroup/cgroup.procs 2>/dev/null || true
done
for pid in $(cat /sys/fs/cgroup/system/cgroup.procs 2>/dev/null); do
    echo "$pid" > /sys/fs/cgroup/cgroup.procs 2>/dev/null || true
done

echo "  Removing cgroups..."
rmdir /sys/fs/cgroup/isolated 2>/dev/null && echo "    Removed isolated cgroup" || echo "    isolated cgroup already gone"
rmdir /sys/fs/cgroup/system 2>/dev/null && echo "    Removed system cgroup" || echo "    system cgroup already gone"

echo ""
echo "  Done. Core isolation reverted."
