#!/usr/bin/env bash
set -euo pipefail

echo ""
echo "  +-------------------------------------------------------------------+"
echo "  |  JitterSnoop — One-time Setup                                     |"
echo "  +-------------------------------------------------------------------+"
echo ""

# Step 1: Rust
if command -v rustc &>/dev/null; then
    echo "  [ok] Rust found: $(rustc --version)"
else
    echo "  [..] Installing Rust..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
    echo "  [ok] Rust installed: $(rustc --version)"
fi

# Step 2: Nightly toolchain
if rustup toolchain list | grep -q nightly; then
    echo "  [ok] Nightly toolchain found"
else
    echo "  [..] Installing nightly toolchain..."
    rustup toolchain install nightly
    echo "  [ok] Nightly installed"
fi

# Step 3: BPF target
# The build uses -Z build-std=core to compile core from source for the BPF
# target, so a prebuilt target is not required — rust-src is sufficient.
if rustup target list --toolchain nightly --installed 2>/dev/null | grep -q bpfel-unknown-none; then
    echo "  [ok] BPF target found (prebuilt)"
else
    echo "  [ok] BPF target will be built from source via -Z build-std=core"
fi

# Step 4: rust-src (needed to build core for BPF)
if rustup component list --toolchain nightly --installed | grep -q rust-src; then
    echo "  [ok] rust-src found"
else
    echo "  [..] Adding rust-src..."
    rustup component add rust-src --toolchain nightly
    echo "  [ok] rust-src added"
fi

# Step 5: Build
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

echo ""
echo "  [..] Building JitterSnoop (first build takes ~60s)..."
echo ""

cargo build -p jittersnoop --release 2>&1

echo ""
echo "  +-------------------------------------------------------------------+"
echo "  |  Setup complete!                                                  |"
echo "  +-------------------------------------------------------------------+"
echo ""
echo "  Run the demo:"
echo ""
echo "    sudo $SCRIPT_DIR/target/release/jittersnoop --demo"
echo ""
echo "  Then open http://localhost:8080 in your browser."
echo ""
echo "  Production usage:"
echo ""
echo "    sudo $SCRIPT_DIR/target/release/jittersnoop --cores 4,5 --pid <PID>"
echo ""
