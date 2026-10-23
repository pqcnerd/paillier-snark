#!/usr/bin/env bash
# Default path: workspace tests + guest-execute demo (no multi-hour STARK prove).
# Cryptographic receipts: DEMO_ZK_PROVE=1 ./scripts/demo.sh
set -euo pipefail
cd "$(dirname "$0")/.."
unset RISC0_DEV_MODE || true
cargo test --workspace
if [[ "${DEMO_ZK_PROVE:-0}" == "1" ]]; then
  echo "DEMO_ZK_PROVE=1: real composite proving (multi-hour on CPU)"
  cargo run --release -p veilgov -- demo --zk-prove
else
  cargo run --release -p veilgov -- demo
fi
cargo run -p veilgov-benchmarks
