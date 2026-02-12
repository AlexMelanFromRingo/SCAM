#!/usr/bin/env bash
set -euo pipefail

if ! command -v cargo-mutants >/dev/null 2>&1; then
  echo "cargo-mutants is not installed. Install with: cargo install cargo-mutants" >&2
  exit 1
fi

# Baseline run for the current workspace. Keep this conservative to stay practical.
cargo mutants \
  --workspace \
  --test-tool cargo \
  --output target/mutants \
  --timeout 120 \
  --minimum-test-timeout 20
