#!/usr/bin/env bash
set -euo pipefail

if ! command -v cargo-mutants >/dev/null 2>&1; then
  echo "cargo-mutants is not installed. Install with: cargo install cargo-mutants" >&2
  exit 1
fi

# Tunables (override via environment).
OUT_DIR="${MUTATION_OUT_DIR:-target/mutants}"
TIMEOUT="${MUTATION_TIMEOUT:-240}"
MIN_TEST_TIMEOUT="${MUTATION_MIN_TEST_TIMEOUT:-20}"
TEST_TOOL="${MUTATION_TEST_TOOL:-cargo}" # cargo | nextest
MUTATION_EXAMINE_RE="${MUTATION_EXAMINE_RE:-}"
MUTATION_EXCLUDE_RE="${MUTATION_EXCLUDE_RE:-}"
MUTATION_SHARD="${MUTATION_SHARD:-}"
MUTATION_ITERATE="${MUTATION_ITERATE:-false}"
# Optional package-scoped mode (space-delimited crate names).
# Example: MUTATION_PACKAGES="scam-core scam-consensus"
MUTATION_PACKAGES="${MUTATION_PACKAGES:-}"

# Conservative-by-default parallelism: half the machine cores, capped.
if [[ -n "${MUTATION_JOBS:-}" ]]; then
  JOBS="${MUTATION_JOBS}"
else
  if command -v nproc >/dev/null 2>&1; then
    cpus="$(nproc)"
  else
    cpus=4
  fi
  jobs="$(( cpus / 2 ))"
  if (( jobs < 2 )); then
    jobs=2
  fi
  if (( jobs > 6 )); then
    jobs=6
  fi
  JOBS="${jobs}"
fi

if [[ "${TEST_TOOL}" == "nextest" ]] && ! command -v cargo-nextest >/dev/null 2>&1; then
  echo "MUTATION_TEST_TOOL=nextest requested, but cargo-nextest is not installed" >&2
  exit 1
fi

echo "[mutation-baseline] out=${OUT_DIR} test_tool=${TEST_TOOL} jobs=${JOBS} timeout=${TIMEOUT}s min_test_timeout=${MIN_TEST_TIMEOUT}s"
if [[ -n "${MUTATION_EXAMINE_RE}" ]]; then
  echo "[mutation-baseline] examine-re=${MUTATION_EXAMINE_RE}"
fi
if [[ -n "${MUTATION_EXCLUDE_RE}" ]]; then
  echo "[mutation-baseline] exclude-re=${MUTATION_EXCLUDE_RE}"
fi
if [[ -n "${MUTATION_SHARD}" ]]; then
  echo "[mutation-baseline] shard=${MUTATION_SHARD}"
fi
if [[ "${MUTATION_ITERATE}" == "true" ]]; then
  echo "[mutation-baseline] iterate=true"
fi

mkdir -p "$(dirname "${OUT_DIR}")"

SCOPE_ARGS=("--workspace")
if [[ -n "${MUTATION_PACKAGES}" ]]; then
  SCOPE_ARGS=()
  for pkg in ${MUTATION_PACKAGES}; do
    SCOPE_ARGS+=("--package" "${pkg}")
  done
  echo "[mutation-baseline] scoped packages: ${MUTATION_PACKAGES}"
fi

# Baseline run for the current workspace.
# Reliability guardrails:
# - baseline run stays enabled,
# - default timeouts unchanged from previous script.
mutants_cmd=(
  cargo mutants
  "${SCOPE_ARGS[@]}"
  --baseline run
  --test-tool "${TEST_TOOL}"
  --jobs "${JOBS}"
  --output "${OUT_DIR}"
  --timeout "${TIMEOUT}"
  --minimum-test-timeout "${MIN_TEST_TIMEOUT}"
)
if [[ -n "${MUTATION_EXAMINE_RE}" ]]; then
  mutants_cmd+=(-F "${MUTATION_EXAMINE_RE}")
fi
if [[ -n "${MUTATION_EXCLUDE_RE}" ]]; then
  mutants_cmd+=(-E "${MUTATION_EXCLUDE_RE}")
fi
if [[ -n "${MUTATION_SHARD}" ]]; then
  mutants_cmd+=(--shard "${MUTATION_SHARD}")
fi
if [[ "${MUTATION_ITERATE}" == "true" ]]; then
  mutants_cmd+=(--iterate)
fi
mutants_cmd+=("$@")

"${mutants_cmd[@]}"
