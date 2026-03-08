#!/usr/bin/env bash
set -euo pipefail

# Launch a local multi-node cluster, optionally attach two miners, and sample sync spread.
#
# Usage:
#   scripts/cluster-sync-sample.sh
#
# Environment overrides:
#   CLUSTER_DIR=target/local-cluster50
#   NODE_COUNT=50
#   BASE_P2P_PORT=44400
#   BASE_RPC_PORT=44000
#   BASE_STRATUM_PORT=45000
#   RUN_STRATUM=true
#   STRATUM_NODE_INDEXES=0,1
#   WIRE_PEERS_PER_NODE=12
#   RELAY_OUTBOUND_MAX_PEERS=16
#   START_MINERS=true
#   MINER_A_ADDRESS=sd1...
#   MINER_B_ADDRESS=sd1...
#   DURATION_SEC=600
#   INTERVAL_SEC=15
#   HTTP_TIMEOUT_SEC=5.0
#   KEEP_RUNNING=false
#   CLEAN_CLUSTER_DIR=true
#   BUILD=false
#   CARGO_PROFILE=debug
#   SCAM_NODE_BIN=target/debug/scam-node

CLUSTER_DIR="${CLUSTER_DIR:-target/local-cluster50}"
NODE_COUNT="${NODE_COUNT:-50}"
BASE_P2P_PORT="${BASE_P2P_PORT:-44400}"
BASE_RPC_PORT="${BASE_RPC_PORT:-44000}"
BASE_STRATUM_PORT="${BASE_STRATUM_PORT:-45000}"
RUN_STRATUM="${RUN_STRATUM:-true}"
STRATUM_NODE_INDEXES="${STRATUM_NODE_INDEXES:-0,1}"
WIRE_PEERS_PER_NODE="${WIRE_PEERS_PER_NODE:-12}"
RELAY_OUTBOUND_MAX_PEERS="${RELAY_OUTBOUND_MAX_PEERS:-16}"
START_MINERS="${START_MINERS:-true}"
MINER_A_ADDRESS="${MINER_A_ADDRESS:-}"
MINER_B_ADDRESS="${MINER_B_ADDRESS:-}"
DURATION_SEC="${DURATION_SEC:-600}"
INTERVAL_SEC="${INTERVAL_SEC:-15}"
HTTP_TIMEOUT_SEC="${HTTP_TIMEOUT_SEC:-5.0}"
KEEP_RUNNING="${KEEP_RUNNING:-false}"
CLEAN_CLUSTER_DIR="${CLEAN_CLUSTER_DIR:-true}"
BUILD="${BUILD:-false}"
CARGO_PROFILE="${CARGO_PROFILE:-debug}"
SCAM_NODE_BIN="${SCAM_NODE_BIN:-target/debug/scam-node}"

MINER_A_DIR="${CLUSTER_DIR}/miner-a"
MINER_B_DIR="${CLUSTER_DIR}/miner-b"
SUMMARY_FILE="${CLUSTER_DIR}/sync-summary.txt"

is_true() {
  local raw="${1:-false}"
  local val="${raw,,}"
  [[ "${val}" == "1" || "${val}" == "true" || "${val}" == "yes" || "${val}" == "on" ]]
}

cleanup() {
  if is_true "${KEEP_RUNNING}"; then
    return 0
  fi
  SCAM_NODE_BIN="${SCAM_NODE_BIN}" WORK_DIR="${MINER_A_DIR}" ./scripts/run-miner.sh stop >/dev/null 2>&1 || true
  SCAM_NODE_BIN="${SCAM_NODE_BIN}" WORK_DIR="${MINER_B_DIR}" ./scripts/run-miner.sh stop >/dev/null 2>&1 || true
  CLUSTER_DIR="${CLUSTER_DIR}" \
  NODE_COUNT="${NODE_COUNT}" \
  BASE_P2P_PORT="${BASE_P2P_PORT}" \
  BASE_RPC_PORT="${BASE_RPC_PORT}" \
  BASE_STRATUM_PORT="${BASE_STRATUM_PORT}" \
  RUN_STRATUM="${RUN_STRATUM}" \
  BUILD="${BUILD}" \
  CARGO_PROFILE="${CARGO_PROFILE}" \
  SCAM_NODE_BIN="${SCAM_NODE_BIN}" \
  ./scripts/local-multinode.sh down >/dev/null 2>&1 || true
}
trap cleanup EXIT

mkdir -p "${CLUSTER_DIR}"

if is_true "${CLEAN_CLUSTER_DIR}"; then
  # Drop stale peer books/anchors/logs from previous topology sizes to avoid
  # noisy dial loops and skewed sync-lag measurements.
  CLUSTER_DIR="${CLUSTER_DIR}" \
  NODE_COUNT="${NODE_COUNT}" \
  BASE_P2P_PORT="${BASE_P2P_PORT}" \
  BASE_RPC_PORT="${BASE_RPC_PORT}" \
  BASE_STRATUM_PORT="${BASE_STRATUM_PORT}" \
  RUN_STRATUM="${RUN_STRATUM}" \
  BUILD="${BUILD}" \
  CARGO_PROFILE="${CARGO_PROFILE}" \
  SCAM_NODE_BIN="${SCAM_NODE_BIN}" \
  ./scripts/local-multinode.sh down >/dev/null 2>&1 || true
  rm -rf "${CLUSTER_DIR}"
  mkdir -p "${CLUSTER_DIR}"
fi

if [[ -z "${MINER_A_ADDRESS}" || -z "${MINER_B_ADDRESS}" ]]; then
  mapfile -t generated < <(
    "${SCAM_NODE_BIN}" wallet new --words 12 | awk -F': ' '/^Address:/ {print $2}'
    "${SCAM_NODE_BIN}" wallet new --words 12 | awk -F': ' '/^Address:/ {print $2}'
  )
  if [[ -z "${MINER_A_ADDRESS}" ]]; then
    MINER_A_ADDRESS="${generated[0]}"
  fi
  if [[ -z "${MINER_B_ADDRESS}" ]]; then
    MINER_B_ADDRESS="${generated[1]}"
  fi
fi

echo "[sample] miner-a address: ${MINER_A_ADDRESS}"
echo "[sample] miner-b address: ${MINER_B_ADDRESS}"

echo "[sample] bringing cluster up"
CLUSTER_DIR="${CLUSTER_DIR}" \
NODE_COUNT="${NODE_COUNT}" \
BASE_P2P_PORT="${BASE_P2P_PORT}" \
BASE_RPC_PORT="${BASE_RPC_PORT}" \
BASE_STRATUM_PORT="${BASE_STRATUM_PORT}" \
RUN_RPC=true \
RUN_STRATUM="${RUN_STRATUM}" \
STRATUM_NODE_INDEXES="${STRATUM_NODE_INDEXES}" \
WIRE_PEERS_PER_NODE="${WIRE_PEERS_PER_NODE}" \
RELAY_OUTBOUND_CONNECT=true \
RELAY_OUTBOUND_REDIAL_SEC=1 \
RELAY_OUTBOUND_MAX_PEERS="${RELAY_OUTBOUND_MAX_PEERS}" \
SYNC_BOOK=false \
BUILD="${BUILD}" \
CARGO_PROFILE="${CARGO_PROFILE}" \
SCAM_NODE_BIN="${SCAM_NODE_BIN}" \
./scripts/local-multinode.sh up

if is_true "${START_MINERS}" && is_true "${RUN_STRATUM}"; then
  echo "[sample] starting miners"
  SCAM_NODE_BIN="${SCAM_NODE_BIN}" WORK_DIR="${MINER_A_DIR}" POOL_ADDR="127.0.0.1:${BASE_STRATUM_PORT}" COINBASE_ADDRESS="${MINER_A_ADDRESS}" ./scripts/run-miner.sh start
  SCAM_NODE_BIN="${SCAM_NODE_BIN}" WORK_DIR="${MINER_B_DIR}" POOL_ADDR="127.0.0.1:$((BASE_STRATUM_PORT + 1))" COINBASE_ADDRESS="${MINER_B_ADDRESS}" ./scripts/run-miner.sh start
fi

echo "[sample] sampling sync spread for ${DURATION_SEC}s (interval=${INTERVAL_SEC}s)"
python3 -u - <<PY | tee "${SUMMARY_FILE}"
import json
import statistics
import time
import urllib.request
import concurrent.futures

BASE = int(${BASE_RPC_PORT})
COUNT = int(${NODE_COUNT})
DURATION = int(${DURATION_SEC})
INTERVAL = int(${INTERVAL_SEC})
TIMEOUT = float(${HTTP_TIMEOUT_SEC})
# Keep sampler pressure below RPC server fan-out to avoid skewing "bad" with probe overload.
MAX_WORKERS = min(32, max(8, (COUNT + 3) // 4))


def fetch(port: int):
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/status", timeout=TIMEOUT) as resp:
            return int(json.load(resp).get("tip_height", 0))
    except Exception:
        return None

samples = []
start = time.time()
rounds = max(1, DURATION // max(1, INTERVAL))
for idx in range(rounds):
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        vals = list(ex.map(fetch, [BASE + n for n in range(COUNT)]))
    heights = [v for v in vals if v is not None]
    bad = COUNT - len(heights)
    elapsed = time.time() - start
    if heights:
        lo = min(heights)
        hi = max(heights)
        spread = hi - lo
        median = statistics.median(heights)
        samples.append((spread, bad))
        print(f"round={idx:03d} t={elapsed:6.1f}s lo={lo:5d} hi={hi:5d} spread={spread:4d} bad={bad:3d} med={median:5.1f}")
    else:
        samples.append((None, bad))
        print(f"round={idx:03d} t={elapsed:6.1f}s no-response bad={bad:3d}")
    time.sleep(INTERVAL)

valid_spreads = [s for s, _ in samples if s is not None]
max_spread = max(valid_spreads) if valid_spreads else None
final_spread = valid_spreads[-1] if valid_spreads else None
avg_bad = sum(b for _, b in samples) / len(samples)
print("SUMMARY", {"rounds": len(samples), "max_spread": max_spread, "final_spread": final_spread, "avg_bad": avg_bad})
PY

echo "[sample] summary written to ${SUMMARY_FILE}"
if is_true "${KEEP_RUNNING}"; then
  echo "[sample] cluster kept running (KEEP_RUNNING=true)"
  echo "[sample] stop manually with: CLUSTER_DIR=${CLUSTER_DIR} ./scripts/local-multinode.sh down"
fi
