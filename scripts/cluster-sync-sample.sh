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
#   WIRE_PEERS_PER_NODE=6
#   RELAY_OUTBOUND_MAX_PEERS=8
#   RELAY_OUTBOUND_SPAWN_BURST=2
#   RELAY_OUTBOUND_SPAWN_LAG_THRESHOLD=4
#   RELAY_OUTBOUND_SPAWN_LAG_MIN_BURST=8
#   RELAY_OUTBOUND_LAG_MAX_PEERS=24
#   RELAY_OUTBOUND_LAG_ROTATE_AFTER_SEC=90
#   RELAY_OUTBOUND_BUCKET_CAP=64
#   RELAY_OUTBOUND_INITIAL_JITTER_MS=12000
#   RELAY_TOKIO_WORKER_THREADS=1  # auto: 1 when NODE_COUNT>=20, else 4
#   P2P_READ_TIMEOUT_SEC=10
#   P2P_WRITE_TIMEOUT_SEC=10
#   RELAY_HANDSHAKE_TIMEOUT_SEC=90
#   START_MINERS=true
#   MINER_START_DELAY_SEC=12
#   MINER_A_ADDRESS=sd1...
#   MINER_B_ADDRESS=sd1...
#   DURATION_SEC=600
#   INTERVAL_SEC=15
#   HTTP_TIMEOUT_SEC=5.0
#   SAMPLE_MODE=telemetry          # telemetry|status
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
WIRE_PEERS_PER_NODE="${WIRE_PEERS_PER_NODE:-6}"
RELAY_OUTBOUND_MAX_PEERS="${RELAY_OUTBOUND_MAX_PEERS:-8}"
RELAY_OUTBOUND_SPAWN_BURST="${RELAY_OUTBOUND_SPAWN_BURST:-2}"
RELAY_OUTBOUND_SPAWN_LAG_THRESHOLD="${RELAY_OUTBOUND_SPAWN_LAG_THRESHOLD:-4}"
RELAY_OUTBOUND_SPAWN_LAG_MIN_BURST="${RELAY_OUTBOUND_SPAWN_LAG_MIN_BURST:-8}"
RELAY_OUTBOUND_LAG_MAX_PEERS="${RELAY_OUTBOUND_LAG_MAX_PEERS:-24}"
RELAY_OUTBOUND_LAG_ROTATE_AFTER_SEC="${RELAY_OUTBOUND_LAG_ROTATE_AFTER_SEC:-90}"
RELAY_OUTBOUND_BUCKET_CAP="${RELAY_OUTBOUND_BUCKET_CAP:-64}"
RELAY_OUTBOUND_INITIAL_JITTER_MS="${RELAY_OUTBOUND_INITIAL_JITTER_MS:-12000}"
if [[ -z "${RELAY_TOKIO_WORKER_THREADS:-}" ]]; then
  if (( NODE_COUNT >= 20 )); then
    RELAY_TOKIO_WORKER_THREADS=1
  else
    RELAY_TOKIO_WORKER_THREADS=4
  fi
fi
P2P_READ_TIMEOUT_SEC="${P2P_READ_TIMEOUT_SEC:-10}"
P2P_WRITE_TIMEOUT_SEC="${P2P_WRITE_TIMEOUT_SEC:-10}"
RELAY_HANDSHAKE_TIMEOUT_SEC="${RELAY_HANDSHAKE_TIMEOUT_SEC:-90}"
START_MINERS="${START_MINERS:-true}"
MINER_START_DELAY_SEC="${MINER_START_DELAY_SEC:-12}"
MINER_A_ADDRESS="${MINER_A_ADDRESS:-}"
MINER_B_ADDRESS="${MINER_B_ADDRESS:-}"
DURATION_SEC="${DURATION_SEC:-600}"
INTERVAL_SEC="${INTERVAL_SEC:-15}"
HTTP_TIMEOUT_SEC="${HTTP_TIMEOUT_SEC:-5.0}"
SAMPLE_MODE="${SAMPLE_MODE:-telemetry}"
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
RELAY_OUTBOUND_SPAWN_BURST="${RELAY_OUTBOUND_SPAWN_BURST}" \
RELAY_OUTBOUND_SPAWN_LAG_THRESHOLD="${RELAY_OUTBOUND_SPAWN_LAG_THRESHOLD}" \
RELAY_OUTBOUND_SPAWN_LAG_MIN_BURST="${RELAY_OUTBOUND_SPAWN_LAG_MIN_BURST}" \
RELAY_OUTBOUND_LAG_MAX_PEERS="${RELAY_OUTBOUND_LAG_MAX_PEERS}" \
RELAY_OUTBOUND_LAG_ROTATE_AFTER_SEC="${RELAY_OUTBOUND_LAG_ROTATE_AFTER_SEC}" \
RELAY_OUTBOUND_BUCKET_CAP="${RELAY_OUTBOUND_BUCKET_CAP}" \
RELAY_OUTBOUND_INITIAL_JITTER_MS="${RELAY_OUTBOUND_INITIAL_JITTER_MS}" \
RELAY_TOKIO_WORKER_THREADS="${RELAY_TOKIO_WORKER_THREADS}" \
P2P_READ_TIMEOUT_SEC="${P2P_READ_TIMEOUT_SEC}" \
P2P_WRITE_TIMEOUT_SEC="${P2P_WRITE_TIMEOUT_SEC}" \
RELAY_HANDSHAKE_TIMEOUT_SEC="${RELAY_HANDSHAKE_TIMEOUT_SEC}" \
SYNC_BOOK=false \
BUILD="${BUILD}" \
CARGO_PROFILE="${CARGO_PROFILE}" \
SCAM_NODE_BIN="${SCAM_NODE_BIN}" \
./scripts/local-multinode.sh up

if is_true "${START_MINERS}" && is_true "${RUN_STRATUM}"; then
  if [[ "${MINER_START_DELAY_SEC}" =~ ^[0-9]+$ ]] && (( MINER_START_DELAY_SEC > 0 )); then
    echo "[sample] waiting ${MINER_START_DELAY_SEC}s before miner start to let relay mesh stabilize"
    sleep "${MINER_START_DELAY_SEC}"
  fi
  echo "[sample] starting miners"
  SCAM_NODE_BIN="${SCAM_NODE_BIN}" WORK_DIR="${MINER_A_DIR}" POOL_ADDR="127.0.0.1:${BASE_STRATUM_PORT}" COINBASE_ADDRESS="${MINER_A_ADDRESS}" ./scripts/run-miner.sh start
  SCAM_NODE_BIN="${SCAM_NODE_BIN}" WORK_DIR="${MINER_B_DIR}" POOL_ADDR="127.0.0.1:$((BASE_STRATUM_PORT + 1))" COINBASE_ADDRESS="${MINER_B_ADDRESS}" ./scripts/run-miner.sh start
fi

echo "[sample] sampling sync spread for ${DURATION_SEC}s (interval=${INTERVAL_SEC}s)"
python3 -u - <<PY | tee "${SUMMARY_FILE}"
import json
import os
import statistics
import time
import urllib.request
import concurrent.futures
from collections import Counter
from pathlib import Path

BASE = int(${BASE_RPC_PORT})
COUNT = int(${NODE_COUNT})
DURATION = int(${DURATION_SEC})
INTERVAL = int(${INTERVAL_SEC})
TIMEOUT = float(${HTTP_TIMEOUT_SEC})
SAMPLE_MODE = "${SAMPLE_MODE}".strip().lower()
CLUSTER_DIR = Path("${CLUSTER_DIR}")
# Keep sampler pressure below RPC server fan-out to avoid skewing "bad" with probe overload.
MAX_WORKERS = min(16, max(6, (COUNT + 7) // 8))


def parse_work(raw):
    if raw is None:
        return 0
    text = str(raw).strip().lower()
    if not text:
        return 0
    if text.startswith("0x"):
        return int(text, 16)
    if all(ch in "0123456789abcdef" for ch in text):
        return int(text, 16)
    return int(text)


def fetch_status(port: int):
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/status", timeout=TIMEOUT) as resp:
            payload = json.load(resp)
            return (
                int(payload.get("tip_height", 0)),
                parse_work(payload.get("cumulative_work", 0)),
                str(payload.get("tip_hash", "")),
            )
    except Exception:
        return None


def fetch_telemetry(node_idx: int):
    path = CLUSTER_DIR / f"node-{node_idx:02d}" / "relay.telemetry.jsonl"
    try:
        with path.open("rb") as handle:
            handle.seek(0, os.SEEK_END)
            size = handle.tell()
            if size == 0:
                return None
            offset = min(size, 65536)
            handle.seek(-offset, os.SEEK_END)
            chunk = handle.read().decode("utf-8", errors="ignore")
        lines = [line.strip() for line in chunk.splitlines() if line.strip()]
        for line in reversed(lines):
            try:
                payload = json.loads(line)
            except Exception:
                continue
            if "tip_height" in payload:
                return (
                    int(payload.get("tip_height", 0)),
                    parse_work(payload.get("cumulative_work", 0)),
                    str(payload.get("tip_hash", "")),
                )
    except Exception:
        return None
    return None


def fetch(node_idx: int):
    if SAMPLE_MODE == "telemetry":
        return fetch_telemetry(node_idx)
    return fetch_status(BASE + node_idx)

samples = []
start = time.time()
rounds = max(1, DURATION // max(1, INTERVAL))
for idx in range(rounds):
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        vals = list(ex.map(fetch, list(range(COUNT))))
    rows = [v for v in vals if v is not None]
    bad = COUNT - len(rows)
    elapsed = time.time() - start
    if rows:
        heights = [row[0] for row in rows]
        works = [row[1] for row in rows]
        tips = [row[2] for row in rows if row[2]]
        lo = min(heights)
        hi = max(heights)
        spread = hi - lo
        median = statistics.median(heights)
        work_spread = max(works) - min(works)
        dominant_tip_count = Counter(tips).most_common(1)[0][1] if tips else 0
        dominant_tip_ratio = dominant_tip_count / max(1, len(rows))
        samples.append((spread, bad))
        print(
            f"round={idx:03d} t={elapsed:6.1f}s lo={lo:5d} hi={hi:5d} spread={spread:4d} "
            f"work_spread={work_spread:6d} bad={bad:3d} med={median:5.1f} "
            f"tip_majority={dominant_tip_ratio:4.2f}"
        )
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
