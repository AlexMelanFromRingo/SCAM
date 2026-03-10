#!/usr/bin/env bash
set -euo pipefail

# Local multi-node launcher for SCAM relay/RPC/Stratum services.
#
# Commands:
#   scripts/local-multinode.sh up
#   scripts/local-multinode.sh down
#   scripts/local-multinode.sh status
#   scripts/local-multinode.sh clean
#
# Key environment variables:
#   NETWORK=devnet
#   CONFIG=config/devnet.toml
#   CLUSTER_DIR=target/local-cluster
#   NODE_COUNT=3
#   BASE_P2P_PORT=19444
#   BASE_RPC_PORT=19080
#   BASE_STRATUM_PORT=19347
#   RUN_RPC=true
#   RUN_STRATUM=false
#   STRATUM_NODE_INDEXES=""     # optional CSV list, e.g. "0,1" to run Stratum only on selected nodes
#   WIRE_PEERS=true
#   WIRE_PEERS_PER_NODE=12      # 0 = full mesh, N > 0 = next-N ring neighbors per node
#   BUILD=true
#   CARGO_PROFILE=debug   # debug|release
#   SYNC_BOOK=true
#   SYNC_MAX_BATCHES_PER_PEER=8
#   RUN_SYNC_LOOP=false
#   SYNC_LOOP_INTERVAL_SEC=5
#   FORCE_SYNC_LOOP_WITH_RELAY=false
#   FORCE_INITIAL_SYNC_BOOK_WITH_RELAY=false
#   P2P_READ_TIMEOUT_SEC=5
#   P2P_WRITE_TIMEOUT_SEC=5
#   RELAY_HANDSHAKE_TIMEOUT_SEC=30
#   RELAY_TOKIO_WORKER_THREADS=4
#   STRATUM_TOKIO_WORKER_THREADS=4
#   RELAY_OUTBOUND_MAX_PEERS=16
#   RELAY_OUTBOUND_SPAWN_BURST=4
#   RELAY_OUTBOUND_SPAWN_LAG_THRESHOLD=8
#   RELAY_OUTBOUND_SPAWN_LAG_MIN_BURST=8
#   RELAY_OUTBOUND_LAG_MAX_PEERS=32
#   RELAY_OUTBOUND_BUCKET_CAP=0        # 0 = use config p2p_max_outbound_per_bucket
#   RELAY_OUTBOUND_INITIAL_JITTER_MS=2000
#   RELAY_OUTBOUND_CONNECT=true
#   RELAY_OUTBOUND_REDIAL_SEC=2
#   WAIT_FOR_RELAY_READY=true
#   RELAY_READY_TIMEOUT_SEC=90
#   RELAY_READY_POLL_MS=200
#   STRATUM_READ_TIMEOUT_SEC=30
#   STRATUM_TELEMETRY_EVERY_SEC=5

COMMAND="${1:-up}"

NETWORK="${NETWORK:-devnet}"
CONFIG="${CONFIG:-config/${NETWORK}.toml}"
CLUSTER_DIR="${CLUSTER_DIR:-target/local-cluster}"
NODE_COUNT="${NODE_COUNT:-3}"
BASE_P2P_PORT="${BASE_P2P_PORT:-19444}"
BASE_RPC_PORT="${BASE_RPC_PORT:-19080}"
BASE_STRATUM_PORT="${BASE_STRATUM_PORT:-19347}"
RUN_RPC="${RUN_RPC:-true}"
RUN_STRATUM="${RUN_STRATUM:-false}"
STRATUM_NODE_INDEXES="${STRATUM_NODE_INDEXES:-}"
WIRE_PEERS="${WIRE_PEERS:-true}"
WIRE_PEERS_PER_NODE="${WIRE_PEERS_PER_NODE:-12}"
BUILD="${BUILD:-true}"
CARGO_PROFILE="${CARGO_PROFILE:-debug}"
SYNC_BOOK="${SYNC_BOOK:-true}"
SYNC_MAX_BATCHES_PER_PEER="${SYNC_MAX_BATCHES_PER_PEER:-8}"
RUN_SYNC_LOOP="${RUN_SYNC_LOOP:-false}"
SYNC_LOOP_INTERVAL_SEC="${SYNC_LOOP_INTERVAL_SEC:-5}"
FORCE_SYNC_LOOP_WITH_RELAY="${FORCE_SYNC_LOOP_WITH_RELAY:-false}"
FORCE_INITIAL_SYNC_BOOK_WITH_RELAY="${FORCE_INITIAL_SYNC_BOOK_WITH_RELAY:-false}"
P2P_READ_TIMEOUT_SEC="${P2P_READ_TIMEOUT_SEC:-5}"
P2P_WRITE_TIMEOUT_SEC="${P2P_WRITE_TIMEOUT_SEC:-5}"
RELAY_HANDSHAKE_TIMEOUT_SEC="${RELAY_HANDSHAKE_TIMEOUT_SEC:-30}"
RELAY_TOKIO_WORKER_THREADS="${RELAY_TOKIO_WORKER_THREADS:-4}"
STRATUM_TOKIO_WORKER_THREADS="${STRATUM_TOKIO_WORKER_THREADS:-4}"
RELAY_OUTBOUND_MAX_PEERS="${RELAY_OUTBOUND_MAX_PEERS:-16}"
RELAY_OUTBOUND_SPAWN_BURST="${RELAY_OUTBOUND_SPAWN_BURST:-4}"
RELAY_OUTBOUND_SPAWN_LAG_THRESHOLD="${RELAY_OUTBOUND_SPAWN_LAG_THRESHOLD:-8}"
RELAY_OUTBOUND_SPAWN_LAG_MIN_BURST="${RELAY_OUTBOUND_SPAWN_LAG_MIN_BURST:-8}"
RELAY_OUTBOUND_LAG_MAX_PEERS="${RELAY_OUTBOUND_LAG_MAX_PEERS:-32}"
RELAY_OUTBOUND_BUCKET_CAP="${RELAY_OUTBOUND_BUCKET_CAP:-0}"
RELAY_OUTBOUND_INITIAL_JITTER_MS="${RELAY_OUTBOUND_INITIAL_JITTER_MS:-2000}"
RELAY_OUTBOUND_CONNECT="${RELAY_OUTBOUND_CONNECT:-true}"
RELAY_OUTBOUND_REDIAL_SEC="${RELAY_OUTBOUND_REDIAL_SEC:-2}"
WAIT_FOR_RELAY_READY="${WAIT_FOR_RELAY_READY:-true}"
RELAY_READY_TIMEOUT_SEC="${RELAY_READY_TIMEOUT_SEC:-90}"
RELAY_READY_POLL_MS="${RELAY_READY_POLL_MS:-200}"
STRATUM_READ_TIMEOUT_SEC="${STRATUM_READ_TIMEOUT_SEC:-30}"
STRATUM_TELEMETRY_EVERY_SEC="${STRATUM_TELEMETRY_EVERY_SEC:-5}"
UI_DIR="${UI_DIR:-web}"
SCAM_NODE_BIN="${SCAM_NODE_BIN:-}"

ENDPOINTS_FILE="${CLUSTER_DIR}/endpoints.tsv"
BIN_PATH="${CLUSTER_DIR}/scam-node.path"

is_true() {
  local raw="${1:-false}"
  local val="${raw,,}"
  [[ "${val}" == "1" || "${val}" == "true" || "${val}" == "yes" || "${val}" == "on" ]]
}

require_positive_int() {
  local name="$1"
  local value="$2"
  if ! [[ "${value}" =~ ^[0-9]+$ ]] || [[ "${value}" == "0" ]]; then
    echo "[cluster] ${name} must be a positive integer, got '${value}'" >&2
    exit 2
  fi
}

require_non_negative_int() {
  local name="$1"
  local value="$2"
  if ! [[ "${value}" =~ ^[0-9]+$ ]]; then
    echo "[cluster] ${name} must be a non-negative integer, got '${value}'" >&2
    exit 2
  fi
}

csv_contains_index() {
  local csv="$1"
  local needle="$2"
  local compact
  compact="$(echo "${csv}" | tr -d '[:space:]')"
  [[ ",${compact}," == *",${needle},"* ]]
}

should_run_stratum_for_idx() {
  local idx="$1"
  if ! is_true "${RUN_STRATUM}"; then
    return 1
  fi
  if [[ -z "${STRATUM_NODE_INDEXES}" ]]; then
    return 0
  fi
  csv_contains_index "${STRATUM_NODE_INDEXES}" "${idx}"
}

node_dir() {
  local idx="$1"
  printf "%s/node-%02d" "${CLUSTER_DIR}" "${idx}"
}

runtime_db_path() {
  local idx="$1"
  printf "%s/runtime.redb" "$(node_dir "${idx}")"
}

peers_dir_path() {
  local idx="$1"
  printf "%s/peers" "$(node_dir "${idx}")"
}

logs_dir_path() {
  local idx="$1"
  printf "%s/logs" "$(node_dir "${idx}")"
}

p2p_port_for() {
  local idx="$1"
  echo $((BASE_P2P_PORT + idx))
}

rpc_port_for() {
  local idx="$1"
  echo $((BASE_RPC_PORT + idx))
}

stratum_port_for() {
  local idx="$1"
  echo $((BASE_STRATUM_PORT + idx))
}

write_pid() {
  local pid_file="$1"
  local pid="$2"
  printf "%s\n" "${pid}" > "${pid_file}"
}

spawn_detached() {
  local pid_file="$1"
  local service_name="$2"
  local log_file="$3"
  shift 3
  nohup "$@" > "${log_file}" 2>&1 < /dev/null &
  write_pid "${pid_file}" "$!"
  ensure_pid_started "${pid_file}" "${service_name}" "${log_file}"
}

ensure_pid_started() {
  local pid_file="$1"
  local service_name="$2"
  local log_file="$3"
  sleep 0.2
  if [[ ! -f "${pid_file}" ]]; then
    echo "[cluster] ${service_name} failed to start: pid file missing (${pid_file})" >&2
    exit 1
  fi
  local pid
  pid="$(cat "${pid_file}")"
  if ! pid_is_alive "${pid}"; then
    echo "[cluster] ${service_name} exited immediately (pid=${pid})" >&2
    if [[ -f "${log_file}" ]]; then
      echo "[cluster] last log lines (${log_file}):" >&2
      tail -n 40 "${log_file}" >&2 || true
    fi
    exit 1
  fi
}

pid_is_alive() {
  local pid="$1"
  if ! [[ "${pid}" =~ ^[0-9]+$ ]]; then
    return 1
  fi
  kill -0 "${pid}" 2>/dev/null
}

peer_book_lock_conflict() {
  local raw="${1:-}"
  [[ "${raw}" == *"Database already open"* || "${raw}" == *"Cannot acquire lock"* || "${raw}" == *"lock-contended"* ]]
}

supports_add_peers_subcommand() {
  local bin="$1"
  if [[ -n "${ADD_PEERS_SUPPORTED_CACHE:-}" ]]; then
    [[ "${ADD_PEERS_SUPPORTED_CACHE}" == "1" ]]
    return
  fi
  if "${bin}" --help 2>/dev/null | grep -qE '^[[:space:]]+add-peers([[:space:]]|$)'; then
    ADD_PEERS_SUPPORTED_CACHE="1"
    return 0
  fi
  ADD_PEERS_SUPPORTED_CACHE="0"
  return 1
}

add_single_peer_with_retry() {
  local bin="$1"
  local network="$2"
  local peersdir="$3"
  local peer="$4"
  local max_attempts="${5:-25}"
  local delay_sec="${6:-0.05}"
  local attempt
  for ((attempt = 1; attempt <= max_attempts; attempt++)); do
    local output
    if output="$("${bin}" add-peer --network "${network}" --peers-dir "${peersdir}" --peer "${peer}" 2>&1)"; then
      return 0
    fi
    if peer_book_lock_conflict "${output}"; then
      sleep "${delay_sec}"
      continue
    fi
    echo "${output}" >&2
    return 1
  done
  return 1
}

add_peers_with_retry() {
  local bin="$1"
  local network="$2"
  local peersdir="$3"
  local max_attempts="${4:-25}"
  local delay_sec="${5:-0.05}"
  shift 5
  local peers=("$@")
  if (( ${#peers[@]} == 0 )); then
    return 0
  fi
  if ! supports_add_peers_subcommand "${bin}"; then
    local peer
    for peer in "${peers[@]}"; do
      if ! add_single_peer_with_retry "${bin}" "${network}" "${peersdir}" "${peer}" "${max_attempts}" "${delay_sec}"; then
        return 1
      fi
    done
    return 0
  fi
  local attempt
  for ((attempt = 1; attempt <= max_attempts; attempt++)); do
    local cmd=(
      "${bin}" add-peers
      --network "${network}"
      --peers-dir "${peersdir}"
    )
    local peer
    for peer in "${peers[@]}"; do
      cmd+=(--peer "${peer}")
    done
    local output
    if output="$("${cmd[@]}" 2>&1)"; then
      return 0
    fi
    if peer_book_lock_conflict "${output}"; then
      sleep "${delay_sec}"
      continue
    fi
    echo "${output}" >&2
    return 1
  done
  return 1
}

wait_for_tcp_listen() {
  local host="$1"
  local port="$2"
  local timeout_sec="$3"
  local poll_ms="$4"
  python3 - "$host" "$port" "$timeout_sec" "$poll_ms" <<'PY'
import socket
import sys
import time

host = sys.argv[1]
port = int(sys.argv[2])
timeout_sec = max(float(sys.argv[3]), 1.0)
poll_ms = max(float(sys.argv[4]), 10.0)
deadline = time.time() + timeout_sec
sleep_sec = poll_ms / 1000.0

while time.time() < deadline:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(0.5)
    try:
        sock.connect((host, port))
    except OSError:
        time.sleep(sleep_sec)
    else:
        raise SystemExit(0)
    finally:
        sock.close()

raise SystemExit(1)
PY
}

wait_for_relays_ready() {
  local timeout_sec="$1"
  local poll_ms="$2"
  echo "[cluster] waiting for relay listeners (${timeout_sec}s timeout)"
  for ((idx = 0; idx < NODE_COUNT; idx++)); do
    local p2p_port
    p2p_port="$(p2p_port_for "${idx}")"
    if ! wait_for_tcp_listen "127.0.0.1" "${p2p_port}" "${timeout_sec}" "${poll_ms}"; then
      echo "[cluster] relay listener did not become ready: node-${idx} 127.0.0.1:${p2p_port}" >&2
      return 1
    fi
  done
  echo "[cluster] relay listeners ready"
}

stop_pid_file() {
  local pid_file="$1"
  if [[ ! -f "${pid_file}" ]]; then
    return 0
  fi
  local pid
  pid="$(cat "${pid_file}")"
  if pid_is_alive "${pid}"; then
    kill "${pid}" 2>/dev/null || true
    sleep 0.2
    if pid_is_alive "${pid}"; then
      kill -9 "${pid}" 2>/dev/null || true
    fi
  fi
  rm -f "${pid_file}"
}

resolve_binary() {
  if [[ -n "${SCAM_NODE_BIN}" ]]; then
    if [[ ! -x "${SCAM_NODE_BIN}" ]]; then
      echo "[cluster] SCAM_NODE_BIN is not executable: ${SCAM_NODE_BIN}" >&2
      exit 2
    fi
    echo "${SCAM_NODE_BIN}" > "${BIN_PATH}"
    echo "${SCAM_NODE_BIN}"
    return
  fi

  if is_true "${BUILD}"; then
    if [[ "${CARGO_PROFILE}" == "release" ]]; then
      echo "[cluster] building scam-node (release)" >&2
      cargo build --release -p scam-node
      echo "target/release/scam-node" > "${BIN_PATH}"
    else
      echo "[cluster] building scam-node (debug)" >&2
      cargo build -p scam-node
      echo "target/debug/scam-node" > "${BIN_PATH}"
    fi
  elif [[ ! -f "${BIN_PATH}" ]]; then
    if [[ "${CARGO_PROFILE}" == "release" && -x "target/release/scam-node" ]]; then
      echo "target/release/scam-node" > "${BIN_PATH}"
    elif [[ -x "target/debug/scam-node" ]]; then
      echo "target/debug/scam-node" > "${BIN_PATH}"
    else
      echo "[cluster] BUILD=false but ${BIN_PATH} is missing; cannot locate binary" >&2
      exit 2
    fi
  fi

  local bin
  bin="$(cat "${BIN_PATH}")"
  if [[ ! -x "${bin}" ]]; then
    echo "[cluster] binary is not executable: ${bin}" >&2
    exit 2
  fi
  echo "${bin}"
}

start_cluster() {
  require_positive_int "NODE_COUNT" "${NODE_COUNT}"
  require_positive_int "BASE_P2P_PORT" "${BASE_P2P_PORT}"
  require_positive_int "BASE_RPC_PORT" "${BASE_RPC_PORT}"
  require_positive_int "BASE_STRATUM_PORT" "${BASE_STRATUM_PORT}"
  require_positive_int "SYNC_MAX_BATCHES_PER_PEER" "${SYNC_MAX_BATCHES_PER_PEER}"
  require_positive_int "SYNC_LOOP_INTERVAL_SEC" "${SYNC_LOOP_INTERVAL_SEC}"
  require_positive_int "P2P_READ_TIMEOUT_SEC" "${P2P_READ_TIMEOUT_SEC}"
  require_positive_int "P2P_WRITE_TIMEOUT_SEC" "${P2P_WRITE_TIMEOUT_SEC}"
  require_positive_int "RELAY_HANDSHAKE_TIMEOUT_SEC" "${RELAY_HANDSHAKE_TIMEOUT_SEC}"
  require_positive_int "RELAY_TOKIO_WORKER_THREADS" "${RELAY_TOKIO_WORKER_THREADS}"
  require_positive_int "STRATUM_TOKIO_WORKER_THREADS" "${STRATUM_TOKIO_WORKER_THREADS}"
  require_positive_int "RELAY_OUTBOUND_MAX_PEERS" "${RELAY_OUTBOUND_MAX_PEERS}"
  require_positive_int "RELAY_OUTBOUND_REDIAL_SEC" "${RELAY_OUTBOUND_REDIAL_SEC}"
  require_positive_int "RELAY_READY_TIMEOUT_SEC" "${RELAY_READY_TIMEOUT_SEC}"
  require_positive_int "RELAY_READY_POLL_MS" "${RELAY_READY_POLL_MS}"
  require_positive_int "STRATUM_READ_TIMEOUT_SEC" "${STRATUM_READ_TIMEOUT_SEC}"
  require_positive_int "STRATUM_TELEMETRY_EVERY_SEC" "${STRATUM_TELEMETRY_EVERY_SEC}"
  require_non_negative_int "WIRE_PEERS_PER_NODE" "${WIRE_PEERS_PER_NODE}"

  mkdir -p "${CLUSTER_DIR}"
  local bin
  bin="$(resolve_binary)"

  echo -e "node\tp2p\trpc\tstratum\tdir" > "${ENDPOINTS_FILE}"

  echo "[cluster] starting ${NODE_COUNT} nodes (network=${NETWORK}, config=${CONFIG})"
  for ((idx = 0; idx < NODE_COUNT; idx++)); do
    local nodedir logsdir peersdir runtime_db p2p_port rpc_port stratum_port
    nodedir="$(node_dir "${idx}")"
    logsdir="$(logs_dir_path "${idx}")"
    peersdir="$(peers_dir_path "${idx}")"
    runtime_db="$(runtime_db_path "${idx}")"
    p2p_port="$(p2p_port_for "${idx}")"
    rpc_port="$(rpc_port_for "${idx}")"
    stratum_port="$(stratum_port_for "${idx}")"

    mkdir -p "${logsdir}" "${peersdir}"
    local relay_extra_args=()
    if is_true "${RELAY_OUTBOUND_CONNECT}"; then
      relay_extra_args+=(--outbound-connect --outbound-redial-sec "${RELAY_OUTBOUND_REDIAL_SEC}")
    fi

    "${bin}" node \
      --network "${NETWORK}" \
      --config "${CONFIG}" \
      --runtime-db "${runtime_db}" \
      > "${logsdir}/bootstrap.log" 2>&1

    spawn_detached \
      "${nodedir}/relay.pid" \
      "node-${idx} relay-serve" \
      "${logsdir}/relay.log" \
      env \
      SCAM_RELAY_HANDSHAKE_TIMEOUT_SEC="${RELAY_HANDSHAKE_TIMEOUT_SEC}" \
      SCAM_RELAY_TOKIO_WORKER_THREADS="${RELAY_TOKIO_WORKER_THREADS}" \
      SCAM_RELAY_OUTBOUND_MAX_PEERS="${RELAY_OUTBOUND_MAX_PEERS}" \
      SCAM_RELAY_OUTBOUND_SPAWN_BURST="${RELAY_OUTBOUND_SPAWN_BURST}" \
      SCAM_RELAY_OUTBOUND_SPAWN_LAG_THRESHOLD="${RELAY_OUTBOUND_SPAWN_LAG_THRESHOLD}" \
      SCAM_RELAY_OUTBOUND_SPAWN_LAG_MIN_BURST="${RELAY_OUTBOUND_SPAWN_LAG_MIN_BURST}" \
      SCAM_RELAY_OUTBOUND_LAG_MAX_PEERS="${RELAY_OUTBOUND_LAG_MAX_PEERS}" \
      SCAM_RELAY_OUTBOUND_BUCKET_CAP="${RELAY_OUTBOUND_BUCKET_CAP}" \
      SCAM_RELAY_OUTBOUND_INITIAL_JITTER_MS="${RELAY_OUTBOUND_INITIAL_JITTER_MS}" \
      "${bin}" relay-serve \
      --network "${NETWORK}" \
      --config "${CONFIG}" \
      --runtime-db "${runtime_db}" \
      --peers-dir "${peersdir}" \
      --bind "127.0.0.1:${p2p_port}" \
      --read-timeout-sec "${P2P_READ_TIMEOUT_SEC}" \
      --write-timeout-sec "${P2P_WRITE_TIMEOUT_SEC}" \
      "${relay_extra_args[@]}" \
      --telemetry-out "${nodedir}/relay.telemetry.jsonl" \
      --telemetry-every-sec 5

    local rpc_value="-"
    if is_true "${RUN_RPC}"; then
      spawn_detached \
        "${nodedir}/rpc.pid" \
        "node-${idx} rpc-serve" \
        "${logsdir}/rpc.log" \
        "${bin}" rpc-serve \
        --network "${NETWORK}" \
        --config "${CONFIG}" \
        --runtime-db "${runtime_db}" \
        --bind "127.0.0.1:${rpc_port}" \
        --ui-dir "${UI_DIR}" \
        --relay-telemetry "${nodedir}/relay.telemetry.jsonl" \
        --stratum-telemetry "${nodedir}/stratum.telemetry.jsonl"
      rpc_value="${rpc_port}"
    fi

    local stratum_value="-"
    if should_run_stratum_for_idx "${idx}"; then
      spawn_detached \
        "${nodedir}/stratum.pid" \
        "node-${idx} stratum-serve" \
        "${logsdir}/stratum.log" \
        env \
        SCAM_STRATUM_TOKIO_WORKER_THREADS="${STRATUM_TOKIO_WORKER_THREADS}" \
        "${bin}" stratum-serve \
        --network "${NETWORK}" \
        --config "${CONFIG}" \
        --runtime-db "${runtime_db}" \
        --bind "127.0.0.1:${stratum_port}" \
        --read-timeout-sec "${STRATUM_READ_TIMEOUT_SEC}" \
        --telemetry-out "${nodedir}/stratum.telemetry.jsonl" \
        --telemetry-every-sec "${STRATUM_TELEMETRY_EVERY_SEC}"
      stratum_value="${stratum_port}"
    fi

    echo -e "${idx}\t${p2p_port}\t${rpc_value}\t${stratum_value}\t${nodedir}" >> "${ENDPOINTS_FILE}"
  done

  sleep 1

  if is_true "${WAIT_FOR_RELAY_READY}"; then
    wait_for_relays_ready "${RELAY_READY_TIMEOUT_SEC}" "${RELAY_READY_POLL_MS}"
  fi

  if is_true "${WIRE_PEERS}"; then
    echo "[cluster] wiring peer books"
    local peers_per_node="${WIRE_PEERS_PER_NODE}"
    local full_mesh_threshold=$((NODE_COUNT - 1))
    local use_full_mesh="false"
    if [[ "${peers_per_node}" == "0" ]] || (( peers_per_node >= full_mesh_threshold )); then
      use_full_mesh="true"
      echo "[cluster] peer topology: full-mesh"
    else
      echo "[cluster] peer topology: ring neighbors (${peers_per_node} outbound peers/node)"
    fi
    local -a wiring_pids=()
    for ((i = 0; i < NODE_COUNT; i++)); do
      (
        local peersdir
        peersdir="$(peers_dir_path "${i}")"
        if [[ "${use_full_mesh}" == "true" ]]; then
          local -a batch_peers=()
          for ((j = 0; j < NODE_COUNT; j++)); do
            if [[ "${i}" == "${j}" ]]; then
              continue
            fi
            batch_peers+=("127.0.0.1:$(p2p_port_for "${j}")")
          done
          if ! add_peers_with_retry \
            "${bin}" \
            "${NETWORK}" \
            "${peersdir}" \
            25 \
            0.05 \
            "${batch_peers[@]}"; then
            echo "[cluster] warning: add-peers failed for node-${i} (full-mesh batch)" >&2
          fi
        else
          local -a batch_peers=()
          for ((offset = 1; offset <= peers_per_node; offset++)); do
            local j
            j=$(((i + offset) % NODE_COUNT))
            batch_peers+=("127.0.0.1:$(p2p_port_for "${j}")")
          done
          if ! add_peers_with_retry \
            "${bin}" \
            "${NETWORK}" \
            "${peersdir}" \
            25 \
            0.05 \
            "${batch_peers[@]}"; then
            echo "[cluster] warning: add-peers failed for node-${i} (ring batch)" >&2
          fi
        fi
      ) &
      wiring_pids+=("$!")
    done
    for pid in "${wiring_pids[@]}"; do
      wait "${pid}"
    done
  else
    echo "[cluster] skipping peer-book wiring (WIRE_PEERS=false)"
  fi

  if is_true "${SYNC_BOOK}"; then
    if ! is_true "${FORCE_INITIAL_SYNC_BOOK_WITH_RELAY}"; then
      echo "[cluster] skip initial sync-book pass: relay runtime holds runtime DB locks and handles realtime propagation"
      echo "[cluster] set FORCE_INITIAL_SYNC_BOOK_WITH_RELAY=true to force one-shot sync-book (not recommended)"
    else
      echo "[cluster] running initial sync-book pass (FORCE_INITIAL_SYNC_BOOK_WITH_RELAY=true)"
      for ((idx = 1; idx < NODE_COUNT; idx++)); do
        local logsdir runtime_db peersdir
        logsdir="$(logs_dir_path "${idx}")"
        runtime_db="$(runtime_db_path "${idx}")"
        peersdir="$(peers_dir_path "${idx}")"
        if ! "${bin}" sync-book \
          --network "${NETWORK}" \
          --config "${CONFIG}" \
          --runtime-db "${runtime_db}" \
          --peers-dir "${peersdir}" \
          --max-peers "${NODE_COUNT}" \
          --max-batches-per-peer "${SYNC_MAX_BATCHES_PER_PEER}" \
          > "${logsdir}/sync-book.log" 2>&1; then
          echo "[cluster] node-${idx} sync-book returned non-zero (see ${logsdir}/sync-book.log)"
        fi
      done
    fi
  fi

  if is_true "${RUN_SYNC_LOOP}"; then
    if ! is_true "${FORCE_SYNC_LOOP_WITH_RELAY}"; then
      echo "[cluster] skip periodic sync-book loops: relay already handles realtime propagation; external sync-loop can cause runtime DB lock contention"
      echo "[cluster] set FORCE_SYNC_LOOP_WITH_RELAY=true to override (not recommended)"
    else
      echo "[cluster] starting periodic sync-book loops (interval=${SYNC_LOOP_INTERVAL_SEC}s)"
      for ((idx = 1; idx < NODE_COUNT; idx++)); do
        local logsdir runtime_db peersdir nodedir
        logsdir="$(logs_dir_path "${idx}")"
        runtime_db="$(runtime_db_path "${idx}")"
        peersdir="$(peers_dir_path "${idx}")"
        nodedir="$(node_dir "${idx}")"
        (
          while true; do
            "${bin}" sync-book \
              --network "${NETWORK}" \
              --config "${CONFIG}" \
              --runtime-db "${runtime_db}" \
              --peers-dir "${peersdir}" \
              --max-peers "${NODE_COUNT}" \
              --max-batches-per-peer "${SYNC_MAX_BATCHES_PER_PEER}" \
              >> "${logsdir}/sync-loop.log" 2>&1 || true
            sleep "${SYNC_LOOP_INTERVAL_SEC}"
          done
        ) &
        write_pid "${nodedir}/sync-loop.pid" "$!"
        ensure_pid_started "${nodedir}/sync-loop.pid" "node-${idx} sync-loop" "${logsdir}/sync-loop.log"
      done
    fi
  fi

  echo "[cluster] up"
  echo "[cluster] endpoints:"
  cat "${ENDPOINTS_FILE}"
  echo "[cluster] logs: ${CLUSTER_DIR}/node-*/logs"
}

stop_cluster() {
  if [[ ! -d "${CLUSTER_DIR}" ]]; then
    echo "[cluster] nothing to stop (${CLUSTER_DIR} missing)"
    return 0
  fi
  for pid_file in "${CLUSTER_DIR}"/node-*/relay.pid; do
    [[ -e "${pid_file}" ]] || continue
    stop_pid_file "${pid_file}"
  done
  for pid_file in "${CLUSTER_DIR}"/node-*/rpc.pid; do
    [[ -e "${pid_file}" ]] || continue
    stop_pid_file "${pid_file}"
  done
  for pid_file in "${CLUSTER_DIR}"/node-*/stratum.pid; do
    [[ -e "${pid_file}" ]] || continue
    stop_pid_file "${pid_file}"
  done
  for pid_file in "${CLUSTER_DIR}"/node-*/sync-loop.pid; do
    [[ -e "${pid_file}" ]] || continue
    stop_pid_file "${pid_file}"
  done
  echo "[cluster] down"
}

status_cluster() {
  if [[ ! -f "${ENDPOINTS_FILE}" ]]; then
    echo "[cluster] endpoints file not found: ${ENDPOINTS_FILE}"
    return 0
  fi
  echo "[cluster] status (${CLUSTER_DIR})"
  while IFS=$'\t' read -r node p2p rpc stratum dir; do
    if [[ "${node}" == "node" ]]; then
      continue
    fi
    local relay_state rpc_state stratum_state sync_state
    relay_state="stopped"
    rpc_state="n/a"
    stratum_state="n/a"
    sync_state="stopped"
    if [[ -f "${dir}/relay.pid" ]] && pid_is_alive "$(cat "${dir}/relay.pid")"; then
      relay_state="running"
    fi
    if [[ "${rpc}" != "-" ]]; then
      rpc_state="stopped"
      if [[ -f "${dir}/rpc.pid" ]] && pid_is_alive "$(cat "${dir}/rpc.pid")"; then
        rpc_state="running"
      fi
    fi
    if [[ "${stratum}" != "-" ]]; then
      stratum_state="stopped"
      if [[ -f "${dir}/stratum.pid" ]] && pid_is_alive "$(cat "${dir}/stratum.pid")"; then
        stratum_state="running"
      fi
    fi
    if [[ -f "${dir}/sync-loop.pid" ]] && pid_is_alive "$(cat "${dir}/sync-loop.pid")"; then
      sync_state="running"
    fi
    echo "  node-${node}: relay=${relay_state} p2p=127.0.0.1:${p2p} rpc=${rpc_state} stratum=${stratum_state} sync=${sync_state}"
  done < "${ENDPOINTS_FILE}"
}

clean_cluster() {
  stop_cluster
  rm -rf "${CLUSTER_DIR}"
  echo "[cluster] cleaned ${CLUSTER_DIR}"
}

case "${COMMAND}" in
  up)
    start_cluster
    ;;
  down)
    stop_cluster
    ;;
  status)
    status_cluster
    ;;
  clean)
    clean_cluster
    ;;
  *)
    echo "usage: $0 {up|down|status|clean}" >&2
    exit 2
    ;;
esac
