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
#   BUILD=true
#   CARGO_PROFILE=debug   # debug|release
#   SYNC_BOOK=true
#   SYNC_MAX_BATCHES_PER_PEER=8

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
BUILD="${BUILD:-true}"
CARGO_PROFILE="${CARGO_PROFILE:-debug}"
SYNC_BOOK="${SYNC_BOOK:-true}"
SYNC_MAX_BATCHES_PER_PEER="${SYNC_MAX_BATCHES_PER_PEER:-8}"
P2P_READ_TIMEOUT_SEC="${P2P_READ_TIMEOUT_SEC:-5}"
P2P_WRITE_TIMEOUT_SEC="${P2P_WRITE_TIMEOUT_SEC:-5}"
UI_DIR="${UI_DIR:-web}"

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
  if is_true "${BUILD}"; then
    if [[ "${CARGO_PROFILE}" == "release" ]]; then
      echo "[cluster] building scam-node (release)"
      cargo build --release -p scam-node
      echo "target/release/scam-node" > "${BIN_PATH}"
    else
      echo "[cluster] building scam-node (debug)"
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
  require_positive_int "P2P_READ_TIMEOUT_SEC" "${P2P_READ_TIMEOUT_SEC}"
  require_positive_int "P2P_WRITE_TIMEOUT_SEC" "${P2P_WRITE_TIMEOUT_SEC}"

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

    "${bin}" node \
      --network "${NETWORK}" \
      --config "${CONFIG}" \
      --runtime-db "${runtime_db}" \
      > "${logsdir}/bootstrap.log" 2>&1

    "${bin}" relay-serve \
      --network "${NETWORK}" \
      --config "${CONFIG}" \
      --runtime-db "${runtime_db}" \
      --bind "127.0.0.1:${p2p_port}" \
      --read-timeout-sec "${P2P_READ_TIMEOUT_SEC}" \
      --write-timeout-sec "${P2P_WRITE_TIMEOUT_SEC}" \
      --telemetry-out "${nodedir}/relay.telemetry.jsonl" \
      --telemetry-every-sec 5 \
      > "${logsdir}/relay.log" 2>&1 &
    write_pid "${nodedir}/relay.pid" "$!"
    ensure_pid_started "${nodedir}/relay.pid" "node-${idx} relay-serve" "${logsdir}/relay.log"

    local rpc_value="-"
    if is_true "${RUN_RPC}"; then
      "${bin}" rpc-serve \
        --network "${NETWORK}" \
        --config "${CONFIG}" \
        --runtime-db "${runtime_db}" \
        --bind "127.0.0.1:${rpc_port}" \
        --ui-dir "${UI_DIR}" \
        --relay-telemetry "${nodedir}/relay.telemetry.jsonl" \
        > "${logsdir}/rpc.log" 2>&1 &
      write_pid "${nodedir}/rpc.pid" "$!"
      ensure_pid_started "${nodedir}/rpc.pid" "node-${idx} rpc-serve" "${logsdir}/rpc.log"
      rpc_value="${rpc_port}"
    fi

    local stratum_value="-"
    if is_true "${RUN_STRATUM}"; then
      "${bin}" stratum-serve \
        --network "${NETWORK}" \
        --config "${CONFIG}" \
        --runtime-db "${runtime_db}" \
        --bind "127.0.0.1:${stratum_port}" \
        > "${logsdir}/stratum.log" 2>&1 &
      write_pid "${nodedir}/stratum.pid" "$!"
      ensure_pid_started "${nodedir}/stratum.pid" "node-${idx} stratum-serve" "${logsdir}/stratum.log"
      stratum_value="${stratum_port}"
    fi

    echo -e "${idx}\t${p2p_port}\t${rpc_value}\t${stratum_value}\t${nodedir}" >> "${ENDPOINTS_FILE}"
  done

  sleep 1

  echo "[cluster] wiring peer books"
  for ((i = 0; i < NODE_COUNT; i++)); do
    local peersdir
    peersdir="$(peers_dir_path "${i}")"
    for ((j = 0; j < NODE_COUNT; j++)); do
      if [[ "${i}" == "${j}" ]]; then
        continue
      fi
      "${bin}" add-peer \
        --network "${NETWORK}" \
        --peer "127.0.0.1:$(p2p_port_for "${j}")" \
        --peers-dir "${peersdir}" \
        > /dev/null
    done
  done

  if is_true "${SYNC_BOOK}"; then
    echo "[cluster] running initial sync-book pass"
    for ((idx = 0; idx < NODE_COUNT; idx++)); do
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
    local relay_state rpc_state stratum_state
    relay_state="stopped"
    rpc_state="n/a"
    stratum_state="n/a"
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
    echo "  node-${node}: relay=${relay_state} p2p=127.0.0.1:${p2p} rpc=${rpc_state} stratum=${stratum_state}"
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
