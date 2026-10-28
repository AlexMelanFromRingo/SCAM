#!/usr/bin/env bash
set -euo pipefail

# Full node + local Stratum server + local miner.
#
# Required for miner payout label:
#   COINBASE_ADDRESS=<your address>
#
# Commands:
#   scripts/run-node-miner.sh start
#   scripts/run-node-miner.sh stop
#   scripts/run-node-miner.sh status
#   scripts/run-node-miner.sh logs
#
# Optional bootstrap peers for node relay:
#   ADD_PEERS="198.51.100.10:18444,203.0.113.7:18444"

COMMAND="${1:-status}"

SCAM_NODE_BIN="${SCAM_NODE_BIN:-target/debug/scam-node}"
NETWORK="${NETWORK:-devnet}"
CONFIG="${CONFIG:-config/${NETWORK}.toml}"
NODE_DIR="${NODE_DIR:-target/run-node-miner}"
RUNTIME_DB="${RUNTIME_DB:-${NODE_DIR}/runtime.redb}"
PEERS_DIR="${PEERS_DIR:-${NODE_DIR}/peers}"
UI_DIR="${UI_DIR:-web}"
RELAY_BIND="${RELAY_BIND:-0.0.0.0:18446}"
RPC_BIND="${RPC_BIND:-127.0.0.1:18081}"
STRATUM_BIND="${STRATUM_BIND:-127.0.0.1:3347}"
COINBASE_ADDRESS="${COINBASE_ADDRESS:-}"
OUTBOUND_CONNECT="${OUTBOUND_CONNECT:-true}"
OUTBOUND_REDIAL_SEC="${OUTBOUND_REDIAL_SEC:-5}"
P2P_READ_TIMEOUT_SEC="${P2P_READ_TIMEOUT_SEC:-5}"
P2P_WRITE_TIMEOUT_SEC="${P2P_WRITE_TIMEOUT_SEC:-5}"
ADD_PEERS="${ADD_PEERS:-}"
STRATUM_READ_TIMEOUT_SEC="${STRATUM_READ_TIMEOUT_SEC:-30}"
MINER_READ_TIMEOUT_SEC="${MINER_READ_TIMEOUT_SEC:-2}"
MINER_MAX_NONCE_PER_CYCLE="${MINER_MAX_NONCE_PER_CYCLE:-250000}"
MINER_MAX_SHARES="${MINER_MAX_SHARES:-0}"
MINER_MAX_RUNTIME_SEC="${MINER_MAX_RUNTIME_SEC:-0}"

LOG_DIR="${NODE_DIR}/logs"
RELAY_LOG="${LOG_DIR}/relay.log"
RPC_LOG="${LOG_DIR}/rpc.log"
STRATUM_LOG="${LOG_DIR}/stratum.log"
MINER_LOG="${LOG_DIR}/miner.log"
RELAY_PID="${NODE_DIR}/relay.pid"
RPC_PID="${NODE_DIR}/rpc.pid"
STRATUM_PID="${NODE_DIR}/stratum.pid"
MINER_PID="${NODE_DIR}/miner.pid"
RELAY_TELEMETRY="${NODE_DIR}/relay.telemetry.jsonl"
STRATUM_TELEMETRY="${NODE_DIR}/stratum.telemetry.jsonl"

require_bin() {
  if [[ ! -x "${SCAM_NODE_BIN}" ]]; then
    echo "[node-miner] SCAM_NODE_BIN is not executable: ${SCAM_NODE_BIN}" >&2
    exit 2
  fi
}

pid_is_alive() {
  local pid="$1"
  [[ "${pid}" =~ ^[0-9]+$ ]] || return 1
  kill -0 "${pid}" 2>/dev/null
}

stop_pid_file() {
  local pid_file="$1"
  [[ -f "${pid_file}" ]] || return 0
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

ensure_started() {
  local pid_file="$1"
  local log_file="$2"
  local name="$3"
  sleep 0.2
  if [[ ! -f "${pid_file}" ]] || ! pid_is_alive "$(cat "${pid_file}")"; then
    echo "[node-miner] ${name} failed to start" >&2
    tail -n 120 "${log_file}" >&2 || true
    exit 1
  fi
}

seed_peer_book_from_env() {
  local peers_raw
  peers_raw="${ADD_PEERS//,/ }"
  [[ -n "${peers_raw//[[:space:]]/}" ]] || return 0

  echo "[node-miner] seeding peer book from ADD_PEERS"
  local peer
  for peer in ${peers_raw}; do
    [[ -n "${peer//[[:space:]]/}" ]] || continue
    "${SCAM_NODE_BIN}" add-peer \
      --network "${NETWORK}" \
      --peer "${peer}" \
      --peers-dir "${PEERS_DIR}" \
      >> "${LOG_DIR}/bootstrap.log" 2>&1
  done
}

start() {
  require_bin
  if [[ -z "${COINBASE_ADDRESS}" ]]; then
    echo "[node-miner] set COINBASE_ADDRESS=<address>" >&2
    exit 2
  fi
  mkdir -p "${NODE_DIR}" "${LOG_DIR}" "${PEERS_DIR}"
  seed_peer_book_from_env

  "${SCAM_NODE_BIN}" node \
    --network "${NETWORK}" \
    --config "${CONFIG}" \
    --runtime-db "${RUNTIME_DB}" \
    > "${LOG_DIR}/bootstrap.log" 2>&1

  stop_pid_file "${MINER_PID}"
  stop_pid_file "${STRATUM_PID}"
  stop_pid_file "${RPC_PID}"
  stop_pid_file "${RELAY_PID}"

  # One node process: P2P relay plus, in-process, RPC/web console and the
  # stratum pool on the same chain and mempool (it owns the data directory).
  local relay_args=(
    serve
    --network "${NETWORK}"
    --config "${CONFIG}"
    --runtime-db "${RUNTIME_DB}"
    --peers-dir "${PEERS_DIR}"
    --bind "${RELAY_BIND}"
    --read-timeout-sec "${P2P_READ_TIMEOUT_SEC}"
    --write-timeout-sec "${P2P_WRITE_TIMEOUT_SEC}"
    --telemetry-out "${RELAY_TELEMETRY}"
    --telemetry-every-sec 5
    --rpc "--bind ${RPC_BIND} --ui-dir '${UI_DIR}' --relay-telemetry '${RELAY_TELEMETRY}' --stratum-telemetry '${STRATUM_TELEMETRY}'"
    --stratum "--bind ${STRATUM_BIND} --read-timeout-sec ${STRATUM_READ_TIMEOUT_SEC} --telemetry-out '${STRATUM_TELEMETRY}' --telemetry-every-sec 5"
  )
  if [[ "${OUTBOUND_CONNECT,,}" == "true" || "${OUTBOUND_CONNECT}" == "1" ]]; then
    relay_args+=(--outbound-connect --outbound-redial-sec "${OUTBOUND_REDIAL_SEC}")
  fi
  "${SCAM_NODE_BIN}" "${relay_args[@]}" > "${RELAY_LOG}" 2>&1 &
  echo "$!" > "${RELAY_PID}"
  ensure_started "${RELAY_PID}" "${RELAY_LOG}" "node"

  "${SCAM_NODE_BIN}" stratum-mine \
    --pool "${STRATUM_BIND}" \
    --user "${COINBASE_ADDRESS}" \
    --read-timeout-sec "${MINER_READ_TIMEOUT_SEC}" \
    --max-nonce-per-cycle "${MINER_MAX_NONCE_PER_CYCLE}" \
    --max-shares "${MINER_MAX_SHARES}" \
    --max-runtime-sec "${MINER_MAX_RUNTIME_SEC}" \
    > "${MINER_LOG}" 2>&1 &
  echo "$!" > "${MINER_PID}"
  ensure_started "${MINER_PID}" "${MINER_LOG}" "miner"

  echo "[node-miner] up"
  echo "[node-miner] relay: ${RELAY_BIND}"
  echo "[node-miner] rpc/ui: http://${RPC_BIND}/"
  echo "[node-miner] stratum: ${STRATUM_BIND}"
  echo "[node-miner] miner user/coinbase address: ${COINBASE_ADDRESS}"
  if [[ -n "${ADD_PEERS//[[:space:]]/}" ]]; then
    echo "[node-miner] bootstrap peers: ${ADD_PEERS}"
  fi
}

stop() {
  stop_pid_file "${MINER_PID}"
  stop_pid_file "${STRATUM_PID}"
  stop_pid_file "${RPC_PID}"
  stop_pid_file "${RELAY_PID}"
  echo "[node-miner] down"
}

status() {
  local relay_state="stopped"
  local rpc_state="stopped"
  local stratum_state="stopped"
  local miner_state="stopped"
  [[ -f "${RELAY_PID}" ]] && pid_is_alive "$(cat "${RELAY_PID}")" && relay_state="running (pid=$(cat "${RELAY_PID}"))"
  # RPC and stratum run inside the node process.
  [[ -f "${RELAY_PID}" ]] && pid_is_alive "$(cat "${RELAY_PID}")" && rpc_state="running (in node pid=$(cat "${RELAY_PID}"))"
  [[ -f "${RELAY_PID}" ]] && pid_is_alive "$(cat "${RELAY_PID}")" && stratum_state="running (in node pid=$(cat "${RELAY_PID}"))"
  [[ -f "${MINER_PID}" ]] && pid_is_alive "$(cat "${MINER_PID}")" && miner_state="running (pid=$(cat "${MINER_PID}"))"
  echo "[node-miner] relay=${relay_state} rpc=${rpc_state} stratum=${stratum_state} miner=${miner_state}"
}

logs() {
  echo "--- relay log ---"
  tail -n 80 "${RELAY_LOG}" 2>/dev/null || echo "(missing ${RELAY_LOG})"
  echo "--- rpc log ---"
  tail -n 80 "${RPC_LOG}" 2>/dev/null || echo "(missing ${RPC_LOG})"
  echo "--- stratum log ---"
  tail -n 80 "${STRATUM_LOG}" 2>/dev/null || echo "(missing ${STRATUM_LOG})"
  echo "--- miner log ---"
  tail -n 80 "${MINER_LOG}" 2>/dev/null || echo "(missing ${MINER_LOG})"
}

case "${COMMAND}" in
  start) start ;;
  stop) stop ;;
  status) status ;;
  logs) logs ;;
  *)
    echo "usage: $0 {start|stop|status|logs}" >&2
    exit 2
    ;;
esac
