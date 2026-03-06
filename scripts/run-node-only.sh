#!/usr/bin/env bash
set -euo pipefail

# Full node (decentralization mode): relay + RPC/UI, without local miner.
#
# Commands:
#   scripts/run-node-only.sh start
#   scripts/run-node-only.sh stop
#   scripts/run-node-only.sh status
#   scripts/run-node-only.sh logs
#
# Notes:
# - A node does not need its own payout address unless it mines.
# - You can still use wallet RPC/UI on this node.
# - Optional bootstrap peers: ADD_PEERS="198.51.100.10:18444,203.0.113.7:18444"

COMMAND="${1:-status}"

SCAM_NODE_BIN="${SCAM_NODE_BIN:-target/debug/scam-node}"
NETWORK="${NETWORK:-devnet}"
CONFIG="${CONFIG:-config/${NETWORK}.toml}"
NODE_DIR="${NODE_DIR:-target/run-node-only}"
RUNTIME_DB="${RUNTIME_DB:-${NODE_DIR}/runtime.redb}"
PEERS_DIR="${PEERS_DIR:-${NODE_DIR}/peers}"
UI_DIR="${UI_DIR:-web}"
RELAY_BIND="${RELAY_BIND:-0.0.0.0:18444}"
RPC_BIND="${RPC_BIND:-127.0.0.1:18080}"
OUTBOUND_CONNECT="${OUTBOUND_CONNECT:-true}"
OUTBOUND_REDIAL_SEC="${OUTBOUND_REDIAL_SEC:-5}"
P2P_READ_TIMEOUT_SEC="${P2P_READ_TIMEOUT_SEC:-5}"
P2P_WRITE_TIMEOUT_SEC="${P2P_WRITE_TIMEOUT_SEC:-5}"
ADD_PEERS="${ADD_PEERS:-}"

LOG_DIR="${NODE_DIR}/logs"
RELAY_LOG="${LOG_DIR}/relay.log"
RPC_LOG="${LOG_DIR}/rpc.log"
RELAY_PID="${NODE_DIR}/relay.pid"
RPC_PID="${NODE_DIR}/rpc.pid"
RELAY_TELEMETRY="${NODE_DIR}/relay.telemetry.jsonl"

require_bin() {
  if [[ ! -x "${SCAM_NODE_BIN}" ]]; then
    echo "[node-only] SCAM_NODE_BIN is not executable: ${SCAM_NODE_BIN}" >&2
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
    echo "[node-only] ${name} failed to start" >&2
    tail -n 120 "${log_file}" >&2 || true
    exit 1
  fi
}

seed_peer_book_from_env() {
  local peers_raw
  peers_raw="${ADD_PEERS//,/ }"
  [[ -n "${peers_raw//[[:space:]]/}" ]] || return 0

  echo "[node-only] seeding peer book from ADD_PEERS"
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
  mkdir -p "${NODE_DIR}" "${LOG_DIR}" "${PEERS_DIR}"
  seed_peer_book_from_env

  # Bootstrap/update runtime DB once (idempotent).
  "${SCAM_NODE_BIN}" node \
    --network "${NETWORK}" \
    --config "${CONFIG}" \
    --runtime-db "${RUNTIME_DB}" \
    > "${LOG_DIR}/bootstrap.log" 2>&1

  stop_pid_file "${RELAY_PID}"
  stop_pid_file "${RPC_PID}"

  local relay_args=(
    relay-serve
    --network "${NETWORK}"
    --config "${CONFIG}"
    --runtime-db "${RUNTIME_DB}"
    --peers-dir "${PEERS_DIR}"
    --bind "${RELAY_BIND}"
    --read-timeout-sec "${P2P_READ_TIMEOUT_SEC}"
    --write-timeout-sec "${P2P_WRITE_TIMEOUT_SEC}"
    --telemetry-out "${RELAY_TELEMETRY}"
    --telemetry-every-sec 5
  )
  if [[ "${OUTBOUND_CONNECT,,}" == "true" || "${OUTBOUND_CONNECT}" == "1" ]]; then
    relay_args+=(--outbound-connect --outbound-redial-sec "${OUTBOUND_REDIAL_SEC}")
  fi
  "${SCAM_NODE_BIN}" "${relay_args[@]}" > "${RELAY_LOG}" 2>&1 &
  echo "$!" > "${RELAY_PID}"
  ensure_started "${RELAY_PID}" "${RELAY_LOG}" "relay"

  "${SCAM_NODE_BIN}" rpc-serve \
    --network "${NETWORK}" \
    --config "${CONFIG}" \
    --runtime-db "${RUNTIME_DB}" \
    --bind "${RPC_BIND}" \
    --ui-dir "${UI_DIR}" \
    --relay-telemetry "${RELAY_TELEMETRY}" \
    > "${RPC_LOG}" 2>&1 &
  echo "$!" > "${RPC_PID}"
  ensure_started "${RPC_PID}" "${RPC_LOG}" "rpc"

  echo "[node-only] up"
  echo "[node-only] relay: ${RELAY_BIND}"
  echo "[node-only] rpc/ui: http://${RPC_BIND}/"
  echo "[node-only] runtime db: ${RUNTIME_DB}"
  if [[ -n "${ADD_PEERS//[[:space:]]/}" ]]; then
    echo "[node-only] bootstrap peers: ${ADD_PEERS}"
  fi
}

stop() {
  stop_pid_file "${RPC_PID}"
  stop_pid_file "${RELAY_PID}"
  echo "[node-only] down"
}

status() {
  local relay_state="stopped"
  local rpc_state="stopped"
  if [[ -f "${RELAY_PID}" ]] && pid_is_alive "$(cat "${RELAY_PID}")"; then
    relay_state="running (pid=$(cat "${RELAY_PID}"))"
  fi
  if [[ -f "${RPC_PID}" ]] && pid_is_alive "$(cat "${RPC_PID}")"; then
    rpc_state="running (pid=$(cat "${RPC_PID}"))"
  fi
  echo "[node-only] relay=${relay_state} rpc=${rpc_state}"
  echo "[node-only] relay bind: ${RELAY_BIND}"
  echo "[node-only] rpc bind: ${RPC_BIND}"
}

logs() {
  echo "--- relay log ---"
  tail -n 120 "${RELAY_LOG}" 2>/dev/null || echo "(missing ${RELAY_LOG})"
  echo "--- rpc log ---"
  tail -n 120 "${RPC_LOG}" 2>/dev/null || echo "(missing ${RPC_LOG})"
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
