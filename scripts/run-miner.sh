#!/usr/bin/env bash
set -euo pipefail

# Standalone Stratum miner launcher.
#
# Required:
#   POOL_ADDR=<host:port>
#   COINBASE_ADDRESS=<address used as miner user/payout label>
#
# Note:
# - This script does not run a relay node, so `add-peer`/peer discovery is not applicable here.
#
# Commands:
#   scripts/run-miner.sh start
#   scripts/run-miner.sh stop
#   scripts/run-miner.sh status
#   scripts/run-miner.sh logs

COMMAND="${1:-status}"

SCAM_NODE_BIN="${SCAM_NODE_BIN:-target/debug/scam-node}"
POOL_ADDR="${POOL_ADDR:-}"
COINBASE_ADDRESS="${COINBASE_ADDRESS:-}"
READ_TIMEOUT_SEC="${READ_TIMEOUT_SEC:-2}"
MAX_NONCE_PER_CYCLE="${MAX_NONCE_PER_CYCLE:-250000}"
MAX_SHARES="${MAX_SHARES:-0}"
MAX_RUNTIME_SEC="${MAX_RUNTIME_SEC:-0}"
RECONNECT_DELAY_SEC="${RECONNECT_DELAY_SEC:-2}"
MAX_RECONNECT_ATTEMPTS="${MAX_RECONNECT_ATTEMPTS:-0}"

WORK_DIR="${WORK_DIR:-target/run-miner}"
LOG_FILE="${WORK_DIR}/miner.log"
PID_FILE="${WORK_DIR}/miner.pid"

require_bin() {
  if [[ ! -x "${SCAM_NODE_BIN}" ]]; then
    echo "[miner] SCAM_NODE_BIN is not executable: ${SCAM_NODE_BIN}" >&2
    exit 2
  fi
}

pid_is_alive() {
  local pid="$1"
  [[ "${pid}" =~ ^[0-9]+$ ]] || return 1
  kill -0 "${pid}" 2>/dev/null
}

start() {
  require_bin
  if [[ -z "${POOL_ADDR}" ]]; then
    echo "[miner] set POOL_ADDR=<host:port>" >&2
    exit 2
  fi
  if [[ -z "${COINBASE_ADDRESS}" ]]; then
    echo "[miner] set COINBASE_ADDRESS=<address>" >&2
    exit 2
  fi
  mkdir -p "${WORK_DIR}"
  if [[ -f "${PID_FILE}" ]]; then
    local existing
    existing="$(cat "${PID_FILE}")"
    if pid_is_alive "${existing}"; then
      echo "[miner] already running (pid=${existing})"
      return 0
    fi
    rm -f "${PID_FILE}"
  fi
  "${SCAM_NODE_BIN}" stratum-mine \
    --pool "${POOL_ADDR}" \
    --user "${COINBASE_ADDRESS}" \
    --read-timeout-sec "${READ_TIMEOUT_SEC}" \
    --max-nonce-per-cycle "${MAX_NONCE_PER_CYCLE}" \
    --max-shares "${MAX_SHARES}" \
    --max-runtime-sec "${MAX_RUNTIME_SEC}" \
    --reconnect-delay-sec "${RECONNECT_DELAY_SEC}" \
    --max-reconnect-attempts "${MAX_RECONNECT_ATTEMPTS}" \
    >"${LOG_FILE}" 2>&1 &
  echo "$!" > "${PID_FILE}"
  sleep 0.2
  if ! pid_is_alive "$(cat "${PID_FILE}")"; then
    echo "[miner] failed to start; last logs:" >&2
    tail -n 80 "${LOG_FILE}" >&2 || true
    exit 1
  fi
  echo "[miner] up"
  echo "[miner] pool: ${POOL_ADDR}"
  echo "[miner] user/coinbase address: ${COINBASE_ADDRESS}"
  echo "[miner] log: ${LOG_FILE}"
}

stop() {
  if [[ ! -f "${PID_FILE}" ]]; then
    echo "[miner] not running"
    return 0
  fi
  local pid
  pid="$(cat "${PID_FILE}")"
  if pid_is_alive "${pid}"; then
    kill "${pid}" 2>/dev/null || true
    sleep 0.2
    if pid_is_alive "${pid}"; then
      kill -9 "${pid}" 2>/dev/null || true
    fi
  fi
  rm -f "${PID_FILE}"
  echo "[miner] down"
}

status() {
  if [[ -f "${PID_FILE}" ]] && pid_is_alive "$(cat "${PID_FILE}")"; then
    echo "[miner] running (pid=$(cat "${PID_FILE}"))"
    echo "[miner] log: ${LOG_FILE}"
  else
    echo "[miner] stopped"
  fi
}

logs() {
  if [[ -f "${LOG_FILE}" ]]; then
    tail -n 120 "${LOG_FILE}"
  else
    echo "[miner] log file not found: ${LOG_FILE}"
  fi
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
