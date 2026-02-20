#!/usr/bin/env bash
set -euo pipefail

# Local functional lab:
# - launches 2+ relay nodes with RPC+Web UI
# - launches one Stratum miner against node-0
# - generates two demo wallets (mnemonic+address files)
#
# Commands:
#   scripts/local-test-lab.sh up
#   scripts/local-test-lab.sh down
#   scripts/local-test-lab.sh status
#   scripts/local-test-lab.sh clean

COMMAND="${1:-up}"

NETWORK="${NETWORK:-devnet}"
CONFIG="${CONFIG:-config/${NETWORK}.toml}"
CLUSTER_DIR="${CLUSTER_DIR:-target/local-test-lab}"
NODE_COUNT="${NODE_COUNT:-2}"
BUILD="${BUILD:-true}"
CARGO_PROFILE="${CARGO_PROFILE:-debug}"
UI_DIR="${UI_DIR:-web}"
SCAM_NODE_BIN="${SCAM_NODE_BIN:-}"

BASE_P2P_PORT="${BASE_P2P_PORT:-19444}"
BASE_RPC_PORT="${BASE_RPC_PORT:-19080}"
BASE_STRATUM_PORT="${BASE_STRATUM_PORT:-19347}"

MINER_USER="${MINER_USER:-lab-miner-01}"
MINER_READ_TIMEOUT_SEC="${MINER_READ_TIMEOUT_SEC:-2}"
MINER_MAX_NONCE_PER_CYCLE="${MINER_MAX_NONCE_PER_CYCLE:-250000}"
MINER_MAX_SHARES="${MINER_MAX_SHARES:-0}"
MINER_MAX_RUNTIME_SEC="${MINER_MAX_RUNTIME_SEC:-0}"
STRATUM_READ_TIMEOUT_SEC="${STRATUM_READ_TIMEOUT_SEC:-30}"
RELAY_OUTBOUND_CONNECT="${RELAY_OUTBOUND_CONNECT:-true}"
RELAY_OUTBOUND_REDIAL_SEC="${RELAY_OUTBOUND_REDIAL_SEC:-2}"
RUN_SYNC_LOOP="${RUN_SYNC_LOOP:-false}"
SYNC_LOOP_INTERVAL_SEC="${SYNC_LOOP_INTERVAL_SEC:-5}"
SYNC_MAX_BATCHES_PER_PEER="${SYNC_MAX_BATCHES_PER_PEER:-8}"

WALLET_WORDS="${WALLET_WORDS:-12}"
WALLET_HRP="${WALLET_HRP:-}"
RESOLVED_WALLET_HRP=""

ENDPOINTS_FILE="${CLUSTER_DIR}/endpoints.tsv"
MINER_PID_FILE="${CLUSTER_DIR}/miner.pid"
MINER_LOG_FILE="${CLUSTER_DIR}/miner.log"
WALLETS_DIR="${CLUSTER_DIR}/wallets"
FOLLOW_SYNC_DIR="${CLUSTER_DIR}/follower-sync"

is_true() {
  local raw="${1:-false}"
  local val="${raw,,}"
  [[ "${val}" == "1" || "${val}" == "true" || "${val}" == "yes" || "${val}" == "on" ]]
}

require_positive_int() {
  local name="$1"
  local value="$2"
  if ! [[ "${value}" =~ ^[0-9]+$ ]] || [[ "${value}" == "0" ]]; then
    echo "[lab] ${name} must be a positive integer, got '${value}'" >&2
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

resolve_binary() {
  if [[ -n "${SCAM_NODE_BIN}" ]]; then
    if [[ ! -x "${SCAM_NODE_BIN}" ]]; then
      echo "[lab] SCAM_NODE_BIN is not executable: ${SCAM_NODE_BIN}" >&2
      exit 2
    fi
    echo "${SCAM_NODE_BIN}"
    return
  fi
  if [[ -f "${CLUSTER_DIR}/scam-node.path" ]]; then
    local from_file
    from_file="$(cat "${CLUSTER_DIR}/scam-node.path")"
    if [[ -x "${from_file}" ]]; then
      echo "${from_file}"
      return
    fi
  fi
  if [[ -x "target/debug/scam-node" ]]; then
    echo "target/debug/scam-node"
    return
  fi
  if [[ -x "target/release/scam-node" ]]; then
    echo "target/release/scam-node"
    return
  fi
  echo "[lab] scam-node binary not found; run with BUILD=true first" >&2
  exit 2
}

extract_col() {
  local node_idx="$1"
  local col="$2"
  awk -F '\t' -v idx="${node_idx}" -v col="${col}" 'NR>1 && $1==idx {print $col}' "${ENDPOINTS_FILE}" | head -n 1
}

generate_demo_wallet() {
  local bin="$1"
  local wallet_idx="$2"
  local out_file="${WALLETS_DIR}/wallet-${wallet_idx}.txt"
  "${bin}" wallet new --words "${WALLET_WORDS}" --hrp "${RESOLVED_WALLET_HRP}" > "${out_file}"
  local mnemonic address
  mnemonic="$(sed -n 's/^Mnemonic: //p' "${out_file}" | head -n 1)"
  address="$(sed -n 's/^Address: //p' "${out_file}" | head -n 1)"
  if [[ -z "${mnemonic}" || -z "${address}" ]]; then
    echo "[lab] failed to parse demo wallet output: ${out_file}" >&2
    return 1
  fi
  printf "WALLET_%s_MNEMONIC=%q\n" "${wallet_idx}" "${mnemonic}" >> "${WALLETS_DIR}/wallets.env"
  printf "WALLET_%s_ADDRESS=%q\n" "${wallet_idx}" "${address}" >> "${WALLETS_DIR}/wallets.env"
}

resolve_wallet_hrp() {
  if [[ -n "${WALLET_HRP}" ]]; then
    echo "${WALLET_HRP}"
    return
  fi
  if [[ -f "${CONFIG}" ]]; then
    local from_config
    from_config="$(
      sed -nE 's/^[[:space:]]*hrp[[:space:]]*=[[:space:]]*"([^"]+)".*/\1/p' "${CONFIG}" | head -n 1
    )"
    if [[ -n "${from_config}" ]]; then
      echo "${from_config}"
      return
    fi
  fi
  echo "sd"
}

stop_follower_sync_loops() {
  if [[ ! -d "${FOLLOW_SYNC_DIR}" ]]; then
    return 0
  fi
  for pid_file in "${FOLLOW_SYNC_DIR}"/sync-node-*.pid; do
    [[ -e "${pid_file}" ]] || continue
    stop_pid_file "${pid_file}"
  done
}

start_follower_sync_loops() {
  local bin="$1"
  if ! is_true "${RUN_SYNC_LOOP}"; then
    return 0
  fi
  mkdir -p "${FOLLOW_SYNC_DIR}"
  for ((idx = 1; idx < NODE_COUNT; idx++)); do
    local node_tag nodedir runtime_db peers_dir pid_file log_file
    node_tag="$(printf "%02d" "${idx}")"
    nodedir="${CLUSTER_DIR}/node-${node_tag}"
    runtime_db="${nodedir}/runtime.redb"
    peers_dir="${nodedir}/peers"
    pid_file="${FOLLOW_SYNC_DIR}/sync-node-${node_tag}.pid"
    log_file="${nodedir}/logs/sync-follow.log"
    (
      while true; do
        "${bin}" sync-book \
          --network "${NETWORK}" \
          --config "${CONFIG}" \
          --runtime-db "${runtime_db}" \
          --peers-dir "${peers_dir}" \
          --max-peers "${NODE_COUNT}" \
          --max-batches-per-peer "${SYNC_MAX_BATCHES_PER_PEER}" \
          >> "${log_file}" 2>&1 || true
        sleep "${SYNC_LOOP_INTERVAL_SEC}"
      done
    ) &
    echo "$!" > "${pid_file}"
  done
}

start_lab() {
  require_positive_int "NODE_COUNT" "${NODE_COUNT}"
  if (( NODE_COUNT < 2 )); then
    echo "[lab] NODE_COUNT must be >= 2 for sync checks" >&2
    exit 2
  fi

  NODE_COUNT="${NODE_COUNT}" \
  NETWORK="${NETWORK}" \
  CONFIG="${CONFIG}" \
  CLUSTER_DIR="${CLUSTER_DIR}" \
  SCAM_NODE_BIN="${SCAM_NODE_BIN}" \
  BASE_P2P_PORT="${BASE_P2P_PORT}" \
  BASE_RPC_PORT="${BASE_RPC_PORT}" \
  BASE_STRATUM_PORT="${BASE_STRATUM_PORT}" \
  RELAY_OUTBOUND_CONNECT="${RELAY_OUTBOUND_CONNECT}" \
  RELAY_OUTBOUND_REDIAL_SEC="${RELAY_OUTBOUND_REDIAL_SEC}" \
  STRATUM_READ_TIMEOUT_SEC="${STRATUM_READ_TIMEOUT_SEC}" \
  RUN_RPC=true \
  RUN_STRATUM=true \
  BUILD="${BUILD}" \
  CARGO_PROFILE="${CARGO_PROFILE}" \
  SYNC_BOOK=true \
  RUN_SYNC_LOOP="${RUN_SYNC_LOOP}" \
  SYNC_MAX_BATCHES_PER_PEER="${SYNC_MAX_BATCHES_PER_PEER}" \
  SYNC_LOOP_INTERVAL_SEC="${SYNC_LOOP_INTERVAL_SEC}" \
  scripts/local-multinode.sh up

  local bin
  bin="$(resolve_binary)"
  RESOLVED_WALLET_HRP="$(resolve_wallet_hrp)"

  mkdir -p "${WALLETS_DIR}"
  : > "${WALLETS_DIR}/wallets.env"
  generate_demo_wallet "${bin}" "01"
  generate_demo_wallet "${bin}" "02"
  local wallet01_addr
  wallet01_addr="$(sed -n 's/^Address: //p' "${WALLETS_DIR}/wallet-01.txt" | head -n 1)"
  if [[ -z "${wallet01_addr}" ]]; then
    echo "[lab] failed to parse wallet-01 address from ${WALLETS_DIR}/wallet-01.txt" >&2
    exit 1
  fi
  local miner_user_effective="${MINER_USER}"
  if [[ "${miner_user_effective}" == "lab-miner-01" ]]; then
    miner_user_effective="${wallet01_addr}"
  fi

  local pool_port
  pool_port="$(extract_col "0" "4")"
  if [[ -z "${pool_port}" || "${pool_port}" == "-" ]]; then
    echo "[lab] cannot find node-0 stratum port in ${ENDPOINTS_FILE}" >&2
    exit 1
  fi

  "${bin}" stratum-mine \
    --pool "127.0.0.1:${pool_port}" \
    --user "${miner_user_effective}" \
    --read-timeout-sec "${MINER_READ_TIMEOUT_SEC}" \
    --max-nonce-per-cycle "${MINER_MAX_NONCE_PER_CYCLE}" \
    --max-shares "${MINER_MAX_SHARES}" \
    --max-runtime-sec "${MINER_MAX_RUNTIME_SEC}" \
    > "${MINER_LOG_FILE}" 2>&1 &
  echo "$!" > "${MINER_PID_FILE}"
  sleep 0.3
  if ! pid_is_alive "$(cat "${MINER_PID_FILE}")"; then
    echo "[lab] miner exited immediately; see ${MINER_LOG_FILE}" >&2
    tail -n 60 "${MINER_LOG_FILE}" >&2 || true
    exit 1
  fi

  start_follower_sync_loops "${bin}"

  local rpc0 rpc1
  rpc0="$(extract_col "0" "3")"
  rpc1="$(extract_col "1" "3")"

  echo "[lab] up"
  echo "[lab] node-0 UI: http://127.0.0.1:${rpc0}/"
  echo "[lab] node-1 UI: http://127.0.0.1:${rpc1}/"
  echo "[lab] miner log: ${MINER_LOG_FILE}"
  echo "[lab] miner user: ${miner_user_effective}"
  echo "[lab] miner payout default wallet: ${wallet01_addr}"
  echo "[lab] wallet hrp: ${RESOLVED_WALLET_HRP}"
  echo "[lab] demo wallets:"
  echo "  ${WALLETS_DIR}/wallet-01.txt"
  echo "  ${WALLETS_DIR}/wallet-02.txt"
  echo "  ${WALLETS_DIR}/wallets.env"
}

down_lab() {
  stop_pid_file "${MINER_PID_FILE}"
  stop_follower_sync_loops
  CLUSTER_DIR="${CLUSTER_DIR}" scripts/local-multinode.sh down
  echo "[lab] down"
}

status_lab() {
  CLUSTER_DIR="${CLUSTER_DIR}" scripts/local-multinode.sh status
  if [[ -f "${MINER_PID_FILE}" ]] && pid_is_alive "$(cat "${MINER_PID_FILE}")"; then
    echo "[lab] miner=running pool=127.0.0.1:$(extract_col "0" "4")"
  else
    echo "[lab] miner=stopped"
  fi
  if [[ -d "${FOLLOW_SYNC_DIR}" ]]; then
    for pid_file in "${FOLLOW_SYNC_DIR}"/sync-node-*.pid; do
      [[ -e "${pid_file}" ]] || continue
      local node_tag
      node_tag="$(basename "${pid_file}" .pid | sed -E 's/^sync-node-//')"
      if pid_is_alive "$(cat "${pid_file}")"; then
        echo "[lab] follower-sync node-${node_tag}=running"
      else
        echo "[lab] follower-sync node-${node_tag}=stopped"
      fi
    done
  fi
}

clean_lab() {
  down_lab || true
  rm -f "${MINER_LOG_FILE}"
  rm -rf "${WALLETS_DIR}"
  CLUSTER_DIR="${CLUSTER_DIR}" scripts/local-multinode.sh clean
}

case "${COMMAND}" in
  up)
    start_lab
    ;;
  down)
    down_lab
    ;;
  status)
    status_lab
    ;;
  clean)
    clean_lab
    ;;
  *)
    echo "usage: $0 {up|down|status|clean}" >&2
    exit 2
    ;;
esac
