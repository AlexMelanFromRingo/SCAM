#!/usr/bin/env bash
set -euo pipefail

# Simple user-facing launcher with sane defaults.
#
# Examples:
#   scripts/scam-easy.sh node
#   scripts/scam-easy.sh relay
#   scripts/scam-easy.sh rpc
#   scripts/scam-easy.sh pool
#   scripts/scam-easy.sh miner
#   MNEMONIC="..." scripts/scam-easy.sh wallet-address
#   MNEMONIC="..." scripts/scam-easy.sh wallet-balance

COMMAND="${1:-help}"
shift || true

NETWORK="${NETWORK:-devnet}"
CONFIG="${CONFIG:-config/${NETWORK}.toml}"
RUNTIME_DB="${RUNTIME_DB:-data/${NETWORK}.runtime.redb}"
PEERS_DIR="${PEERS_DIR:-data/peers}"
RELAY_BIND="${RELAY_BIND:-0.0.0.0:18444}"
RPC_BIND="${RPC_BIND:-127.0.0.1:18080}"
RPC_UI_DIR="${RPC_UI_DIR:-web}"
RPC_RELAY_TELEMETRY="${RPC_RELAY_TELEMETRY:-data/relay.telemetry.jsonl}"
POOL_BIND="${POOL_BIND:-127.0.0.1:3347}"
POOL_ADDR="${POOL_ADDR:-127.0.0.1:3347}"
MINER_USER="${MINER_USER:-local-miner}"
HRP="${HRP:-sd}"
WORDS="${WORDS:-12}"
ACCOUNT="${ACCOUNT:-0}"
INDEX="${INDEX:-0}"
PASSPHRASE="${PASSPHRASE:-}"
MNEMONIC="${MNEMONIC:-}"
TO_ADDRESS="${TO_ADDRESS:-}"
AMOUNT="${AMOUNT:-1}"
FEE="${FEE:-1}"

USE_CARGO="${USE_CARGO:-true}"
BIN_PATH="${BIN_PATH:-target/debug/scam-node}"

is_true() {
  local raw="${1:-false}"
  local val="${raw,,}"
  [[ "${val}" == "1" || "${val}" == "true" || "${val}" == "yes" || "${val}" == "on" ]]
}

run_node_cmd() {
  if is_true "${USE_CARGO}"; then
    cargo run -p scam-node -- "$@"
  else
    if [[ ! -x "${BIN_PATH}" ]]; then
      echo "[easy] BIN_PATH is not executable: ${BIN_PATH}" >&2
      exit 2
    fi
    "${BIN_PATH}" "$@"
  fi
}

require_mnemonic() {
  if [[ -z "${MNEMONIC}" ]]; then
    echo "[easy] set MNEMONIC env var for '${COMMAND}' command" >&2
    exit 2
  fi
}

usage() {
  cat <<'EOF'
Usage: scripts/scam-easy.sh <command>

Commands:
  node            bootstrap runtime DB
  status          print chain status
  relay           start P2P relay server
  rpc             start RPC + Web UI server
  pool            start Stratum pool server
  miner           start Stratum miner client
  add-peer        add peer from PEER env var (host:port)
  sync-peer       sync from PEER env var (host:port)
  sync-book       sync from peer book
  wallet-new      generate mnemonic + address
  wallet-address  derive address from MNEMONIC env var
  wallet-balance  show balance for MNEMONIC env var
  wallet-balance-address show balance for ADDRESS env var
  wallet-send     build signed tx preview for MNEMONIC env var
  help            show this message

Important env vars:
  NETWORK, CONFIG, RUNTIME_DB, PEERS_DIR
  RELAY_BIND, RPC_BIND, RPC_UI_DIR, RPC_RELAY_TELEMETRY
  POOL_BIND, POOL_ADDR, MINER_USER
  MNEMONIC, TO_ADDRESS, AMOUNT, FEE
  ADDRESS
EOF
}

case "${COMMAND}" in
  node)
    run_node_cmd node --network "${NETWORK}" --config "${CONFIG}" --runtime-db "${RUNTIME_DB}" "$@"
    ;;
  status)
    run_node_cmd status --network "${NETWORK}" --config "${CONFIG}" "$@"
    ;;
  relay)
    run_node_cmd relay-serve --network "${NETWORK}" --config "${CONFIG}" --runtime-db "${RUNTIME_DB}" --bind "${RELAY_BIND}" "$@"
    ;;
  rpc)
    run_node_cmd rpc-serve --network "${NETWORK}" --config "${CONFIG}" --runtime-db "${RUNTIME_DB}" --bind "${RPC_BIND}" --ui-dir "${RPC_UI_DIR}" --relay-telemetry "${RPC_RELAY_TELEMETRY}" "$@"
    ;;
  pool)
    run_node_cmd stratum-serve --network "${NETWORK}" --config "${CONFIG}" --runtime-db "${RUNTIME_DB}" --bind "${POOL_BIND}" "$@"
    ;;
  miner)
    run_node_cmd stratum-mine --pool "${POOL_ADDR}" --user "${MINER_USER}" "$@"
    ;;
  add-peer)
    if [[ -z "${PEER:-}" ]]; then
      echo "[easy] set PEER env var to host:port" >&2
      exit 2
    fi
    run_node_cmd add-peer --network "${NETWORK}" --peer "${PEER}" --peers-dir "${PEERS_DIR}" "$@"
    ;;
  sync-peer)
    if [[ -z "${PEER:-}" ]]; then
      echo "[easy] set PEER env var to host:port" >&2
      exit 2
    fi
    run_node_cmd sync-peer --network "${NETWORK}" --config "${CONFIG}" --runtime-db "${RUNTIME_DB}" --peer "${PEER}" "$@"
    ;;
  sync-book)
    run_node_cmd sync-book --network "${NETWORK}" --config "${CONFIG}" --runtime-db "${RUNTIME_DB}" --peers-dir "${PEERS_DIR}" "$@"
    ;;
  wallet-new)
    run_node_cmd wallet new --words "${WORDS}" --passphrase "${PASSPHRASE}" --account "${ACCOUNT}" --index "${INDEX}" --hrp "${HRP}" "$@"
    ;;
  wallet-address)
    require_mnemonic
    run_node_cmd wallet address --mnemonic "${MNEMONIC}" --passphrase "${PASSPHRASE}" --account "${ACCOUNT}" --index "${INDEX}" --hrp "${HRP}" "$@"
    ;;
  wallet-balance)
    require_mnemonic
    run_node_cmd wallet balance --network "${NETWORK}" --config "${CONFIG}" --mnemonic "${MNEMONIC}" --passphrase "${PASSPHRASE}" --account "${ACCOUNT}" --index "${INDEX}" "$@"
    ;;
  wallet-balance-address)
    if [[ -z "${ADDRESS:-}" ]]; then
      echo "[easy] set ADDRESS env var" >&2
      exit 2
    fi
    run_node_cmd wallet balance-address --network "${NETWORK}" --config "${CONFIG}" --address "${ADDRESS}" "$@"
    ;;
  wallet-send)
    require_mnemonic
    if [[ -z "${TO_ADDRESS}" ]]; then
      echo "[easy] set TO_ADDRESS env var" >&2
      exit 2
    fi
    run_node_cmd wallet send --network "${NETWORK}" --config "${CONFIG}" --mnemonic "${MNEMONIC}" --passphrase "${PASSPHRASE}" --account "${ACCOUNT}" --index "${INDEX}" --to "${TO_ADDRESS}" --amount "${AMOUNT}" --fee "${FEE}" "$@"
    ;;
  help|-h|--help)
    usage
    ;;
  *)
    echo "[easy] unknown command: ${COMMAND}" >&2
    usage
    exit 2
    ;;
esac
