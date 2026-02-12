#!/usr/bin/env bash
set -euo pipefail

NETWORK="${NETWORK:-devnet}"
RUNTIME_DB="${RUNTIME_DB:-data/${NETWORK}.runtime.redb}"
ROUNDS="${ROUNDS:-720}"
BLOCKS_PER_ROUND="${BLOCKS_PER_ROUND:-1}"
INTERVAL_SEC="${INTERVAL_SEC:-120}"
MAX_NONCE="${MAX_NONCE:-500000}"
PERSIST_EVERY_ROUNDS="${PERSIST_EVERY_ROUNDS:-60}"
TXS_PER_ROUND="${TXS_PER_ROUND:-1}"
TX_AMOUNT="${TX_AMOUNT:-1000}"
TX_FEE="${TX_FEE:-1}"
SLEEP_PER_ROUND_SEC="${SLEEP_PER_ROUND_SEC:-120}"

cargo run -p scam-node -- soak \
  --network "${NETWORK}" \
  --runtime-db "${RUNTIME_DB}" \
  --rounds "${ROUNDS}" \
  --blocks-per-round "${BLOCKS_PER_ROUND}" \
  --interval-sec "${INTERVAL_SEC}" \
  --max-nonce "${MAX_NONCE}" \
  --persist-every-rounds "${PERSIST_EVERY_ROUNDS}" \
  --txs-per-round "${TXS_PER_ROUND}" \
  --tx-amount "${TX_AMOUNT}" \
  --tx-fee "${TX_FEE}" \
  --sleep-per-round-sec "${SLEEP_PER_ROUND_SEC}" \
  "$@"
