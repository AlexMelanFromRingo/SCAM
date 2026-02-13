#!/usr/bin/env bash
set -euo pipefail

NETWORK="${NETWORK:-devnet}"
CONFIG="${CONFIG:-config/${NETWORK}.toml}"
RUNTIME_DB="${RUNTIME_DB:-data/${NETWORK}.runtime.redb}"
ROUNDS="${ROUNDS:-50}"
RUN_SEC_MIN="${RUN_SEC_MIN:-180}"
RUN_SEC_MAX="${RUN_SEC_MAX:-900}"
SOAK_ROUNDS="${SOAK_ROUNDS:-1000000}"
BLOCKS_PER_ROUND="${BLOCKS_PER_ROUND:-1}"
INTERVAL_SEC="${INTERVAL_SEC:-2}"
MAX_NONCE="${MAX_NONCE:-500000}"
PERSIST_EVERY_ROUNDS="${PERSIST_EVERY_ROUNDS:-5}"
TXS_PER_ROUND="${TXS_PER_ROUND:-1}"
TX_AMOUNT="${TX_AMOUNT:-1000}"
TX_FEE="${TX_FEE:-1}"

if (( RUN_SEC_MAX < RUN_SEC_MIN )); then
  echo "RUN_SEC_MAX must be >= RUN_SEC_MIN" >&2
  exit 1
fi

echo "[chaos] network=${NETWORK} rounds=${ROUNDS} runtime_db=${RUNTIME_DB}"
for ((i=1; i<=ROUNDS; i++)); do
  run_for=$((RUN_SEC_MIN + RANDOM % (RUN_SEC_MAX - RUN_SEC_MIN + 1)))
  echo "[chaos] cycle ${i}/${ROUNDS}: running soak for ${run_for}s, then kill -9"

  cargo run -p scam-node -- soak \
    --network "${NETWORK}" \
    --config "${CONFIG}" \
    --runtime-db "${RUNTIME_DB}" \
    --rounds "${SOAK_ROUNDS}" \
    --blocks-per-round "${BLOCKS_PER_ROUND}" \
    --interval-sec "${INTERVAL_SEC}" \
    --max-nonce "${MAX_NONCE}" \
    --persist-every-rounds "${PERSIST_EVERY_ROUNDS}" \
    --txs-per-round "${TXS_PER_ROUND}" \
    --tx-amount "${TX_AMOUNT}" \
    --tx-fee "${TX_FEE}" &
  pid=$!

  sleep "${run_for}"
  kill -9 "${pid}" 2>/dev/null || true
  wait "${pid}" 2>/dev/null || true

  echo "[chaos] cycle ${i}: validating DB can be reopened"
  cargo run -p scam-node -- node run \
    --network "${NETWORK}" \
    --config "${CONFIG}" \
    --runtime-db "${RUNTIME_DB}" >/dev/null

done

echo "[chaos] completed ${ROUNDS} crash-recovery cycles"
