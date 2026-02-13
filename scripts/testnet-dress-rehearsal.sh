#!/usr/bin/env bash
set -euo pipefail

NETWORK="${NETWORK:-testnet}"
CONFIG="${CONFIG:-config/${NETWORK}.toml}"
RUNTIME_DB="${RUNTIME_DB:-data/${NETWORK}.runtime.redb}"
TELEMETRY_OUT="${TELEMETRY_OUT:-data/${NETWORK}.dress.telemetry.jsonl}"
PEER="${PEER:-}"
STRICT_SYNC_BOOK="${STRICT_SYNC_BOOK:-false}"

echo "[dress] network=${NETWORK} config=${CONFIG} runtime_db=${RUNTIME_DB}"

echo "[dress] step 1/7: bootstrap runtime"
cargo run -p scam-node -- node \
  --network "${NETWORK}" \
  --config "${CONFIG}" \
  --runtime-db "${RUNTIME_DB}"

if [[ -n "${PEER}" ]]; then
  echo "[dress] step 2/7: manual peer bootstrap (${PEER})"
  cargo run -p scam-node -- add-peer --network "${NETWORK}" --peer "${PEER}"
  cargo run -p scam-node -- sync-peer \
    --network "${NETWORK}" \
    --config "${CONFIG}" \
    --runtime-db "${RUNTIME_DB}" \
    --peer "${PEER}" \
    --max-batches 8
else
  echo "[dress] step 2/7: manual peer bootstrap skipped (set PEER=host:port to enable)"
fi

echo "[dress] step 3/7: multi-peer sync-book"
set +e
cargo run -p scam-node -- sync-book \
  --network "${NETWORK}" \
  --config "${CONFIG}" \
  --runtime-db "${RUNTIME_DB}" \
  --max-peers 8 \
  --max-batches-per-peer 8
sync_book_rc=$?
set -e
if [[ "${sync_book_rc}" -ne 0 ]]; then
  if [[ "${STRICT_SYNC_BOOK}" == "true" ]]; then
    echo "[dress] sync-book failed and STRICT_SYNC_BOOK=true, aborting" >&2
    exit "${sync_book_rc}"
  fi
  echo "[dress] sync-book failed but continuing (STRICT_SYNC_BOOK=false)"
fi

echo "[dress] step 4/7: short soak with telemetry"
cargo run -p scam-node -- soak \
  --network "${NETWORK}" \
  --config "${CONFIG}" \
  --runtime-db "${RUNTIME_DB}" \
  --rounds 12 \
  --blocks-per-round 1 \
  --interval-sec 120 \
  --persist-every-rounds 3 \
  --txs-per-round 2 \
  --tx-amount 1000 \
  --tx-fee 1 \
  --telemetry-out "${TELEMETRY_OUT}" \
  --telemetry-every-rounds 1

echo "[dress] step 5/7: reindex integrity"
cargo run -p scam-node -- reindex-runtime \
  --network "${NETWORK}" \
  --config "${CONFIG}" \
  --runtime-db "${RUNTIME_DB}"

echo "[dress] step 6/7: final status"
cargo run -p scam-node -- status --network "${NETWORK}" --config "${CONFIG}"

echo "[dress] step 7/7: telemetry threshold checks"
scripts/telemetry-alert-check.py --input "${TELEMETRY_OUT}"

echo "[dress] complete. telemetry=${TELEMETRY_OUT}"
