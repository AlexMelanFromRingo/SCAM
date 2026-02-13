#!/usr/bin/env bash
set -euo pipefail

OUT_DIR="${OUT_DIR:-target/sv2-conformance}"
RUNTIME_DB="${RUNTIME_DB:-data/devnet.runtime.redb}"
CORPUS="${CORPUS:-docs/sv2-corpus/default.json}"
POOL_BIND="${POOL_BIND:-127.0.0.1:3347}"
SECURE_POOL_BIND="${SECURE_POOL_BIND:-127.0.0.1:3348}"

mkdir -p "${OUT_DIR}"

echo "[sv2-matrix] preparing runtime db=${RUNTIME_DB}"
cargo run -p scam-node -- node \
  --network devnet \
  --config config/devnet.toml \
  --runtime-db "${RUNTIME_DB}" >/dev/null

echo "[sv2-matrix] local plaintext stack"
cargo run -p scam-node -- stratum-serve \
  --network devnet \
  --config config/devnet.toml \
  --runtime-db "${RUNTIME_DB}" \
  --bind "${POOL_BIND}" \
  --max-clients 1 >/tmp/scam-sv2-plain.log 2>&1 &
plain_pid=$!
sleep 1
cargo run -p scam-node -- sv2-conformance \
  --pool "${POOL_BIND}" \
  --stack-name "scam-local-plain" \
  --user "matrix-miner" \
  --corpus "${CORPUS}" \
  --out "${OUT_DIR}/scam-local-plain.json"
wait "${plain_pid}" || true

echo "[sv2-matrix] local secure noise_xx stack"
SERVER_KEY_HEX="${SERVER_KEY_HEX:-1111111111111111111111111111111111111111111111111111111111111111}"
CLIENT_KEY_HEX="${CLIENT_KEY_HEX:-2222222222222222222222222222222222222222222222222222222222222222}"
cargo run -p scam-node -- stratum-serve \
  --network devnet \
  --config config/devnet.toml \
  --runtime-db "${RUNTIME_DB}" \
  --bind "${SECURE_POOL_BIND}" \
  --max-clients 1 \
  --secure-transport \
  --secure-transport-mode noise-xx \
  --secure-static-secret-key-hex "${SERVER_KEY_HEX}" >/tmp/scam-sv2-noise.log 2>&1 &
secure_pid=$!
sleep 1
cargo run -p scam-node -- sv2-conformance \
  --pool "${SECURE_POOL_BIND}" \
  --stack-name "scam-local-noise-xx" \
  --user "matrix-miner-secure" \
  --secure-transport \
  --secure-transport-mode noise-xx \
  --secure-static-secret-key-hex "${CLIENT_KEY_HEX}" \
  --corpus "${CORPUS}" \
  --out "${OUT_DIR}/scam-local-noise-xx.json"
wait "${secure_pid}" || true

if [[ -n "${SV2_EXTERNAL_TARGETS:-}" ]]; then
  # Format: "name,host:port,secure,mode,secret_hex;name2,host:port,secure,mode,secret_hex"
  IFS=';' read -ra targets <<<"${SV2_EXTERNAL_TARGETS}"
  for target in "${targets[@]}"; do
    [[ -z "${target}" ]] && continue
    IFS=',' read -r stack_name endpoint secure mode secret <<<"${target}"
    args=(
      --pool "${endpoint}"
      --stack-name "${stack_name}"
      --user "matrix-${stack_name}"
      --corpus "${CORPUS}"
      --out "${OUT_DIR}/${stack_name}.json"
    )
    if [[ "${secure}" == "true" ]]; then
      args+=(--secure-transport)
    fi
    if [[ -n "${mode}" ]]; then
      args+=(--secure-transport-mode "${mode}")
    fi
    if [[ -n "${secret}" ]]; then
      args+=(--secure-static-secret-key-hex "${secret}")
    fi
    echo "[sv2-matrix] external stack=${stack_name} endpoint=${endpoint}"
    cargo run -p scam-node -- sv2-conformance "${args[@]}"
  done
fi

python3 scripts/sv2-conformance-report.py \
  --input-dir "${OUT_DIR}" \
  --summary-out "${OUT_DIR}/summary.json" \
  --matrix-out "${OUT_DIR}/matrix.md"

echo "[sv2-matrix] done: ${OUT_DIR}"
