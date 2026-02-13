#!/usr/bin/env bash
set -euo pipefail

POOL="${POOL:-}"
CORPUS="${CORPUS:-docs/sv2-corpus/default.json}"
OUT="${OUT:-target/sv2-conformance/corpus-replay.json}"
STACK_NAME="${STACK_NAME:-external-corpus-replay}"
USER_NAME="${USER_NAME:-corpus-miner}"

if [[ -z "${POOL}" ]]; then
  echo "POOL must be set, e.g. POOL=127.0.0.1:3347 scripts/sv2-corpus-replay.sh" >&2
  exit 1
fi

args=(
  --pool "${POOL}"
  --stack-name "${STACK_NAME}"
  --user "${USER_NAME}"
  --corpus "${CORPUS}"
  --out "${OUT}"
)

if [[ "${SECURE_TRANSPORT:-false}" == "true" ]]; then
  args+=(--secure-transport)
fi
if [[ -n "${SECURE_TRANSPORT_MODE:-}" ]]; then
  args+=(--secure-transport-mode "${SECURE_TRANSPORT_MODE}")
fi
if [[ -n "${SECURE_STATIC_SECRET_KEY_HEX:-}" ]]; then
  args+=(--secure-static-secret-key-hex "${SECURE_STATIC_SECRET_KEY_HEX}")
fi
if [[ -n "${SECURE_EXPECTED_REMOTE_STATIC_PUBKEY_HEX:-}" ]]; then
  args+=(--secure-expected-remote-static-pubkey-hex "${SECURE_EXPECTED_REMOTE_STATIC_PUBKEY_HEX}")
fi

cargo run -p scam-node -- sv2-conformance "${args[@]}"
echo "[sv2-corpus] report=${OUT}"

