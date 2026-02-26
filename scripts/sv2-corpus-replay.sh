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

if (( ${SETUP_MIN_VERSION:-2} > ${SETUP_MAX_VERSION:-2} )); then
  echo "SETUP_MIN_VERSION must be <= SETUP_MAX_VERSION" >&2
  exit 1
fi

args=(
  --pool "${POOL}"
  --stack-name "${STACK_NAME}"
  --user "${USER_NAME}"
  --setup-protocol "${SETUP_PROTOCOL:-2}"
  --setup-min-version "${SETUP_MIN_VERSION:-2}"
  --setup-max-version "${SETUP_MAX_VERSION:-2}"
  --setup-flags "${SETUP_FLAGS:-0}"
  --connect-timeout-sec "${CONNECT_TIMEOUT_SEC:-5}"
  --connect-retries "${CONNECT_RETRIES:-2}"
  --connect-retry-delay-ms "${CONNECT_RETRY_DELAY_MS:-250}"
  --min-job-messages "${MIN_JOB_MESSAGES:-0}"
  --corpus "${CORPUS}"
  --out "${OUT}"
)

if [[ -n "${REQUIRE_SETUP_VERSION:-}" ]]; then
  args+=(--require-setup-version "${REQUIRE_SETUP_VERSION}")
fi
if [[ "${REQUIRE_SETUP_FLAGS_MASK:-0}" != "0" ]]; then
  args+=(--require-setup-flags-mask "${REQUIRE_SETUP_FLAGS_MASK}")
fi
if [[ "${FORBID_SETUP_FLAGS_MASK:-0}" != "0" ]]; then
  args+=(--forbid-setup-flags-mask "${FORBID_SETUP_FLAGS_MASK}")
fi

if [[ "${EXPECT_SET_TARGET:-false}" == "true" ]]; then
  args+=(--expect-set-target)
fi
if [[ -n "${REQUIRE_OBSERVED_KINDS:-}" ]]; then
  IFS=';' read -ra kinds <<<"${REQUIRE_OBSERVED_KINDS}"
  for kind in "${kinds[@]}"; do
    [[ -z "${kind}" ]] && continue
    args+=(--require-observed-kind "${kind}")
  done
fi
if [[ -n "${REQUIRE_OBSERVED_SEQUENCE:-}" ]]; then
  args+=(--require-observed-sequence "${REQUIRE_OBSERVED_SEQUENCE}")
fi
if [[ -n "${FORBID_OBSERVED_KINDS:-}" ]]; then
  IFS=';' read -ra kinds <<<"${FORBID_OBSERVED_KINDS}"
  for kind in "${kinds[@]}"; do
    [[ -z "${kind}" ]] && continue
    args+=(--forbid-observed-kind "${kind}")
  done
fi

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
