#!/usr/bin/env bash
set -euo pipefail

CONFIG="${CONFIG:-config/mainnet.toml}"
OUT="${OUT:-docs/mainnet-freeze.lock.json}"

if [[ ! -f "${CONFIG}" ]]; then
  echo "config not found: ${CONFIG}" >&2
  exit 1
fi

status_json="$(cargo run -p scam-node -- status --network mainnet --config "${CONFIG}")"
genesis_hash="$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["tip_hash"])' <<<"${status_json}")"
config_hash="$(sha256sum "${CONFIG}" | awk '{print $1}')"
generated_at="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

mkdir -p "$(dirname "${OUT}")"
cat >"${OUT}" <<JSON
{
  "network": "mainnet",
  "config_path": "${CONFIG}",
  "config_sha256": "${config_hash}",
  "genesis_hash": "${genesis_hash}",
  "generated_at_utc": "${generated_at}"
}
JSON

echo "[mainnet-freeze] lock written: ${OUT}"
cat "${OUT}"

