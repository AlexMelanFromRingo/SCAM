#!/usr/bin/env bash
set -euo pipefail

OUT_DIR="${OUT_DIR:-target/sv2-conformance}"
RUNTIME_DB="${RUNTIME_DB:-data/devnet.runtime.redb}"
CORPUS="${CORPUS:-docs/sv2-corpus/default.json}"
POOL_BIND="${POOL_BIND:-127.0.0.1:3347}"
SECURE_POOL_BIND="${SECURE_POOL_BIND:-127.0.0.1:3348}"
SV2_EXTERNAL_TARGETS_FILE="${SV2_EXTERNAL_TARGETS_FILE:-}"
EXTERNAL_RESULTS_JSONL="${OUT_DIR}/external-target-results.jsonl"
unexpected_external_failures=0

mkdir -p "${OUT_DIR}"
rm -f "${EXTERNAL_RESULTS_JSONL}"

run_conformance_target() {
  local stack_name="$1"
  local endpoint="$2"
  local secure="$3"
  local mode="$4"
  local secret="$5"
  local expected="${6:-pass}"
  local vendor="${7:-}"
  local version="${8:-}"

  local args=(
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

  echo "[sv2-matrix] target=${stack_name} endpoint=${endpoint} secure=${secure} mode=${mode:-auto} expected=${expected}"
  if cargo run -p scam-node -- sv2-conformance "${args[@]}"; then
    result="pass"
    rc=0
  else
    result="fail"
    rc=$?
  fi

  python3 - <<'PY' "${EXTERNAL_RESULTS_JSONL}" "${stack_name}" "${endpoint}" "${secure}" "${mode}" "${expected}" "${vendor}" "${version}" "${result}" "${rc}"
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
record = {
    "stack_name": sys.argv[2],
    "endpoint": sys.argv[3],
    "secure": sys.argv[4] == "true",
    "mode": sys.argv[5] or None,
    "expected": sys.argv[6],
    "vendor": sys.argv[7] or None,
    "version": sys.argv[8] or None,
    "result": sys.argv[9],
    "exit_code": int(sys.argv[10]),
}
path.parent.mkdir(parents=True, exist_ok=True)
with path.open("a", encoding="utf-8") as fh:
    fh.write(json.dumps(record, ensure_ascii=True) + "\n")
PY

  case "${expected}" in
    pass)
      if [[ ${rc} -ne 0 ]]; then
        unexpected_external_failures=$((unexpected_external_failures + 1))
      fi
      ;;
    fail)
      if [[ ${rc} -eq 0 ]]; then
        unexpected_external_failures=$((unexpected_external_failures + 1))
      fi
      ;;
    *)
      echo "[sv2-matrix] warning: unknown expected='${expected}', treating as pass"
      if [[ ${rc} -ne 0 ]]; then
        unexpected_external_failures=$((unexpected_external_failures + 1))
      fi
      ;;
  esac
}

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
run_conformance_target "scam-local-plain" "${POOL_BIND}" "false" "legacy" "" "pass" "scam" "local"
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
run_conformance_target "scam-local-noise-xx" "${SECURE_POOL_BIND}" "true" "noise-xx" "${CLIENT_KEY_HEX}" "pass" "scam" "local"
wait "${secure_pid}" || true

if [[ -n "${SV2_EXTERNAL_TARGETS:-}" ]]; then
  # Format: "name,host:port,secure,mode,secret_hex;name2,host:port,secure,mode,secret_hex"
  IFS=';' read -ra targets <<<"${SV2_EXTERNAL_TARGETS}"
  for target in "${targets[@]}"; do
    [[ -z "${target}" ]] && continue
    IFS=',' read -r stack_name endpoint secure mode secret expected vendor version <<<"${target}"
    run_conformance_target \
      "${stack_name}" \
      "${endpoint}" \
      "${secure:-false}" \
      "${mode:-legacy}" \
      "${secret:-}" \
      "${expected:-pass}" \
      "${vendor:-}" \
      "${version:-}"
  done
fi

if [[ -n "${SV2_EXTERNAL_TARGETS_FILE}" ]]; then
  while IFS=$'\t' read -r stack_name endpoint secure mode secret expected vendor version; do
    [[ -z "${stack_name}" ]] && continue
    run_conformance_target \
      "${stack_name}" \
      "${endpoint}" \
      "${secure:-false}" \
      "${mode:-legacy}" \
      "${secret:-}" \
      "${expected:-pass}" \
      "${vendor:-}" \
      "${version:-}"
  done < <(python3 - <<'PY' "${SV2_EXTERNAL_TARGETS_FILE}"
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
targets = json.loads(path.read_text(encoding="utf-8"))
for target in targets:
    print(
        "\t".join(
            [
                str(target.get("name", "")),
                str(target.get("endpoint", "")),
                "true" if bool(target.get("secure", False)) else "false",
                str(target.get("mode", "legacy")),
                str(target.get("secret_hex", "")),
                str(target.get("expected", "pass")),
                str(target.get("vendor", "")),
                str(target.get("version", "")),
            ]
        )
    )
PY
)
fi

python3 scripts/sv2-conformance-report.py \
  --input-dir "${OUT_DIR}" \
  --summary-out "${OUT_DIR}/summary.json" \
  --matrix-out "${OUT_DIR}/matrix.md"

if [[ ${unexpected_external_failures} -ne 0 ]]; then
  echo "[sv2-matrix] unexpected external failures: ${unexpected_external_failures}"
  exit 1
fi

echo "[sv2-matrix] done: ${OUT_DIR}"
