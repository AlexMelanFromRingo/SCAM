#!/usr/bin/env bash
set -euo pipefail

OUT_DIR="${OUT_DIR:-target/sv2-conformance}"
RUNTIME_DB="${RUNTIME_DB:-data/devnet.runtime.redb}"
CORPUS="${CORPUS:-docs/sv2-corpus/default.json}"
POOL_BIND="${POOL_BIND:-127.0.0.1:3347}"
SECURE_POOL_BIND="${SECURE_POOL_BIND:-127.0.0.1:3348}"
SV2_EXTERNAL_TARGETS_FILE="${SV2_EXTERNAL_TARGETS_FILE:-}"
EXTERNAL_RESULTS_JSONL="${OUT_DIR}/external-target-results.jsonl"
SV2_CONFORMANCE_CONNECT_TIMEOUT_SEC="${SV2_CONFORMANCE_CONNECT_TIMEOUT_SEC:-5}"
SV2_CONFORMANCE_CONNECT_RETRIES="${SV2_CONFORMANCE_CONNECT_RETRIES:-4}"
SV2_CONFORMANCE_CONNECT_RETRY_DELAY_MS="${SV2_CONFORMANCE_CONNECT_RETRY_DELAY_MS:-300}"
SV2_CONFORMANCE_READ_TIMEOUT_SEC="${SV2_CONFORMANCE_READ_TIMEOUT_SEC:-3}"
SV2_CONFORMANCE_MIN_JOB_MESSAGES="${SV2_CONFORMANCE_MIN_JOB_MESSAGES:-1}"
SV2_CONFORMANCE_EXPECT_SET_TARGET="${SV2_CONFORMANCE_EXPECT_SET_TARGET:-true}"
SV2_CONFORMANCE_REQUIRED_OBSERVED_KINDS="${SV2_CONFORMANCE_REQUIRED_OBSERVED_KINDS:-}"
SV2_CONFORMANCE_FORBIDDEN_OBSERVED_KINDS="${SV2_CONFORMANCE_FORBIDDEN_OBSERVED_KINDS:-}"
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
  local role="${9:-mining_proxy}"
  local corpus_override="${10:-}"
  local read_timeout_sec="${11:-${SV2_CONFORMANCE_READ_TIMEOUT_SEC}}"
  local connect_timeout_sec="${12:-${SV2_CONFORMANCE_CONNECT_TIMEOUT_SEC}}"
  local connect_retries="${13:-${SV2_CONFORMANCE_CONNECT_RETRIES}}"
  local connect_retry_delay_ms="${14:-${SV2_CONFORMANCE_CONNECT_RETRY_DELAY_MS}}"
  local expect_set_target="${15:-${SV2_CONFORMANCE_EXPECT_SET_TARGET}}"
  local min_job_messages="${16:-${SV2_CONFORMANCE_MIN_JOB_MESSAGES}}"
  local workaround="${17:-}"
  local notes="${18:-}"
  local required_observed_kinds="${19:-${SV2_CONFORMANCE_REQUIRED_OBSERVED_KINDS}}"
  local forbidden_observed_kinds="${20:-${SV2_CONFORMANCE_FORBIDDEN_OBSERVED_KINDS}}"

  if [[ -z "${stack_name}" || -z "${endpoint}" ]]; then
    echo "[sv2-matrix] invalid target entry: missing stack_name or endpoint"
    unexpected_external_failures=$((unexpected_external_failures + 1))
    return
  fi
  case "${secure}" in
    true|false) ;;
    *)
      echo "[sv2-matrix] warning: secure must be true|false for ${stack_name}; got '${secure}', forcing false"
      secure="false"
      ;;
  esac
  case "${mode}" in
    legacy|noise-xx|noise_xx) ;;
    *)
      echo "[sv2-matrix] warning: unsupported mode '${mode}' for ${stack_name}; forcing legacy"
      mode="legacy"
      ;;
  esac
  if [[ "${mode}" == "noise_xx" ]]; then
    mode="noise-xx"
  fi
  case "${expected}" in
    pass|fail) ;;
    *)
      echo "[sv2-matrix] warning: expected must be pass|fail for ${stack_name}; got '${expected}', forcing pass"
      expected="pass"
      ;;
  esac
  case "${expect_set_target}" in
    true|false) ;;
    *)
      echo "[sv2-matrix] warning: expect_set_target must be true|false for ${stack_name}; got '${expect_set_target}', forcing true"
      expect_set_target="true"
      ;;
  esac
  if [[ -z "${read_timeout_sec}" ]]; then
    read_timeout_sec="${SV2_CONFORMANCE_READ_TIMEOUT_SEC}"
  fi
  if [[ -z "${connect_timeout_sec}" ]]; then
    connect_timeout_sec="${SV2_CONFORMANCE_CONNECT_TIMEOUT_SEC}"
  fi
  if [[ -z "${connect_retries}" ]]; then
    connect_retries="${SV2_CONFORMANCE_CONNECT_RETRIES}"
  fi
  if [[ -z "${connect_retry_delay_ms}" ]]; then
    connect_retry_delay_ms="${SV2_CONFORMANCE_CONNECT_RETRY_DELAY_MS}"
  fi
  if [[ -z "${min_job_messages}" ]]; then
    min_job_messages="${SV2_CONFORMANCE_MIN_JOB_MESSAGES}"
  fi
  local effective_corpus="${corpus_override:-${CORPUS}}"
  if [[ -z "${effective_corpus}" ]]; then
    effective_corpus="docs/sv2-corpus/default.json"
  fi

  local args=(
    --pool "${endpoint}"
    --stack-name "${stack_name}"
    --user "matrix-${stack_name}"
    --read-timeout-sec "${read_timeout_sec}"
    --connect-timeout-sec "${connect_timeout_sec}"
    --connect-retries "${connect_retries}"
    --connect-retry-delay-ms "${connect_retry_delay_ms}"
    --min-job-messages "${min_job_messages}"
    --corpus "${effective_corpus}"
    --out "${OUT_DIR}/${stack_name}.json"
  )
  if [[ "${expect_set_target}" == "true" ]]; then
    args+=(--expect-set-target)
  fi
  if [[ -n "${required_observed_kinds}" ]]; then
    IFS=';' read -ra required_kinds <<<"${required_observed_kinds}"
    for kind in "${required_kinds[@]}"; do
      [[ -z "${kind}" ]] && continue
      args+=(--require-observed-kind "${kind}")
    done
  fi
  if [[ -n "${forbidden_observed_kinds}" ]]; then
    IFS=';' read -ra forbidden_kinds <<<"${forbidden_observed_kinds}"
    for kind in "${forbidden_kinds[@]}"; do
      [[ -z "${kind}" ]] && continue
      args+=(--forbid-observed-kind "${kind}")
    done
  fi
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

  python3 - <<'PY' "${EXTERNAL_RESULTS_JSONL}" "${stack_name}" "${endpoint}" "${secure}" "${mode}" "${expected}" "${vendor}" "${version}" "${role}" "${read_timeout_sec}" "${connect_timeout_sec}" "${connect_retries}" "${connect_retry_delay_ms}" "${expect_set_target}" "${min_job_messages}" "${workaround}" "${notes}" "${required_observed_kinds}" "${forbidden_observed_kinds}" "${result}" "${rc}"
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
    "role": sys.argv[9] or None,
    "read_timeout_sec": int(sys.argv[10]),
    "connect_timeout_sec": int(sys.argv[11]),
    "connect_retries": int(sys.argv[12]),
    "connect_retry_delay_ms": int(sys.argv[13]),
    "expect_set_target": sys.argv[14] == "true",
    "min_job_messages": int(sys.argv[15]),
    "workaround": sys.argv[16] or None,
    "notes": sys.argv[17] or None,
    "required_observed_kinds": [k for k in sys.argv[18].split(";") if k],
    "forbidden_observed_kinds": [k for k in sys.argv[19].split(";") if k],
    "result": sys.argv[20],
    "exit_code": int(sys.argv[21]),
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
  # Legacy format: "name,host:port,secure,mode,secret_hex,expected,vendor,version"
  # Extended format:
  # "name,endpoint,secure,mode,secret,expected,vendor,version,role,corpus,read_timeout_sec,\
  #  connect_timeout_sec,connect_retries,connect_retry_delay_ms,expect_set_target,\
  #  min_job_messages,workaround,notes"
  IFS=';' read -ra targets <<<"${SV2_EXTERNAL_TARGETS}"
  for target in "${targets[@]}"; do
    [[ -z "${target}" ]] && continue
    IFS=',' read -r \
      stack_name \
      endpoint \
      secure \
      mode \
      secret \
      expected \
      vendor \
      version \
      role \
      corpus_override \
      read_timeout_sec \
      connect_timeout_sec \
      connect_retries \
      connect_retry_delay_ms \
      expect_set_target \
      min_job_messages \
      workaround \
      notes \
      required_observed_kinds \
      forbidden_observed_kinds <<<"${target}"
    run_conformance_target \
      "${stack_name}" \
      "${endpoint}" \
      "${secure:-false}" \
      "${mode:-legacy}" \
      "${secret:-}" \
      "${expected:-pass}" \
      "${vendor:-}" \
      "${version:-}" \
      "${role:-mining_proxy}" \
      "${corpus_override:-}" \
      "${read_timeout_sec:-${SV2_CONFORMANCE_READ_TIMEOUT_SEC}}" \
      "${connect_timeout_sec:-${SV2_CONFORMANCE_CONNECT_TIMEOUT_SEC}}" \
      "${connect_retries:-${SV2_CONFORMANCE_CONNECT_RETRIES}}" \
      "${connect_retry_delay_ms:-${SV2_CONFORMANCE_CONNECT_RETRY_DELAY_MS}}" \
      "${expect_set_target:-${SV2_CONFORMANCE_EXPECT_SET_TARGET}}" \
      "${min_job_messages:-${SV2_CONFORMANCE_MIN_JOB_MESSAGES}}" \
      "${workaround:-}" \
      "${notes:-}" \
      "${required_observed_kinds:-}" \
      "${forbidden_observed_kinds:-}"
  done
fi

if [[ -n "${SV2_EXTERNAL_TARGETS_FILE}" ]]; then
  while IFS=$'\t' read -r \
    stack_name \
    endpoint \
    secure \
    mode \
    secret \
    expected \
    vendor \
    version \
    role \
    corpus_override \
    read_timeout_sec \
    connect_timeout_sec \
    connect_retries \
    connect_retry_delay_ms \
    expect_set_target \
    min_job_messages \
    workaround \
    notes \
    required_observed_kinds \
    forbidden_observed_kinds; do
    [[ -z "${stack_name}" ]] && continue
    run_conformance_target \
      "${stack_name}" \
      "${endpoint}" \
      "${secure:-false}" \
      "${mode:-legacy}" \
      "${secret:-}" \
      "${expected:-pass}" \
      "${vendor:-}" \
      "${version:-}" \
      "${role:-mining_proxy}" \
      "${corpus_override:-}" \
      "${read_timeout_sec:-${SV2_CONFORMANCE_READ_TIMEOUT_SEC}}" \
      "${connect_timeout_sec:-${SV2_CONFORMANCE_CONNECT_TIMEOUT_SEC}}" \
      "${connect_retries:-${SV2_CONFORMANCE_CONNECT_RETRIES}}" \
      "${connect_retry_delay_ms:-${SV2_CONFORMANCE_CONNECT_RETRY_DELAY_MS}}" \
      "${expect_set_target:-${SV2_CONFORMANCE_EXPECT_SET_TARGET}}" \
      "${min_job_messages:-${SV2_CONFORMANCE_MIN_JOB_MESSAGES}}" \
      "${workaround:-}" \
      "${notes:-}" \
      "${required_observed_kinds:-}" \
      "${forbidden_observed_kinds:-}"
  done < <(python3 - <<'PY' "${SV2_EXTERNAL_TARGETS_FILE}"
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
targets = json.loads(path.read_text(encoding="utf-8"))

def join_kinds(value):
    if isinstance(value, list):
        return ";".join(str(item) for item in value if str(item))
    if isinstance(value, str):
        return value
    return ""

for target in targets:
    if target.get("enabled", True) is False:
        continue
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
                str(target.get("role", "mining_proxy")),
                str(target.get("corpus", "")),
                str(target.get("read_timeout_sec", "")),
                str(target.get("connect_timeout_sec", "")),
                str(target.get("connect_retries", "")),
                str(target.get("connect_retry_delay_ms", "")),
                "true" if bool(target.get("expect_set_target", True)) else "false",
                str(target.get("min_job_messages", "")),
                str(target.get("workaround", "")),
                str(target.get("notes", "")),
                join_kinds(target.get("required_observed_kinds", [])),
                join_kinds(target.get("forbidden_observed_kinds", [])),
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
