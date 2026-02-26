#!/usr/bin/env bash
set -euo pipefail

OUT_DIR="${OUT_DIR:-target/sv2-release-gate}"
MATRIX_OUT_DIR="${OUT_DIR}/matrix"
REQUIRE_EXTERNAL="${REQUIRE_EXTERNAL:-false}"
MIN_LOCAL_TARGETS="${MIN_LOCAL_TARGETS:-2}"
MIN_SECURE_LOCAL_TARGETS="${MIN_SECURE_LOCAL_TARGETS:-1}"

mkdir -p "${OUT_DIR}"

echo "[sv2-release-gate] running matrix into ${MATRIX_OUT_DIR}"
OUT_DIR="${MATRIX_OUT_DIR}" scripts/sv2-conformance-matrix.sh

python3 - <<'PY' "${MATRIX_OUT_DIR}/summary.json" "${OUT_DIR}/release-gate.json" "${REQUIRE_EXTERNAL}" "${MIN_LOCAL_TARGETS}" "${MIN_SECURE_LOCAL_TARGETS}"
import json
import pathlib
import sys
import time

summary_path = pathlib.Path(sys.argv[1])
out_path = pathlib.Path(sys.argv[2])
require_external = sys.argv[3].lower() == "true"
min_local_targets = int(sys.argv[4])
min_secure_local_targets = int(sys.argv[5])

if not summary_path.exists():
    raise SystemExit(f"[sv2-release-gate] missing summary file: {summary_path}")

summary = json.loads(summary_path.read_text(encoding="utf-8"))
reports = summary.get("reports", [])
external = summary.get("external", {})

local_total = int(summary.get("total", 0))
local_passed = int(summary.get("passed", 0))
local_all_pass = local_total > 0 and local_total == local_passed
local_target_floor_ok = local_total >= min_local_targets
secure_local_passed = sum(
    1
    for report in reports
    if bool(report.get("secure_transport")) and bool(report.get("pass"))
)
secure_local_floor_ok = secure_local_passed >= min_secure_local_targets

external_total = int(external.get("total", 0))
external_unexpected = int(external.get("unexpected", 0))
external_parse_errors = int(external.get("parse_errors", 0))
external_expectation_ok = external_unexpected == 0 and external_parse_errors == 0
external_required_ok = (not require_external) or external_total > 0

gate_pass = all(
    [
        local_all_pass,
        local_target_floor_ok,
        secure_local_floor_ok,
        external_expectation_ok,
        external_required_ok,
    ]
)

result = {
    "timestamp_unix_sec": int(time.time()),
    "pass": gate_pass,
    "checks": {
        "local_all_pass": local_all_pass,
        "local_target_floor_ok": local_target_floor_ok,
        "secure_local_floor_ok": secure_local_floor_ok,
        "external_expectation_ok": external_expectation_ok,
        "external_required_ok": external_required_ok,
    },
    "local": {
        "total": local_total,
        "passed": local_passed,
        "min_targets_required": min_local_targets,
        "secure_passed": secure_local_passed,
        "min_secure_required": min_secure_local_targets,
    },
    "external": {
        "required": require_external,
        "total": external_total,
        "unexpected": external_unexpected,
        "parse_errors": external_parse_errors,
    },
    "summary_path": str(summary_path),
}

out_path.parent.mkdir(parents=True, exist_ok=True)
out_path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
print(f"[sv2-release-gate] report: {out_path}")
if not gate_pass:
    print("[sv2-release-gate] gate failed")
    raise SystemExit(1)
print("[sv2-release-gate] gate passed")
PY
