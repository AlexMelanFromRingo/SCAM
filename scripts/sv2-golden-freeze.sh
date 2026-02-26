#!/usr/bin/env bash
set -euo pipefail

WORK_DIR="${WORK_DIR:-target/sv2-golden-freeze}"
EXPECT_OUT="${EXPECT_OUT:-docs/sv2-corpus/golden/expectations.json}"

echo "[sv2-golden-freeze] running matrix into ${WORK_DIR}"
OUT_DIR="${WORK_DIR}" scripts/sv2-conformance-matrix.sh

python3 - <<'PY' "${WORK_DIR}" "${EXPECT_OUT}"
import json
import pathlib
import time
import sys

work_dir = pathlib.Path(sys.argv[1])
expect_out = pathlib.Path(sys.argv[2])

targets = []
for path in sorted(work_dir.glob("*.json")):
    if path.name in {"summary.json", "release-gate.json", "external-targets.json"}:
        continue
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        continue
    stack_name = str(data.get("stack_name", ""))
    if not stack_name.startswith("scam-local-"):
        continue
    required_kinds = ["SetupConnectionSuccess", "OpenStandardMiningChannelSuccess"]
    if bool(data.get("expect_set_target")):
        required_kinds.append("SetTarget")
    target = {
        "stack_name": stack_name,
        "require_pass": True,
        "require_setup_success": True,
        "require_channel_opened": True,
        "require_set_target_seen": bool(data.get("expect_set_target", False)),
        "min_job_messages_seen": max(0, int(data.get("min_job_messages_required", 0))),
        "require_setup_version": data.get("setup_used_version"),
        "required_observed_kinds": required_kinds,
        "forbidden_observed_kinds": [
            "SetupConnectionError",
            "OpenStandardMiningChannelError",
            "SubmitSharesError",
        ],
    }
    targets.append(target)

if not targets:
    raise SystemExit("[sv2-golden-freeze] no scam-local-* reports found to freeze")

payload = {
    "generated_at_unix_sec": int(time.time()),
    "source": str(work_dir),
    "targets": targets,
}
expect_out.parent.mkdir(parents=True, exist_ok=True)
expect_out.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
print(f"[sv2-golden-freeze] expectations: {expect_out}")
PY

echo "[sv2-golden-freeze] done"
