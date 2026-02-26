#!/usr/bin/env python3
"""Verify SV2 conformance reports against golden expectations."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="SV2 golden conformance verifier")
    parser.add_argument("--input-dir", required=True, help="Directory with conformance *.json reports")
    parser.add_argument("--golden", required=True, help="Golden expectation JSON path")
    parser.add_argument("--out", default=None, help="Optional output report JSON path")
    return parser.parse_args()


def load_reports(input_dir: Path) -> dict[str, dict[str, Any]]:
    reports: dict[str, dict[str, Any]] = {}
    for path in sorted(input_dir.glob("*.json")):
        if path.name in {"summary.json", "release-gate.json", "external-targets.json"}:
            continue
        try:
            report = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            continue
        if not isinstance(report, dict):
            continue
        stack_name = report.get("stack_name")
        if isinstance(stack_name, str) and stack_name:
            reports[stack_name] = report
    return reports


def verify_target(expectation: dict[str, Any], report: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    checks = [
        ("require_pass", "pass"),
        ("require_setup_success", "setup_success"),
        ("require_channel_opened", "channel_opened"),
        ("require_set_target_seen", "set_target_seen"),
    ]
    for expected_key, report_key in checks:
        if expected_key in expectation:
            expected_value = bool(expectation[expected_key])
            observed = bool(report.get(report_key))
            if observed != expected_value:
                errors.append(f"{report_key}: expected {expected_value}, observed {observed}")

    min_jobs = int(expectation.get("min_job_messages_seen", 0))
    observed_jobs = int(report.get("job_messages_seen", 0))
    if observed_jobs < min_jobs:
        errors.append(
            f"job_messages_seen: expected >= {min_jobs}, observed {observed_jobs}"
        )

    if "require_setup_version" in expectation and expectation["require_setup_version"] is not None:
        expected_version = int(expectation["require_setup_version"])
        observed_version = report.get("setup_used_version")
        if observed_version != expected_version:
            errors.append(
                f"setup_used_version: expected {expected_version}, observed {observed_version}"
            )

    required = [str(kind) for kind in expectation.get("required_observed_kinds", [])]
    forbidden = [str(kind) for kind in expectation.get("forbidden_observed_kinds", [])]
    observed_kinds = {str(kind) for kind in report.get("observed_messages", [])}
    for kind in required:
        if kind not in observed_kinds:
            errors.append(f"required observed message missing: {kind}")
    for kind in forbidden:
        if kind in observed_kinds:
            errors.append(f"forbidden observed message present: {kind}")
    return errors


def main() -> int:
    args = parse_args()
    input_dir = Path(args.input_dir)
    golden_path = Path(args.golden)
    reports = load_reports(input_dir)
    golden = json.loads(golden_path.read_text(encoding="utf-8"))
    targets = golden.get("targets", [])
    failures: list[dict[str, Any]] = []

    for target in targets:
        stack_name = str(target.get("stack_name", "")).strip()
        if not stack_name:
            failures.append({"stack_name": "", "errors": ["missing stack_name in golden target"]})
            continue
        report = reports.get(stack_name)
        if report is None:
            failures.append({"stack_name": stack_name, "errors": ["missing report"]})
            continue
        errors = verify_target(target, report)
        if errors:
            failures.append({"stack_name": stack_name, "errors": errors})

    result = {
        "pass": len(failures) == 0,
        "targets_checked": len(targets),
        "failures": failures,
        "input_dir": str(input_dir),
        "golden": str(golden_path),
    }

    if args.out:
        out_path = Path(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        print(f"[sv2-golden] report: {out_path}")

    if failures:
        print("[sv2-golden] verification failed")
        for failure in failures:
            print(f"  - {failure['stack_name']}: " + "; ".join(failure["errors"]))
        return 1
    print("[sv2-golden] verification passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
