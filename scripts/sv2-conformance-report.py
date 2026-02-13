#!/usr/bin/env python3
"""Aggregate SV2 conformance JSON reports into summary JSON + markdown matrix."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="SV2 conformance report aggregator")
    parser.add_argument("--input-dir", required=True, help="Directory with *.json reports")
    parser.add_argument("--summary-out", required=True, help="Output summary JSON path")
    parser.add_argument("--matrix-out", required=True, help="Output markdown matrix path")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    input_dir = Path(args.input_dir)
    reports = []
    for path in sorted(input_dir.glob("*.json")):
        try:
            reports.append(json.loads(path.read_text(encoding="utf-8")))
        except Exception as exc:  # noqa: BLE001
            print(f"[sv2-report] cannot parse {path}: {exc}")
            return 1

    if not reports:
        print(f"[sv2-report] no reports in {input_dir}")
        return 1

    total = len(reports)
    passed = sum(1 for report in reports if bool(report.get("pass")))
    summary = {
        "total": total,
        "passed": passed,
        "failed": total - passed,
        "pass_rate": passed / total,
        "reports": reports,
    }

    summary_out = Path(args.summary_out)
    summary_out.parent.mkdir(parents=True, exist_ok=True)
    summary_out.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")

    lines = [
        "# SV2 Conformance Matrix",
        "",
        f"total: {total}, passed: {passed}, failed: {total - passed}",
        "",
        "| stack | endpoint | secure | mode | pass | setup | channel | jobs | set_target |",
        "|---|---|---:|---|---:|---:|---:|---:|---:|",
    ]
    for report in reports:
        lines.append(
            "| {stack} | {endpoint} | {secure} | {mode} | {pass_} | {setup} | {channel} | {jobs} | {target} |".format(
                stack=report.get("stack_name", "unknown"),
                endpoint=report.get("endpoint", "unknown"),
                secure=str(bool(report.get("secure_transport"))).lower(),
                mode=report.get("secure_transport_mode", "unknown"),
                pass_=str(bool(report.get("pass"))).lower(),
                setup=str(bool(report.get("setup_success"))).lower(),
                channel=str(bool(report.get("channel_opened"))).lower(),
                jobs=int(report.get("job_messages_seen", 0)),
                target=str(bool(report.get("set_target_seen"))).lower(),
            )
        )

    matrix_out = Path(args.matrix_out)
    matrix_out.parent.mkdir(parents=True, exist_ok=True)
    matrix_out.write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(f"[sv2-report] summary: {summary_out}")
    print(f"[sv2-report] matrix: {matrix_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

