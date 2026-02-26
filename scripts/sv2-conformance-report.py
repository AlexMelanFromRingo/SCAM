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
    parser.add_argument(
        "--external-jsonl",
        default=None,
        help="Optional JSONL file with external target results "
        "(default: <input-dir>/external-target-results.jsonl if present)",
    )
    return parser.parse_args()


def markdown_cell(value: object) -> str:
    text = "" if value is None else str(value)
    return text.replace("|", "\\|").replace("\n", "<br>")


def expected_matches_result(record: dict[str, object]) -> bool:
    expected = str(record.get("expected", "pass"))
    result = str(record.get("result", "fail"))
    if expected == "pass":
        return result == "pass"
    if expected == "fail":
        return result == "fail"
    return False


def load_external_records(path: Path) -> tuple[list[dict[str, object]], int]:
    records: list[dict[str, object]] = []
    parse_errors = 0
    if not path.exists():
        return records, parse_errors
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            parsed = json.loads(line)
        except json.JSONDecodeError:
            parse_errors += 1
            continue
        if isinstance(parsed, dict):
            records.append(parsed)
        else:
            parse_errors += 1
    return records, parse_errors


def main() -> int:
    args = parse_args()
    input_dir = Path(args.input_dir)
    reports = []
    skipped = []
    for path in sorted(input_dir.glob("*.json")):
        if path.name in {"summary.json", "release-gate.json", "external-targets.json"}:
            continue
        try:
            report = json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:  # noqa: BLE001
            print(f"[sv2-report] cannot parse {path}: {exc}")
            return 1
        if not isinstance(report, dict) or "stack_name" not in report or "pass" not in report:
            skipped.append(path.name)
            continue
        reports.append(report)

    if not reports:
        print(f"[sv2-report] no reports in {input_dir}")
        return 1

    total = len(reports)
    passed = sum(1 for report in reports if bool(report.get("pass")))
    external_jsonl = (
        Path(args.external_jsonl)
        if args.external_jsonl
        else input_dir / "external-target-results.jsonl"
    )
    external_records, external_parse_errors = load_external_records(external_jsonl)
    external_unexpected = sum(
        1 for record in external_records if not expected_matches_result(record)
    )
    external_with_workarounds = sum(
        1 for record in external_records if record.get("workaround")
    )
    summary = {
        "total": total,
        "passed": passed,
        "failed": total - passed,
        "pass_rate": passed / total,
        "external": {
            "jsonl": str(external_jsonl),
            "total": len(external_records),
            "unexpected": external_unexpected,
            "parse_errors": external_parse_errors,
            "with_workarounds": external_with_workarounds,
            "records": external_records,
        },
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
        "## Built-in / Local Targets",
        "",
        "| stack | endpoint | secure | mode | pass | setup | setup_proto | setup_req_range | setup_req_flags | setup_version | setup_flags | req_version | req_flags | forbid_flags | channel | jobs | min_jobs | set_target | expect_set_target |",
        "|---|---|---:|---|---:|---:|---:|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for report in reports:
        lines.append(
            "| {stack} | {endpoint} | {secure} | {mode} | {pass_} | {setup} | {setup_proto} | {setup_req_range} | {setup_req_flags} | {setup_version} | {setup_flags} | {req_version} | {req_flags} | {forbid_flags} | {channel} | {jobs} | {min_jobs} | {target} | {expect_target} |".format(
                stack=markdown_cell(report.get("stack_name", "unknown")),
                endpoint=markdown_cell(report.get("endpoint", "unknown")),
                secure=str(bool(report.get("secure_transport"))).lower(),
                mode=markdown_cell(report.get("secure_transport_mode", "unknown")),
                pass_=str(bool(report.get("pass"))).lower(),
                setup=str(bool(report.get("setup_success"))).lower(),
                setup_proto=markdown_cell(report.get("setup_protocol", "")),
                setup_req_range=markdown_cell(
                    f"[{report.get('setup_min_version', '')},{report.get('setup_max_version', '')}]"
                ),
                setup_req_flags=markdown_cell(
                    f"0x{int(report.get('setup_flags_requested', 0)):08x}"
                ),
                setup_version=markdown_cell(report.get("setup_used_version", "")),
                setup_flags=markdown_cell(
                    f"0x{int(report.get('setup_flags', 0)):08x}"
                    if report.get("setup_flags") is not None
                    else ""
                ),
                req_version=markdown_cell(report.get("require_setup_version", "")),
                req_flags=markdown_cell(
                    f"0x{int(report.get('require_setup_flags_mask', 0)):08x}"
                ),
                forbid_flags=markdown_cell(
                    f"0x{int(report.get('forbid_setup_flags_mask', 0)):08x}"
                ),
                channel=str(bool(report.get("channel_opened"))).lower(),
                jobs=int(report.get("job_messages_seen", 0)),
                min_jobs=int(report.get("min_job_messages_required", 0)),
                target=str(bool(report.get("set_target_seen"))).lower(),
                expect_target=str(bool(report.get("expect_set_target"))).lower(),
            )
        )
    if external_records:
        lines.extend(
            [
                "",
                "## External Interop Targets",
                "",
                f"rows: {len(external_records)}, unexpected: {external_unexpected}, "
                f"parse_errors: {external_parse_errors}",
                "",
                "| stack | vendor | version | role | endpoint | secure | mode | expected | result | rc | jobs>= | set_target? | workaround | notes |",
                "|---|---|---|---|---|---:|---|---|---|---:|---:|---:|---|---|",
            ]
        )
        for record in external_records:
            lines.append(
                "| {stack} | {vendor} | {version} | {role} | {endpoint} | {secure} | {mode} | {expected} | {result} | {rc} | {min_jobs} | {expect_set_target} | {workaround} | {notes} |".format(
                    stack=markdown_cell(record.get("stack_name", "")),
                    vendor=markdown_cell(record.get("vendor", "")),
                    version=markdown_cell(record.get("version", "")),
                    role=markdown_cell(record.get("role", "")),
                    endpoint=markdown_cell(record.get("endpoint", "")),
                    secure=str(bool(record.get("secure"))).lower(),
                    mode=markdown_cell(record.get("mode", "")),
                    expected=markdown_cell(record.get("expected", "")),
                    result=markdown_cell(record.get("result", "")),
                    rc=markdown_cell(record.get("exit_code", "")),
                    min_jobs=markdown_cell(record.get("min_job_messages", "")),
                    expect_set_target=str(bool(record.get("expect_set_target"))).lower(),
                    workaround=markdown_cell(record.get("workaround", "")),
                    notes=markdown_cell(record.get("notes", "")),
                )
            )
            required = record.get("required_observed_kinds") or []
            required_sequence = record.get("required_observed_sequence") or []
            forbidden = record.get("forbidden_observed_kinds") or []
            req_setup_version = record.get("require_setup_version")
            req_setup_flags_mask = int(record.get("require_setup_flags_mask", 0))
            forbid_setup_flags_mask = int(record.get("forbid_setup_flags_mask", 0))
            if (
                required
                or required_sequence
                or forbidden
                or req_setup_version is not None
                or req_setup_flags_mask != 0
                or forbid_setup_flags_mask != 0
                or int(record.get("setup_protocol", 0)) != 0
            ):
                lines.append(
                    "|  |  |  |  |  |  |  |  |  |  |  |  | require={required} require_seq={required_sequence} forbid={forbidden}; req_setup_version={req_setup_version}; req_setup_flags=0x{req_setup_flags_mask:08x}; forbid_setup_flags=0x{forbid_setup_flags_mask:08x}; setup={{protocol={setup_protocol},min={setup_min},max={setup_max},flags=0x{setup_flags:08x}}} |  |".format(
                        required=markdown_cell(",".join(required)),
                        required_sequence=markdown_cell(",".join(required_sequence)),
                        forbidden=markdown_cell(",".join(forbidden)),
                        req_setup_version=markdown_cell(req_setup_version),
                        req_setup_flags_mask=req_setup_flags_mask,
                        forbid_setup_flags_mask=forbid_setup_flags_mask,
                        setup_protocol=int(record.get("setup_protocol", 0)),
                        setup_min=int(record.get("setup_min_version", 0)),
                        setup_max=int(record.get("setup_max_version", 0)),
                        setup_flags=int(record.get("setup_flags", 0)),
                    )
                )
        lines.extend(["", "## Vendor Quirks / Workarounds", ""])
        workaround_rows = [
            record for record in external_records if record.get("workaround")
        ]
        if workaround_rows:
            lines.append("| stack | workaround | notes |")
            lines.append("|---|---|---|")
            for record in workaround_rows:
                lines.append(
                    "| {stack} | {workaround} | {notes} |".format(
                        stack=markdown_cell(record.get("stack_name", "")),
                        workaround=markdown_cell(record.get("workaround", "")),
                        notes=markdown_cell(record.get("notes", "")),
                    )
                )
        else:
            lines.append("_No workaround rows recorded in this run._")

    matrix_out = Path(args.matrix_out)
    matrix_out.parent.mkdir(parents=True, exist_ok=True)
    matrix_out.write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(f"[sv2-report] summary: {summary_out}")
    print(f"[sv2-report] matrix: {matrix_out}")
    if skipped:
        print(f"[sv2-report] skipped non-report json files: {', '.join(sorted(skipped))}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
