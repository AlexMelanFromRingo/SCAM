#!/usr/bin/env python3
"""Build a compact role-service telemetry dashboard from JSONL snapshots."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="SCAM role telemetry dashboard")
    parser.add_argument(
        "--input",
        action="append",
        required=True,
        help="Role telemetry JSONL file (can be provided multiple times)",
    )
    parser.add_argument(
        "--out",
        required=True,
        help="Output markdown dashboard path",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    rows: dict[str, dict[str, int]] = {}
    max_ts = 0

    for input_path in args.input:
        path = Path(input_path)
        if not path.exists():
            print(f"[role-dashboard] missing input: {path}")
            return 1
        with path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                snap = json.loads(line)
                role = str(snap.get("role", "unknown"))
                row = rows.setdefault(
                    role,
                    {"requests_total": 0, "success_total": 0, "error_total": 0},
                )
                row["requests_total"] = max(
                    row["requests_total"], int(snap.get("requests_total", 0))
                )
                row["success_total"] = max(
                    row["success_total"], int(snap.get("success_total", 0))
                )
                row["error_total"] = max(row["error_total"], int(snap.get("error_total", 0)))
                max_ts = max(max_ts, int(snap.get("timestamp_unix_sec", 0)))

    if not rows:
        print("[role-dashboard] no telemetry rows found")
        return 1

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "# SV2 Role Telemetry Dashboard",
        "",
        f"snapshot_unix_sec: {max_ts}",
        "",
        "| role | requests_total | success_total | error_total | error_rate |",
        "|---|---:|---:|---:|---:|",
    ]
    for role in sorted(rows):
        row = rows[role]
        requests = row["requests_total"]
        errors = row["error_total"]
        error_rate = (errors / requests) if requests else 0.0
        lines.append(
            f"| {role} | {requests} | {row['success_total']} | {errors} | {error_rate:.4f} |"
        )

    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"[role-dashboard] wrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

