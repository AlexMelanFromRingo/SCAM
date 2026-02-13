#!/usr/bin/env python3
"""Check SCAM soak telemetry JSONL against simple alert thresholds.

Exit code 0: all thresholds satisfied.
Exit code 1: one or more thresholds exceeded.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="SCAM soak telemetry alert checker")
    parser.add_argument("--input", required=True, help="Path to soak telemetry JSONL")
    parser.add_argument(
        "--max-rate-limited",
        type=int,
        default=0,
        help="Maximum allowed gossip_replacement_rate_limited_total",
    )
    parser.add_argument(
        "--max-orphan-pool-len",
        type=int,
        default=500,
        help="Maximum allowed orphan_pool_len in any snapshot",
    )
    parser.add_argument(
        "--max-mempool-len",
        type=int,
        default=50_000,
        help="Maximum allowed mempool_len in any snapshot",
    )
    parser.add_argument(
        "--max-conflict-rejections",
        type=int,
        default=10_000,
        help="Maximum allowed mempool_rejected_conflict_total",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    path = Path(args.input)
    if not path.exists():
        print(f"[alert] telemetry file not found: {path}")
        return 1

    max_rate_limited = 0
    max_orphan_len = 0
    max_mempool_len = 0
    max_conflict_rejections = 0
    rows = 0

    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            rows += 1
            snap = json.loads(line)
            max_rate_limited = max(
                max_rate_limited, int(snap.get("gossip_replacement_rate_limited_total", 0))
            )
            max_orphan_len = max(max_orphan_len, int(snap.get("orphan_pool_len", 0)))
            max_mempool_len = max(max_mempool_len, int(snap.get("mempool_len", 0)))
            max_conflict_rejections = max(
                max_conflict_rejections,
                int(snap.get("mempool_rejected_conflict_total", 0)),
            )

    if rows == 0:
        print(f"[alert] telemetry file has no snapshots: {path}")
        return 1

    failures: list[str] = []
    if max_rate_limited > args.max_rate_limited:
        failures.append(
            f"gossip_replacement_rate_limited_total={max_rate_limited} exceeds {args.max_rate_limited}"
        )
    if max_orphan_len > args.max_orphan_pool_len:
        failures.append(f"orphan_pool_len={max_orphan_len} exceeds {args.max_orphan_pool_len}")
    if max_mempool_len > args.max_mempool_len:
        failures.append(f"mempool_len={max_mempool_len} exceeds {args.max_mempool_len}")
    if max_conflict_rejections > args.max_conflict_rejections:
        failures.append(
            "mempool_rejected_conflict_total="
            f"{max_conflict_rejections} exceeds {args.max_conflict_rejections}"
        )

    print(f"[alert] snapshots={rows}")
    print(f"[alert] max gossip_replacement_rate_limited_total={max_rate_limited}")
    print(f"[alert] max orphan_pool_len={max_orphan_len}")
    print(f"[alert] max mempool_len={max_mempool_len}")
    print(f"[alert] max mempool_rejected_conflict_total={max_conflict_rejections}")

    if failures:
        print("[alert] FAIL")
        for failure in failures:
            print(f"[alert] {failure}")
        return 1

    print("[alert] PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
