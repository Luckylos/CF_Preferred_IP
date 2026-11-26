#!/usr/bin/env python3
"""Read-only replay of retained request observations at a historical cutoff."""
from __future__ import annotations

import argparse
import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path

import rank
from quality_evidence import assess, load_batches


@dataclass(frozen=True)
class Day:
    end: datetime
    top3: list[str]
    batches: int
    quality: dict[str, str]
    strength: list[str]


def replay(observations: Path, reference: str, days: int, cfg: rank.Config,
           now: datetime, pool: list[str] | None = None) -> list[Day]:
    out = []
    incumbents = []
    for i in range(days - 1, -1, -1):
        end = now - timedelta(days=i)
        batches = load_batches(observations, end, reference)
        day_pool = sorted({b.ip for b in batches}) if pool is None else pool
        result = rank.run_rank([], day_pool, incumbents, end, cfg,
                               evidence=batches, reference=reference)
        incumbents = result.published or incumbents
        quality = {ip: assess(batches, ip, reference, end).state for ip in day_pool}
        out.append(Day(end, incumbents, len(batches), quality, [r.ip for r in result.ranked]))
    return out


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="structured evidence replay (read-only)")
    p.add_argument("--observations", type=Path, required=True)
    p.add_argument("--reference", required=True, help="参考路径 SHA-256")
    p.add_argument("--now", required=True, help="历史截止时间 YYYY-MM-DD HH:MM:SS")
    p.add_argument("--days", type=int, default=1)
    p.add_argument("--contenders", type=Path)
    rank.add_config_args(p)
    args = p.parse_args(argv)
    now = rank.parse_ts(args.now)
    if now is None or not re.fullmatch(r"[a-f0-9]{64}", args.reference) or not 1 <= args.days <= 7:
        p.error("invalid cutoff, reference key, or replay day count")
    pool = [c.ip for c in rank.read_contenders(args.contenders)] if args.contenders else None
    for day in replay(args.observations, args.reference, args.days, rank.config_from_args(args), now, pool):
        print(f"{day.end:{rank.TS_FORMAT}} batches={day.batches} proposed={','.join(day.top3) or '-'}")
        print("strength=" + ",".join(day.strength))
        print("quality=" + ",".join(f"{ip}:{state}" for ip, state in sorted(day.quality.items())))
    print("historical_guard=unreconstructable actual_dns=unreconstructable actual_misub=unreconstructable")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
