#!/usr/bin/env python3
"""质量与容量冷却共用的有效期和原子写入契约。"""
from __future__ import annotations

import argparse
import math
from datetime import datetime, timedelta
from pathlib import Path

from atomic_io import atomic_write
from ip_validation import is_valid_ipv4

TS_FORMAT = "%Y-%m-%d %H:%M:%S"


def entries(path: Path, now: datetime, hours: float) -> dict[str, datetime]:
    if not math.isfinite(hours) or hours <= 0:
        raise ValueError("cooldown hours must be finite and positive")
    if not path.exists():
        return {}
    out: dict[str, datetime] = {}
    cutoff = now - timedelta(hours=hours)
    for line in path.read_text(encoding="utf-8").splitlines():
        parts = line.split("\t")
        if len(parts) < 2 or not is_valid_ipv4(parts[0]):
            continue
        try:
            ts = datetime.strptime(parts[1], TS_FORMAT)
        except ValueError:
            continue
        if cutoff <= ts <= now:
            out[parts[0]] = max(ts, out.get(parts[0], ts))
    return out


def active(path: Path, now: datetime, hours: float) -> set[str]:
    return set(entries(path, now, hours))


def record(path: Path, ips: list[str], now: datetime, hours: float) -> None:
    rows = entries(path, now, hours)
    for ip in ips:
        if not is_valid_ipv4(ip):
            raise ValueError("invalid cooldown IP")
        rows[ip] = now
    if rows or path.exists():
        atomic_write(path, "".join(f"{ip}\t{ts.strftime(TS_FORMAT)}\n"
                                  for ip, ts in sorted(rows.items())))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--quality', type=Path, required=True)
    parser.add_argument('--capacity', type=Path, required=True)
    parser.add_argument('--quality-hours', type=float, default=24)
    parser.add_argument('--capacity-hours', type=float, default=6)
    parser.add_argument('--now', required=True)
    parser.add_argument('--prune', action='store_true')
    args = parser.parse_args()
    if args.quality_hours <= 0 or args.capacity_hours <= 0:
        parser.error('cooldown hours must be positive')
    now = datetime.strptime(args.now, TS_FORMAT)
    if args.prune:
        record(args.quality, [], now, args.quality_hours)
        record(args.capacity, [], now, args.capacity_hours)
    for ip in sorted(active(args.quality, now, args.quality_hours)
                     | active(args.capacity, now, args.capacity_hours)):
        print(ip)


if __name__ == '__main__':
    main()
