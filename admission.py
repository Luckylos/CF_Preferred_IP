#!/usr/bin/env python3
"""请求集合约束下的限额准入；未获接纳的通过者保持等待，不记失败。"""
from __future__ import annotations

import argparse
import math
from datetime import datetime
from pathlib import Path

from atomic_io import atomic_write
from cooldown import record
from ip_validation import is_valid_ipv4
from rank import Contender, TS_FORMAT, read_contenders, write_contenders


def _ips(path: Path) -> list[str]:
    return list(dict.fromkeys(line.strip() for line in path.read_text().splitlines()
                              if is_valid_ipv4(line.strip())))


def process_screen(contenders: Path, requested: Path, passed: Path, queue: Path,
                   blacklist: Path, now: datetime, pool_max: int, max_fail: int,
                   quality_hours: float = 24) -> list[str]:
    if not math.isfinite(quality_hours) or quality_hours <= 0:
        raise ValueError("quality cooldown hours must be finite and positive")
    if pool_max <= 0 or max_fail <= 0:
        raise ValueError('pool_max and max_fail must be positive')
    pool = read_contenders(contenders)
    known = {c.ip for c in pool}
    observed = set(_ips(requested))
    successful = set(_ips(passed)) & observed
    slots = max(0, pool_max - len(pool))
    admitted = [ip for ip in _ips(requested) if ip in successful and ip not in known][:slots]
    stamp = now.strftime(TS_FORMAT)
    pool.extend(Contender(ip, stamp, stamp, 'screen') for ip in admitted)
    accepted = known | set(admitted)
    kept: list[str] = []
    failed: list[str] = []
    for line in queue.read_text().splitlines():
        parts = line.split('\t')
        if len(parts) < 2 or not is_valid_ipv4(parts[1]):
            continue
        ip = parts[1]
        if ip in accepted:
            continue
        if ip in observed and ip not in successful:
            count = int(parts[2]) if len(parts) >= 3 and parts[2].isdigit() else 0
            count += 1
            if count >= max_fail:
                failed.append(ip)
                continue
            latency = parts[3] if len(parts) >= 4 else ''
            line = f'{parts[0]}\t{ip}\t{count}\t{latency}'
        kept.append(line)
    # 先持久化池/冷却，再出队；中断重试时集合去重，不会丢失已接纳者。
    write_contenders(contenders, pool)
    record(blacklist, failed, now, quality_hours)
    atomic_write(queue, ''.join(line+'\n' for line in kept))
    atomic_write(passed, ''.join(ip+'\n' for ip in admitted))
    return admitted


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ['contenders', 'requested', 'passed', 'queue', 'blacklist']:
        parser.add_argument('--'+name, type=Path, required=True)
    parser.add_argument('--now', required=True)
    parser.add_argument('--pool-max', type=int, required=True)
    parser.add_argument('--max-fail', type=int, required=True)
    parser.add_argument('--quality-hours', type=float, default=24)
    args = parser.parse_args()
    process_screen(args.contenders, args.requested, args.passed, args.queue, args.blacklist,
                   datetime.strptime(args.now, TS_FORMAT), args.pool_max, args.max_fail,
                   args.quality_hours)


if __name__ == '__main__':
    main()
