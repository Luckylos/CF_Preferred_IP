#!/usr/bin/env python3
"""发现队列维护、限额选择与准入；锁、网络和调度由调用方持有。"""
from __future__ import annotations

import argparse
import math
import re
import sys
from datetime import datetime, timedelta
from pathlib import Path

from atomic_io import atomic_write
from cooldown import active, record
from ip_validation import is_valid_ipv4
from rank import Contender, TS_FORMAT, read_contenders, write_contenders


def _distinct_paths(*paths: Path | None) -> None:
    present = [p for p in paths if p is not None]
    for i, path in enumerate(present):
        for other in present[:i]:
            if path.resolve() == other.resolve() or (
                    path.exists() and other.exists() and path.samefile(other)):
                raise ValueError('state, input and output paths must be distinct')


def _positive_hours(hours: float) -> None:
    if not math.isfinite(hours) or hours <= 0:
        raise ValueError('hours must be finite and positive')


def _ips(path: Path) -> list[str]:
    return list(dict.fromkeys(line.strip() for line in path.read_text().splitlines()
                             if is_valid_ipv4(line.strip())))


def _queue_text(path: Path) -> str:
    try:
        return path.read_text()
    except FileNotFoundError:
        return ''  # 未创建的发现队列允许首次启动；其他读取错误不能视为空队列。


def _rows(text: str) -> list[tuple[str, list[str]]]:
    rows = []
    for line in text.splitlines():
        fields = line.split('\t')
        if len(fields) >= 2 and is_valid_ipv4(fields[1]):
            rows.append((line, fields))
    return rows


def _count(fields: list[str]) -> str:
    return fields[2] if len(fields) >= 3 and re.fullmatch(r'[0-9]+', fields[2]) else '0'


def maintain_queue(queue: Path, now: datetime, ttl_hours: float, limit: int, *,
                   incoming: Path | None = None, excluded: Path | None = None,
                   targets: Path | None = None,
                   discovered_at: datetime | None = None) -> tuple[int, int]:
    """原子整理/合并队列，返回(总数, 有发现延迟的条数)。"""
    _positive_hours(ttl_hours)
    if limit <= 0:
        raise ValueError('queue limit must be positive')
    _distinct_paths(queue, incoming, excluded, targets)
    cutoff = (now - timedelta(hours=ttl_hours)).strftime(TS_FORMAT)
    blocked = set(_ips(excluded)) if excluded is not None else set()
    rows = _rows(_queue_text(queue))
    if incoming is not None:
        stamp = (discovered_at or now).strftime(TS_FORMAT)
        for line in incoming.read_text().splitlines():
            fields = line.split('\t')
            if fields and is_valid_ipv4(fields[0]):
                rows.append(('', [stamp, fields[0], '0', fields[1] if len(fields) > 1 else '']))
    kept: dict[str, list[str]] = {}
    for _, fields in rows:
        stamp, ip = fields[:2]
        if stamp >= cutoff and ip not in blocked and ip not in kept:
            kept[ip] = [stamp, ip, _count(fields), fields[3] if len(fields) >= 4 else '']
    # 同时间按IP字典序；两次稳定排序保持既有sort -k1,1r -k2,2语义。
    ordered = sorted(kept.values(), key=lambda row: row[1])
    ordered.sort(key=lambda row: row[0], reverse=True)
    ordered = sorted(ordered[:limit], key=lambda row: (row[0], row[1]))
    atomic_write(queue, ''.join('\t'.join(row) + '\n' for row in ordered))
    if targets is not None:
        atomic_write(targets, ''.join(row[1] + '\n' for row in ordered))
    return len(ordered), sum(bool(row[3]) for row in ordered)


def select_candidates(contenders: Path, queue: Path, excluded: Path, requested: Path,
                      pool_max: int, screen_max: int) -> list[str]:
    """只生成请求，不修改队列/失败数；容量与队列优先级只有这一处实现。"""
    if pool_max <= 0 or screen_max <= 0:
        raise ValueError('pool_max and screen_max must be positive')
    _distinct_paths(contenders, queue, excluded, requested)
    pool = read_contenders(contenders)
    blocked = {c.ip for c in pool} | set(_ips(excluded))
    budget = min(screen_max, max(0, pool_max - len(pool)))
    candidates = []
    for _, fields in _rows(_queue_text(queue)):
        if fields[1] not in blocked:
            count = _count(fields)
            # 旧sort未指定tab分隔：第二键是日期，其后按完整投影行比较。
            projected = f'{count}\t{fields[0]}\t{fields[1]}'
            candidates.append((int(count), fields[0].split()[0] if fields[0].split() else '',
                               projected, fields[1]))
    chosen = list(dict.fromkeys(row[3] for row in sorted(candidates)))[:budget]
    atomic_write(requested, ''.join(ip + '\n' for ip in chosen))
    return chosen


def process_screen(contenders: Path, requested: Path, passed: Path, queue: Path,
                   blacklist: Path, now: datetime, pool_max: int, max_fail: int,
                   quality_hours: float = 24) -> list[str]:
    _positive_hours(quality_hours)
    if pool_max <= 0 or max_fail <= 0:
        raise ValueError('pool_max and max_fail must be positive')
    _distinct_paths(contenders, requested, passed, queue, blacklist)
    pool = read_contenders(contenders)
    known = {c.ip for c in pool}
    request = _ips(requested)
    observed = set(request)
    successful = set(_ips(passed)) & observed
    queue_rows = _rows(queue.read_text())
    active(blacklist, now, quality_hours)  # 先验证可读性；不在池已写入后才发现输入错误。
    slots = max(0, pool_max - len(pool))
    admitted = [ip for ip in request if ip in successful and ip not in known][:slots]
    stamp = now.strftime(TS_FORMAT)
    pool.extend(Contender(ip, stamp, stamp, 'screen') for ip in admitted)
    accepted = known | set(admitted)
    kept: list[str] = []
    failed: list[str] = []
    for line, parts in queue_rows:
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
    # 先持久化池/冷却，再出队。单文件原子，不承诺跨文件回滚或exactly-once。
    write_contenders(contenders, pool)
    record(blacklist, failed, now, quality_hours)
    atomic_write(queue, ''.join(line+'\n' for line in kept))
    atomic_write(passed, ''.join(ip+'\n' for ip in admitted))
    return admitted


def main(argv: list[str] | None = None) -> None:
    args = list(sys.argv[1:] if argv is None else argv)
    command = args.pop(0) if args and args[0] in {'maintain', 'select'} else 'screen'
    parser = argparse.ArgumentParser(description=__doc__)
    if command == 'maintain':
        parser.add_argument('--queue', type=Path, required=True)
        parser.add_argument('--now', required=True)
        parser.add_argument('--ttl-hours', type=float, required=True)
        parser.add_argument('--limit', type=int, required=True)
        parser.add_argument('--incoming', type=Path)
        parser.add_argument('--excluded', type=Path)
        parser.add_argument('--targets', type=Path)
        parser.add_argument('--discovered-at')
        ns = parser.parse_args(args)
        print(*maintain_queue(ns.queue, datetime.strptime(ns.now, TS_FORMAT), ns.ttl_hours,
                             ns.limit, incoming=ns.incoming, excluded=ns.excluded,
                             targets=ns.targets, discovered_at=(
                                 datetime.strptime(ns.discovered_at, TS_FORMAT)
                                 if ns.discovered_at else None)))
    elif command == 'select':
        for name in ['contenders', 'queue', 'excluded', 'requested']:
            parser.add_argument('--'+name, type=Path, required=True)
        parser.add_argument('--pool-max', type=int, required=True)
        parser.add_argument('--screen-max', type=int, required=True)
        ns = parser.parse_args(args)
        select_candidates(ns.contenders, ns.queue, ns.excluded, ns.requested,
                          ns.pool_max, ns.screen_max)
    else:
        for name in ['contenders', 'requested', 'passed', 'queue', 'blacklist']:
            parser.add_argument('--'+name, type=Path, required=True)
        parser.add_argument('--now', required=True)
        parser.add_argument('--pool-max', type=int, required=True)
        parser.add_argument('--max-fail', type=int, required=True)
        parser.add_argument('--quality-hours', type=float, default=24)
        ns = parser.parse_args(args)
        process_screen(ns.contenders, ns.requested, ns.passed, ns.queue, ns.blacklist,
                       datetime.strptime(ns.now, TS_FORMAT), ns.pool_max, ns.max_fail,
                       ns.quality_hours)


if __name__ == '__main__':
    main()
