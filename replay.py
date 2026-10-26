#!/usr/bin/env python3
"""
replay.py — 只读回放工具：按日滚动窗口终点调用 rank.run_rank，输出每日 Top3 与变化次数。

用法：replay.py --history FILE [--days 5] [--now TS] [--contenders FILE] [rank 阈值参数…]
池 = --contenders（若给出）否则 history 中出现过的全部 IP。不写任何文件。
"""
from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import rank  # noqa: E402


@dataclass(frozen=True)
class Day:
    end: datetime
    top3: list[str]
    samples: int


@dataclass(frozen=True)
class Replay:
    days: list[Day]
    changes: int


def last_timestamp(path: Path) -> datetime | None:
    last: datetime | None = None
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            ts = rank.parse_ts(line.split("\t", 1)[0])
            if ts is not None and (last is None or ts > last):
                last = ts
    return last


def replay(history: Path, days: int, cfg: rank.Config, now: datetime | None = None,
           pool: list[str] | None = None) -> Replay:
    end = now or last_timestamp(history)
    if end is None:
        return Replay([], 0)
    out: list[Day] = []
    incumbents: list[str] = []
    for i in range(days - 1, -1, -1):
        day_end = end - timedelta(days=i)
        samples = rank.load_history(history, day_end, cfg.window_days)
        day_pool = pool if pool is not None else sorted({s.ip for s in samples})
        res = rank.run_rank(samples, day_pool, incumbents, day_end, cfg, guard="none")
        top3 = (res.published or incumbents)[: cfg.publish_top_n]
        incumbents = top3
        out.append(Day(day_end, top3, len(samples)))
    changes = sum(1 for i in range(1, len(out)) if out[i].top3 != out[i - 1].top3)
    return Replay(out, changes)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="rank replay (read-only)")
    p.add_argument("--history", type=Path, required=True)
    p.add_argument("--days", type=int, default=5)
    p.add_argument("--now", default=None, help="窗口终点，默认 history 最后一行时间")
    p.add_argument("--contenders", type=Path, default=None)
    rank.add_config_args(p)
    args = p.parse_args(argv)
    cfg = rank.config_from_args(args)
    now = rank.parse_ts(args.now) if args.now else None
    if args.now and now is None:
        print(f"replay: invalid --now {args.now!r}", file=sys.stderr)
        return 2
    pool = [c.ip for c in rank.read_contenders(args.contenders)] if args.contenders else None
    res = replay(args.history, args.days, cfg, now, pool)
    for d in res.days:
        print(f"{d.end.strftime(rank.TS_FORMAT)}  samples={d.samples:<5d} top3={','.join(d.top3) or '-'}")
    print(f"replay: days={len(res.days)} changes={res.changes}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
