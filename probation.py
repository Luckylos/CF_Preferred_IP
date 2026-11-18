#!/usr/bin/env python3
"""入池试用期门控 — 只放行「全天可用」的候选。

背景：单次快筛无区分度。移动出口在 04:00-09:00 平峰期，大量平庸 IP 的
VLESS TTFB 会短暂跌到 ~45ms 通过 VLESS_ADMIT_TTFB，白天拥塞回到 ~195ms
后被 ttfb_decay 逐出，形成每日无效进出循环，永久沉淀 0 个新 IP。

本门控要求候选在评估窗口内同时满足：
  1. 达标 PASS（median <= admit_ttfb）覆盖 >= min_passes 个不同小时轮次
  2. 首末达标记录跨度 >= min_span_hours（确保横跨平峰/拥塞两种状态）
  3. 至少 1 次达标发生在拥塞时段（peak hours）—— 这是唯一有区分度的证据
  4. 拥塞时段达标样本的中位数 <= admit_ttfb（真正的判别器：全天稳定 IP
     在拥塞窗口约 45ms，分时段振荡 IP 约 195ms，差 4 倍）
  5. 真实劣化记录（有测得 median 且超标，如 slow_ttfb）数 <= max_slow（默认 0）
  6. 瞬时抖动记录（FAIL 且 median=0，如单次 timeout）数 <= max_blips（默认 1）

失败分两类是必要的：实测确认全天稳定的 master IP 也会出现孤立单次 timeout
（同一时刻其他 master 全部 PASS，其余 11 轮均 43-49ms），零容忍会误杀。
而分时段振荡 IP 的特征是 median 系统性升到 176-2043ms，由第 4/5 条拦下。

证据来源为 vless_history.tsv（verify_vless.sh 的权威 VLESS TTFB 记录），
不引入新状态文件。
"""
from __future__ import annotations

import argparse
import sys
from datetime import datetime, timedelta
from pathlib import Path

from ip_validation import is_valid_ipv4

TS_FMT = "%Y-%m-%d %H:%M:%S"


def parse_peak_hours(spec: str) -> set[int]:
    """解析 '10-23,0-3' 形式的时段规格为小时集合。"""
    hours: set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo_s, hi_s = part.split("-", 1)
            lo, hi = int(lo_s), int(hi_s)
            if lo <= hi:
                hours.update(range(lo, hi + 1))
            else:  # 跨零点写法，如 22-3
                hours.update(range(lo, 24))
                hours.update(range(0, hi + 1))
        else:
            hours.add(int(part))
    return {h for h in hours if 0 <= h <= 23}


def read_candidates(path: Path) -> list[str]:
    if not path.exists():
        return []
    out: list[str] = []
    seen: set[str] = set()
    for raw in path.read_text(encoding="utf-8").splitlines():
        v = raw.strip()
        if v and not v.startswith("#") and is_valid_ipv4(v) and v not in seen:
            seen.add(v)
            out.append(v)
    return out


def load_history(path: Path, cutoff: datetime) -> dict[str, list[tuple[datetime, str, int]]]:
    """读取 vless_history.tsv 中 cutoff 之后的记录。

    行格式: 时间戳<TAB>IP<TAB>PASS|FAIL|PARTIAL<TAB>median_ms<TAB>reason
    """
    records: dict[str, list[tuple[datetime, str, int]]] = {}
    if not path.exists():
        return records
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        fields = raw.split("\t")
        if len(fields) < 4:
            continue
        try:
            ts = datetime.strptime(fields[0], TS_FMT)
        except ValueError:
            continue
        if ts < cutoff:
            continue
        ip = fields[1]
        if not is_valid_ipv4(ip):
            continue
        status = fields[2].upper()
        if status not in {"PASS", "FAIL", "PARTIAL"}:
            continue
        try:
            median = int(fields[3])
        except ValueError:
            continue
        records.setdefault(ip, []).append((ts, status, median))
    return records


def _median_ms(values: list[int]) -> int:
    """按 verifier 契约计算毫秒 median：偶数样本平均并四舍五入。"""
    ordered = sorted(values)
    count = len(ordered)
    if count == 0:
        return 0
    if count % 2:
        return ordered[count // 2]
    return (ordered[count // 2 - 1] + ordered[count // 2] + 1) // 2


def evaluate(
    recs: list[tuple[datetime, str, int]],
    admit_ttfb: int,
    min_passes: int,
    min_span_hours: int,
    peak_hours: set[int],
    require_peak: bool,
    max_slow: int,
    max_blips: int,
) -> tuple[bool, str]:
    """返回 (是否放行, 说明)。"""
    if not recs:
        return False, "no_evidence"

    partial = [1 for _ts, st, _m in recs if st == "PARTIAL"]
    if partial:
        return False, f"incomplete(partial={len(partial)})"

    good = [(ts, m) for ts, st, m in recs if st == "PASS" and m <= admit_ttfb]
    # 真实劣化：测到了 median 但超标（slow_ttfb / PASS 但慢）—— 分时段振荡的指纹
    slow = [(ts, m) for ts, st, m in recs
            if m > admit_ttfb and not (st == "PASS" and m <= admit_ttfb)]
    # 瞬时抖动：完全没测到 median（timeout / 连接失败），可能是网络毛刺
    blips = [ts for ts, st, m in recs if m <= 0 and st != "PASS"]

    if len(slow) > max_slow:
        worst = max(m for _, m in slow)
        return False, f"degraded(slow={len(slow)} worst={worst}ms)"
    if len(blips) > max_blips:
        return False, f"flaky(blips={len(blips)}/{max_blips})"

    buckets = {ts.strftime("%Y-%m-%d %H") for ts, _ in good}
    if len(buckets) < min_passes:
        return False, f"insufficient_rounds({len(buckets)}/{min_passes})"

    span_h = (max(ts for ts, _ in good) - min(ts for ts, _ in good)).total_seconds() / 3600.0
    if span_h < min_span_hours:
        return False, f"span_too_short({span_h:.1f}h/{min_span_hours}h)"

    good_medians = [m for _, m in good]
    med = _median_ms(good_medians)

    if not require_peak:
        return True, f"ok(rounds={len(buckets)} span={span_h:.1f}h med={med}ms)"

    peak = [m for ts, m in good if ts.hour in peak_hours]
    if not peak:
        return False, "no_peak_evidence"
    # 拥塞窗口中位数是真正的判别器
    peak_med = _median_ms(peak)
    if peak_med > admit_ttfb:
        return False, f"peak_slow(peak_med={peak_med}ms)"

    return True, (f"ok(rounds={len(buckets)} span={span_h:.1f}h "
                  f"peak={len(peak)} peak_med={peak_med}ms med={med}ms)")


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="入池试用期门控：只放行全天可用候选")
    p.add_argument("--candidates", type=Path, required=True,
                   help="本轮快筛达标的候选 IP 列表（verify_vless --screen 输出）")
    p.add_argument("--history", type=Path, required=True, help="vless_history.tsv")
    p.add_argument("--out", type=Path, required=True, help="放行 IP 输出文件")
    p.add_argument("--admit-ttfb", type=int, default=100)
    p.add_argument("--min-passes", type=int, default=3)
    p.add_argument("--min-span-hours", type=int, default=8)
    p.add_argument("--window-hours", type=int, default=24)
    p.add_argument("--peak-hours", default="10-23,0-3")
    p.add_argument("--require-peak", type=int, default=1)
    p.add_argument("--max-slow", type=int, default=0,
                   help="容忍的真实劣化次数（median 超标），默认 0")
    p.add_argument("--max-blips", type=int, default=1,
                   help="容忍的瞬时抖动次数（timeout，无 median），默认 1")
    p.add_argument("--now", default=None, help="评估基准时间（默认当前）")
    p.add_argument("--report-all", action="store_true",
                   help="报告所有候选的判定理由（审计用，不写 out）")
    return p.parse_args()


def main() -> None:
    args = parse_args()
    now = datetime.strptime(args.now, TS_FMT) if args.now else datetime.now()
    cutoff = now - timedelta(hours=args.window_hours)
    peak_hours = parse_peak_hours(args.peak_hours)

    candidates = read_candidates(args.candidates)
    history = load_history(args.history, cutoff)

    promoted: list[str] = []
    for ip in candidates:
        ok, reason = evaluate(
            history.get(ip, []),
            args.admit_ttfb,
            args.min_passes,
            args.min_span_hours,
            peak_hours,
            bool(args.require_peak),
            args.max_slow,
            args.max_blips,
        )
        if ok:
            promoted.append(ip)
        if args.report_all:
            print(f"  {ip:<18} {'PROMOTE' if ok else 'PROBATION'}  {reason}", file=sys.stderr)

    if not args.report_all:
        args.out.write_text("".join(f"{ip}\n" for ip in promoted), encoding="utf-8")

    print(
        f"probation: candidates={len(candidates)} promoted={len(promoted)} "
        f"held={len(candidates) - len(promoted)} "
        f"(need rounds>={args.min_passes} span>={args.min_span_hours}h "
        f"peak_med<={args.admit_ttfb}ms slow<={args.max_slow} blips<={args.max_blips})"
    )


if __name__ == "__main__":
    main()
