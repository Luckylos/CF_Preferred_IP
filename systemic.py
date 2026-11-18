#!/usr/bin/env python3
"""系统性劣化守卫 — 判定一轮 master audit 是否为共因故障。

问题（2026-08-26 04:00 实测）：
本地出口/上游整体劣化一轮时，master 池里 39/42 个 IP 同时 PASS 但 median
集中到 346-414ms，只有 3 个仍在 ~45ms。现行链路会把这 40 条慢记录当作
**IP 级证据**：
  - pool.py 给每个 IP misses+1，连续 6 轮即 ttfb_decay 硬退役
  - probation_pool recheck 判 degraded → fail+1，达 PROBATION_FAIL_LIMIT 拉黑
  - 发现队列快筛全部撞 VLESS_ADMIT_TTFB，连撞 VLESS_SCREEN_MAX_FAIL 轮拉黑 24h
一次共因故障因此会连锁清空可恢复的候选池。

判据：master-only PASS 样本的 p10（第 10 百分位 TTFB）。
标定依据（/root/.hermes/tmp/cfst-analysis/p10_verify.py，8319 行历史、84 轮）：

  正常轮 p10   min=43.0  p50=45.0  p90=47.0  次高轮=48.5
  事件轮 p10   380.0                          分离度 7.8x
  阈值 80/100/120/150/200/250/300ms 全部只命中同一轮 → 判据极不敏感

为什么是 p10 而不是别的统计量：
  - min（floor）漏判：事件轮 floor 仍是 45ms（3 个 IP 未受影响）
  - median 误判：半数 IP 劣化就会翻转，那仍是 IP 级证据而非共因
  - p10 表达「连最快的一批都慢了」—— 共因故障的指纹，且对单 IP 离群免疫

守卫只抑制处罚，不改变正常轮的任何行为；任何自身异常一律 fail-open
（判为非 systemic），宁可照常处罚也不要静默冻结退役。
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from ip_validation import is_valid_ipv4

AUDIT_MARKER = "=== AUDIT RESULTS"


def parse_audit(text: str) -> list[tuple[str, str, int]]:
    """解析 verify_vless.sh --audit 输出 → [(ip, status, median_ms)]。

    契约与 run.sh:76-86、probation_pool.py:243-253 一致：
    只取 `=== AUDIT RESULTS` 之后、首字段为 IPv4 的行。
    行形如 `  <ip>  PASS 45` / `  <ip>  FAIL 0 (timeout)`。
    """
    records: list[tuple[str, str, int]] = []
    in_block = False
    for line in text.splitlines():
        if AUDIT_MARKER in line:
            in_block = True
            continue
        if not in_block:
            continue
        parts = line.split()
        if len(parts) < 3 or not is_valid_ipv4(parts[0]):
            continue
        try:
            median = int(parts[2])
        except ValueError:
            continue
        records.append((parts[0], parts[1], median))
    return records


def percentile(sorted_vals: list[float], q: float) -> float:
    """线性插值分位数，q ∈ [0,1]。

    必须与标定脚本 p10_verify.py 的 pct() 同算法，否则 150ms 阈值不可迁移。
    """
    if not sorted_vals:
        return float("nan")
    if len(sorted_vals) == 1:
        return float(sorted_vals[0])
    pos = q * (len(sorted_vals) - 1)
    lo = int(pos)
    hi = min(lo + 1, len(sorted_vals) - 1)
    frac = pos - lo
    return sorted_vals[lo] * (1 - frac) + sorted_vals[hi] * frac


def evaluate(
    records: list[tuple[str, str, int]],
    p10_threshold_ms: int,
    min_samples: int,
) -> tuple[bool, str]:
    """返回 (是否共因劣化, 说明)。

    只用 PASS 且 median>0 的样本：FAIL 的 median=0 混进分位数会把 p10 压到 0，
    让守卫在真正的故障轮永久沉默。

    样本不足时 fail-open（返回 False）：p10 在小样本下无意义，
    且若在此 fail-closed，master 池小于 min_samples 时退役会被永久冻结。
    """
    passed = sorted(
        float(median) for _ip, status, median in records
        if status == "PASS" and median > 0
    )
    if len(passed) < min_samples:
        return False, f"insufficient_samples({len(passed)}/{min_samples})"

    p10 = percentile(passed, 0.10)
    med = percentile(passed, 0.50)
    detail = f"p10={p10:.1f}ms med={med:.1f}ms n={len(passed)}"
    if p10 > p10_threshold_ms:
        return True, f"systemic({detail} > {p10_threshold_ms}ms)"
    return False, f"normal({detail})"


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="判定一轮 master VLESS audit 是否为共因（系统性）劣化"
    )
    p.add_argument("--audit", type=Path, required=True,
                   help="verify_vless.sh --audit 的输出文件")
    p.add_argument("--p10-threshold", type=int, required=True,
                   help="master-only PASS p10 超过该值（ms）判为共因劣化")
    p.add_argument("--min-samples", type=int, required=True,
                   help="PASS 样本少于该数时不表态（fail-open）")
    return p.parse_args()


def main() -> None:
    """stdout 输出单 token 供 run.sh 取用：1=systemic，0=正常轮。

    说明写 stderr，让 run.sh 能把它记进本轮日志。
    任何异常都输出 0 并 exit 0：守卫故障不得冻结退役，
    也不得让 set -e 的 run.sh 整轮崩掉。
    """
    try:
        args = parse_args()
        text = args.audit.read_text(encoding="utf-8", errors="replace")
        flagged, reason = evaluate(
            parse_audit(text), args.p10_threshold, args.min_samples
        )
        print("1" if flagged else "0")
        print(f"systemic guard: {reason}", file=sys.stderr)
    except Exception as exc:  # noqa: BLE001 — fail-open 是刻意的
        print("0")
        print(f"systemic guard: unavailable ({exc.__class__.__name__}: {exc})",
              file=sys.stderr)
    sys.exit(0)


if __name__ == "__main__":
    main()
