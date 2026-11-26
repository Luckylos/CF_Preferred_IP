#!/usr/bin/env python3
"""
rank.py — Contender Pool 排名：单池连续采样 + 不确定性驱动排名。

设计：docs/superpowers/specs/2026-10-15-contender-pool-design.md
输入：vless_history.tsv（ts<TAB>ip<TAB>PASS|FAIL|PARTIAL<TAB>median<TAB>reason）
      contenders.tsv（ip<TAB>first_seen<TAB>last_sampled<TAB>origin）
输出：contenders.tsv（更新）、best_ips.txt（Top N，含 BEST_IPS 标记段）、
      .screen_blacklist.tsv（追加淘汰）、DIR/core.txt、DIR/challengers.txt
      （--dry-run 不写前三者；--tiers-out 为调度草稿，dry-run 下仍写），
      stdout 最后一行摘要：
      rank: pool=N core=N challengers=N evicted=N published=a,b,c changed=0|1 guard=none|coverage|systemic|no_evidence

估计：每个样本一个效用分 s=f(去共因 TTFB)（失败=0），权重 = 时效衰减 × 时段相关性（晚高峰 ×peak_weight）；
      mu/σ̂ 为加权均值/标准差，n_eff = min(Σ时效, Kish)；lcb/ucb = mu ∓ z·√(σ̂²+σ0²)/√n_eff。
      惩罚（丢 core/发布位、淘汰）看保守侧，探索看 ucb，两侧同一个估计量；区间宽度由样本离散度决定。
守卫：guard 优先级 no_evidence(--audit-ok 0) > systemic(--systemic 1 或自动识别：--now 所在
10 分钟桶 / 15 分钟内最新桶失败率 ≥50%) > coverage(returned < 0.8*requested)；守卫轮不淘汰。
淘汰：1) n_eff ≥ evict_min_neff 且 ucb < 第 POOL_TARGET 名"已证明"(n_eff ≥ min_neff) IP 的 lcb；
2) n_eff ≥ min_neff 且失败率 Wilson 下界 > hard；3) 连续 unreachable_rounds 轮不可达；
4) 池 > pool_max − trim_headroom 时，在已表征且不在前 POOL_TARGET 名的 IP 中按 ucb 裁最差者，每轮 ≤ trim_headroom。
发布：粘性顺序 + 滞回；资格 = n_eff ≥ publish_min_neff 且近 24h 晚高峰样本 ≥ peak_min_samples 且失败率 ≤ hard；
同 /16 ≤ max_per_segment（仅滞回内有跨段合格者时替换）。
所有阈值由 CLI 参数传入（带默认值）；不读 config.sh。仅标准库。
纯函数优先：load_history → bucket_rounds → round_baselines → ip_stats → utility
→ derive_tiers / evict / sticky_publish，便于单测与回放（replay.py）。
"""
from __future__ import annotations

import argparse
import json
from cycle_result import RankReceipt, assess_audit, preflight_receipt
import math
import sys
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta
from pathlib import Path
from statistics import median as _median

sys.path.insert(0, str(Path(__file__).resolve().parent))
from atomic_io import atomic_write
from cooldown import record as record_cooldown  # noqa: E402
from ip_validation import is_valid_ipv4  # noqa: E402
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from quality_evidence import Batch, Quality

TS_FORMAT = "%Y-%m-%d %H:%M:%S"
BEST_MARKER = "# --- BEST_IPS (machine-readable, one IP per line) ---"
CONTENDERS_HEADER = "# contenders.tsv — ip<TAB>first_seen<TAB>last_sampled<TAB>origin<TAB>evaluated_at"

# u_tail 分段曲线常量（自 score.py 原样迁移）
VLESS_GOOD_TTFB = 80.0
VLESS_OK_TTFB = 150.0
VLESS_BAD_TTFB = 300.0
# soft 折扣生效的最小样本数（自 score.py VLESS_MIN_SAMPLES 迁移）
SOFT_MIN_SAMPLES = 3.0


# ── 数据结构 ────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class Sample:
    ts: datetime
    ip: str
    status: str      # PASS | FAIL | PARTIAL
    median: int
    reason: str = ""


@dataclass(frozen=True)
class RoundInfo:
    baseline: float
    systemic_fail: bool


@dataclass(frozen=True)
class Stats:
    """单个 IP 的证据摘要。

    mu/sigma：逐样本效用 s=f(q)（失败=0）的（时段×时效）加权均值与标准差——排名与淘汰只看这两个量；
    n_eff：证据量 = min(Σ时效权重, Kish 等效样本数)，与时段权重无关（晚高峰样本更"重要"，不代表更"多"）；
    fail/med/tail：只按时效加权的原始失败率 / 中位数 / p90，供硬失败规则与展示；
    peak_samples：最近 24h 落在晚高峰时段的（非系统性轮）样本数，发布新鲜度门槛；
    evaluation_completed：已获得完整晚高峰覆盖的生命周期状态，不随窗口滚动撤销。"""
    n_eff: float
    fail: float
    med: float | None
    tail: float | None
    peak_ok: bool
    last_seen: datetime | None
    consecutive_unreachable: int
    mu: float = 0.0
    sigma: float = 0.0
    peak_samples: int = 0
    evaluation_completed: bool = False
    quality: Quality | None = None


@dataclass
class Config:
    half_life_hours: float = 24.0
    floor_ms: float = 50.0
    z: float = 1.0              # 置信半宽 z：lcb/ucb = mu ∓ z·√(σ̂²+σ0²)/√n_eff
    sigma0: float = 0.15        # 逐样本效用的先验标准差：样本少时 σ̂ 不可信，σ0 是区间宽度的下限
    peak_weight: float = 3.0    # 晚高峰样本在 mu/σ̂ 估计中的相对权重（不计入 n_eff）
    peak_min_samples: int = 3   # 发布新鲜度门槛：近 24h 晚高峰样本数
    trim_headroom: int = 20     # 规则 4：池 > pool_max − headroom 时每轮最多裁这么多已表征的最差者（0=关闭）
    core_n: int = 10
    challenger_max: int = 10
    explore_slots: int = 5      # 挑战者中的探索槽（n_eff < min_neff）；其余为晋升槽，一侧不足另一侧补齐
    max_per_segment: int = 2    # 发布集内同一 /16 最多 N 个（0=关闭）；仅当滞回内有跨段合格者时才替换
    evict_min_neff: float = 8.0 # 规则 1、4 所需最少证据量：剔除近乎不可逆，比 core 资格（min_neff）要求更多
    pool_target: int = 60
    pool_max: int = 90
    publish_min_neff: float = 6.0
    publish_margin: float = 0.02
    top_n: int = 5
    publish_top_n: int = 3
    hard_max_fail: float = 0.30
    peak_hours: set[int] = field(default_factory=lambda: parse_peak_hours("20-23,0"))
    window_days: int = 7
    round_minutes: int = 10
    baseline_min_pass: int = 10
    min_neff: float = 3.0           # core / 淘汰规则 1、2 的 n_eff 门槛
    unreachable_rounds: int = 3


@dataclass(frozen=True)
class Ranked:
    ip: str
    stats: Stats
    u: float
    lcb: float
    ucb: float


# ── 解析 ────────────────────────────────────────────────────────────────

def parse_ts(value: str) -> datetime | None:
    try:
        return datetime.strptime(value, TS_FORMAT)
    except (TypeError, ValueError):
        return None


def parse_peak_hours(spec: str) -> set[int]:
    """解析 '10-23,0-3' 形式的时段规格为小时集合（复制自 probation.py）。"""
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


def _parse_median(value: str) -> int | None:
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return None
    if not math.isfinite(parsed) or parsed < 0 or not parsed.is_integer():
        return None
    return int(parsed)


def load_history(path: Path, now: datetime, days: float) -> list[Sample]:
    """读取 (now - days, now] 窗口内的样本；畸形行跳过并在 stderr 计数。"""
    if not path.exists():
        return []
    cutoff = now - timedelta(days=days)
    out: list[Sample] = []
    invalid = 0
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            parts = line.rstrip("\r\n").split("\t")
            if len(parts) < 4:
                invalid += 1
                continue
            ts = parse_ts(parts[0])
            status = parts[2].upper()
            med = _parse_median(parts[3])
            if ts is None or med is None or not is_valid_ipv4(parts[1]) \
                    or status not in ("PASS", "FAIL", "PARTIAL"):
                invalid += 1
                continue
            if ts < cutoff or ts > now:
                continue
            reason = parts[4] if len(parts) > 4 else ""
            out.append(Sample(ts, parts[1], status, med, reason))
    if invalid:
        print(f"rank: ignored {invalid} malformed history row(s)", file=sys.stderr)
    return out


# ── 轮桶 / 基线 / 去共因 ────────────────────────────────────────────────

def bucket_key(ts: datetime, minutes: int) -> datetime:
    return ts.replace(minute=(ts.minute // minutes) * minutes, second=0, microsecond=0)


def bucket_rounds(samples: list[Sample], minutes: int = 10) -> dict[datetime, list[Sample]]:
    rounds: dict[datetime, list[Sample]] = {}
    for s in samples:
        rounds.setdefault(bucket_key(s.ts, minutes), []).append(s)
    return rounds


def round_baselines(rounds: dict[datetime, list[Sample]], floor: float,
                    min_pass: int = 10, systemic_min_samples: int = 5) -> dict[datetime, RoundInfo]:
    """轮基线 = PASS median 的中位数（PASS ≥ min_pass），否则 floor；
    轮样本 ≥ systemic_min_samples 且失败率 ≥50% → systemic_fail（单个 IP 的失败不构成"系统性"）。"""
    out: dict[datetime, RoundInfo] = {}
    for key, items in rounds.items():
        passes = [s.median for s in items if s.status == "PASS" and s.median > 0]
        baseline = float(_median(passes)) if len(passes) >= min_pass else float(floor)
        fails = sum(1 for s in items if s.status != "PASS")
        systemic = len(items) >= systemic_min_samples and fails * 2 >= len(items)
        out[key] = RoundInfo(baseline, systemic)
    return out


def detect_systemic_round(baselines: dict[datetime, RoundInfo], now: datetime,
                          round_minutes: int, lookback_minutes: int = 15) -> bool:
    """now 所在桶（或 now 之前 lookback 分钟内的最新桶）是否为系统性失败轮。"""
    recent = [k for k in baselines if now - timedelta(minutes=lookback_minutes) <= k <= now]
    if not recent:
        return False
    return baselines[max(recent)].systemic_fail


def decommon(ttfb: float, baseline: float, floor: float) -> float:
    """q = ttfb − max(0, baseline − floor)，下限 0。"""
    return max(0.0, ttfb - max(0.0, baseline - floor))


# ── 加权统计 ─────────────────────────────────────────────────────────────

def sample_weight(ts: datetime, now: datetime, half_life_hours: float) -> float:
    age_h = max(0.0, (now - ts).total_seconds() / 3600.0)
    return 0.5 ** (age_h / half_life_hours)


FAIL_Z = 1.0  # 失败率 Wilson 下界的 z（规则 2）
TAIL_Q = 0.9


def weighted_quantile(values: list[float], weights: list[float], q: float) -> float | None:
    if not values:
        return None
    pairs = sorted(zip(values, weights))
    total = sum(w for _, w in pairs)
    if total <= 0:
        return None
    target = q * total
    acc = 0.0
    for v, w in pairs:
        acc += w
        if acc >= target - 1e-12:
            return v
    return pairs[-1][0]


def is_unreachable(s: Sample) -> bool:
    """不可达 = 非 PASS 且无任何延迟读数（median<=0）。PARTIAL 带 median 的样本只是慢/部分超时。"""
    return s.status != "PASS" and s.median <= 0


def ip_stats(samples: list[Sample], baselines: dict[datetime, RoundInfo],
             now: datetime, half_life_hours: float, peak_hours: set[int],
             floor: float, round_minutes: int = 10, peak_weight: float = 3.0,
             peak_min_samples: int = 3) -> dict[str, Stats]:
    """逐样本效用的加权均值/方差。

    每个样本一个分数 s∈[0,1]：PASS → f(去共因 TTFB)，非 PASS → 0。系统性轮的失败不计。
    权重 w = 时效衰减 d(age) × 时段相关性（晚高峰 peak_weight，其余 1）。
    mu = Σws/Σw，σ̂² = Σw(s−mu)²/Σw；n_eff = min(Σd, (Σw)²/Σw²)：
    时段权重只改变"哪些样本更能代表用户体验"，不虚增证据量；Kish 项保证权重极不均时不高估。
    尾部与失败都在同一个有界随机变量里（300ms 样本 s≈0.10、失败 s=0），均值的区间有 CLT 支撑。"""
    by_ip: dict[str, list[Sample]] = {}
    for s in samples:
        by_ip.setdefault(s.ip, []).append(s)
    peak_cutoff = now - timedelta(hours=24)
    out: dict[str, Stats] = {}
    for ip, items in by_ip.items():
        items = sorted(items, key=lambda s: s.ts)
        sum_d = 0.0
        sum_w = 0.0
        sum_w2 = 0.0
        sum_ws = 0.0
        sum_ws2 = 0.0
        fail_d = 0.0
        qs: list[float] = []
        qw: list[float] = []
        peak_samples = 0
        for s in items:
            info = baselines.get(bucket_key(s.ts, round_minutes))
            systemic = info.systemic_fail if info else False
            baseline = info.baseline if info else floor
            if s.status != "PASS" and systemic:
                continue  # 系统性轮的失败不是证据
            d = sample_weight(s.ts, now, half_life_hours)
            in_peak = s.ts.hour in peak_hours
            w = d * (peak_weight if in_peak else 1.0)
            if s.status == "PASS" and s.median > 0:
                q = decommon(s.median, baseline, floor)
                score = u_tail(q)
                qs.append(q)
                qw.append(d)
            else:
                score = 0.0
                if s.status != "PASS":
                    fail_d += d
            sum_d += d
            sum_w += w
            sum_w2 += w * w
            sum_ws += w * score
            sum_ws2 += w * score * score
            if in_peak and s.ts >= peak_cutoff:
                peak_samples += 1
        streak = 0
        for s in reversed(items):
            info = baselines.get(bucket_key(s.ts, round_minutes))
            if s.status != "PASS" and info and info.systemic_fail:
                continue
            if is_unreachable(s):
                streak += 1
            else:
                break
        if sum_w > 0:
            mu = sum_ws / sum_w
            var = max(0.0, sum_ws2 / sum_w - mu * mu)
            n_eff = min(sum_d, sum_w * sum_w / sum_w2)
        else:
            mu, var, n_eff = 0.0, 0.0, 0.0
        out[ip] = Stats(
            n_eff=n_eff,
            fail=(fail_d / sum_d) if sum_d > 0 else 0.0,
            med=weighted_quantile(qs, qw, 0.5),
            tail=weighted_quantile(qs, qw, TAIL_Q),
            peak_ok=peak_samples >= peak_min_samples,
            last_seen=items[-1].ts,
            consecutive_unreachable=streak,
            mu=mu,
            sigma=math.sqrt(var),
            peak_samples=peak_samples,
        )
    return out


# ── 效用与置信区间 ───────────────────────────────────────────────────────

def u_tail(tail: float | None) -> float:
    """逐样本 TTFB 效用曲线 f(q)：分段线性，阈值 80/150/300ms 来自 tail-aware 体感回放。"""
    if tail is None:
        return 0.15  # only fails
    avg = float(tail)
    if avg <= VLESS_GOOD_TTFB:
        return 0.85 + 0.15 * (VLESS_GOOD_TTFB - avg) / VLESS_GOOD_TTFB
    if avg <= VLESS_OK_TTFB:
        return 0.45 + 0.40 * (VLESS_OK_TTFB - avg) / (VLESS_OK_TTFB - VLESS_GOOD_TTFB)
    if avg <= VLESS_BAD_TTFB:
        return 0.10 + 0.35 * (VLESS_BAD_TTFB - avg) / (VLESS_BAD_TTFB - VLESS_OK_TTFB)
    return max(0.0, 0.10 * (500.0 - avg) / 200.0)


def fail_lcb(fail: float, n_eff: float, z: float = FAIL_Z) -> float:
    """失败率的 Wilson 置信下界（规则 2）：硬失败只认统计上成立的失败率。
    1/3 → ≈0.14、1/5 → ≈0.08 不触发 30% 硬门；20/87 → ≈0.19，3/3 → 0.5 照常。"""
    if n_eff <= 0 or fail <= 0:
        return 0.0
    p = min(1.0, fail)
    z2 = z * z
    denom = 1.0 + z2 / n_eff
    center = p + z2 / (2.0 * n_eff)
    margin = z * math.sqrt(p * (1.0 - p) / n_eff + z2 / (4.0 * n_eff * n_eff))
    return max(0.0, (center - margin) / denom)


def utility(st: Stats, cfg: Config) -> tuple[float, float, float]:
    """(u, lcb, ucb) = (mu, mu − half, mu + half)，half = z·√(σ̂² + σ0²)/√n_eff。

    区间宽度来自样本自身的离散度：稳定在 50ms 的 IP σ̂≈0.03，区间≈σ0/√n；
    白天 50ms、晚高峰偶发 300ms 的 IP σ̂≈0.3，区间宽一倍以上——它丢 core/发布位（lcb 低），
    但在证据充分前不会被剔除（ucb 仍高）。惩罚看 lcb、探索/免剔看 ucb，两侧同一个估计量。"""
    if st.n_eff <= 0:
        return 0.5, -0.5, 1.5
    half = cfg.z * math.sqrt(st.sigma * st.sigma + cfg.sigma0 * cfg.sigma0) / math.sqrt(st.n_eff)
    return st.mu, st.mu - half, st.mu + half


def rank_pool(pool: list[str], stats: dict[str, Stats], cfg: Config) -> list[Ranked]:
    """按 lcb 降序（并列按 u、ip）排序池内 IP；无样本的 IP n_eff=0。"""
    empty = Stats(0.0, 0.0, None, None, False, None, 0)
    rows = []
    for ip in pool:
        st = stats.get(ip, empty)
        u, lcb, ucb = utility(st, cfg)
        rows.append(Ranked(ip, st, u, lcb, ucb))
    rows.sort(key=lambda r: (-r.lcb, -r.u, r.ip))
    return rows


# ── 层派生 ───────────────────────────────────────────────────────────────

def derive_tiers(ranked: list[Ranked], cfg: Config) -> tuple[list[str], list[str], list[str]]:
    """core = lcb 前 CORE_N 且 n_eff ≥ min_neff；challenger = ucb > core 末位 lcb（最多 challenger_max）；其余 reserve。

    挑战者分两槽：探索槽收 n_eff < min_neff 的新 IP，晋升槽收正在攒发布资格的候选；各按 ucb 降序，
    一侧不足另一侧补齐。不分槽时新 IP 的宽区间 ucb 天然最高，会把攒到 4–5 个样本的候选挤回 reserve。"""
    core = [r for r in ranked if r.stats.n_eff >= cfg.min_neff][:cfg.core_n]
    core_ips = {r.ip for r in core}
    threshold = core[-1].lcb if len(core) >= cfg.core_n else float("-inf")
    rest = [r for r in ranked if r.ip not in core_ips]
    cands = sorted((r for r in rest if r.ucb > threshold), key=lambda r: (-r.ucb, r.ip))
    explore = [r for r in cands if r.stats.n_eff < cfg.min_neff]
    promote = [r for r in cands if r.stats.n_eff >= cfg.min_neff]
    n_explore = min(len(explore), max(0, min(cfg.explore_slots, cfg.challenger_max)))
    n_promote = min(len(promote), cfg.challenger_max - n_explore)
    n_explore = min(len(explore), cfg.challenger_max - n_promote)   # 晋升候选不足时探索槽补齐
    chal = sorted(explore[:n_explore] + promote[:n_promote], key=lambda r: (-r.ucb, r.ip))
    chal_ips = {r.ip for r in chal}
    reserve = [r.ip for r in rest if r.ip not in chal_ips]
    return [r.ip for r in core], [r.ip for r in chal], reserve


# ── 淘汰 ─────────────────────────────────────────────────────────────────

def evict(ranked: list[Ranked], cfg: Config, guard: str,
          protected: frozenset[str] = frozenset()) -> tuple[list[str], list[tuple[str, str]]]:
    """守卫轮（guard != none）一律不淘汰。返回 (kept_ips, [(ip, reason)])。
    规则 1、4 只接受已完成晚高峰验证且 n_eff≥evict_min_neff 的退出者。
    规则 1 的阈值 = 第 POOL_TARGET 名"已证明"(n_eff ≥ min_neff) IP 的 lcb：未证明 IP 的 lcb
    是宽区间的下界，不能作为"有 POOL_TARGET 个确定更好的 IP"的证据。前 POOL_TARGET 名不参与容量退出。"""
    if guard != "none":
        return [r.ip for r in ranked], []
    evicted: dict[str, str] = {}
    proven = [r for r in ranked if r.stats.n_eff >= cfg.min_neff]
    target_lcb = proven[cfg.pool_target - 1].lcb if len(proven) >= cfg.pool_target else None
    for r in ranked:
        st = r.stats
        if st.quality is not None and st.quality.state == "ineligible":
            evicted[r.ip] = "quality_budget"
        elif (r.ip not in protected and target_lcb is not None and st.evaluation_completed
                and st.n_eff >= cfg.evict_min_neff and r.ucb < target_lcb):
            evicted[r.ip] = "unworthy"
        elif st.quality is None and st.n_eff >= cfg.min_neff and fail_lcb(st.fail, st.n_eff) > cfg.hard_max_fail:
            evicted[r.ip] = "hard_fail"   # 发布资格仍用原始失败率（保守）
        elif st.quality is None and st.consecutive_unreachable >= cfg.unreachable_rounds:
            evicted[r.ip] = "unreachable"
    # 规则 4：规则 1 是相对规则，池同质化时停摆（谁也证明不了比第 POOL_TARGET 名差），池满 → 快筛停。
    # 此时在"已表征（n_eff ≥ evict_min_neff）且不在 lcb 前 POOL_TARGET 名"的 IP 中按 ucb 升序裁最差者，
    # 每轮最多 trim_headroom 个（渐进收敛）。不裁未表征的（凭运气）、不裁前 POOL_TARGET 名；
    # 池由优质 + 未表征组成时裁不到任何人——此时快筛暂停是对的。
    limit = cfg.pool_max - cfg.trim_headroom
    remaining = [r for r in ranked if r.ip not in evicted]
    if cfg.trim_headroom > 0 and len(remaining) > limit:
        bench = {r.ip for r in remaining[: cfg.pool_target]}
        characterized = sorted((r for r in remaining
                                if (r.stats.quality is not None or
                                    (r.stats.evaluation_completed and r.stats.n_eff >= cfg.evict_min_neff))
                                and r.ip not in bench and r.ip not in protected),
                               key=lambda r: (r.ucb, r.ip))
        for r in characterized[: min(cfg.trim_headroom, len(remaining) - limit)]:
            evicted[r.ip] = "overflow"
    kept = [r.ip for r in ranked if r.ip not in evicted]
    return kept, [(r.ip, evicted[r.ip]) for r in ranked if r.ip in evicted]


def append_blacklist(path: Path, ips: list[str], now: datetime) -> None:
    if not ips:
        return
    existing = path.read_text(encoding="utf-8") if path.exists() else ""
    stamp = now.strftime(TS_FORMAT)
    atomic_write(path, existing + "".join(f"{ip}\t{stamp}\n" for ip in ips))


# ── 粘性发布 ─────────────────────────────────────────────────────────────

def publish_eligible(r: Ranked, cfg: Config, evicted: set[str]) -> bool:
    st = r.stats
    if st.quality is not None:
        return r.ip not in evicted and st.quality.state == "eligible"
    return (r.ip not in evicted and st.n_eff >= cfg.publish_min_neff and st.peak_ok
            and st.fail <= cfg.hard_max_fail)


def sticky_publish(ranked: list[Ranked], incumbents: list[str], cfg: Config,
                   evicted: set[str]) -> list[str] | None:
    """在任者保持相对顺序；仅当后位 lcb 高出前位 lcb + margin 时才上移/换入。
    合格数 < publish_top_n → None（调用方不改写 best）。返回最多 top_n 个。"""
    eligible = {r.ip: r for r in ranked if publish_eligible(r, cfg, evicted)}
    if len(eligible) < cfg.publish_top_n:
        return None
    order = [ip for ip in incumbents if ip in eligible]
    seen = set(order)
    order += [r.ip for r in ranked if r.ip in eligible and r.ip not in seen]
    changed = True
    while changed:
        changed = False
        for i in range(len(order) - 1):
            a, b = eligible[order[i]], eligible[order[i + 1]]
            if b.lcb > a.lcb + cfg.publish_margin:
                order[i], order[i + 1] = order[i + 1], order[i]
                changed = True
    if cfg.max_per_segment > 0:
        order = diversify_publish(order, eligible, cfg)
    if any(r.stats.quality is not None for r in ranked):
        members = order[:cfg.publish_top_n]
        slots = incumbents[:cfg.publish_top_n]
        newcomers = iter(ip for ip in members if ip not in slots)
        order[:cfg.publish_top_n] = [ip if ip in members else next(newcomers) for ip in slots]
        order[len(slots):cfg.publish_top_n] = list(newcomers)
    return order[: cfg.top_n]


def segment16(ip: str) -> str:
    parts = ip.split(".")
    return ".".join(parts[:2]) if len(parts) == 4 else ip


def diversify_publish(order: list[str], eligible: dict[str, Ranked], cfg: Config) -> list[str]:
    """发布集（前 publish_top_n）内同一 /16 最多 max_per_segment 个。

    同一 /16 共享路由故障域（实测池 110 个里 93 个在 172.66.0.0/16）。替换规则：找发布集中超额网段里
    lcb 最低的成员，在候补中按序找第一个所属网段未满、且 lcb ≥ 该成员 lcb − publish_margin 的 IP 换入；
    找不到则保持原样——不拿质量换多样性。被换出者落到候补原位，候补集不丢人。"""
    pub = order[: cfg.publish_top_n]
    rest = order[cfg.publish_top_n:]
    for _ in range(len(pub)):
        counts: dict[str, int] = {}
        for ip in pub:
            counts[segment16(ip)] = counts.get(segment16(ip), 0) + 1
        over = [s for s, c in counts.items() if c > cfg.max_per_segment]
        if not over:
            break
        seg = over[0]
        victim = min((ip for ip in pub if segment16(ip) == seg), key=lambda ip: eligible[ip].lcb)
        swapped = False
        for j, alt in enumerate(rest):
            if counts.get(segment16(alt), 0) >= cfg.max_per_segment:
                continue
            if eligible[alt].lcb >= eligible[victim].lcb - cfg.publish_margin:
                pub[pub.index(victim)] = alt
                rest[j] = victim
                swapped = True
                break
        if not swapped:
            break
    return pub + rest


# ── best_ips.txt ─────────────────────────────────────────────────────────

def read_incumbents(path: Path, publish_top_n: int) -> list[str]:
    """等价于 config.sh publish_set()：标记行之后以数字开头的行，取前 publish_top_n。"""
    if not path.exists():
        return []
    out: list[str] = []
    seen_marker = False
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if line.startswith("# --- BEST_IPS"):
            seen_marker = True
            continue
        if seen_marker and line[:1].isdigit():
            out.append(line.strip())
            if len(out) >= publish_top_n:
                break
    return out


def _fmt(v: float | None, spec: str = ".0f") -> str:
    return "-" if v is None else format(v, spec)


def write_best(path: Path, ranked: list[Ranked], published: list[str],
               now: datetime, cfg: Config) -> None:
    by_ip = {r.ip: r for r in ranked}
    lines = [
        f"# CFST Rank (contender pool) — {now.strftime(TS_FORMAT)}",
        f"# Top {cfg.top_n} by lcb | window {cfg.window_days}d | half-life {cfg.half_life_hours:g}h | z={cfg.z:g} sigma0={cfg.sigma0:g} peak_weight={cfg.peak_weight:g}",
        "# u = mu of per-sample f(decommoned TTFB), fail=0, peak-hour weighted ; lcb/ucb = mu -/+ z*sqrt(sigma^2+sigma0^2)/sqrt(n_eff)",
        f"# Publish gate: n_eff>={cfg.publish_min_neff:g} peak_samples>={cfg.peak_min_samples} fail<={int(cfg.hard_max_fail * 100)}% ; margin={cfg.publish_margin:g} ; max_per_/16={cfg.max_per_segment}",
        "#",
        "# IP               lcb     u       ucb     n_eff   fail%  med   p90",
        "# " + "-" * 70,
    ]
    for ip in published:
        r = by_ip[ip]
        st = r.stats
        lines.append(
            f"  {ip:<18s} {r.lcb:.4f}  {r.u:.4f}  {r.ucb:.4f}  {st.n_eff:6.2f}  "
            f"{st.fail * 100:5.1f}  {_fmt(st.med):>4s}  {_fmt(st.tail):>4s}"
        )
    lines.append("")
    lines.append(BEST_MARKER)
    lines.extend(published)
    lines.append("")
    extra = [r for r in ranked if r.ip not in set(published)][:20]
    if extra:
        lines.append(f"# --- Extended ranking ({len(published) + 1}-{len(published) + len(extra)}) ---")
        for r in extra:
            lines.append(
                f"# {r.ip:<18s} lcb={r.lcb:.4f} u={r.u:.4f} n_eff={r.stats.n_eff:.2f} "
                f"sigma={r.stats.sigma:.3f} fail={r.stats.fail * 100:.1f}% p90={_fmt(r.stats.tail)} peak24={r.stats.peak_samples}"
            )
    atomic_write(path, "\n".join(lines) + "\n")


# ── contenders.tsv ───────────────────────────────────────────────────────

@dataclass(frozen=True)
class Contender:
    ip: str
    first_seen: str
    last_sampled: str
    origin: str
    evaluated_at: str = "-"


def read_contenders(path: Path) -> list[Contender]:
    """五列状态（兼容旧四列）；非法 IP 跳过，重复保留首见，未知评估状态默认为待验证。"""
    if not path.exists():
        return []
    out: list[Contender] = []
    seen: set[str] = set()
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.rstrip("\r")
        if not line.strip() or line.startswith("#"):
            continue
        parts = line.split("\t")
        ip = parts[0].strip()
        if not is_valid_ipv4(ip) or ip in seen:
            continue
        seen.add(ip)
        get = lambda i: parts[i].strip() if len(parts) > i and parts[i].strip() else "-"  # noqa: E731
        out.append(Contender(ip, get(1), get(2), get(3), get(4)))
    return out


def _lifecycle_rows(path: Path, reference: str) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}
    return data["rows"] if data["reference"] == reference else {}


def read_lifecycle(path: Path, reference: str, now: datetime) -> dict[str, tuple[str, str]]:
    cutoff = (now - timedelta(days=7)).strftime(TS_FORMAT)
    return {ip: (first, completed) for ip, (first, completed, seen) in _lifecycle_rows(path, reference).items()
            if seen >= cutoff and is_valid_ipv4(ip) and parse_ts(first)
            and (completed == "-" or parse_ts(completed))}


def write_lifecycle(path: Path, reference: str, previous: dict[str, tuple[str, str]],
                    active: list[Contender], capacity: list[Contender], now: datetime) -> None:
    rows = {ip: row for ip, row in _lifecycle_rows(path, reference).items() if ip in previous}
    stamp = now.strftime(TS_FORMAT)
    rows.update({c.ip: [c.first_seen, c.evaluated_at, stamp] for c in active + capacity
                 if parse_ts(c.first_seen)})
    atomic_write(path, json.dumps({"reference": reference, "rows": rows}) + "\n")


def write_contenders(path: Path, rows: list[Contender]) -> None:
    body = "".join(f"{r.ip}\t{r.first_seen}\t{r.last_sampled}\t{r.origin}\t{r.evaluated_at}\n" for r in rows)
    atomic_write(path, CONTENDERS_HEADER + "\n" + body)


def complete_evaluations(contenders: list[Contender], samples: list[Sample],
                         baselines: dict[datetime, RoundInfo], stats: dict[str, Stats],
                         now: datetime, cfg: Config) -> dict[str, str]:
    """同一晚 20–21/22–23/00 时段的有效观察 + n_eff≥8；完成状态不随窗口滚动撤销。"""
    completed: dict[str, str] = {}
    pending: dict[str, datetime] = {}
    for c in contenders:
        first = parse_ts(c.first_seen)
        saved = parse_ts(c.evaluated_at)
        if first is not None and saved is not None and first <= saved <= now:
            completed[c.ip] = c.evaluated_at
        elif first is not None:
            pending[c.ip] = first
    coverage: dict[tuple[str, object], set[int]] = {}
    for sample in samples:
        first = pending.get(sample.ip)
        if first is None or not first <= sample.ts <= now or sample.ts.hour not in cfg.peak_hours:
            continue
        hour = sample.ts.hour
        if hour not in (20, 21, 22, 23, 0):
            continue
        info = baselines.get(bucket_key(sample.ts, cfg.round_minutes))
        if info is None or info.systemic_fail:
            continue
        night = (sample.ts - timedelta(days=1) if hour == 0 else sample.ts).date()
        slot = 0 if hour in (20, 21) else 1 if hour in (22, 23) else 2
        coverage.setdefault((sample.ip, night), set()).add(slot)
    for (ip, _), slots in coverage.items():
        st = stats.get(ip)
        if len(slots) == 3 and st is not None and st.n_eff >= cfg.evict_min_neff:
            completed[ip] = now.strftime(TS_FORMAT)
    return completed


# ── 一轮排名（纯函数，供 CLI 与 replay 复用） ────────────────────────────

@dataclass(frozen=True)
class Outcome:
    ranked: list[Ranked]
    core: list[str]
    challengers: list[str]
    kept: list[str]
    evicted: list[tuple[str, str]]
    published: list[str] | None   # None = 合格数不足，不改写 best
    guard: str                    # 生效守卫（含自动识别的系统性轮）
    evaluations: dict[str, str] = field(default_factory=dict)


def opportunity_tiers(ranked: list[Ranked], cfg: Config, now: datetime) -> tuple[list[str], list[str]]:
    from quality_evidence import phase

    core = [r.ip for r in ranked if r.stats.n_eff >= cfg.min_neff][:min(cfg.core_n, 10)]
    rest = [r for r in ranked if r.ip not in core and r.stats.quality.state != "ineligible"]
    slot = phase(now)

    def priority(r: Ranked):
        q = r.stats.quality
        return (not (slot and slot not in q.covered), q.last_attempt or datetime.min, -r.ucb, r.ip)

    explore = sorted((r for r in rest if r.stats.n_eff < cfg.min_neff), key=priority)
    promote = sorted((r for r in rest if r.stats.n_eff >= cfg.min_neff), key=priority)
    budget = min(cfg.challenger_max, 10)
    urgent = sorted((r for r in rest if slot and slot not in r.stats.quality.covered), key=priority)
    selected = urgent[:budget]
    chosen = {r.ip for r in selected}
    explore = [r for r in explore if r.ip not in chosen]
    promote = [r for r in promote if r.ip not in chosen]
    quota = min(cfg.explore_slots, (budget - len(selected) + 1) // 2)
    selected.extend((explore[:quota] + promote + explore[quota:])[:budget - len(selected)])
    return core, [r.ip for r in selected]


def run_rank(samples: list[Sample], pool: list[str], incumbents: list[str],
             now: datetime, cfg: Config, guard: str = "none", *,
             contenders: list[Contender] | None = None,
             evidence: list[Batch] | None = None, reference: str = "",
             lifecycle: dict[str, tuple[str, str]] | None = None,
             current_run: str | None = None) -> Outcome:
    """samples 须为窗口内全部样本（不按池过滤）：轮基线/系统性轮是轮的属性，
    与池无关，否则池收缩会改变 q，破坏幂等。"""
    qualities = {}
    if evidence is not None:
        from quality_evidence import assess, phase

        cfg = replace(cfg, peak_hours={20, 21, 22, 23}, peak_min_samples=1)
        qualities = {ip: assess(evidence, ip, reference, now) for ip in {b.ip for b in evidence} | set(pool)}
        if guard == "none" and current_run is not None and not any(
                b.run == current_run for ip in pool for b in qualities[ip].usable
        ):
            guard = "no_evidence"
        samples = []
        for ip, q in qualities.items():
            for b in q.usable:
                warm = [r for r in b.requests[1:] if r.state != "not_started"]
                tt = [r.ttfb for r in warm if r.state == "ok" and r.ttfb is not None]
                status = "PASS" if len(tt) == len(warm) else "PARTIAL" if tt else "FAIL"
                samples.append(Sample(b.ts, ip, status, round(_median(tt)) if tt else 0))
    rounds = bucket_rounds(samples, cfg.round_minutes)
    baselines = round_baselines(rounds, cfg.floor_ms, cfg.baseline_min_pass)
    if (evidence is None and guard in ("none", "coverage")
            and detect_systemic_round(baselines, now, cfg.round_minutes)):
        guard = "systemic"   # 自动识别：最新轮失败率 ≥50%
    stats = ip_stats(samples, baselines, now, cfg.half_life_hours, cfg.peak_hours,
                     cfg.floor_ms, cfg.round_minutes,
                     peak_weight=cfg.peak_weight, peak_min_samples=cfg.peak_min_samples)
    if contenders is None:
        first_seen: dict[str, datetime] = {}
        for sample in samples:
            first_seen[sample.ip] = min(sample.ts, first_seen.get(sample.ip, sample.ts))
        contenders = [Contender(ip, first_seen[ip].strftime(TS_FORMAT), "-", "replay")
                      for ip in pool if ip in first_seen]
    protected = frozenset()
    if evidence is None:
        evaluations = complete_evaluations(contenders, samples, baselines, stats, now, cfg)
    else:
        evaluations = {ip: done for ip, (_, done) in (lifecycle or {}).items()
                       if ip in pool and done != "-"}
        for c in contenders:
            q = qualities[c.ip]
            coverage = {}
            for b in q.usable:
                if phase(b.ts):
                    coverage.setdefault(b.ts.date(), set()).add(phase(b.ts))
            if q.n_eff >= cfg.evict_min_neff and {1, 2} in coverage.values():
                evaluations.setdefault(c.ip, now.strftime(TS_FORMAT))
        protected = frozenset(incumbents) | frozenset(c.ip for c in contenders
                              if (parse_ts(c.first_seen) or now) > now - timedelta(hours=48))
        for ip in pool:
            stats.setdefault(ip, Stats(0, 0, None, None, False, None, 0))
    stats = {ip: replace(st, evaluation_completed=ip in evaluations, quality=qualities.get(ip))
             for ip, st in stats.items()}
    ranked = rank_pool(pool, stats, cfg)
    if evidence is None:
        core, chal, _reserve = derive_tiers(ranked, cfg)
        kept, evicted = evict(ranked, cfg, guard, frozenset(core))
    else:
        kept, evicted = evict(ranked, cfg, guard, protected)
        kept_set = set(kept)
        core, chal = opportunity_tiers([r for r in ranked if r.ip in kept_set], cfg, now)
    published = None if evidence is not None and guard != "none" else sticky_publish(
        ranked, incumbents, cfg, {ip for ip, _ in evicted})
    return Outcome(ranked, core, chal, kept, evicted, published, guard, evaluations)


# ── CLI ──────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="contender pool ranking")
    p.add_argument("--history", type=Path, help=argparse.SUPPRESS)
    p.add_argument("--observations", type=Path)
    p.add_argument("--reference-file", type=Path)
    p.add_argument("--audit-start-ns", type=int)
    p.add_argument("--audit-run")
    p.add_argument("--audit-targets", type=Path)
    p.add_argument("--audit-p10-ms", type=int, default=150)
    p.add_argument("--audit-min-samples", type=int, default=10)
    p.add_argument("--contenders", type=Path, required=True)
    p.add_argument("--best", type=Path, required=True)
    p.add_argument("--blacklist", type=Path, required=True)
    p.add_argument("--capacity-cooldown", type=Path, default=None)
    p.add_argument("--capacity-cooldown-hours", type=float, default=6)
    p.add_argument("--now", required=True, help="YYYY-MM-DD HH:MM:SS")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--initialize-publication", action="store_true",
                   help="allow an uninitialized isolated shadow output")
    p.add_argument("--audit-requested", type=int, default=None)
    p.add_argument("--audit-returned", type=int, default=None)
    p.add_argument("--systemic", type=int, choices=(0, 1), default=0)
    p.add_argument("--audit-ok", type=int, choices=(0, 1), default=1)
    p.add_argument("--tiers-out", type=Path, default=None)
    p.add_argument("--result-out", type=Path, default=None)
    p.add_argument("--audit-min-coverage-percent", type=int, default=80)
    add_config_args(p)
    return p


def add_config_args(p: argparse.ArgumentParser) -> None:
    d = Config()
    p.add_argument("--half-life-hours", type=float, default=d.half_life_hours)
    p.add_argument("--floor-ms", type=float, default=d.floor_ms)
    p.add_argument("--z", type=float, default=d.z)
    p.add_argument("--sigma0", type=float, default=d.sigma0)
    p.add_argument("--peak-weight", type=float, default=d.peak_weight)
    p.add_argument("--peak-min-samples", type=int, default=d.peak_min_samples)
    p.add_argument("--trim-headroom", type=int, default=d.trim_headroom)
    p.add_argument("--core-n", type=int, default=d.core_n)
    p.add_argument("--challenger-max", type=int, default=d.challenger_max)
    p.add_argument("--explore-slots", type=int, default=d.explore_slots)
    p.add_argument("--max-per-segment", type=int, default=d.max_per_segment)
    p.add_argument("--evict-min-neff", type=float, default=d.evict_min_neff)
    p.add_argument("--pool-target", type=int, default=d.pool_target)
    p.add_argument("--pool-max", type=int, default=d.pool_max,
                   help="入池门控在 cycle.sh；池 > pool_max − trim_headroom 时规则 4 生效")
    p.add_argument("--publish-min-neff", type=float, default=d.publish_min_neff)
    p.add_argument("--publish-margin", type=float, default=d.publish_margin)
    p.add_argument("--top-n", type=int, default=d.top_n)
    p.add_argument("--publish-top-n", type=int, default=d.publish_top_n)
    p.add_argument("--hard-max-fail", type=float, default=d.hard_max_fail)
    p.add_argument("--peak-hours", default="20-23,0")
    p.add_argument("--window-days", type=int, default=d.window_days)


def config_from_args(args: argparse.Namespace) -> Config:
    return Config(
        half_life_hours=args.half_life_hours, floor_ms=args.floor_ms, z=args.z, sigma0=args.sigma0,
        peak_weight=args.peak_weight, peak_min_samples=args.peak_min_samples,
        trim_headroom=args.trim_headroom,
        core_n=args.core_n, challenger_max=args.challenger_max, explore_slots=args.explore_slots,
        max_per_segment=args.max_per_segment, evict_min_neff=args.evict_min_neff,
        pool_target=args.pool_target, pool_max=args.pool_max,
        publish_min_neff=args.publish_min_neff, publish_margin=args.publish_margin,
        top_n=args.top_n, publish_top_n=args.publish_top_n,
        hard_max_fail=args.hard_max_fail,
        peak_hours=parse_peak_hours(args.peak_hours), window_days=args.window_days,
    )


def resolve_guard(args: argparse.Namespace) -> str:
    return assess_audit(args.audit_requested, args.audit_returned,
                        audit_ok=args.audit_ok != 0, systemic=args.systemic == 1,
                        percent=getattr(args, 'audit_min_coverage_percent', 80)).guard


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.observations is None and (args.history is None or not args.dry_run):
        parser.error("--observations is required for online ranking; --history requires --dry-run")
    if args.observations is not None and (not args.audit_run or args.audit_targets is None
                                          or args.reference_file is None or args.audit_start_ns is None):
        parser.error("structured ranking requires a cycle ID, audit targets, receipt and start time")
    return _run_cli(args)


def _run_cli(args: argparse.Namespace) -> int:
    now = parse_ts(args.now)
    if now is None:
        print(f"rank: invalid --now {args.now!r}", file=sys.stderr)
        return 2
    cfg = config_from_args(args)
    if not math.isfinite(args.capacity_cooldown_hours) or args.capacity_cooldown_hours <= 0:
        print("rank: capacity cooldown hours must be finite and positive", file=sys.stderr)
        return 2
    capacity_path = args.capacity_cooldown or args.blacklist.with_name(".capacity_cooldown.tsv")
    if capacity_path.resolve() == args.blacklist.resolve():
        print("rank: quality and capacity cooldown paths must differ", file=sys.stderr)
        return 2
    lifecycle_path = args.contenders.with_name(args.contenders.name + ".lifecycle.json")
    if args.result_out is not None:
        paths = [args.contenders, args.best, args.blacklist, capacity_path]
        if args.history is not None:
            paths.append(args.history)
        if args.audit_targets is not None:
            paths.append(args.audit_targets)
        if args.observations is not None:
            paths.extend([args.observations, lifecycle_path, args.best.with_name(".publish_desired.json")])
        if args.reference_file is not None:
            paths.append(args.reference_file)
        if args.tiers_out is not None:
            paths.extend([args.tiers_out, args.tiers_out / 'core.txt', args.tiers_out / 'challengers.txt'])
        preflight_receipt(args.result_out, paths)
    guard = resolve_guard(args)

    contenders = read_contenders(args.contenders)   # 文件不存在 → 空池，不报错
    pool = [c.ip for c in contenders]
    samples = [] if args.observations is not None else load_history(args.history, now, cfg.window_days)
    reference = ""
    batch_id = ""
    evidence = None
    lifecycle = {}
    if args.observations is not None:
        from audit_evidence import completed

        started = datetime.fromtimestamp(args.audit_start_ns // 10**9)
        audit = completed(args.observations, args.reference_file,
                          args.audit_targets.read_text().split(), args.audit_run, started, now,
                          percent=args.audit_min_coverage_percent, p10_ms=args.audit_p10_ms,
                          min_samples=args.audit_min_samples)
        guard = audit.guard if args.audit_ok else "no_evidence"
        reference = audit.reference
        evidence = list(audit.evidence)
        batch_id = args.audit_run
        if reference:
            lifecycle = read_lifecycle(lifecycle_path, reference, now)
            contenders = [replace(c, first_seen=lifecycle.get(c.ip, (now.strftime(TS_FORMAT), "-"))[0])
                          for c in contenders]
    from dns_selection import Choice
    from publication_snapshot import FILENAME, Publication, read, write

    publication_path = args.best.with_name(FILENAME)
    previous_publication = None
    previous_choice = Choice("")
    if evidence is None:
        incumbents = read_incumbents(args.best, cfg.publish_top_n)
    else:
        try:
            previous_publication = read(publication_path, expected_count=cfg.publish_top_n)
            incumbents = list(previous_publication.members)
            previous_choice = previous_publication.choice
        except FileNotFoundError:
            if not (args.initialize_publication or args.dry_run):
                print(f"rank: publication snapshot missing at {publication_path}", file=sys.stderr)
                return 1
            incumbents = read_incumbents(args.best, cfg.publish_top_n)
        except (OSError, TypeError, ValueError) as exc:
            print(f"rank: invalid publication snapshot: {exc}", file=sys.stderr)
            return 1
    out = run_rank(samples, pool, incumbents, now, cfg, guard, contenders=contenders,
                   evidence=evidence, reference=reference, lifecycle=lifecycle,
                   current_run=batch_id if evidence is not None else None)
    guard = out.guard

    if guard == "no_evidence" or out.published is None:
        published = incumbents
        changed = 0
        write_best_file = False
    else:
        published = out.published
        changed = int(published[: cfg.publish_top_n] != incumbents)
        write_best_file = True

    # 更新 contenders：last_sampled = 窗口内最近样本；淘汰者移除
    evicted_ips = {ip for ip, _ in out.evicted}
    by_ip = {r.ip: r for r in out.ranked}
    new_rows: list[Contender] = []
    for c in contenders:
        if c.ip in evicted_ips:
            continue
        seen = by_ip[c.ip].stats.last_seen
        last = seen.strftime(TS_FORMAT) if seen else c.last_sampled
        completed = c.evaluated_at if evidence is not None and not reference else out.evaluations.get(c.ip, "-")
        new_rows.append(Contender(c.ip, c.first_seen, last, c.origin, completed))

    # 人类可读输出
    print(f"rank: now={args.now} samples={len(samples)} pool_in={len(pool)} guard={guard}"
          f"{' (dry-run)' if args.dry_run else ''}")
    if evidence is not None:
        print(f"rank: stable MiSub members={len(published)}; current reference only")
        print(f"Top {cfg.top_n} by lcb (strength):")
        display = [r.ip for r in out.ranked[:cfg.top_n]]
    else:
        print(f"Top {cfg.top_n} by lcb (published set first):")
        display = published
    for ip in display:
        r = by_ip.get(ip)
        if r is None:
            print(f"  {ip:<18s} (incumbent, not in pool)")
            continue
        st = r.stats
        print(f"  {ip:<18s} lcb={r.lcb:.4f} u={r.u:.4f} ucb={r.ucb:.4f} n_eff={st.n_eff:.2f} "
              f"sigma={st.sigma:.3f} fail={st.fail * 100:.1f}% med={_fmt(st.med)} p90={_fmt(st.tail)} "
              f"peak24={st.peak_samples} peak_ok={int(st.peak_ok)}")
        if st.quality is not None:
            q = st.quality
            for name, window in (("offpeak", q.offpeak), ("peak", q.peak)):
                print(f"    {q.state} {name}: n_eff={q.n_eff:.2f} unresolved={q.unresolved} "
                      f"warm={window.successes}/{window.attempts} "
                      f"med={_fmt(window.median)} p90={_fmt(window.p90)} p95={_fmt(window.p95)}")
    if len(out.kept) > cfg.pool_max - cfg.trim_headroom:
        print(f"rank: note: pool size {len(out.kept)} > POOL_MAX−headroom {cfg.pool_max - cfg.trim_headroom}; "
              f"rule 4 trims <= {cfg.trim_headroom} characterized IPs per run")
    if out.evicted:
        print("Evicted:" if not args.dry_run else "Eviction candidates:")
        for ip, reason in out.evicted:
            print(f"  {ip:<18s} {reason}")
    if out.published is None and guard != "no_evidence":
        print(f"rank: WARNING eligible publish set < {cfg.publish_top_n}; best not rewritten", file=sys.stderr)

    if not args.dry_run:
        if reference:
            capacity = {ip for ip, why in out.evicted if why == "overflow"}
            evicted_rows = [replace(c, evaluated_at=out.evaluations.get(c.ip, "-"))
                            for c in contenders if c.ip in capacity]
            write_lifecycle(lifecycle_path, reference, lifecycle, new_rows, evicted_rows, now)
        publication = previous_publication
        if (evidence is not None and guard == "none" and published
                and (write_best_file or (reference and batch_id))):
            from dns_selection import batch_order, choose

            members = published[:cfg.publish_top_n]
            previous = previous_choice
            if not previous.active:
                previous = replace(previous, active=incumbents[0] if incumbents else members[0])
            if reference and batch_id:
                eligible = {r.ip for r in out.ranked if publish_eligible(r, cfg, evicted_ips)}
                rejected = evicted_ips | {r.ip for r in out.ranked if r.stats.quality.state == "ineligible"}
                order = [r.ip for r in out.ranked]
                fresh = {ip for ip in eligible if any(b.run == batch_id for b in by_ip[ip].stats.quality.usable)}
                if previous.active in rejected or previous.active not in members:
                    eligible = fresh
                winner = next((ip for ip in order if ip in eligible and ip in members), "")
                if winner in fresh and batch_order(batch_id) > batch_order(previous.last_batch):
                    if previous.reference != reference:
                        previous = replace(previous, challenger="")
                    previous = replace(choose(previous, members, eligible, rejected, order, batch_id),
                                       reference=reference)
            if previous.active not in members:
                previous = replace(previous, active="", challenger="")
            publication = Publication(tuple(members), previous)
        write_contenders(args.contenders, new_rows)
        if write_best_file:
            kept_set = set(out.kept)
            write_best(args.best, [r for r in out.ranked if r.ip in kept_set], published, now, cfg)
        if publication is not None and publication != previous_publication:
            write(publication_path, publication)
        append_blacklist(args.blacklist, [ip for ip, why in out.evicted if why != "overflow"], now)
        record_cooldown(capacity_path, [ip for ip, why in out.evicted if why == "overflow"],
                        now, args.capacity_cooldown_hours)
    # tiers 是调度草稿而非生产数据：dry-run 也要写，fast 周期靠它决定采样对象
    if args.tiers_out is not None:
        args.tiers_out.mkdir(parents=True, exist_ok=True)
        atomic_write(args.tiers_out / "core.txt", "".join(f"{ip}\n" for ip in out.core))
        atomic_write(args.tiers_out / "challengers.txt", "".join(f"{ip}\n" for ip in out.challengers))

    receipt = RankReceipt(now.isoformat(), len(new_rows), len(out.core), len(out.challengers), len(out.evicted),
                          published[:cfg.publish_top_n], bool(changed), guard,
                          sum(c.evaluated_at != '-' for c in new_rows), sum(c.evaluated_at == '-' for c in new_rows),
                          sum(why != 'overflow' for _, why in out.evicted),
                          sum(why == 'overflow' for _, why in out.evicted), args.dry_run)
    if args.result_out is not None:
        receipt.write(args.result_out)
    print(receipt.summary())

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
