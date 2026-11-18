"""rank.py 统计核心：半衰期加权、轮桶与去共因、加权分位数、置信区间。

全部为纯函数断言，不触网、不读生产数据。
"""
from __future__ import annotations

import math
import sys
from datetime import datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import rank  # noqa: E402

NOW = datetime(2026, 10, 15, 12, 0, 0)


def S(ts: datetime, ip: str, status: str, median: int, reason: str = ""):
    return rank.Sample(ts, ip, status, median, reason)


def test_half_life_weights_and_n_eff() -> None:
    samples = [
        S(NOW, "10.0.0.1", "PASS", 50),
        S(NOW - timedelta(hours=24), "10.0.0.1", "PASS", 50),
        S(NOW - timedelta(hours=48), "10.0.0.1", "PASS", 50),
    ]
    assert rank.sample_weight(samples[1].ts, NOW, 24.0) == 0.5
    assert rank.sample_weight(samples[2].ts, NOW, 24.0) == 0.25
    stats = rank.ip_stats(samples, {}, NOW, 24.0, set(), 50)
    assert math.isclose(stats["10.0.0.1"].n_eff, 1.75)


def test_bucket_rounds_groups_ten_minute_windows() -> None:
    t0 = datetime(2026, 10, 15, 12, 3, 0)
    samples = [
        S(t0, "10.0.0.1", "PASS", 50),
        S(t0 + timedelta(minutes=6), "10.0.0.2", "PASS", 50),   # 12:09 同桶
        S(t0 + timedelta(minutes=8), "10.0.0.3", "PASS", 50),   # 12:11 下一桶
    ]
    rounds = rank.bucket_rounds(samples, 10)
    assert sorted(rounds) == [datetime(2026, 10, 15, 12, 0), datetime(2026, 10, 15, 12, 10)]
    assert [s.ip for s in rounds[datetime(2026, 10, 15, 12, 0)]] == ["10.0.0.1", "10.0.0.2"]


def test_round_baseline_requires_ten_pass_samples() -> None:
    t0 = datetime(2026, 10, 15, 12, 0, 0)
    small = [S(t0, f"10.0.0.{i}", "PASS", 300) for i in range(9)]
    big = [S(t0, f"10.0.1.{i}", "PASS", 300) for i in range(10)]
    small_info = rank.round_baselines(rank.bucket_rounds(small, 10), 50, 10)[t0]
    big_info = rank.round_baselines(rank.bucket_rounds(big, 10), 50, 10)[t0]
    assert small_info.baseline == 50
    assert big_info.baseline == 300
    assert small_info.systemic_fail is False and big_info.systemic_fail is False


def test_decommon_q_subtracts_round_excess_only() -> None:
    assert rank.decommon(300, 300, 50) == 50
    assert rank.decommon(120, 300, 50) == 0      # 不为负
    assert rank.decommon(120, 50, 50) == 120
    assert rank.decommon(120, 30, 50) == 120


def test_systemic_round_fail_not_charged_to_ip() -> None:
    t0 = datetime(2026, 10, 15, 11, 50, 0)
    bad_round = [S(t0, f"10.0.0.{i}", "FAIL", 0, "timeout") for i in range(5)]
    bad_round += [S(t0, f"10.0.1.{i}", "PASS", 50) for i in range(5)]  # 50% 失败
    good_round = [S(NOW, f"10.0.0.{i}", "PASS", 50) for i in range(1, 6)]
    good_round += [S(NOW, "10.0.0.0", "FAIL", 0, "timeout")]
    rounds = rank.bucket_rounds(bad_round + good_round, 10)
    baselines = rank.round_baselines(rounds, 50, 10)
    assert baselines[t0].systemic_fail is True
    assert baselines[datetime(2026, 10, 15, 12, 0)].systemic_fail is False
    stats = rank.ip_stats(bad_round + good_round, baselines, NOW, 24.0, set(), 50)
    assert stats["10.0.0.1"].fail == 0.0          # 系统性轮 FAIL 不计
    assert stats["10.0.0.0"].fail == 1.0          # 正常轮 FAIL 计入
    assert stats["10.0.0.0"].consecutive_unreachable == 1
    assert stats["10.0.0.1"].consecutive_unreachable == 0


def test_weighted_quantiles_hand_built() -> None:
    values = [10, 20, 30, 40, 50]
    weights = [1.0, 1.0, 1.0, 1.0, 1.0]
    assert rank.weighted_quantile(values, weights, 0.5) == 30
    assert rank.weighted_quantile(values, weights, 0.9) == 50
    # 权重偏向小值：p50 落在 10
    assert rank.weighted_quantile(values, [4.0, 1.0, 0.5, 0.5, 0.5], 0.5) == 10
    assert rank.weighted_quantile([5, 1, 3], [1, 1, 1], 0.5) == 3  # 输入无需有序
    assert rank.weighted_quantile([], [], 0.5) is None


def test_ip_stats_tail_and_med_use_decommoned_q() -> None:
    t0 = datetime(2026, 10, 15, 11, 0, 0)
    # 一个基线 300 的轮：10 个 PASS=300，目标 IP 在该轮 PASS=350 → q=100
    crowd = [S(t0, f"10.0.9.{i}", "PASS", 300) for i in range(10)]
    target = [S(t0, "10.0.0.1", "PASS", 350), S(NOW, "10.0.0.1", "PASS", 60)]
    rounds = rank.bucket_rounds(crowd + target, 10)
    baselines = rank.round_baselines(rounds, 50, 10)
    stats = rank.ip_stats(crowd + target, baselines, NOW, 24.0, set(), 50)["10.0.0.1"]
    assert stats.tail == 100
    assert stats.med == 60
    assert stats.last_seen == NOW


def test_consecutive_unreachable_counts_latest_streak() -> None:
    ip = "10.0.0.1"
    samples = [
        S(NOW - timedelta(hours=3), ip, "PASS", 50),
        S(NOW - timedelta(hours=2), ip, "FAIL", 0, "timeout"),
        S(NOW - timedelta(hours=1), ip, "FAIL", 0, "timeout"),
        S(NOW, ip, "FAIL", 0, "timeout"),
    ]
    assert rank.ip_stats(samples, {}, NOW, 24.0, set(), 50)[ip].consecutive_unreachable == 3
    broken = samples + [S(NOW + timedelta(minutes=1), ip, "PASS", 50)]
    assert rank.ip_stats(broken, {}, NOW, 24.0, set(), 50)[ip].consecutive_unreachable == 0
    slow = samples[:3] + [S(NOW, ip, "FAIL", 600, "slow_ttfb")]
    assert rank.ip_stats(slow, {}, NOW, 24.0, set(), 50)[ip].consecutive_unreachable == 0


def test_utility_without_samples_is_maximally_uncertain() -> None:
    st = rank.Stats(n_eff=0.0, fail=0.0, med=None, tail=None, peak_ok=False,
                    last_seen=None, consecutive_unreachable=0)
    u, lcb, ucb = rank.utility(st, rank.Config())
    assert lcb <= 0.0 and ucb >= 1.0


def test_load_history_window_and_validation(tmp_path: Path) -> None:
    p = tmp_path / "h.tsv"
    p.write_text(
        "2026-10-15 11:00:00\t10.0.0.1\tPASS\t50\t\n"
        "2026-10-07 11:00:00\t10.0.0.1\tPASS\t50\t\n"      # 超出 7 天
        "2026-10-15 13:00:00\t10.0.0.1\tPASS\t50\t\n"      # 晚于 now
        "bad line\n"
        "2026-10-15 11:00:00\t999.1.1.1\tPASS\t50\t\n"
        "2026-10-15 11:30:00\t10.0.0.2\tFAIL\t0\ttimeout\n",
        encoding="utf-8",
    )
    samples = rank.load_history(p, NOW, 7)
    assert [(s.ip, s.status, s.median, s.reason) for s in samples] == [
        ("10.0.0.1", "PASS", 50, ""),
        ("10.0.0.2", "FAIL", 0, "timeout"),
    ]
    assert rank.load_history(tmp_path / "missing.tsv", NOW, 7) == []


def test_detect_systemic_round_uses_now_bucket_or_latest_within_15min() -> None:
    def mk(t: datetime, fails: int, passes: int) -> list:
        return [S(t, f"10.0.0.{i}", "FAIL", 0, "timeout") for i in range(fails)] + \
               [S(t, f"10.0.1.{i}", "PASS", 50) for i in range(passes)]
    bad = mk(datetime(2026, 10, 15, 11, 52), 5, 5)
    good = mk(datetime(2026, 10, 15, 11, 52), 1, 9)
    assert rank.detect_systemic_round(rank.round_baselines(rank.bucket_rounds(bad, 10), 50, 10),
                                      datetime(2026, 10, 15, 11, 58), 10) is True   # now 同桶
    assert rank.detect_systemic_round(rank.round_baselines(rank.bucket_rounds(bad, 10), 50, 10),
                                      datetime(2026, 10, 15, 12, 4), 10) is True    # 15 分钟内最新桶
    assert rank.detect_systemic_round(rank.round_baselines(rank.bucket_rounds(bad, 10), 50, 10),
                                      datetime(2026, 10, 15, 12, 6), 10) is False   # 桶 11:50 已超 15 分钟
    assert rank.detect_systemic_round(rank.round_baselines(rank.bucket_rounds(good, 10), 50, 10),
                                      datetime(2026, 10, 15, 11, 58), 10) is False
    # 15 分钟内有更新的正常桶 → 以最新桶为准
    mixed = bad + mk(datetime(2026, 10, 15, 12, 1), 0, 10)
    assert rank.detect_systemic_round(rank.round_baselines(rank.bucket_rounds(mixed, 10), 50, 10),
                                      datetime(2026, 10, 15, 12, 4), 10) is False
    assert rank.detect_systemic_round({}, datetime(2026, 10, 15, 12, 4), 10) is False


# ── 失败率置信下界（规则 2 硬失败）────────────────────────────────────────
# 硬失败只认统计上成立的失败率：Wilson 下界（z=1）。1/5 → ≈0.08、1/3 → ≈0.14 不触发 30% 硬门；
# 20/87 → ≈0.19、3/3 → 0.5 照常。

def test_fail_lcb_is_wilson_lower_bound_z1() -> None:
    assert rank.fail_lcb(0.0, 5.0) == 0.0
    assert rank.fail_lcb(0.2, 0.0) == 0.0
    assert math.isclose(rank.fail_lcb(0.2, 5.0), 0.0794, abs_tol=5e-4)
    assert math.isclose(rank.fail_lcb(20 / 87, 87.0), 0.188, abs_tol=2e-3)
    assert math.isclose(rank.fail_lcb(1 / 3, 3.0), 0.136, abs_tol=2e-3)
    assert rank.fail_lcb(1.0, 3.0) > 0.5
    # 单调：样本越多下界越接近点估计
    assert rank.fail_lcb(0.3, 10.0) < rank.fail_lcb(0.3, 100.0) < 0.3


# ── 估计量：逐样本效用 → 时效×时段加权均值/方差 → 方差感知区间 ─────────────
# 排名与淘汰只看一个估计量 mu 及其置信区间；尾部与失败都在逐样本分数里（300ms → 0.10，失败 → 0），
# 区间宽度来自样本离散度 σ̂（加先验 σ0）。

def test_u_tail_is_the_per_sample_curve_with_feel_thresholds() -> None:
    assert math.isclose(rank.u_tail(50), 0.90625)
    assert math.isclose(rank.u_tail(80), 0.85)
    assert math.isclose(rank.u_tail(150), 0.45)
    assert math.isclose(rank.u_tail(300), 0.10)
    assert rank.u_tail(500) == 0.0
    assert rank.u_tail(None) == 0.15


def test_ip_stats_mu_is_weighted_mean_of_per_sample_scores_and_fail_scores_zero() -> None:
    ip = "10.0.0.1"
    ts = [NOW - timedelta(minutes=10 * i) for i in range(4)]        # 近乎同权
    samples = [S(ts[0], ip, "PASS", 50), S(ts[1], ip, "PASS", 50), S(ts[2], ip, "PASS", 300), S(ts[3], ip, "FAIL", 0, "timeout")]
    st = rank.ip_stats(samples, {}, NOW, 24.0, set(), 50)[ip]
    scores = [rank.u_tail(50), rank.u_tail(50), rank.u_tail(300), 0.0]
    assert math.isclose(st.mu, sum(scores) / 4, abs_tol=0.01)
    assert st.sigma > 0.3                                             # 双峰 → 大离散度
    assert math.isclose(st.fail, 0.25, abs_tol=0.01)
    assert math.isclose(st.n_eff, 4.0, abs_tol=0.05)
    assert st.tail == 300 and st.med == 50                            # 展示量仍在


def test_ip_stats_peak_weight_shapes_mu_but_not_n_eff() -> None:
    ip = "10.0.0.1"
    peak = rank.parse_peak_hours("20-23,0")
    now = datetime(2026, 10, 15, 23, 0, 0)
    day = [S(now.replace(hour=h), ip, "PASS", 50) for h in (10, 12, 14, 16, 18)]   # 白天 5 个 50ms
    night = [S(now.replace(hour=h), ip, "PASS", 300) for h in (20, 22)]           # 晚高峰 2 个 300ms
    flat = rank.ip_stats(day + night, {}, now, 1e9, peak, 50, peak_weight=1.0)[ip]
    weighted = rank.ip_stats(day + night, {}, now, 1e9, peak, 50, peak_weight=3.0)[ip]
    s_good, s_bad = rank.u_tail(50), rank.u_tail(300)
    assert math.isclose(flat.mu, (5 * s_good + 2 * s_bad) / 7, abs_tol=1e-6)
    assert math.isclose(weighted.mu, (5 * s_good + 6 * s_bad) / 11, abs_tol=1e-6)
    assert weighted.mu < flat.mu                                      # 晚高峰差的 IP 被看见
    # n_eff = min(Σd, Kish)：Σd=7；Kish=(5+6)²/(5+2·9)=121/23≈5.26 → 不因加权虚增
    assert math.isclose(flat.n_eff, 7.0, abs_tol=1e-6)
    assert math.isclose(weighted.n_eff, 121 / 23, abs_tol=1e-6)
    assert weighted.peak_samples == 2 and flat.peak_samples == 2


def test_peak_ok_requires_peak_min_samples_within_24h() -> None:
    peak = rank.parse_peak_hours("20-23,0")
    assert peak == {20, 21, 22, 23, 0}
    assert rank.parse_peak_hours("22-3") == {22, 23, 0, 1, 2, 3}
    ip = "10.0.0.1"
    now = datetime(2026, 10, 16, 9, 0, 0)
    three = [S(datetime(2026, 10, 15, 20, 0), ip, "PASS", 50), S(datetime(2026, 10, 15, 22, 0), ip, "PASS", 50),
             S(datetime(2026, 10, 16, 0, 0), ip, "PASS", 50)]
    two = three[:2]
    stale = two + [S(datetime(2026, 10, 14, 23, 0), ip, "PASS", 50)]     # >24h 前
    offpeak = two + [S(datetime(2026, 10, 16, 5, 0), ip, "PASS", 50)]
    peak_fail = two + [S(datetime(2026, 10, 16, 0, 0), ip, "FAIL", 0, "timeout")]  # 失败也是"扛过"的证据
    st = lambda rows, **kw: rank.ip_stats(rows, {}, now, 24.0, peak, 50, **kw)[ip]
    assert st(three).peak_ok is True and st(three).peak_samples == 3
    assert st(two).peak_ok is False
    assert st(stale).peak_ok is False
    assert st(offpeak).peak_ok is False
    assert st(peak_fail).peak_ok is True
    assert st(two, peak_min_samples=2).peak_ok is True


def test_utility_interval_is_variance_aware_with_prior_floor() -> None:
    cfg = rank.Config()
    assert cfg.z == 1.0 and cfg.sigma0 == 0.15
    stable = rank.Stats(n_eff=9.0, fail=0.0, med=50, tail=50, peak_ok=True, last_seen=NOW,
                        consecutive_unreachable=0, mu=0.90, sigma=0.03)
    spiky = rank.Stats(n_eff=9.0, fail=0.0, med=50, tail=300, peak_ok=True, last_seen=NOW,
                       consecutive_unreachable=0, mu=0.80, sigma=0.30)
    u, lcb, ucb = rank.utility(stable, cfg)
    assert u == 0.90
    assert math.isclose(ucb - u, math.sqrt(0.03 ** 2 + 0.15 ** 2) / 3) and math.isclose(u - lcb, ucb - u)
    u2, lcb2, ucb2 = rank.utility(spiky, cfg)
    assert math.isclose(ucb2 - u2, math.sqrt(0.30 ** 2 + 0.15 ** 2) / 3)
    assert (ucb2 - u2) > 2 * (ucb - u)             # 离散 IP 区间宽一倍以上
    assert lcb2 < lcb and ucb2 > lcb               # 丢 core 位（lcb 低）但不"确定更差"（ucb 仍高于稳定者的 lcb）
    # 5×50ms + 1×300ms：mu≈0.77，σ̂≈0.30，n=6 → half≈0.137 → ucb≈0.91 → 不会被判"确定更差"
    blip = rank.Stats(n_eff=6.0, fail=0.0, med=50, tail=300, peak_ok=True, last_seen=NOW,
                      consecutive_unreachable=0, mu=0.772, sigma=0.30)
    _, _, ucb3 = rank.utility(blip, cfg)
    assert ucb3 > 0.90
