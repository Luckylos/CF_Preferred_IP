"""rank.py 策略层：层派生、守卫淘汰、粘性发布、best_ips 写法、幂等。"""
from __future__ import annotations

import subprocess
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import rank  # noqa: E402

NOW = datetime(2026, 10, 15, 12, 0, 0)
CFG = rank.Config()


def R(ip: str, lcb: float, ucb: float | None = None, n_eff: float = 10.0,
      fail: float = 0.0, peak_ok: bool = True, unreachable: int = 0) -> rank.Ranked:
    st = rank.Stats(n_eff=n_eff, fail=fail, med=50, tail=50, peak_ok=peak_ok,
                    last_seen=NOW, consecutive_unreachable=unreachable, evaluation_completed=True)
    u = lcb + 0.05
    return rank.Ranked(ip, st, u, lcb, ucb if ucb is not None else u + 0.05)


def ranked(rows: list[rank.Ranked]) -> list[rank.Ranked]:
    return sorted(rows, key=lambda r: (-r.lcb, -r.u, r.ip))


# ── 层派生 ──────────────────────────────────────────────────────────────

def test_derive_tiers_core_challenger_reserve() -> None:
    rows = [R(f"10.0.0.{i}", 0.90 - i * 0.01) for i in range(10)]      # lcb 0.90..0.81
    rows += [R("198.51.100.10", 0.80, ucb=0.805), R("198.51.100.11", 0.79, ucb=0.81)]  # ucb ≤ 0.81 → reserve
    rows.append(R("198.51.100.12", 0.50, ucb=0.85, n_eff=1.0))             # ucb > core 末位 lcb(0.81)
    rows.append(R("198.51.100.13", 0.50, ucb=0.70, n_eff=1.0))             # reserve
    rows.append(R("198.51.100.14", 0.95, ucb=0.99, n_eff=2.0))             # n_eff<3 不进 core 但是 challenger
    core, chal, reserve = rank.derive_tiers(ranked(rows), CFG)
    assert core == [f"10.0.0.{i}" for i in range(10)]
    assert set(chal) == {"198.51.100.14", "198.51.100.12"}
    assert "198.51.100.10" in reserve and "198.51.100.11" in reserve and "198.51.100.13" in reserve


def test_derive_tiers_challenger_capped() -> None:
    rows = [R(f"10.0.0.{i}", 0.90 - i * 0.01) for i in range(10)]
    rows += [R(f"10.0.1.{i}", 0.30, ucb=0.95, n_eff=1.0) for i in range(15)]
    core, chal, reserve = rank.derive_tiers(ranked(rows), CFG)
    assert len(core) == 10 and len(chal) == 10 and len(reserve) == 5


# ── 淘汰 ────────────────────────────────────────────────────────────────

def _big_pool(n: int = 61) -> list[rank.Ranked]:
    return [R(f"10.1.{i // 256}.{i % 256}", 0.90 - i * 0.001) for i in range(n)]


def test_evict_rule1_ucb_below_pool_target_lcb() -> None:
    rows = _big_pool(60)                       # 60 个成熟 IP，第 60 名 lcb = 0.841
    rows.append(R("192.0.2.10", 0.50, ucb=0.80, n_eff=8.0))
    rows.append(R("192.0.2.11", 0.50, ucb=0.80, n_eff=7.9))   # n_eff<evict_min_neff(8) 豁免
    kept, evicted = rank.evict(ranked(rows), CFG, guard="none")
    assert dict(evicted) == {"192.0.2.10": "unworthy"}
    assert "192.0.2.11" in kept


def test_evict_rule1_threshold_uses_proven_ips_only() -> None:
    # 未证明 IP（n_eff<3）的 lcb 是宽区间下界，169 个 2 样本 IP 会把"第 60 名 lcb"抬到 0.845 误判成熟 IP。
    # 阈值只能来自已证明 IP；不足 POOL_TARGET 个则不触发。
    proven = [R(f"10.0.{i // 256}.{i % 256}", 0.90 - i * 0.001) for i in range(30)]
    fresh = [R(f"10.1.{i // 256}.{i % 256}", 0.845, ucb=1.0, n_eff=2.0) for i in range(169)]
    weak = R("192.0.2.10", 0.70, ucb=0.80, n_eff=18.0)    # 成熟但 ucb 低于试用者 lcb
    cfg = rank.Config(trim_headroom=0)                   # 隔离规则 1（规则 4 见 test_evict_rule4_*）
    kept, evicted = rank.evict(ranked(proven + fresh + [weak]), cfg, guard="none")
    assert evicted == [] and "192.0.2.10" in kept         # 已证明 IP 只有 31 个 < 60 → 不触发
    proven60 = [R(f"10.0.{i // 256}.{i % 256}", 0.90 - i * 0.001) for i in range(60)]
    kept, evicted = rank.evict(ranked(proven60 + fresh + [weak]), cfg, guard="none")
    assert dict(evicted) == {"192.0.2.10": "unworthy"}     # 第 60 名已证明 lcb=0.841 > ucb 0.80


def test_evict_rule2_hard_fail() -> None:
    # 硬失败按置信下界：0.5@n=40 下界≈0.42 > 0.30 → 淘汰；n_eff<3 豁免；0.31@n=3 见下一个测试
    rows = [R("198.51.100.15", 0.9), R("198.51.100.16", 0.5, fail=0.5, n_eff=40.0),
            R("198.51.100.17", 0.5, fail=0.9, n_eff=2.5)]
    kept, evicted = rank.evict(ranked(rows), CFG, guard="none")
    assert dict(evicted) == {"198.51.100.16": "hard_fail"}


def test_evict_rule3_consecutive_unreachable() -> None:
    rows = [R("198.51.100.15", 0.9), R("198.51.100.16", 0.5, unreachable=3, n_eff=1.0),
            R("198.51.100.17", 0.5, unreachable=2)]
    kept, evicted = rank.evict(ranked(rows), CFG, guard="none")
    assert dict(evicted) == {"198.51.100.16": "unreachable"}


def test_evict_rule4_overflow_trims_only_characterized_lowest_ucb_and_at_most_headroom() -> None:
    # 规则 1 是相对规则，池同质化时停摆（谁也证明不了比第 60 名差），池满 → 快筛停。
    # 池 > pool_max − headroom 时按 ucb 升序裁已表征（n_eff ≥ evict_min_neff）且不在前 POOL_TARGET 名的最差者，
    # 每轮 ≤ headroom；未表征的不裁（凭运气）；超大池渐进收敛。
    cfg = rank.Config(pool_max=90, trim_headroom=20, evict_min_neff=8.0, pool_target=60)
    mature = [R(f"10.0.{i // 256}.{i % 256}", 0.90 - i * 0.001, ucb=0.95 - i * 0.001, n_eff=20.0) for i in range(60)]
    # 同质的中庸 IP：lcb 低于前 60 名但 ucb 高于第 60 名 lcb（0.841）→ 规则 1 证明不了它们更差
    weak = [R(f"10.2.0.{i}", 0.80 - i * 0.001, ucb=0.90 - i * 0.001, n_eff=9.0) for i in range(30)]
    fresh = [R(f"10.1.{i // 256}.{i % 256}", 0.30, ucb=1.2, n_eff=0.5) for i in range(200)]            # 未表征
    rows = ranked(mature + weak + fresh)       # 290 > 70
    assert rank.evict(rows, rank.Config(pool_max=90, trim_headroom=0, pool_target=60), guard="none")[1] == []  # 规则 1 停摆
    kept, evicted = rank.evict(rows, cfg, guard="none")
    reasons = dict(evicted)
    assert len(evicted) == 20 and set(reasons.values()) == {"overflow"}          # 每轮最多 headroom 个
    assert set(reasons) == {f"10.2.0.{i}" for i in range(10, 30)}               # ucb 最低的 20 个已表征者
    assert all(r.ip in kept for r in fresh) and all(r.ip in kept for r in mature)
    # 池在余量以内：不裁
    assert rank.evict(ranked(mature + weak[:10]), cfg, guard="none")[1] == []
    # 只差 3 个：只裁 3 个
    kept, evicted = rank.evict(ranked(mature + weak[:13]), cfg, guard="none")
    assert len(evicted) == 3 and set(dict(evicted)) == {f"10.2.0.{i}" for i in range(10, 13)}
    # 优质 + 未表征：前 POOL_TARGET 名受保护，裁不到任何人（快筛暂停，先把手里的看清楚）
    assert rank.evict(ranked(mature + fresh), cfg, guard="none")[1] == []
    # 守卫轮不裁
    assert rank.evict(rows, cfg, guard="coverage")[1] == []


def test_evict_guard_blocks_all_rules() -> None:
    rows = _big_pool(95)
    rows.append(R("192.0.2.10", 0.1, ucb=0.2, n_eff=5.0, fail=0.5, unreachable=3))
    for guard in ("coverage", "systemic", "no_evidence"):
        kept, evicted = rank.evict(ranked(rows), CFG, guard=guard)
        assert evicted == [] and len(kept) == 96


def test_blacklist_line_format(tmp_path: Path) -> None:
    bl = tmp_path / "bl.tsv"
    bl.write_text("203.0.113.10\t2026-10-14 00:00:00\n", encoding="utf-8")
    rank.append_blacklist(bl, ["198.51.100.16", "198.51.100.17"], NOW)
    assert bl.read_text(encoding="utf-8") == (
        "203.0.113.10\t2026-10-14 00:00:00\n"
        "198.51.100.16\t2026-10-15 12:00:00\n198.51.100.17\t2026-10-15 12:00:00\n"
    )


# ── 粘性发布 ─────────────────────────────────────────────────────────────

def test_sticky_publish_keeps_order_within_margin_and_swaps_beyond() -> None:
    rows = ranked([R("B", 0.900), R("A", 0.890), R("D", 0.880), R("C", 0.850)])
    out = rank.sticky_publish(rows, ["A", "B", "C"], CFG, evicted=set())
    assert out[:3] == ["A", "B", "D"]


def test_sticky_publish_incumbent_losing_eligibility_is_replaced_immediately() -> None:
    rows = ranked([R("A", 0.90, fail=0.35), R("B", 0.89), R("C", 0.88), R("D", 0.879)])
    assert rank.sticky_publish(rows, ["A", "B", "C"], CFG, evicted=set())[:3] == ["B", "C", "D"]
    rows = ranked([R("A", 0.90, peak_ok=False), R("B", 0.89), R("C", 0.88), R("D", 0.879)])
    assert rank.sticky_publish(rows, ["A", "B", "C"], CFG, evicted=set())[:3] == ["B", "C", "D"]
    rows = ranked([R("A", 0.90), R("B", 0.89), R("C", 0.88), R("D", 0.879)])
    assert rank.sticky_publish(rows, ["A", "B", "C"], CFG, evicted={"A"})[:3] == ["B", "C", "D"]


def test_sticky_publish_requires_min_neff_and_returns_none_when_short() -> None:
    rows = ranked([R("A", 0.90, n_eff=5.9), R("B", 0.89), R("C", 0.88)])
    assert rank.sticky_publish(rows, [], CFG, evicted=set()) is None
    rows = ranked([R("A", 0.90), R("B", 0.89), R("C", 0.88), R("D", 0.80)])
    assert rank.sticky_publish(rows, [], CFG, evicted=set()) == ["A", "B", "C", "D"]


def test_sticky_publish_without_incumbents_is_lcb_order_top_n() -> None:
    rows = ranked([R(f"10.0.0.{i}", 0.9 - i * 0.01) for i in range(8)])
    assert rank.sticky_publish(rows, [], CFG, evicted=set()) == [f"10.0.0.{i}" for i in range(5)]


# ── best_ips.txt 写法 ────────────────────────────────────────────────────

def test_write_best_marker_and_publish_set_parse(tmp_path: Path) -> None:
    best = tmp_path / "best_ips.txt"
    rows = ranked([R(f"10.0.0.{i}", 0.9 - i * 0.01) for i in range(6)])
    rank.write_best(best, rows, [f"10.0.0.{i}" for i in range(5)], NOW, CFG)
    text = best.read_text(encoding="utf-8")
    assert rank.BEST_MARKER in text
    tail = text.split(rank.BEST_MARKER, 1)[1].strip().splitlines()
    assert tail[:5] == [f"10.0.0.{i}" for i in range(5)]
    assert rank.read_incumbents(best, 3) == ["10.0.0.0", "10.0.0.1", "10.0.0.2"]
    assert rank.read_incumbents(tmp_path / "none.txt", 3) == []
    # config.sh publish_set() 的 sed 解析必须兼容
    got = subprocess.run(
        ["bash", "-c", "sed -n '/^# --- BEST_IPS/,$ { /^[0-9]/ p }' \"$1\" | head -n 3", "_", str(best)],
        capture_output=True, text=True, check=True,
    ).stdout.split()
    assert got == ["10.0.0.0", "10.0.0.1", "10.0.0.2"]
    # 原子写：目录内无残留临时文件
    assert [p.name for p in tmp_path.iterdir()] == ["best_ips.txt"]


def test_evict_rule2_uses_fail_lower_bound_not_point_estimate() -> None:
    # 3 样本 1 失败 = 33% 点估计，但下界≈0.14 < 0.30 → 不是硬失败；40 样本 50% 下界≈0.42 → 淘汰
    rows = [R("198.51.100.15", 0.9), R("198.51.100.16", 0.5, fail=1 / 3, n_eff=3.0),
            R("198.51.100.17", 0.5, fail=0.5, n_eff=40.0)]
    kept, evicted = rank.evict(ranked(rows), CFG, guard="none")
    assert dict(evicted) == {"198.51.100.17": "hard_fail"}
    assert "198.51.100.16" in kept


# ── 挑战者分槽 ──────────────────────────────────────────────────────────
# 挑战者按 ucb 排，n_eff<3 的新 IP 区间最宽、ucb 天然最高：每轮 20 个新 IP 会把攒到 4–5 个样本、
# 正要拿发布资格（n_eff≥6）的候选挤回 reserve（2h 才采一次）。拆成探索槽（n_eff<3）+ 晋升槽（n_eff≥3），
# 一侧不足时另一侧补齐。

def test_derive_tiers_splits_challengers_into_explore_and_promote_slots() -> None:
    core_rows = [R(f"10.0.0.{i}", 0.90 - i * 0.01) for i in range(10)]          # core 末位 lcb 0.81
    fresh = [R(f"10.1.0.{i}", 0.30, ucb=0.99 - i * 0.001, n_eff=1.0) for i in range(12)]   # 探索候选 ×12
    maturing = [R(f"10.2.0.{i}", 0.70, ucb=0.90 - i * 0.001, n_eff=4.5) for i in range(8)]  # 晋升候选 ×8
    core, chal, reserve = rank.derive_tiers(ranked(core_rows + fresh + maturing), CFG)
    assert len(chal) == 10
    explore = [ip for ip in chal if ip.startswith("10.1.")]
    promote = [ip for ip in chal if ip.startswith("10.2.")]
    assert len(explore) == 5 and len(promote) == 5, (explore, promote)
    assert explore == [f"10.1.0.{i}" for i in range(5)], "探索槽内按 ucb 降序"
    assert promote == [f"10.2.0.{i}" for i in range(5)], "晋升槽内按 ucb 降序"


def test_derive_tiers_slots_backfill_each_other() -> None:
    core_rows = [R(f"10.0.0.{i}", 0.90 - i * 0.01) for i in range(10)]
    fresh = [R(f"10.1.0.{i}", 0.30, ucb=0.99, n_eff=1.0) for i in range(12)]
    maturing = [R("203.0.113.13", 0.70, ucb=0.90, n_eff=4.5)]
    core, chal, _ = rank.derive_tiers(ranked(core_rows + fresh + maturing), CFG)
    assert "203.0.113.13" in chal and len(chal) == 10 and sum(ip.startswith("10.1.") for ip in chal) == 9
    core, chal, _ = rank.derive_tiers(ranked(core_rows + maturing * 1 + [
        R(f"10.2.0.{i}", 0.70, ucb=0.90, n_eff=4.5) for i in range(2, 14)]), CFG)
    assert len(chal) == 10 and all(ip.startswith("10.2.") for ip in chal), "无探索候选时晋升槽补满"


def test_derive_tiers_challenger_still_requires_ucb_above_core_floor() -> None:
    core_rows = [R(f"10.0.0.{i}", 0.90 - i * 0.01) for i in range(10)]
    low = [R(f"10.1.0.{i}", 0.30, ucb=0.80, n_eff=1.0) for i in range(3)]          # ucb ≤ 0.81 → reserve
    core, chal, reserve = rank.derive_tiers(ranked(core_rows + low), CFG)
    assert chal == [] and len(reserve) == 3


def test_config_explore_slots_default_and_cli() -> None:
    assert rank.Config().explore_slots == 5
    cfg = rank.Config(explore_slots=2, challenger_max=4)
    core_rows = [R(f"10.0.0.{i}", 0.90 - i * 0.01) for i in range(10)]
    fresh = [R(f"10.1.0.{i}", 0.30, ucb=0.99, n_eff=1.0) for i in range(6)]
    maturing = [R(f"10.2.0.{i}", 0.70, ucb=0.90, n_eff=4.5) for i in range(6)]
    _, chal, _ = rank.derive_tiers(ranked(core_rows + fresh + maturing), cfg)
    assert sum(ip.startswith("10.1.") for ip in chal) == 2 and sum(ip.startswith("10.2.") for ip in chal) == 2


# ── 发布段多样性 ────────────────────────────────────────────────────────
# 池内绝大多数 IP 在同一个 /16（共享路由故障域）。发布集同 /16 最多 2 个；但只在存在 lcb 差距
# 不超过滞回（publish_margin）的跨段合格者时才替换，不拿质量换多样性。

def test_publish_diversity_caps_two_per_slash16_when_alternative_within_margin() -> None:
    rows = ranked([R("192.0.2.1275", 0.900), R("192.0.2.1090", 0.895), R("192.0.2.1276", 0.890),
                   R("203.0.113.191", 0.885), R("192.0.2.1277", 0.880)])
    out = rank.sticky_publish(rows, [], CFG, evicted=set())
    assert out[:3] == ["192.0.2.1275", "192.0.2.1090", "203.0.113.191"], out
    assert set(out) == {"192.0.2.1275", "192.0.2.1090", "192.0.2.1276", "203.0.113.191", "192.0.2.1277"}, "候补集仍完整"


def test_publish_diversity_does_not_sacrifice_quality_beyond_margin() -> None:
    rows = ranked([R("192.0.2.1275", 0.900), R("192.0.2.1090", 0.895), R("192.0.2.1276", 0.890),
                   R("203.0.113.191", 0.860)])                       # 差距 0.03 > margin 0.02
    out = rank.sticky_publish(rows, [], CFG, evicted=set())
    assert out[:3] == ["192.0.2.1275", "192.0.2.1090", "192.0.2.1276"]


def test_publish_diversity_is_sticky_and_replaces_lowest_same_segment_incumbent() -> None:
    # 在任 [A(172.66), B(172.66), C(104.21)]：新同段 D 以超滞回优势换入第 3 位会形成 3×172.66；
    # C 与 D 差距 > margin，不以 C 替代 D（质量优先）→ 允许 3×172.66
    rows = ranked([R("192.0.2.1277", 0.930), R("192.0.2.1275", 0.900), R("192.0.2.1090", 0.895),
                   R("203.0.113.191", 0.870)])
    out = rank.sticky_publish(rows, ["192.0.2.1275", "192.0.2.1090", "203.0.113.191"], CFG, evicted=set())
    assert out[:3] == ["192.0.2.1277", "192.0.2.1275", "192.0.2.1090"]
    # 若另有跨段合格者 E 在滞回内，则替换发布集中 lcb 最低的同段成员
    rows = ranked([R("192.0.2.1277", 0.930), R("192.0.2.1275", 0.900), R("192.0.2.1090", 0.895),
                   R("203.0.113.114", 0.880), R("203.0.113.191", 0.870)])
    out = rank.sticky_publish(rows, ["192.0.2.1275", "192.0.2.1090", "203.0.113.191"], CFG, evicted=set())
    assert out[:3] == ["192.0.2.1277", "192.0.2.1275", "203.0.113.114"]


def test_publish_diversity_leaves_already_diverse_set_untouched() -> None:
    rows = ranked([R("203.0.113.114", 0.900), R("203.0.113.191", 0.895), R("192.0.2.1275", 0.890), R("192.0.2.1090", 0.889)])
    out = rank.sticky_publish(rows, ["203.0.113.114", "203.0.113.191", "192.0.2.1275"], CFG, evicted=set())
    assert out[:3] == ["203.0.113.114", "203.0.113.191", "192.0.2.1275"]


def test_publish_diversity_can_be_disabled() -> None:
    cfg = rank.Config(max_per_segment=0)
    rows = ranked([R("192.0.2.1275", 0.900), R("192.0.2.1090", 0.895), R("192.0.2.1276", 0.890), R("203.0.113.191", 0.885)])
    assert rank.sticky_publish(rows, [], cfg, evicted=set())[:3] == ["192.0.2.1275", "192.0.2.1090", "192.0.2.1276"]


def test_evict_rule1_requires_more_evidence_than_core_membership() -> None:
    # 连续两个 300ms 样本占 n_eff≈6.5 候选近 30% 的近期权重，任何置信界都会判它"当前差"；
    # 但 7 个样本就近乎不可逆地剔除仍是凭运气。规则 1 要求 n_eff ≥ evict_min_neff(=8)；
    # 已证明阈值与 core 资格用 min_neff=3；规则 2/3 不受影响。
    assert rank.Config().evict_min_neff == 8.0
    proven = [R(f"10.0.{i // 256}.{i % 256}", 0.90 - i * 0.001) for i in range(60)]
    young = R("192.0.2.10", 0.30, ucb=0.50, n_eff=6.5)
    old = R("192.0.2.11", 0.30, ucb=0.50, n_eff=8.0)
    kept, evicted = rank.evict(ranked(proven + [young, old]), CFG, guard="none")
    assert dict(evicted) == {"192.0.2.11": "unworthy"} and "192.0.2.10" in kept
    failing = R("192.0.2.12", 0.30, ucb=0.50, n_eff=3.0, fail=1.0)   # 规则 2 仍只需 n_eff≥3
    kept, evicted = rank.evict(ranked(proven + [failing]), CFG, guard="none")
    assert dict(evicted) == {"192.0.2.12": "hard_fail"}
