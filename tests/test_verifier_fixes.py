"""Task 8 复核修正的回归测试（verifier 发现项）。"""
from __future__ import annotations

import json
import re
import sys
from datetime import datetime
from pathlib import Path

CFST = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(CFST))
import rank  # noqa: E402
import status  # noqa: E402

CYCLE = (CFST / "cycle.sh").read_text(encoding="utf-8")


def S(ts, ip, st, med, reason=""):
    return rank.Sample(ts, ip, st, med, reason)


# ── 阻断：rank 的 --now 必须在 audit 之后取样，否则本轮样本全部落在窗口外 ──
def test_cycle_rank_now_sampled_after_audit() -> None:
    i_audit = CYCLE.index('verify_vless.sh" --audit')
    m = re.search(r'^RANK_NOW=\$\(date', CYCLE, re.M)
    assert m and m.start() > i_audit, "RANK_NOW 必须在 audit 之后取样"
    assert '--now "$RANK_NOW"' in CYCLE


# ── 中：影子轮不 probe；影子轮 flock 等待而非立即放弃 ──
def test_cycle_shadow_skips_probe_and_waits_for_lock() -> None:
    i = CYCLE.index('probe.sh" --all')
    assert re.search(r'"\$SHADOW" = "0"', CYCLE[i - 400:i]), "probe 必须由 SHADOW=0 门控"
    assert re.search(r'flock -w \d+ 9', CYCLE)


# ── 中：run.sh 影子块任何失败都不得让 run.sh 非零退出 ──
# ── 中：PARTIAL 且 median>0 且 reason 含 timeouts=0 不是 unreachable ──
def test_is_unreachable_ignores_partial_with_latency() -> None:
    t = datetime(2026, 10, 15, 12, 0)
    assert rank.is_unreachable(S(t, "1.1.1.1", "PARTIAL", 120, "ok=2 timeouts=0 slow=1")) is False
    assert rank.is_unreachable(S(t, "1.1.1.1", "FAIL", 0, "timeout")) is True
    assert rank.is_unreachable(S(t, "1.1.1.1", "FAIL", 0, "")) is True
    assert rank.is_unreachable(S(t, "1.1.1.1", "FAIL", 300, "slow")) is False


# ── 低：系统性轮判定需要最少样本数，单样本轮不算 ──
def test_systemic_round_requires_min_samples() -> None:
    t = datetime(2026, 10, 15, 12, 0)
    one = [S(t, "1.1.1.1", "FAIL", 0, "timeout")]
    b = rank.round_baselines(rank.bucket_rounds(one, 10), 50, 10)
    assert b[t].systemic_fail is False
    five = [S(t, f"1.1.1.{i}", "FAIL", 0, "timeout") for i in range(5)]
    b = rank.round_baselines(rank.bucket_rounds(five, 10), 50, 10)
    assert b[t].systemic_fail is True


# ── 高：影子硬门必须同时读 fast.log 中的 shadow 行 ──
def test_collect_shadow_reads_fast_log_too(tmp_path: Path, monkeypatch) -> None:
    (tmp_path / "results").mkdir()
    (tmp_path / "results" / "shadow.log").write_text(
        "[2026-10-15 10:00:00] shadow: legacy=10.0.0.1,10.0.0.2,10.0.0.3 new=10.0.0.1,10.0.0.2,10.0.0.3 same=1\n")
    (tmp_path / "results" / "fast.log").write_text(
        "[2026-10-15 10:15:00] cycle: mode=fast shadow=1 guard=none rank=ok\n"
        "[2026-10-15 10:15:00] shadow: legacy=10.0.0.1,10.0.0.2,10.0.0.3 new=10.0.0.9,10.0.0.2,10.0.0.3 same=0\n"
        "[2026-10-15 10:30:00] shadow: legacy=10.0.0.1,10.0.0.2,10.0.0.3 new=10.0.0.1,10.0.0.2,10.0.0.3 same=1\n")
    (tmp_path / "vless_history.tsv").write_text("")
    s = status.collect_shadow(tmp_path / "results" / "shadow.log", tmp_path / "vless_history.tsv",
                              datetime(2026, 10, 15, 11, 0, 0), extra_logs=(tmp_path / "results" / "fast.log",))
    assert s["rounds_48h"] == 3
    assert s["changes_48h"] == 2
    assert s["latest"]["at"] == "2026-10-15 10:30:00"


# ── 低：合格集中 PARTIAL 也算失败 ──
def test_qualified_set_treats_partial_as_failure() -> None:
    hist = ("2026-10-15 13:00:00\t10.0.0.1\tPASS\t50\t\n"
            "2026-10-15 13:00:01\t10.0.0.1\tPARTIAL\t200\tslow\n"
            "2026-10-15 13:00:02\t10.0.0.2\tPASS\t50\t\n")
    assert status.qualified_set(hist, datetime(2026, 10, 15, 15, 0)) == {"10.0.0.2"}


# ── 低：fast 模式 tiers 只缺一个文件时不得丢掉另一个 ──
def test_cycle_fast_reads_each_tier_file_independently() -> None:
    i = CYCLE.index("nothing to audit")
    seg = CYCLE[i:i + 600]
    assert 'cat "$TIERS_DIR/core.txt" "$TIERS_DIR/challengers.txt"' not in seg
    assert seg.count("[ -f ") >= 2 or "for f in" in seg
