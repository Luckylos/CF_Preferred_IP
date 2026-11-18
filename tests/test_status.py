"""status.py 只读状态汇总：解析契约与告警边界。"""
from __future__ import annotations

import importlib.util
import os
import json
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("status", ROOT / "status.py")
status = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(status)

ROUND = """[2026-10-15 14:00:01] slow audit (VLESS): targets=3
[2026-10-15 14:00:02] verify_vless: 10.0.0.1 PASS (median=50ms)
[2026-10-15 14:00:02] verify_vless: 10.0.0.2 PASS (median=90ms)
[2026-10-15 14:00:03] verify_vless: 10.0.0.3 FAIL (timeout)
[2026-10-15 14:00:58] verify_vless: 2/3 IPs passed, 1 failed
systemic guard: normal(p10=49.0ms med=54.0ms n=2)
[2026-10-15 14:00:59] audit evidence: returned=3/3 (need >=2) audit_ok=1 systemic=0 guard=none
[2026-10-15 14:01:00] rank: pool=70 core=2 challengers=1 evicted=4 published=10.0.0.1,10.0.0.2,10.0.0.7 changed=1 guard=none
[2026-10-15 14:01:01] discovery screen: candidates=20 (admit TTFB<=100ms, max_fail=3)
[2026-10-15 14:02:07] verify_vless: 10.0.0.9 PASS (median=999ms)
[2026-10-15 14:02:10] discovery screen: screen_pass=13 contenders=83 queue=160
[2026-10-15 14:03:00] apply: pushed 3 IPs -> 10.0.0.1 10.0.0.2 10.0.0.5 
[2026-10-15 14:03:05] cycle: mode=slow guard=none rank=ok
"""


def test_parse_round_only_uses_audit_section_for_ttfb() -> None:
    r = status.parse_round(ROUND)
    assert r["audit_ttfb"] == {"10.0.0.1": 50, "10.0.0.2": 90}
    assert r["ttfb_max"] == 90, "发现快筛样本不得混入池审计分布"
    assert (r["returned"], r["requested"], r["audit_ok"], r["unreachable"]) == (3, 3, True, 1)
    assert (r["evicted"], r["screen_pass"], r["screened"]) == (4, 13, 20)
    assert r["pushed"] == ["10.0.0.1", "10.0.0.2", "10.0.0.5"]
    assert r["systemic"] is False and r["guard"] == "none"


def _fixture(tmp_path: Path, round_name: str, cron: str) -> None:
    (tmp_path / "results").mkdir()
    (tmp_path / "results" / round_name).write_text(ROUND, encoding="utf-8")
    (tmp_path / "results" / "cron.log").write_text(cron, encoding="utf-8")
    (tmp_path / "best_ips.txt").write_text(
        "# header\n  10.0.0.1  0.7\n  10.0.0.2  0.6\n  10.0.0.7  0.5\n  10.0.0.8  0.4\n", encoding="utf-8")
    (tmp_path / "config.sh").write_text("POOL_MAX=90\n", encoding="utf-8")


def test_collect_healthy_has_no_warnings(tmp_path: Path, monkeypatch) -> None:
    _fixture(tmp_path, "20261015_140001.log",
             "[2026-10-15 14:03:00] apply: pushed 3 IPs -> 10.0.0.1 10.0.0.2 10.0.0.5\n"
             "[2026-10-15 15:11:14] latency scan: targets=249 discovered=5 queued=180 lat_covered=180\n")
    monkeypatch.setattr(status, "CFST", tmp_path)
    rep = status.collect(datetime(2026, 10, 15, 15, 15, 0))
    assert rep["top3"] == [{"ip": "10.0.0.1", "ttfb_ms": 50}, {"ip": "10.0.0.2", "ttfb_ms": 90},
                           {"ip": "10.0.0.7", "ttfb_ms": None}]
    assert rep["flow_7d"] == {"rounds": 1, "screened": 20, "admitted": 13, "evicted": 4, "pool_now": 70, "pool_max": 90}
    assert rep["flow_7d"]["pool_now"] < rep["flow_7d"]["pool_max"]
    assert rep["last_publish"]["age_h"] == 1.2
    assert rep["last_scan_age_min"] == 3
    assert rep["warnings"] == ["池审计 1 个 IP 本轮不可达"]


def test_collect_flags_stale_round_and_scan(tmp_path: Path, monkeypatch) -> None:
    _fixture(tmp_path, "20261015_140001.log", "")
    monkeypatch.setattr(status, "CFST", tmp_path)
    rep = status.collect(datetime(2026, 10, 15, 18, 0, 0))
    joined = " ".join(rep["warnings"])
    assert "239 分钟" in joined and "轻扫停摆" in joined
    assert rep["last_publish"]["at"] == "2026-10-15 14:03:00", "slow日志自身的确切推送也应识别"


def test_cli_json_is_readonly_and_parseable(tmp_path: Path) -> None:
    import shutil
    sandbox = tmp_path / "status-site"
    sandbox.mkdir()
    _fixture(sandbox, "20261015_140001.log", "")
    for name in ("status.py", "cycle_result.py", "atomic_io.py", "ip_validation.py"):
        shutil.copy2(ROOT / name, sandbox / name)
    before = {p: p.stat().st_mtime for p in sandbox.rglob("*") if p.is_file()}
    proc = subprocess.run([sys.executable, str(sandbox / "status.py"), "--json"],
                          cwd=sandbox, capture_output=True, text=True, check=False,
                          env={k:v for k,v in os.environ.items() if k != "PYTHONDONTWRITEBYTECODE"})
    assert proc.returncode == 0, proc.stderr
    assert set(json.loads(proc.stdout)) >= {"now", "warnings", "latest_round", "top3"}
    assert before == {p: p.stat().st_mtime for p in sandbox.rglob("*") if p.is_file()}


# ── Contender pool（2026-10-15 重构）：rank/cycle 行与影子对照 ──────────────

FAST_LOG = """[2026-10-15 15:00:03] cycle: mode=fast guard=none rank=ok
[2026-10-15 15:00:03] rank: pool=61 core=10 challengers=4 evicted=1 published=10.0.0.1,10.0.0.2,10.0.0.7 changed=0 guard=none
[2026-10-15 15:15:02] cycle: mode=fast guard=coverage rank=skipped
[2026-10-15 15:15:02] rank: pool=61 core=10 challengers=5 evicted=0 published=10.0.0.1,10.0.0.2,10.0.0.7 changed=0 guard=coverage
"""

SHADOW_LOG = """[2026-10-13 10:00:00] shadow: legacy=10.0.0.1,10.0.0.2,10.0.0.7 new=10.0.0.1,10.0.0.2,10.0.0.7 same=1
[2026-10-14 10:00:00] shadow: legacy=10.0.0.1,10.0.0.2,10.0.0.7 new=10.0.0.1,10.0.0.2,10.0.0.7 same=1
[2026-10-14 12:00:00] shadow: legacy=10.0.0.1,10.0.0.2,10.0.0.7 new=10.0.0.1,10.0.0.2,10.0.0.8 same=0
[2026-10-14 14:00:00] shadow: legacy=10.0.0.1,10.0.0.2,10.0.0.7 new=10.0.0.1,10.0.0.2,10.0.0.8 same=0
[2026-10-15 14:00:00] shadow: legacy=10.0.0.1,10.0.0.2,10.0.0.7 new=10.0.0.2,10.0.0.1,10.0.0.7 same=0
"""

# 10.0.0.8：7 天内有 FAIL → 不合格；10.0.0.1/2/7 p90 ≤65 且 fail=0 → 合格；
# 10.0.0.9：p90 >65 → 不合格；10.0.0.5：8 天前的样本不计入窗口
HISTORY = "".join([
    "2026-10-15 13:00:00\t10.0.0.1\tPASS\t50\t\n",
    "2026-10-15 13:00:01\t10.0.0.2\tPASS\t60\t\n",
    "2026-10-15 13:00:02\t10.0.0.7\tPASS\t65\t\n",
    "2026-10-15 13:00:03\t10.0.0.8\tPASS\t40\t\n",
    "2026-10-13 13:00:03\t10.0.0.8\tFAIL\t900\tslow_ttfb\n",
    "2026-10-15 13:00:04\t10.0.0.9\tPASS\t66\t\n",
    "2026-10-06 13:00:04\t10.0.0.5\tPASS\t30\t\n",
])


def test_parse_rank_line_contract() -> None:
    r = status.parse_rank_line(FAST_LOG.splitlines()[1])
    assert r == {"pool": 61, "core": 10, "challengers": 4, "evicted": 1,
                 "published": ["10.0.0.1", "10.0.0.2", "10.0.0.7"], "changed": False, "guard": "none"}
    assert status.parse_rank_line("[ts] verify_vless: 10.0.0.1 PASS") is None
    bare = status.parse_rank_line("rank: pool=5 core=3 challengers=0 evicted=0 published= changed=1 guard=no_evidence")
    assert bare["pool"] == 5 and bare["published"] == [] and bare["changed"] is True and bare["guard"] == "no_evidence"
    assert status.parse_cycle_line("[2026-10-15 15:00:03] cycle: mode=slow guard=systemic rank=failed") == {
        "mode": "slow", "guard": "systemic", "rank": "failed"}


def test_collect_contender_section_from_fast_log(tmp_path: Path, monkeypatch) -> None:
    _fixture(tmp_path, "20261015_140001.log", "")
    (tmp_path / "results" / "fast.log").write_text(FAST_LOG, encoding="utf-8")
    monkeypatch.setattr(status, "CFST", tmp_path)
    rep = status.collect(datetime(2026, 10, 15, 15, 20, 0))
    c = rep["contender"]
    assert (c["pool"], c["core"], c["challengers"]) == (61, 10, 5)
    assert c["published"] == ["10.0.0.1", "10.0.0.2", "10.0.0.7"]
    assert c["guard"] == "coverage"
    assert c["fast_age_min"] == 4
    assert c["last_cycle"] == {"mode": "fast", "guard": "coverage", "rank": "skipped"}
    text = status.render(rep)
    assert "Contender 池: pool 61 / core 10 / challengers 5" in text
    assert "最近 fast 周期 4 分钟前" in text and "最近 guard coverage" in text


def test_collect_contender_prefers_latest_across_slow_and_fast(tmp_path: Path, monkeypatch) -> None:
    _fixture(tmp_path, "20261015_140001.log", "")
    (tmp_path / "results" / "20261015_140001.log").write_text(
        ROUND + "[2026-10-15 16:00:05] rank: pool=70 core=10 challengers=2 evicted=0 published=10.0.0.1,10.0.0.2,10.0.0.7 changed=1 guard=none\n",
        encoding="utf-8")
    (tmp_path / "results" / "fast.log").write_text(FAST_LOG, encoding="utf-8")
    monkeypatch.setattr(status, "CFST", tmp_path)
    rep = status.collect(datetime(2026, 10, 15, 16, 10, 0))
    assert rep["contender"]["pool"] == 70 and rep["contender"]["changed"] is True
    assert rep["contender"]["fast_age_min"] == 54, "fast 周期年龄只看 fast.log（15:15:02 → 16:10:00）"


def test_collect_contender_absent_before_switch(tmp_path: Path, monkeypatch) -> None:
    _fixture(tmp_path, "20261015_140001.log", "")
    legacy = "\n".join(l for l in ROUND.splitlines() if not re.search(r"\] (rank|cycle):", l)) + "\n"
    (tmp_path / "results" / "20261015_140001.log").write_text(legacy, encoding="utf-8")
    monkeypatch.setattr(status, "CFST", tmp_path)
    rep = status.collect(datetime(2026, 10, 15, 15, 15, 0))
    assert rep["contender"] is None and rep["shadow"] is None
    text = status.render(rep)
    assert "Contender 池: 未启用" in text and "影子对照: 未启用" in text
    assert not any("Contender" in w or "影子" in w for w in rep["warnings"]), "未启用不得新增告警"


def test_shadow_section_hidden_after_cutover(tmp_path: Path, monkeypatch) -> None:
    """切换后 .shadow/ 不存在：即使 shadow.log 仍在，也不再展示影子对照。"""
    _fixture(tmp_path, "20261015_140001.log", "")
    (tmp_path / "results" / "shadow.log").write_text(SHADOW_LOG, encoding="utf-8")
    monkeypatch.setattr(status, "CFST", tmp_path)
    rep = status.collect(datetime(2026, 10, 15, 15, 15, 0))
    assert rep["shadow"] is None


def test_qualified_set_from_history_raw_p90_and_zero_fail() -> None:
    q = status.qualified_set(HISTORY, datetime(2026, 10, 15, 15, 0, 0))
    assert q == {"10.0.0.1", "10.0.0.2", "10.0.0.7"}


def test_collect_shadow_changes_48h_and_qualified_subset(tmp_path: Path, monkeypatch) -> None:
    _fixture(tmp_path, "20261015_140001.log", "")
    (tmp_path / "results" / "shadow.log").write_text(SHADOW_LOG, encoding="utf-8")
    (tmp_path / ".shadow").mkdir()
    (tmp_path / "vless_history.tsv").write_text(HISTORY, encoding="utf-8")
    monkeypatch.setattr(status, "CFST", tmp_path)
    now = datetime(2026, 10, 15, 15, 0, 0)
    rep = status.collect(now)
    s = rep["shadow"]
    # 48h 窗口 = 2026-10-13 15:00 之后：4 行；变化 2 次（12:00 换入 .8；10-15 14:00 顺序互换）
    assert s["rounds_48h"] == 4
    assert s["changes_48h"] == 2
    assert s["latest"]["new"] == ["10.0.0.2", "10.0.0.1", "10.0.0.7"] and s["latest"]["same"] is False
    assert [c["qualified"] for c in s["changes"]] == [False, True]
    assert s["changes"][0]["top3"] == ["10.0.0.1", "10.0.0.2", "10.0.0.8"]
    assert s["changes"][0]["unqualified"] == ["10.0.0.8"]
    text = status.render(rep)
    assert "影子对照 48h" in text and "变化 2 次" in text
    assert "⊄" in text and "10.0.0.8" in text
    json.dumps(rep)


def test_rank_line_reports_evaluation_and_exit_reasons():
    line = FAST_LOG.splitlines()[1] + ' evaluated=80 waiting=50 quality_evicted=2 capacity_evicted=3'
    parsed = status.parse_rank_line(line)
    assert parsed['evaluated'] == 80
    assert parsed['waiting'] == 50
    assert parsed['quality_evicted'] == 2
    assert parsed['capacity_evicted'] == 3
