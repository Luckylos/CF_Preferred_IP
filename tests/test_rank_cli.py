"""rank.py CLI：contenders 往返、dry-run 零写入、摘要行契约、守卫、幂等、回放确定性。"""
from __future__ import annotations

import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import rank  # noqa: E402
import replay  # noqa: E402

FIXTURE = ROOT / "tests" / "fixtures" / "history_7d.tsv"
NOW = "2026-10-15 16:10:00"


def run_rank(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run([sys.executable, str(ROOT / "rank.py"), *args],
                          capture_output=True, text=True)


def summary_of(out: str) -> dict[str, str]:
    last = out.rstrip("\n").splitlines()[-1]
    assert last.startswith("rank: "), last
    return dict(kv.split("=", 1) for kv in last[len("rank: "):].split(" "))


def make_env(tmp_path: Path, history: str | None = None, pool_ips: list[str] | None = None) -> dict[str, Path]:
    hist = tmp_path / "history.tsv"
    hist.write_text(history if history is not None else FIXTURE.read_text(encoding="utf-8"), encoding="utf-8")
    if pool_ips is None:
        pool_ips = sorted({l.split("\t")[1] for l in hist.read_text(encoding="utf-8").splitlines() if "\t" in l})
    cont = tmp_path / "contenders.tsv"
    cont.write_text(rank.CONTENDERS_HEADER + "\n" + "".join(
        f"{ip}\t2026-10-08 00:00:00\t2026-10-08 00:00:00\tmaster\n" for ip in pool_ips), encoding="utf-8")
    return {"history": hist, "contenders": cont, "best": tmp_path / "best_ips.txt",
            "blacklist": tmp_path / "bl.tsv", "tiers": tmp_path / "tiers"}


def base_args(env: dict[str, Path], now: str = NOW) -> list[str]:
    return ["--history", str(env["history"]), "--contenders", str(env["contenders"]),
            "--best", str(env["best"]), "--blacklist", str(env["blacklist"]),
            "--now", now, "--tiers-out", str(env["tiers"])]


# ── contenders.tsv 往返 ─────────────────────────────────────────────────

def test_contenders_roundtrip(tmp_path: Path) -> None:
    p = tmp_path / "c.tsv"
    p.write_text(
        "# contenders.tsv — ip\tfirst_seen\tlast_sampled\torigin\n"
        "198.51.100.15\t2026-10-01 00:00:00\t2026-10-02 00:00:00\tmaster\n"
        "198.51.100.16\t2026-10-01 00:00:00\t-\tscreen\n"
        "198.51.100.15\t2026-10-03 00:00:00\t-\tdup\n"       # 重复：保留首见
        "999.0.0.1\t2026-10-01 00:00:00\t-\tbad\n"
        "\n",
        encoding="utf-8",
    )
    rows = rank.read_contenders(p)
    assert [r.ip for r in rows] == ["198.51.100.15", "198.51.100.16"]
    assert rows[0].origin == "master" and rows[1].last_sampled == "-"
    out = tmp_path / "o.tsv"
    rank.write_contenders(out, rows)
    assert rank.read_contenders(out) == rows
    assert out.read_text(encoding="utf-8").startswith(rank.CONTENDERS_HEADER + "\n")
    assert rank.read_contenders(tmp_path / "missing.tsv") == []


# ── dry-run ─────────────────────────────────────────────────────────────

def test_dry_run_writes_nothing(tmp_path: Path) -> None:
    env = make_env(tmp_path)
    env["best"].write_text(rank.BEST_MARKER + "\n203.0.113.10\n", encoding="utf-8")
    before = {p: (p.stat().st_mtime_ns, p.read_bytes()) for p in (env["contenders"], env["best"])}
    r = run_rank(base_args(env) + ["--dry-run"])
    assert r.returncode == 0, r.stderr
    s = summary_of(r.stdout)
    assert int(s["pool"]) > 0 and s["guard"] == "none"
    assert {p: (p.stat().st_mtime_ns, p.read_bytes()) for p in before} == before
    assert not env["blacklist"].exists()
    assert "Top" in r.stdout
    # --tiers-out 是调度草稿而非生产数据：dry-run 仍写 core/challengers（影子期 fast 周期依赖）
    core = (env["tiers"] / "core.txt").read_text(encoding="utf-8").split()
    chal = (env["tiers"] / "challengers.txt").read_text(encoding="utf-8").split()
    assert len(core) == int(s["core"]) == 10 and len(chal) == int(s["challengers"])
    assert sorted(p.name for p in env["tiers"].iterdir()) == ["challengers.txt", "core.txt"]


def test_dry_run_without_tiers_out_writes_no_tiers(tmp_path: Path) -> None:
    env = make_env(tmp_path)
    args = [a for a in base_args(env) if a != "--tiers-out" and a != str(env["tiers"])]
    r = run_rank(args + ["--dry-run"])
    assert r.returncode == 0, r.stderr
    assert not env["tiers"].exists()
    assert sorted(p.name for p in tmp_path.iterdir()) == ["contenders.tsv", "history.tsv"]


def test_missing_contenders_is_empty_pool(tmp_path: Path) -> None:
    env = make_env(tmp_path)
    env["contenders"].unlink()
    r = run_rank(base_args(env) + ["--dry-run"])
    assert r.returncode == 0, r.stderr
    s = summary_of(r.stdout)
    assert s == {"pool": "0", "core": "0", "challengers": "0", "evicted": "0",
                 "published": "", "changed": "0", "guard": "none",
                 "evaluated": "0", "waiting": "0", "quality_evicted": "0", "capacity_evicted": "0"}
    assert not env["contenders"].exists()
    r = run_rank(base_args(env))
    assert r.returncode == 0, r.stderr
    assert env["contenders"].read_text(encoding="utf-8") == rank.CONTENDERS_HEADER + "\n"
    assert (env["tiers"] / "core.txt").read_text(encoding="utf-8") == ""


# ── 写入模式与摘要契约 ────────────────────────────────────────────────────

def test_write_mode_outputs_and_summary_contract(tmp_path: Path) -> None:
    env = make_env(tmp_path)
    r = run_rank(base_args(env))
    assert r.returncode == 0, r.stderr
    s = summary_of(r.stdout)
    assert set(s) == {"pool", "core", "challengers", "evicted", "published", "changed", "guard",
                      "evaluated", "waiting", "quality_evicted", "capacity_evicted"}
    assert s["changed"] == "1" and s["guard"] == "none"
    published = s["published"].split(",")
    assert len(published) == 3
    assert rank.read_incumbents(env["best"], 3) == published
    core = (env["tiers"] / "core.txt").read_text(encoding="utf-8").split()
    chal = (env["tiers"] / "challengers.txt").read_text(encoding="utf-8").split()
    assert len(core) == int(s["core"]) and len(chal) == int(s["challengers"])
    assert all(rank.is_valid_ipv4(ip) for ip in core + chal)
    rows = rank.read_contenders(env["contenders"])
    assert len(rows) == int(s["pool"])
    assert all(row.last_sampled != "2026-10-08 00:00:00" for row in rows if row.ip in core)


def test_idempotent_second_run_is_byte_identical(tmp_path: Path) -> None:
    # 规则 4 对超限池是渐进裁剪（每轮 ≤ headroom），本身不幂等；关掉它验证其余链路幂等
    env = make_env(tmp_path)
    r1 = run_rank(base_args(env) + ["--trim-headroom", "0"])
    snap1 = {n: (tmp_path / n).read_bytes() for n in ("contenders.tsv", "best_ips.txt")}
    r2 = run_rank(base_args(env) + ["--trim-headroom", "0"])
    snap2 = {n: (tmp_path / n).read_bytes() for n in ("contenders.tsv", "best_ips.txt")}
    assert r1.returncode == 0 and r2.returncode == 0
    assert snap1 == snap2
    s1, s2 = summary_of(r1.stdout), summary_of(r2.stdout)
    assert s1["published"] == s2["published"] and s2["changed"] == "0"


def test_unsampled_contender_kept_and_history_only_ip_not_admitted(tmp_path: Path) -> None:
    hist = "".join(f"2026-10-15 1{h}:00:00\t198.51.100.15\tPASS\t50\t\n" for h in range(6))
    hist += "2026-10-15 15:00:00\t198.51.100.19\tPASS\t45\t\n"
    env = make_env(tmp_path, history=hist, pool_ips=["198.51.100.15", "198.51.100.16"])
    r = run_rank(base_args(env))
    assert r.returncode == 0, r.stderr
    rows = {row.ip: row for row in rank.read_contenders(env["contenders"])}
    assert set(rows) == {"198.51.100.15", "198.51.100.16"}
    assert rows["198.51.100.16"].last_sampled == "2026-10-08 00:00:00"
    s = summary_of(r.stdout)
    assert s["published"] == "" and s["changed"] == "0"
    assert not env["best"].exists()        # 合格数 <3 不写 best


# ── 守卫 ────────────────────────────────────────────────────────────────

def _guard_env(tmp_path: Path) -> dict[str, Path]:
    # 一个必被淘汰的 IP（连续 3 轮不可达）+ 三个合格 IP；合格 IP 必须扛过一个晚高峰（20/22/00 三个样本）
    hist = ""
    stamps = ["2026-10-14 20:00:00", "2026-10-14 22:00:00", "2026-10-15 00:00:00"] + \
             [f"2026-10-15 {h:02d}:00:00" for h in range(8, 16)]
    for ts in stamps:
        for ip, ms in (("198.51.100.15", 50), ("198.51.100.16", 55), ("198.51.100.17", 60)):
            hist += f"{ts}\t{ip}\tPASS\t{ms}\t\n"
        hist += f"{ts}\t198.51.100.20\tFAIL\t0\ttimeout\n"
    return make_env(tmp_path, history=hist, pool_ips=["198.51.100.15", "198.51.100.16", "198.51.100.17", "198.51.100.20"])


def test_guard_none_evicts(tmp_path: Path) -> None:
    env = _guard_env(tmp_path)
    s = summary_of(run_rank(base_args(env)).stdout)
    assert s["evicted"] == "1" and s["guard"] == "none" and s["pool"] == "3"
    assert env["blacklist"].read_text(encoding="utf-8") == "198.51.100.20\t2026-10-15 16:10:00\n"


def test_guard_coverage_systemic_no_evidence(tmp_path: Path) -> None:
    cases = [
        (["--audit-requested", "10", "--audit-returned", "7"], "coverage"),
        (["--audit-requested", "10", "--audit-returned", "8"], "none"),
        (["--systemic", "1"], "systemic"),
        (["--audit-ok", "0"], "no_evidence"),
        (["--audit-ok", "0", "--systemic", "1", "--audit-requested", "10", "--audit-returned", "1"], "no_evidence"),
    ]
    for i, (extra, expect) in enumerate(cases):
        case_dir = tmp_path / f"case{i}"
        case_dir.mkdir()
        env = _guard_env(case_dir)
        r = run_rank(base_args(env) + extra)
        assert r.returncode == 0, r.stderr
        s = summary_of(r.stdout)
        assert s["guard"] == expect, (extra, s)
        if expect == "none":
            assert s["evicted"] == "1"
        else:
            assert s["evicted"] == "0" and s["pool"] == "4" and not env["blacklist"].exists()
        if expect == "no_evidence":
            assert s["changed"] == "0" and s["published"] == "" and not env["best"].exists()
            # 统计仍更新
            rows = {row.ip: row for row in rank.read_contenders(env["contenders"])}
            assert rows["198.51.100.15"].last_sampled == "2026-10-15 15:00:00"
        else:
            assert s["changed"] == "1" and env["best"].exists()


def test_no_evidence_keeps_incumbents_in_summary(tmp_path: Path) -> None:
    env = _guard_env(tmp_path)
    env["best"].write_text(rank.BEST_MARKER + "\n198.51.100.17\n198.51.100.16\n198.51.100.15\n", encoding="utf-8")
    mtime = env["best"].stat().st_mtime_ns
    s = summary_of(run_rank(base_args(env) + ["--audit-ok", "0"]).stdout)
    assert s["published"] == "198.51.100.17,198.51.100.16,198.51.100.15" and s["changed"] == "0"
    assert env["best"].stat().st_mtime_ns == mtime


def test_auto_systemic_round_escalates_guard(tmp_path: Path) -> None:
    # 最新轮（16:00）6 个样本里 3 FAIL → 轮失败率 50% → guard=systemic，不淘汰
    (tmp_path / "a").mkdir()
    env = _guard_env(tmp_path / "a")
    extra = ("2026-10-15 16:00:00\t198.51.100.15\tPASS\t50\t\n"
             "2026-10-15 16:00:00\t198.51.100.16\tPASS\t55\t\n"
             "2026-10-15 16:00:00\t198.51.100.17\tFAIL\t0\ttimeout\n"
             "2026-10-15 16:00:00\t198.51.100.20\tFAIL\t0\ttimeout\n"
             # 198.51.100.21/.6 不在池内，但轮基线/系统性判定使用全部 history 样本（≥5 样本门槛）
             "2026-10-15 16:00:00\t198.51.100.21\tFAIL\t0\ttimeout\n"
             "2026-10-15 16:00:00\t198.51.100.22\tPASS\t52\t\n")
    env["history"].write_text(env["history"].read_text(encoding="utf-8") + extra, encoding="utf-8")
    r = run_rank(base_args(env, now="2026-10-15 16:05:00"))
    assert r.returncode == 0, r.stderr
    s = summary_of(r.stdout)
    assert s["guard"] == "systemic" and s["evicted"] == "0" and s["pool"] == "4"
    assert not env["blacklist"].exists()
    # 同一 history，now 推后到 16:20 → 16:00 桶已超 15 分钟 → guard=none，淘汰执行
    s2 = summary_of(run_rank(base_args(env, now="2026-10-15 16:20:00")).stdout)
    assert s2["guard"] == "none" and s2["evicted"] == "1"
    # no_evidence 优先级高于自动 systemic
    (tmp_path / "b").mkdir()
    env2 = _guard_env(tmp_path / "b")
    env2["history"].write_text(env["history"].read_text(encoding="utf-8"), encoding="utf-8")
    s3 = summary_of(run_rank(base_args(env2, now="2026-10-15 16:05:00") + ["--audit-ok", "0"]).stdout)
    assert s3["guard"] == "no_evidence"


# ── 回放 ────────────────────────────────────────────────────────────────

def test_replay_fixture_is_deterministic() -> None:
    cfg = rank.Config()
    a = replay.replay(FIXTURE, days=5, cfg=cfg)
    b = replay.replay(FIXTURE, days=5, cfg=cfg)
    assert a == b
    assert len(a.days) == 5
    assert all(len(d.top3) <= 3 for d in a.days)
    assert a.changes == sum(1 for i in range(1, 5) if a.days[i].top3 != a.days[i - 1].top3)
    r = subprocess.run([sys.executable, str(ROOT / "replay.py"), "--history", str(FIXTURE), "--days", "5"],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    assert r.stdout.rstrip().splitlines()[-1].startswith("replay: days=5 changes=")
