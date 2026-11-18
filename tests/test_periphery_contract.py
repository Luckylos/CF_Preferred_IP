"""Task 5 周边适配的结构契约：watchdog 紧急路径、scan_latency 排除集、config.sh 新阈值。

不执行任何会触发网络/推送的脚本，只做文本契约与 bash -n。
"""
from __future__ import annotations

import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WATCHDOG = ROOT / "watchdog.sh"
SCAN = ROOT / "scan_latency.sh"
CONFIG = ROOT / "config.sh"


def code(path: Path) -> str:
    return "\n".join(
        ln for ln in path.read_text(encoding="utf-8").splitlines()
        if not ln.lstrip().startswith("#")
    )


# ── watchdog.sh ──────────────────────────────────────────────────────────

def test_watchdog_has_no_legacy_score_path() -> None:
    text = WATCHDOG.read_text(encoding="utf-8")
    assert "score.py" not in text and "contenders.tsv" not in text


def test_watchdog_emergency_calls_cycle_fast_emergency() -> None:
    assert re.search(r'"\$CFST_DIR/cycle\.sh"\s+fast\s+--emergency', code(WATCHDOG)), \
        "紧急路径必须调用 cycle.sh fast --emergency"


def test_watchdog_has_rc75_lock_busy_branch_retaining_miss_state() -> None:
    text = code(WATCHDOG)
    start = text.index('"$CFST_DIR/cycle.sh" fast --emergency')
    block = text[start:start + 800]
    assert re.search(r"-eq 75", block), "cycle.sh 返回 75（锁忙）需单独分支"
    busy = block[block.index("-eq 75"):]
    busy = busy[:busy.index("fi")]
    assert "exit 75" in busy, "锁忙分支必须 exit 75"
    assert "WATCHDOG_STATE" not in busy or "rm" not in busy, "锁忙分支不得清除 miss 计数"


def test_watchdog_push_disabled_gate_precedes_cycle_and_exits_75() -> None:
    text = code(WATCHDOG)
    cycle_at = text.index('"$CFST_DIR/cycle.sh" fast --emergency')
    gate_at = text.index('.push_disabled')
    assert gate_at < cycle_at, ".push_disabled 检查必须在触发 cycle 之前"
    gate_block = text[gate_at:gate_at + 300]
    assert "exit 75" in gate_block


def test_watchdog_cycle_path_does_not_call_apply_separately() -> None:
    text = code(WATCHDOG)
    start = text.index('"$CFST_DIR/cycle.sh" fast --emergency')
    # 新链路分支到外层（顶格）else 为止；其后是切换前的旧链路
    end = text.index("\nelse\n", start)
    assert '"$CFST_DIR/apply.sh"' not in text[start:end], "cycle.sh fast 已含 apply，不得重复调用"


def test_watchdog_keeps_cooldown_logic() -> None:
    text = code(WATCHDOG)
    assert "WATCHDOG_COOLDOWN" in text and ".watchdog_cooldown" in text


def _watchdog_sandbox(tmp_path: Path, cycle_body: str, *, disabled: bool = False) -> Path:
    """切换后沙箱：contenders.tsv 存在，cycle.sh 为桩；timeout 桩让 TCP 检测必失败。"""
    sb = tmp_path / "wd"
    (sb / "bin").mkdir(parents=True)
    (sb / "best_ips.txt").write_text("# --- BEST_IPS\n1.1.1.1\n", encoding="utf-8")
    (sb / "contenders.tsv").write_text("# contenders.tsv\n1.1.1.1\tx\tx\tmaster\n", encoding="utf-8")
    (sb / "config.sh").write_text(
        f'CFST_DIR={sb}\nBEST="$CFST_DIR/best_ips.txt"\nWATCHDOG_STATE="$CFST_DIR/.watchdog_state"\n'
        'WATCHDOG_MISS_THRESHOLD=1\nWATCHDOG_COOLDOWN=3600\n', encoding="utf-8")
    for name in ("watchdog.sh", "ip_validation.py"):
        (sb / name).write_bytes((ROOT / name).read_bytes())
    (sb / "watchdog.sh").chmod(0o755)
    (sb / "bin" / "timeout").write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
    (sb / "bin" / "timeout").chmod(0o755)
    # 桩内一律用自身目录（watchdog 不 export CFST_DIR）
    (sb / "cycle.sh").write_text("#!/bin/sh\nD=$(dirname \"$0\")\nprintf '%s\\n' \"$*\" > \"$D/.cycle_args\"\n"
                                 + cycle_body, encoding="utf-8")
    (sb / "cycle.sh").chmod(0o755)
    # apply.sh 桩：cycle 路径下若被单独调用则留痕
    (sb / "apply.sh").write_text("#!/bin/sh\ntouch \"$(dirname \"$0\")/.apply_called\"\n", encoding="utf-8")
    (sb / "apply.sh").chmod(0o755)
    if disabled:
        (sb / ".push_disabled").write_text("test\n", encoding="utf-8")
    return sb


def _run_watchdog(sb: Path) -> subprocess.CompletedProcess[str]:
    import os
    env = os.environ.copy()
    env["PATH"] = f"{sb / 'bin'}:{env['PATH']}"
    return subprocess.run([str(sb / "watchdog.sh")], cwd=sb, env=env,
                          capture_output=True, text=True, timeout=10, check=False)


def test_watchdog_runtime_lock_busy_exits_75_and_keeps_miss(tmp_path: Path) -> None:
    sb = _watchdog_sandbox(tmp_path, "exit 75\n")
    proc = _run_watchdog(sb)
    assert proc.returncode == 75
    assert (sb / ".cycle_args").read_text().strip() == "fast --emergency"
    assert (sb / ".watchdog_state").read_text().startswith("1.1.1.1 1")
    assert not (sb / ".watchdog_cooldown").exists()
    assert not (sb / ".apply_called").exists()
    assert "lock busy" in proc.stderr


def test_watchdog_runtime_cycle_failure_retains_miss(tmp_path: Path) -> None:
    sb = _watchdog_sandbox(tmp_path, "exit 9\n")
    proc = _run_watchdog(sb)
    assert proc.returncode == 9
    assert (sb / ".watchdog_state").exists() and not (sb / ".watchdog_cooldown").exists()


def test_watchdog_runtime_success_enters_cooldown_without_apply(tmp_path: Path) -> None:
    sb = _watchdog_sandbox(tmp_path, "printf verified > \"$D/.apply_state\"\nexit 0\n")
    (sb / ".apply_cooldown").write_text("1\n", encoding="utf-8")
    proc = _run_watchdog(sb)
    assert proc.returncode == 0, proc.stderr
    assert (sb / ".watchdog_cooldown").exists() and not (sb / ".watchdog_state").exists()
    assert not (sb / ".apply_called").exists(), "不得单独调用 apply.sh"
    assert "emergency push done" in proc.stderr


def test_watchdog_runtime_success_without_verified_state_retains_miss(tmp_path: Path) -> None:
    sb = _watchdog_sandbox(tmp_path, "exit 0\n")
    proc = _run_watchdog(sb)
    assert proc.returncode == 1, proc.stderr
    assert "without verified state" in proc.stderr
    assert (sb / ".watchdog_state").exists() and not (sb / ".watchdog_cooldown").exists()


def test_watchdog_runtime_uses_cycle_even_without_contenders_file(tmp_path: Path) -> None:
    """Task 10 之后 watchdog 只有 cycle 路径：contenders.tsv 缺失不再回退到 score.py。"""
    sb = _watchdog_sandbox(tmp_path, "printf verified > \"$D/.apply_state\"\nexit 0\n")
    (sb / "contenders.tsv").unlink()
    proc = _run_watchdog(sb)
    assert proc.returncode == 0, proc.stderr
    assert (sb / ".cycle_args").read_text(encoding="utf-8").strip() == "fast --emergency"
    assert not (sb / ".apply_called").exists()


def test_watchdog_runtime_push_disabled_skips_cycle(tmp_path: Path) -> None:
    sb = _watchdog_sandbox(tmp_path, "exit 0\n", disabled=True)
    proc = _run_watchdog(sb)
    assert proc.returncode == 75
    assert not (sb / ".cycle_args").exists(), ".push_disabled 时不得触发 cycle"
    assert (sb / ".watchdog_state").exists() and not (sb / ".watchdog_cooldown").exists()


# ── scan_latency.sh ──────────────────────────────────────────────────────

def test_scan_latency_exclusion_set_includes_contenders_and_master() -> None:
    text = code(SCAN)
    assert '"$CONTENDERS"' in text, "排除集必须读取 contenders.tsv（$CONTENDERS）"
    # 过渡期仍并入 master_ips.txt
    assert '"$MASTER"' in text


def test_scan_latency_known_set_function_unions_both_sources(tmp_path: Path) -> None:
    """抽出 known_ip_set 函数在沙箱执行：contenders 第 1 列 ∪ master，非法行被剔除。"""
    text = SCAN.read_text(encoding="utf-8")
    start = text.index("known_ip_set() {")
    end = text.index("\n}\n", start) + 3
    func = text[start:end]
    (tmp_path / "contenders.tsv").write_text(
        "# contenders.tsv — ip\tfirst_seen\tlast_sampled\torigin\n"
        "10.0.0.1\t2026-10-15 00:00:00\t2026-10-15 00:00:00\tmaster\n"
        "bad.ip\t2026-10-15 00:00:00\t2026-10-15 00:00:00\tprobation\n"
        "10.0.0.2\t2026-10-15 00:00:00\t2026-10-15 00:00:00\tprobation\n",
        encoding="utf-8")
    (tmp_path / "master_ips.txt").write_text("# header\n10.0.0.1\n10.0.0.3\n", encoding="utf-8")
    out = tmp_path / "known"
    script = (
        f'set -euo pipefail\nCFST_DIR="{ROOT}"\n'
        f'CONTENDERS="{tmp_path}/contenders.tsv"\nMASTER="{tmp_path}/master_ips.txt"\n'
        f'{func}\nknown_ip_set "{out}"\n'
    )
    r = subprocess.run(["bash", "-c", script], capture_output=True, text=True, check=False)
    assert r.returncode == 0, r.stderr
    assert set(out.read_text().split()) == {"10.0.0.1", "10.0.0.2", "10.0.0.3"}

    # 只有 master（切换前）
    (tmp_path / "contenders.tsv").unlink()
    r = subprocess.run(["bash", "-c", script], capture_output=True, text=True, check=False)
    assert r.returncode == 0, r.stderr
    assert set(out.read_text().split()) == {"10.0.0.1", "10.0.0.3"}

    # 两者都没有 → 空集但不报错
    (tmp_path / "master_ips.txt").unlink()
    r = subprocess.run(["bash", "-c", script], capture_output=True, text=True, check=False)
    assert r.returncode == 0, r.stderr
    assert out.read_text().strip() == ""


def test_scan_latency_target_set_includes_contenders() -> None:
    text = code(SCAN)
    block = text[: text.index('> "$TARGET"')]
    assert '"$CONTENDERS"' in block, "扫描目标集也应包含 contenders（在用 IP）"


# ── config.sh ────────────────────────────────────────────────────────────

EXPECTED_CONFIG = {
    "RANK_HALF_LIFE_HOURS": "24",
    "RANK_FLOOR_MS": "50",
    "RANK_Z": "1.0",
    "RANK_SIGMA0": "0.15",
    "RANK_PEAK_HOURS": '"20-23,0"',
    "RANK_PEAK_WEIGHT": "3",
    "RANK_PEAK_MIN_SAMPLES": "3",
    "CORE_N": "10",
    "POOL_TARGET": "60",
    "POOL_MAX": "150",
    "PUBLISH_MIN_NEFF": "6",
    "PUBLISH_MARGIN": "0.02",
    "VLESS_HARD_MAX_FAIL": "0.30",
    "CONTENDERS": '"$CFST_DIR/contenders.tsv"',
    "TIERS_DIR": '"$CFST_DIR/.tiers"',
}


def test_config_has_contender_pool_section_with_all_variables() -> None:
    text = CONFIG.read_text(encoding="utf-8")
    assert "# ── Contender pool（2026-10-15 重构）──" in text
    section = text[text.index("Contender pool（2026-10-15 重构）"):]
    for key, val in EXPECTED_CONFIG.items():
        m = re.search(rf"^{key}=(\S+)", section, re.M)
        assert m, f"config.sh 缺少 {key}"
        assert m.group(1) == val, f"{key} 期望 {val}，实际 {m.group(1)}"


def test_config_legacy_pipeline_knobs_are_gone() -> None:
    """Task 10：旧 master/probation/score 链路阈值与函数不再声明；只保留迁移/回滚用的路径变量。"""
    text = CONFIG.read_text(encoding="utf-8")
    for gone in ("probation_screen_backpressure", "PROBATION_POOL_MAX=", "PROBATION_ENABLED=", "MASTER_LIMIT=",
                 "RETIRE_UNREACHABLE=", "RETIRE_TTFB_DECAY=", "SCORE_WINDOW_DAYS=", "VLESS_RETIRE_TTFB=",
                 "MASTER_CHALLENGE_", "PROBATION_FAIL_LIMIT=", "PROBATION_MAX_SLOW=",
                 "PROBATION_PEAK_HOURS=", "RANK_K=", "VLESS_SOFT_MAX_FAIL="):
        assert gone not in text, f"旧链路变量应已删除: {gone}"
    for kept in ("SCREEN_PEAK_HOURS=", "MASTER=", "MASTER_STATE=", "PROBATION_POOL=", "SCORE_TOP_N="):
        assert kept in text, f"仍有消费者的变量不得删除 {kept}"


def test_config_sourcing_exports_new_variables() -> None:
    r = subprocess.run(
        ["bash", "-c", f'source "{CONFIG}" >/dev/null 2>&1; echo "$CORE_N $POOL_MAX $CONTENDERS $TIERS_DIR ${{VLESS_HARD_MAX_FAIL:?}} ${{RANK_PEAK_HOURS:?}}"'],
        capture_output=True, text=True, check=False)
    assert r.returncode == 0, r.stderr
    assert r.stdout.split() == ["10", "150", "/opt/cfst/contenders.tsv", "/opt/cfst/.tiers", "0.30", "20-23,0"]


# ── bash -n ──────────────────────────────────────────────────────────────

def test_all_lane_scripts_parse_and_are_strict() -> None:
    for name in ("watchdog.sh", "scan_latency.sh", "config.sh", "migrate.sh", "rollback.sh"):
        path = ROOT / name
        r = subprocess.run(["bash", "-n", str(path)], capture_output=True, text=True, check=False)
        assert r.returncode == 0, f"{name}: {r.stderr}"
        if name != "config.sh":
            assert "set -euo pipefail" in path.read_text(encoding="utf-8"), name
