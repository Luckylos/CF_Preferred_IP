"""migrate.sh / rollback.sh：临时目录内往返、集合与 origin 正确、幂等、锁忙退出 75。

通过 MIGRATE_ROOT 指定数据根目录（config.sh 的 CFST_DIR 为硬编码 /opt/cfst，不可覆盖），
MIGRATE_LOCK 指定锁文件，避免碰生产锁与生产数据。
"""
from __future__ import annotations

import fcntl
import os
import subprocess
from datetime import datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MIGRATE = ROOT / "migrate.sh"
ROLLBACK = ROOT / "rollback.sh"

MASTER = "# master_ips.txt — header\n10.0.0.1\n10.0.0.2\n10.0.0.3\n"
MASTER_STATE = (
    "# master_state.tsv — IP\tlast_pass\tconsecutive_misses\tlast_checked\tfail_type\n"
    "10.0.0.1\t2026-10-01 02:00:00\t0\t2026-10-15 16:00:01\t\n"
    "10.0.0.2\t2026-10-02 04:00:00\t1\t2026-10-15 14:00:01\tunreachable\n"
)
PROBATION = (
    "# probation_pool.tsv — 首次达标时间\tIP\t证据条数\n"
    "2026-10-14 04:00:01\t10.0.0.9\t0\n"
    "2026-10-14 06:00:01\t10.0.0.2\t1\n"          # 与 master 重复 → master 优先
    "2026-10-14 08:00:01\tnot-an-ip\t0\n"         # 非法行剔除
    "2026-10-14 10:00:01\t10.0.0.10\t0\n"
    "2026-10-14 11:00:01\t10.0.0.11\t0\n"        # 24h 内只有 FAIL → 不导入
    "2026-10-14 12:00:01\t10.0.0.12\t0\n"        # PASS 在 30h 前 → 不导入
)
RUN_SH = "#!/bin/bash\n# legacy run.sh\necho legacy\n"


def _history(now: datetime) -> str:
    """10.0.0.9 / 10.0.0.10 近 24h 内有 PASS；10.0.0.11 只有 FAIL；10.0.0.12 的 PASS 在 30h 前。"""
    f = "%Y-%m-%d %H:%M:%S"
    return "".join([
        f"{(now - timedelta(hours=1)).strftime(f)}\t10.0.0.9\tPASS\t50\t\n",
        f"{(now - timedelta(hours=23)).strftime(f)}\t10.0.0.10\tPASS\t60\t\n",
        f"{(now - timedelta(hours=2)).strftime(f)}\t10.0.0.11\tFAIL\t900\tslow_ttfb\n",
        f"{(now - timedelta(hours=30)).strftime(f)}\t10.0.0.12\tPASS\t40\t\n",
        f"{(now - timedelta(hours=3)).strftime(f)}\t10.0.0.1\tPASS\t40\t\n",
    ])


def _seed(tmp_path: Path) -> Path:
    root = tmp_path / "cfst"
    root.mkdir()
    (root / "master_ips.txt").write_text(MASTER, encoding="utf-8")
    (root / "master_state.tsv").write_text(MASTER_STATE, encoding="utf-8")
    (root / "probation_pool.tsv").write_text(PROBATION, encoding="utf-8")
    (root / "run.sh").write_text(RUN_SH, encoding="utf-8")
    (root / "vless_history.tsv").write_text(_history(datetime.now()), encoding="utf-8")
    return root


def _run(script: Path, root: Path) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["MIGRATE_ROOT"] = str(root)
    env["MIGRATE_LOCK"] = str(root / ".test.lock")
    return subprocess.run(["bash", str(script)], env=env, cwd=root,
                          capture_output=True, text=True, check=False, timeout=30)


def _rows(path: Path) -> list[list[str]]:
    return [ln.split("\t") for ln in path.read_text(encoding="utf-8").splitlines()
            if ln and not ln.startswith("#")]


def test_migrate_builds_contenders_and_renames_legacy(tmp_path: Path) -> None:
    root = _seed(tmp_path)
    r = _run(MIGRATE, root)
    assert r.returncode == 0, r.stderr
    cont = root / "contenders.tsv"
    assert cont.exists()
    head = cont.read_text(encoding="utf-8").splitlines()[0]
    assert head.startswith("# contenders.tsv") and "ip\tfirst_seen\tlast_sampled\torigin" in head
    rows = _rows(cont)
    by_ip = {r[0]: r for r in rows}
    assert set(by_ip) == {"10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.9", "10.0.0.10"}
    assert len(rows) == len(by_ip), "必须去重"
    assert all(len(r) == 4 for r in rows)
    assert {ip: r[3] for ip, r in by_ip.items()} == {
        "10.0.0.1": "master", "10.0.0.2": "master", "10.0.0.3": "master",
        "10.0.0.9": "probation", "10.0.0.10": "probation",
    }
    # first_seen：master 用 master_state.last_pass；probation 用第 1 列；缺失用当前时间
    assert by_ip["10.0.0.1"][1] == "2026-10-01 02:00:00"
    assert by_ip["10.0.0.2"][1] == "2026-10-02 04:00:00"
    assert by_ip["10.0.0.9"][1] == "2026-10-14 04:00:01"
    assert by_ip["10.0.0.3"][1].startswith("20") and len(by_ip["10.0.0.3"][1]) == 19
    # last_sampled：master 用 last_checked
    assert by_ip["10.0.0.1"][2] == "2026-10-15 16:00:01"

    for name in ("master_ips.txt", "master_state.tsv", "probation_pool.tsv"):
        assert not (root / name).exists()
        assert (root / f"{name}.legacy").exists()
    assert (root / "run.sh.legacy").read_text(encoding="utf-8") == RUN_SH
    run_sh = (root / "run.sh").read_text(encoding="utf-8")
    assert 'exec "$CFST_DIR/cycle.sh" slow "$@"' in run_sh
    assert os.access(root / "run.sh", os.X_OK)
    assert "7-59/15 * * * * cd /opt/cfst && /usr/bin/bash cycle.sh fast >> results/fast.log 2>&1" in r.stdout


def test_migrate_is_idempotent(tmp_path: Path) -> None:
    root = _seed(tmp_path)
    assert _run(MIGRATE, root).returncode == 0
    before = (root / "contenders.tsv").read_bytes()
    r = _run(MIGRATE, root)
    assert r.returncode == 0, r.stderr
    assert "已迁移" in r.stdout or "already" in r.stdout.lower()
    assert (root / "contenders.tsv").read_bytes() == before
    assert (root / "run.sh.legacy").read_text(encoding="utf-8") == RUN_SH, "重复运行不得覆盖备份"


def test_migrate_without_probation_or_state_uses_now(tmp_path: Path) -> None:
    root = _seed(tmp_path)
    (root / "probation_pool.tsv").unlink()
    (root / "master_state.tsv").unlink()
    r = _run(MIGRATE, root)
    assert r.returncode == 0, r.stderr
    rows = _rows(root / "contenders.tsv")
    assert {r[0] for r in rows} == {"10.0.0.1", "10.0.0.2", "10.0.0.3"}
    assert all(r[3] == "master" and len(r[1]) == 19 for r in rows)


def test_roundtrip_restores_legacy_files_and_is_idempotent(tmp_path: Path) -> None:
    root = _seed(tmp_path)
    assert _run(MIGRATE, root).returncode == 0
    r = _run(ROLLBACK, root)
    assert r.returncode == 0, r.stderr
    assert (root / "master_ips.txt").read_text(encoding="utf-8") == MASTER
    assert (root / "master_state.tsv").read_text(encoding="utf-8") == MASTER_STATE
    assert (root / "probation_pool.tsv").read_text(encoding="utf-8") == PROBATION
    assert (root / "run.sh").read_text(encoding="utf-8") == RUN_SH
    for name in ("master_ips.txt", "master_state.tsv", "probation_pool.tsv", "run.sh"):
        assert not (root / f"{name}.legacy").exists()
    assert not (root / "contenders.tsv").exists()
    assert (root / "contenders.tsv.rolledback").exists()
    assert "cycle.sh fast" in r.stdout, "需提示删除 fast cron 行"
    # tmp 目录不是 git 仓库：旧链路模块无法恢复时必须明确告警而非静默
    assert "旧链路模块缺失" in r.stderr and "无法从 git" in r.stderr, r.stderr

    r2 = _run(ROLLBACK, root)
    assert r2.returncode == 0, r2.stderr
    assert (root / "master_ips.txt").read_text(encoding="utf-8") == MASTER

    # 回滚后可再次迁移，集合一致
    assert _run(MIGRATE, root).returncode == 0
    assert {r[0] for r in _rows(root / "contenders.tsv")} == {
        "10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.9", "10.0.0.10"}


def test_rollback_restores_legacy_modules_from_git_history(tmp_path: Path) -> None:
    """Task 10 删除了 score.py/pool.py/probation_pool.py；回滚时从 git 历史恢复到根目录。"""
    root = _seed(tmp_path)
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    (root / "score.py").write_text("print('legacy score')\n", encoding="utf-8")
    (root / "pool.py").write_text("print('legacy pool')\n", encoding="utf-8")
    (root / "probation_pool.py").write_text("print('legacy probation')\n", encoding="utf-8")
    env = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@x", GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@x")
    subprocess.run(["git", "-C", str(root), "add", "score.py", "pool.py", "probation_pool.py"], check=True, env=env)
    subprocess.run(["git", "-C", str(root), "commit", "-q", "-m", "legacy"], check=True, env=env)
    sha = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"], capture_output=True, text=True, check=True).stdout.strip()
    for m in ("score.py", "pool.py", "probation_pool.py"):
        (root / m).unlink()
    assert _run(MIGRATE, root).returncode == 0
    env2 = os.environ.copy()
    env2.update(MIGRATE_ROOT=str(root), MIGRATE_LOCK=str(root / ".test.lock"), LEGACY_MODULES_COMMIT=sha)
    r = subprocess.run(["bash", str(ROLLBACK)], env=env2, cwd=root, capture_output=True, text=True, check=False)
    assert r.returncode == 0, r.stderr
    assert (root / "score.py").read_text(encoding="utf-8") == "print('legacy score')\n"
    assert (root / "probation_pool.py").exists() and (root / "pool.py").exists()
    assert "旧链路模块缺失" not in r.stderr


def test_scripts_exit_75_when_lock_is_held(tmp_path: Path) -> None:
    root = _seed(tmp_path)
    lock = root / ".test.lock"
    with open(lock, "w", encoding="utf-8") as fh:
        fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
        assert _run(MIGRATE, root).returncode == 75
        assert (root / "master_ips.txt").exists(), "锁忙时不得改动任何文件"
        assert _run(ROLLBACK, root).returncode == 75
        fcntl.flock(fh, fcntl.LOCK_UN)


def test_migrate_imports_all_probation_when_history_missing(tmp_path: Path) -> None:
    """无 history 无法判断活跃度 → 全部导入，避免误删候选。"""
    root = _seed(tmp_path)
    (root / "vless_history.tsv").unlink()
    r = _run(MIGRATE, root)
    assert r.returncode == 0, r.stderr
    rows = _rows(root / "contenders.tsv")
    assert {r[0] for r in rows if r[3] == "probation"} == {"10.0.0.9", "10.0.0.10", "10.0.0.11", "10.0.0.12"}


def test_migrate_probation_window_is_configurable(tmp_path: Path) -> None:
    root = _seed(tmp_path)
    env = os.environ.copy()
    env.update(MIGRATE_ROOT=str(root), MIGRATE_LOCK=str(root / ".test.lock"), MIGRATE_PROBATION_HOURS="48")
    r = subprocess.run(["bash", str(MIGRATE)], env=env, cwd=root, capture_output=True, text=True, check=False)
    assert r.returncode == 0, r.stderr
    rows = _rows(root / "contenders.tsv")
    assert {r[0] for r in rows if r[3] == "probation"} == {"10.0.0.9", "10.0.0.10", "10.0.0.12"}, "48h 窗口应纳入 30h 前的 PASS，FAIL-only 仍排除"


def test_migrate_history_path_override(tmp_path: Path) -> None:
    root = _seed(tmp_path)
    (root / "vless_history.tsv").unlink()
    alt = tmp_path / "alt_history.tsv"
    alt.write_text(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\t10.0.0.12\tPASS\t40\t\n", encoding="utf-8")
    env = os.environ.copy()
    env.update(MIGRATE_ROOT=str(root), MIGRATE_LOCK=str(root / ".test.lock"), VLESS_HISTORY=str(alt))
    r = subprocess.run(["bash", str(MIGRATE)], env=env, cwd=root, capture_output=True, text=True, check=False)
    assert r.returncode == 0, r.stderr
    rows = _rows(root / "contenders.tsv")
    assert {r[0] for r in rows if r[3] == "probation"} == {"10.0.0.12"}

def test_migrate_adopts_shadow_pool_when_present(tmp_path: Path) -> None:
    """影子期结束时 .shadow/ 的池已连续采样/淘汰 48h：切换应采用它而不是重新从 master+probation 生成。
    影子池 ∪ 当前 master（影子期间新晋升的 master 不丢）；影子黑名单并入 .screen_blacklist.tsv；影子目录改名留档。"""
    root = _seed(tmp_path)
    shadow = root / ".shadow"
    shadow.mkdir()
    (shadow / "contenders.tsv").write_text(
        "# contenders.tsv — ip\tfirst_seen\tlast_sampled\torigin\n"
        "10.0.0.1\t2026-10-01 02:00:00\t2026-10-15 18:00:00\tmaster\n"
        "10.0.0.9\t2026-10-14 04:00:01\t2026-10-15 18:00:00\tprobation\n"
        "10.0.0.50\t2026-10-15 10:00:00\t2026-10-15 18:00:00\tscreen\n", encoding="utf-8")
    (shadow / "blacklist.tsv").write_text("10.0.0.2\t2026-10-15 12:00:00\n", encoding="utf-8")
    (shadow / "best_ips.txt").write_text("# shadow best\n", encoding="utf-8")
    (root / ".screen_blacklist.tsv").write_text("10.0.0.77\t2026-10-15 11:00:00\n", encoding="utf-8")
    r = _run(MIGRATE, root)
    assert r.returncode == 0, r.stderr
    rows = [l.split("\t") for l in (root / "contenders.tsv").read_text().splitlines() if not l.startswith("#")]
    by_ip = {row[0]: row for row in rows}
    assert set(by_ip) == {"10.0.0.1", "10.0.0.9", "10.0.0.50", "10.0.0.3"}   # 10.0.0.2 在影子黑名单 → 不补入；10.0.0.3 是 master 但不在影子池 → 补入
    assert by_ip["10.0.0.50"][3] == "screen" and by_ip["10.0.0.1"][2] == "2026-10-15 18:00:00"
    assert by_ip["10.0.0.3"][3] == "master"
    bl = (root / ".screen_blacklist.tsv").read_text()
    assert "10.0.0.77\t" in bl and "10.0.0.2\t2026-10-15 12:00:00" in bl
    assert not (root / ".shadow").exists() and (root / ".shadow.adopted").is_dir()
    assert "影子池" in r.stdout
