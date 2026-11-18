"""Batch 3 RED/回归：锁、状态一致性与失败传播。

所有场景只使用临时 sandbox 和本地 fake 命令；不访问 MiSub、Cloudflare
或其他远端，也不修改 /opt/cfst 的运行态文件。

每个测试都保留 Given / When / Then 的用户可观察契约，而不是只断言私有
实现细节。
"""
from __future__ import annotations

import os
import shutil
import stat
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _write_executable(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


def _apply_sandbox(tmp_path: Path) -> Path:
    sandbox = tmp_path / "apply-sandbox"
    sandbox.mkdir()
    (sandbox / "best_ips.txt").write_text("# --- BEST_IPS\n1.1.1.1\n", encoding="utf-8")
    (sandbox / "misub.env").write_text("MISUB_TOKEN=fake\n", encoding="utf-8")
    (sandbox / "misub.env").chmod(0o600)
    (sandbox / "config.sh").write_text(
        f'''CFST_DIR={sandbox}
BEST="$CFST_DIR/best_ips.txt"
APPLY_STATE="$CFST_DIR/.apply_state"
MISUB_TOKEN_FILE="$CFST_DIR/misub.env"
PUBLISH_TOP_N=1
APPLY_COOLDOWN=0
publish_set() {{ printf '%s\\n' '1.1.1.1'; }}
compute_apply_state() {{ printf '%s\\n' 'same-state'; }}
''',
        encoding="utf-8",
    )
    shutil.copy2(ROOT / "apply.sh", sandbox / "apply.sh")
    (sandbox / "apply.sh").chmod((sandbox / "apply.sh").stat().st_mode | stat.S_IXUSR)
    _write_executable(
        sandbox / "push_to_misub.py",
        """#!/usr/bin/env python3
import os
import time
from pathlib import Path
marker = Path(os.environ["PUSH_MARKER"])
with marker.open("a", encoding="utf-8") as handle:
    handle.write("start\\n")
time.sleep(0.8)
with marker.open("a", encoding="utf-8") as handle:
    handle.write("end\\n")
""",
    )
    return sandbox


def test_apply_allows_at_most_one_concurrent_external_reconcile(tmp_path: Path) -> None:
    """Given two apply callers overlap, Then the fake external reconcile runs once."""
    sandbox = _apply_sandbox(tmp_path)
    marker = sandbox / "pushes.log"
    env = os.environ.copy()
    env["PUSH_MARKER"] = str(marker)
    first = subprocess.Popen(
        [str(sandbox / "apply.sh")],
        cwd=sandbox,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    second = subprocess.Popen(
        [str(sandbox / "apply.sh")],
        cwd=sandbox,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    first_rc = first.wait(timeout=10)
    second_rc = second.wait(timeout=10)
    assert first_rc in (0, 75)
    assert second_rc in (0, 75)

    lines = marker.read_text(encoding="utf-8").splitlines()
    assert lines.count("start") == 1


def _probe_sandbox(tmp_path: Path) -> Path:
    sandbox = tmp_path / "probe-sandbox"
    bindir = sandbox / "bin"
    barrier = sandbox / "barrier"
    bindir.mkdir(parents=True)
    barrier.mkdir()
    (sandbox / "config.sh").write_text(
        f'''CFST_DIR={sandbox}
BYPASS_GID=0
COLO_HOST=example.invalid
ROUTES="$CFST_DIR/routes.tsv"
''',
        encoding="utf-8",
    )
    shutil.copy2(ROOT / "probe.sh", sandbox / "probe.sh")
    shutil.copy2(ROOT / "ip_validation.py", sandbox / "ip_validation.py")
    (sandbox / "probe.sh").chmod((sandbox / "probe.sh").stat().st_mode | stat.S_IXUSR)
    _write_executable(
        sandbox / "parse_mtr.py",
        "#!/usr/bin/env python3\nprint('CF[edge]')\n",
    )
    _write_executable(
        bindir / "setpriv",
        "#!/bin/sh\nshift 3\nexec \"$@\"\n",
    )
    _write_executable(
        bindir / "curl",
        """#!/bin/sh
case "$*" in
  *cdn-cgi/trace*) printf '%s\\n' 'colo=HKG' ;;
  *) printf '%s\\n' 'curl-ok' ;;
esac
""",
    )
    _write_executable(
        bindir / "mtr",
        "#!/bin/sh\nprintf '%s\\n' 'mtr-ok'\n",
    )
    _write_executable(
        bindir / "awk",
        """#!/bin/sh
/usr/bin/awk "$@"
exec 9>"$BARRIER_DIR/awk.lock"
flock 9
count=0
[ -f "$BARRIER_DIR/awk-count" ] && count=$(cat "$BARRIER_DIR/awk-count")
count=$((count + 1))
printf '%s\\n' "$count" > "$BARRIER_DIR/awk-count"
if [ "$count" -ge 2 ]; then
  : > "$BARRIER_DIR/awk-release"
fi
flock -u 9
i=0
while [ ! -f "$BARRIER_DIR/awk-release" ] && [ "$i" -lt 20 ]; do
  sleep 0.05
  i=$((i + 1))
done
""",
    )
    return sandbox


def test_probe_concurrent_runs_preserve_both_route_rows(tmp_path: Path) -> None:
    """Given two probe callers overlap, Then both complete and retain their rows."""
    sandbox = _probe_sandbox(tmp_path)
    env = os.environ.copy()
    env["PATH"] = f"{sandbox / 'bin'}:{env['PATH']}"
    env["BARRIER_DIR"] = str(sandbox / "barrier")
    processes = [
        subprocess.Popen(
            [str(sandbox / "probe.sh"), ip],
            cwd=sandbox,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        for ip in ("1.1.1.1", "2.2.2.2")
    ]
    results = [process.communicate(timeout=10) for process in processes]

    assert [process.returncode for process in processes] == [0, 0], results
    rows = (sandbox / "routes.tsv").read_text(encoding="utf-8").splitlines()
    assert {row.split("\t")[1] for row in rows if "\t" in row} == {
        "1.1.1.1",
        "2.2.2.2",
    }


