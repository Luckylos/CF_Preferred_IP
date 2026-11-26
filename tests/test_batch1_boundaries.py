"""Batch 1: 输入边界、评分域、单文件持久化与发现队列契约。

这些测试优先验证用户/调度器可观察的文件、退出码和候选集合，而不是
把实现细节当作行为。测试中的网络/CloudflareST 均为本地 fake，不访问外部。
"""
from __future__ import annotations

import builtins
import importlib.util
import os
import shutil
import stat
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


PUSH_SPEC = importlib.util.spec_from_file_location("push_batch1", ROOT / "push_to_misub.py")
assert PUSH_SPEC and PUSH_SPEC.loader
push = importlib.util.module_from_spec(PUSH_SPEC)
sys.modules[PUSH_SPEC.name] = push
PUSH_SPEC.loader.exec_module(push)


class _FailingWriter:
    def __init__(self, wrapped):
        self._wrapped = wrapped

    def __enter__(self):
        self._wrapped.__enter__()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return self._wrapped.__exit__(exc_type, exc_value, traceback)

    def write(self, _data):
        raise OSError("simulated write failure after truncate")

    def __getattr__(self, name):
        return getattr(self._wrapped, name)


def _write_executable(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


def _scan_sandbox(
    tmp_path: Path,
    discovered: str,
    blacklist: str = "",
    scan_input: str = "192.0.2.1\n",
    cfst_rows: str = "",
    capacity: str = "",
    admission_override: str | None = None,
    master: str = "",
    contenders: str = "",
    cfst_rc: int = 0,
) -> tuple[Path, subprocess.CompletedProcess[str]]:
    sandbox = tmp_path / "scan-sandbox"
    sandbox.mkdir()
    results = sandbox / "results"
    results.mkdir()
    (sandbox / "master_ips.txt").write_text(master, encoding="utf-8")
    (sandbox / "contenders.tsv").write_text(contenders, encoding="utf-8")
    (sandbox / "discovered_ips.tsv").write_text(discovered, encoding="utf-8")
    (sandbox / "ip_ranges.txt").write_text(scan_input, encoding="utf-8")
    (sandbox / ".screen_blacklist.tsv").write_text(blacklist, encoding="utf-8")
    (sandbox / ".capacity_cooldown.tsv").write_text(capacity, encoding="utf-8")
    (sandbox / "config.sh").write_text(
        f'''CFST_DIR={sandbox}
RESULT_DIR="$CFST_DIR/results"
CFST_LOCK="$CFST_DIR/cfst.lock"
MASTER="$CFST_DIR/master_ips.txt"
DISCOVERED="$CFST_DIR/discovered_ips.tsv"
SCAN="$CFST_DIR/ip_ranges.txt"
SCREEN_BLACKLIST="$CFST_DIR/.screen_blacklist.tsv"
SCREEN_BLACKLIST_HOURS=24
DISCOVERY_TTL_HOURS=24
DISCOVERY_LIMIT=3
BYPASS_GID=1
QUAL_LAT=70
SCAN_TIMEOUT=10
SCAN_TIMEOUT_GRACE=1
''',
        encoding="utf-8",
    )
    _write_executable(
        sandbox / "setpriv",
        "#!/bin/sh\nshift 3\nexec \"$@\"\n",
    )
    _write_executable(
        sandbox / "cfst",
        f"""#!/bin/sh
out=""
target=""
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-o" ]; then out="$2"; shift 2
  elif [ "$1" = "-f" ]; then target="$2"; shift 2
  else shift
  fi
done
cp "$target" "$CFST_CAPTURE_TARGET"
printf 'IP,Sent,Received,Loss,Average,Speed,Region\\n' > "$out"
if [ -n "{cfst_rows}" ]; then
  printf '%s\\n' "{cfst_rows}" >> "$out"
fi
exit {cfst_rc}
""",
    )
    shutil.copy2(ROOT / "scan_latency.sh", sandbox / "scan_latency.sh")
    for name in ("ip_validation.py", "atomic_io.py", "cooldown.py", "rank.py", "admission.py", "cycle_result.py"):
        shutil.copy2(ROOT / name, sandbox / name)
    if admission_override is not None:
        shutil.copy2(sandbox / "admission.py", sandbox / "admission_real.py")
        (sandbox / "admission.py").write_text(admission_override)
    (sandbox / "scan_latency.sh").chmod((sandbox / "scan_latency.sh").stat().st_mode | stat.S_IXUSR)
    env = os.environ.copy()
    env["PATH"] = f"{sandbox}:{env['PATH']}"
    env["CFST_CAPTURE_TARGET"] = str(sandbox / "captured-target")
    proc = subprocess.run(
        [str(sandbox / "scan_latency.sh")],
        cwd=sandbox,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    return sandbox, proc


def test_scanner_skips_cfst_when_configured_input_and_pools_are_empty(tmp_path: Path) -> None:
    sandbox, result = _scan_sandbox(tmp_path, discovered="", scan_input="")
    assert result.returncode == 0, result.stderr
    assert not (sandbox / "captured-target").exists()
    assert "no valid scan targets" in result.stdout


def test_ipv4_boundary_rejects_semantic_and_shell_invalid_values() -> None:
    """合法 IPv4 通过；越界、IPv6 和 shell 特殊值必须拒绝。"""
    proc = subprocess.run(
        [sys.executable, str(ROOT / "ip_validation.py"), "--strict"],
        input="1.1.1.1\n255.255.255.255\n999.999.999.999\n2001:db8::1\n1.1.1.1;touch /tmp/marker\n",
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode != 0
    assert proc.stdout.splitlines() == ["1.1.1.1", "255.255.255.255"]


def test_push_read_best_ips_rejects_invalid_machine_entries(tmp_path: Path) -> None:
    best = tmp_path / "best_ips.txt"
    best.write_text(
        "# --- BEST_IPS (machine-readable) ---\n"
        "999.999.999.999\n1.1.1.1\n2.2.2.2\n",
        encoding="utf-8",
    )
    old = push.BEST_IPS_FILE
    vars(push)["BEST_IPS_FILE"] = str(best)
    try:
        with pytest.raises(RuntimeError, match="invalid IPv4"):
            push.read_best_ips()
    finally:
        vars(push)["BEST_IPS_FILE"] = old


def test_real_scan_queue_eviction_keeps_newest_same_day_rows(tmp_path: Path) -> None:
    # 时间戳必须相对 now 生成（本地时区，与 scan_latency.sh 的 `date -d "-N hours"` 同基准）。
    # 硬编码日期会在写作日 +DISCOVERY_TTL_HOURS 之后让所有行先被 CUTOFF 判为过期，
    # 队列变空后本断言就不再检验“溢出淘汰保留最新”，掩盖真正的淘汰排序回归。
    now = datetime.now().replace(microsecond=0)
    rows = "".join(
        f"{now - timedelta(hours=6 - index):%Y-%m-%d %H:%M:%S}\t10.0.0.{index + 1}\t0\t45\n"
        for index in range(6)
    )
    sandbox, proc = _scan_sandbox(tmp_path, rows)
    assert proc.returncode == 0, proc.stderr
    kept = [line.split("\t")[1] for line in (sandbox / "discovered_ips.tsv").read_text().splitlines()]
    assert kept == ["10.0.0.4", "10.0.0.5", "10.0.0.6"]


def test_real_scan_does_not_reenqueue_active_blacklist(tmp_path: Path) -> None:
    now = datetime.now(timezone.utc).replace(microsecond=0, tzinfo=None)
    active = now - timedelta(hours=1)
    expired = now - timedelta(hours=48)
    blacklist = (
        f"8.8.8.8\t{active:%Y-%m-%d %H:%M:%S}\n"
        f"7.7.7.7\t{expired:%Y-%m-%d %H:%M:%S}\n"
    )
    sandbox, proc = _scan_sandbox(
        tmp_path,
        "",
        blacklist,
        scan_input="8.8.8.8\n9.9.9.9\n7.7.7.7\n",
        cfst_rows=(
            "8.8.8.8,10,10,0,40,,\n"
            "9.9.9.9,10,10,0,50,,\n"
            "7.7.7.7,10,10,0,45,,\n"
        ),
    )
    assert proc.returncode == 0, proc.stderr
    kept = [line.split("\t")[1] for line in (sandbox / "discovered_ips.tsv").read_text().splitlines()]
    assert "8.8.8.8" not in kept
    assert "9.9.9.9" in kept
    assert "7.7.7.7" in kept


def test_real_scan_preserves_valid_cidr_scan_ranges(tmp_path: Path) -> None:
    sandbox, proc = _scan_sandbox(
        tmp_path,
        "",
        scan_input="192.0.2.0/24\n999.999.0.0/16\n2001:db8::/32\n",
    )
    assert proc.returncode == 0, proc.stderr
    target = (sandbox / "captured-target").read_text(encoding="utf-8").splitlines()
    assert "192.0.2.0/24" in target
    assert "999.999.0.0/16" not in target
    assert "2001:db8::/32" not in target


def test_queue_capacity_compares_full_timestamp_not_just_date(tmp_path: Path) -> None:
    from admission import maintain_queue
    queue = tmp_path / "queue"
    queue.write_text("2026-10-28 08:00:00\t10.100.0.9\t0\t49\n"
                     "2026-10-28 09:00:00\t10.100.0.1\t0\t41\n")
    maintain_queue(queue, datetime(2026, 10, 28, 10), 24, 1)
    assert queue.read_text() == "2026-10-28 09:00:00\t10.100.0.1\t0\t41\n"


def test_real_watchdog_rejects_injection(tmp_path: Path) -> None:
    marker = tmp_path / "injected"
    payload = f"127.0.0.1/443; touch {marker} #"
    (tmp_path / "best_ips.txt").write_text(
        "# --- BEST_IPS (machine-readable) ---\n" + payload + "\n",
        encoding="utf-8",
    )
    (tmp_path / "config.sh").write_text(
        f'CFST_DIR={tmp_path}\nBEST="$CFST_DIR/best_ips.txt"\n'
        'WATCHDOG_STATE="$CFST_DIR/.watchdog_state"\n'
        'WATCHDOG_MISS_THRESHOLD=3\nWATCHDOG_COOLDOWN=3600\n',
        encoding="utf-8",
    )
    shutil.copy2(ROOT / "watchdog.sh", tmp_path / "watchdog.sh")
    shutil.copy2(ROOT / "ip_validation.py", tmp_path / "ip_validation.py")
    (tmp_path / "watchdog.sh").chmod((tmp_path / "watchdog.sh").stat().st_mode | stat.S_IXUSR)

    proc = subprocess.run(
        [str(tmp_path / "watchdog.sh")],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    assert not marker.exists()
    assert not (tmp_path / ".watchdog_state").exists()


def test_real_probe_rejects_invalid_single_ip_before_network(tmp_path: Path) -> None:
    (tmp_path / "config.sh").write_text(
        f'CFST_DIR={tmp_path}\nBEST="$CFST_DIR/best_ips.txt"\n'
        'ROUTES="$CFST_DIR/routes.tsv"\nBYPASS_GID=1\nCOLO_HOST=example.invalid\n',
        encoding="utf-8",
    )
    shutil.copy2(ROOT / "probe.sh", tmp_path / "probe.sh")
    shutil.copy2(ROOT / "ip_validation.py", tmp_path / "ip_validation.py")
    (tmp_path / "probe.sh").chmod((tmp_path / "probe.sh").stat().st_mode | stat.S_IXUSR)

    proc = subprocess.run(
        [str(tmp_path / "probe.sh"), "999.999.999.999;touch /tmp/probe-marker"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 2
    assert not (tmp_path / "routes.tsv").exists()


def test_real_scan_excludes_active_capacity_cooldown_only(tmp_path: Path) -> None:
    now = datetime.now()
    stamp = now.strftime("%Y-%m-%d %H:%M:%S")
    old = (now-timedelta(hours=7)).strftime("%Y-%m-%d %H:%M:%S")
    sandbox, proc = _scan_sandbox(
        tmp_path, '', capacity=f'8.8.8.8\t{stamp}\n9.9.9.9\t{old}\n',
        cfst_rows='8.8.8.8,4,4,0,40,0,HKG\n9.9.9.9,4,4,0,40,0,HKG\n')
    assert proc.returncode == 0, proc.stderr
    kept = [line.split('\t')[1] for line in (sandbox/'discovered_ips.tsv').read_text().splitlines()]
    assert '8.8.8.8' not in kept
    assert '9.9.9.9' in kept
