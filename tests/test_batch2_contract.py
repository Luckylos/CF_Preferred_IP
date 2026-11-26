"""Batch 2 RED/回归：VLESS 测量与 probation 状态契约。

所有外部命令均为本地 fake；测试不访问 MiSub、Cloudflare 或其他远端。
测试尽量走 verify_vless.sh 的真实 shell 入口，避免只测私有 helper。
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


def _verify_sandbox(
    tmp_path: Path,
    *,
    tries: int,
    time_rows: str,
    http_rows: str,
    history_name: str = "history.tsv",
    curl_rc: int = 0,
) -> tuple[Path, subprocess.CompletedProcess[str], Path]:
    sandbox = tmp_path / "vcheck-sandbox"
    (sandbox / "bin").mkdir(parents=True)
    (sandbox / "results").mkdir()
    (sandbox / "shm").mkdir()
    history = sandbox / history_name
    history.write_text("", encoding="utf-8")
    secret = sandbox / "vless.env"
    secret.write_text("VLESS_UUID=00000000-0000-4000-8000-000000000001\n", encoding="utf-8")
    secret.chmod(0o600)
    input_file = sandbox / "ips.txt"
    input_file.write_text("1.1.1.1\n", encoding="utf-8")

    (sandbox / "config.sh").write_text(
        f'''CFST_DIR={sandbox}
RESULT_DIR="$CFST_DIR/results"
BYPASS_GID=0
BEST="$CFST_DIR/best_ips.txt"
VLESS_HISTORY="$CFST_DIR/{history_name}"
VLESS_SECRET_FILE="$CFST_DIR/vless.env"
VERIFY_TMPDIR_BASE="$CFST_DIR/shm"
VLESS_TRIES={tries}
VLESS_VERIFY_TIMEOUT=1
VLESS_BATCH_SIZE=1
VLESS_TEMPLATE=HK
SCORE_TOP_N=5
VLESS_UUID=$(sed -n 's/^VLESS_UUID=//p' "$VLESS_SECRET_FILE" | tail -n1)
declare -A NODE_HK=( [host]="example.invalid" [path]="/test" [uuid]="$VLESS_UUID" [fp]="chrome" )
declare -A NODE_SG=( [host]="example.invalid" [path]="/test" [uuid]="$VLESS_UUID" [fp]="chrome" )
''',
        encoding="utf-8",
    )
    shutil.copy2(ROOT / "verify_vless.sh", sandbox / "vcheck.sh")
    shutil.copy2(ROOT / "ip_validation.py", sandbox / "ip_validation.py")
    shutil.copy2(ROOT / "vless_template.py", sandbox / "vless_template.py")
    shutil.copy2(ROOT / "quality_evidence.py", sandbox / "quality_evidence.py")
    shutil.copy2(ROOT / "atomic_io.py", sandbox / "atomic_io.py")
    (sandbox / "vcheck.sh").chmod(
        (sandbox / "vcheck.sh").stat().st_mode | stat.S_IXUSR
    )

    _write_executable(
        sandbox / "bin" / "xray",
        "#!/bin/sh\ntrap 'exit 0' TERM INT\nwhile :; do sleep 1; done\n",
    )
    _write_executable(
        sandbox / "bin" / "setpriv",
        "#!/bin/sh\nshift 3\nexec \"$@\"\n",
    )
    _write_executable(
        sandbox / "bin" / "ss",
        "#!/bin/sh\nprintf '%s\\n' 'LISTEN 0 128 127.0.0.1:41000 0.0.0.0:*'\n",
    )
    _write_executable(
        sandbox / "bin" / "curl",
        """#!/bin/sh
case "$*" in
  *http_code*) printf '%s\\n' "$FAKE_HTTP_ROWS" ;;
  *) printf '%s\\n' "$FAKE_TIME_ROWS" ;;
esac
exit "${FAKE_CURL_RC:-0}"
""",
    )

    env = os.environ.copy()
    env["PATH"] = f"{sandbox / 'bin'}:{env['PATH']}"
    env["FAKE_TIME_ROWS"] = time_rows
    env["FAKE_HTTP_ROWS"] = http_rows
    env["FAKE_CURL_RC"] = str(curl_rc)
    if http_rows.startswith("0\t"):
        env["VLESS_REFERENCE_OUT"] = str(sandbox / "ref.txt")
    proc = subprocess.run(
        [str(sandbox / "vcheck.sh"), "--audit", str(input_file)],
        cwd=sandbox,
        env=env,
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    return sandbox, proc, history


def test_verify_records_structured_audit_without_changing_the_summary(tmp_path: Path) -> None:
    from datetime import datetime
    from quality_evidence import load_batches

    sandbox, proc, history = _verify_sandbox(
        tmp_path, tries=3, time_rows="",
        http_rows="0\t200\t0.440\t0\n1\t200\t0.050\t0\n2\t000\t0\t28\n3\t200\t0.065\t0\n",
    )
    assert proc.returncode == 0, proc.stderr
    assert "PARTIAL 58" in proc.stdout
    key, run = (sandbox / "ref.txt").read_text().splitlines()
    [batch] = load_batches(history.with_suffix(history.suffix + ".requests.jsonl"), datetime.now(), key)
    assert batch.run == run
    assert [(r.state, r.ttfb) for r in batch.requests] == [
        ("ok", 440), ("ok", 50), ("timeout", None), ("ok", 65),
    ]


def test_verify_even_samples_use_arithmetic_median(tmp_path: Path) -> None:
    """[40, 600] 的 conventional median 必须是 320，而不是下中位 40。"""
    _sandbox, proc, history = _verify_sandbox(
        tmp_path,
        tries=2,
        time_rows="0.010000\n0.040000\n0.600000\n",
        http_rows="200\t0.010000\n200\t0.040000\n200\t0.600000\n",
    )
    assert proc.returncode == 0, proc.stderr
    assert "1.1.1.1  PASS 320" in proc.stdout
    assert "\tPASS\t320\t" in history.read_text(encoding="utf-8")


def test_verify_partial_samples_are_not_pass(tmp_path: Path) -> None:
    """1 个成功 + 2 个 timeout 必须留下 PARTIAL 证据且不得伪装为 PASS。"""
    _sandbox, proc, history = _verify_sandbox(
        tmp_path,
        tries=3,
        time_rows="0.010000\n0.045000\n0.000000\n0.000000\n",
        http_rows="200\t0.010000\n200\t0.045000\n000\t0.000000\n000\t0.000000\n",
    )
    assert proc.returncode == 0, proc.stderr
    assert "1.1.1.1  PARTIAL 45" in proc.stdout
    assert "partial_success=1/3" in proc.stdout
    history_row = history.read_text(encoding="utf-8")
    assert "\tPARTIAL\t45\t" in history_row
    assert "\tPASS\t" not in history_row


def test_verify_non_2xx_response_is_not_pass(tmp_path: Path) -> None:
    """有 TTFB 但 HTTP 404 不能被当作业务 PASS。"""
    _sandbox, proc, history = _verify_sandbox(
        tmp_path,
        tries=3,
        time_rows="0.010000\n0.045000\n0.045000\n0.045000\n",
        http_rows="200\t0.010000\n404\t0.045000\n404\t0.045000\n404\t0.045000\n",
    )
    assert proc.returncode == 0, proc.stderr
    assert "1.1.1.1  PASS " not in proc.stdout
    assert "http_status" in proc.stdout
    assert "\tPASS\t" not in history.read_text(encoding="utf-8")


def test_verify_mixed_success_and_http_failure_is_partial(tmp_path: Path) -> None:
    """2xx 与非 2xx 混合时必须保留 partial 与 HTTP failure 证据。"""
    _sandbox, proc, history = _verify_sandbox(
        tmp_path,
        tries=3,
        time_rows="0.010000\n0.045000\n0.045000\n0.000000\n",
        http_rows="200\t0.010000\n200\t0.045000\n404\t0.045000\n000\t0.000000\n",
    )
    assert proc.returncode == 0, proc.stderr
    assert "1.1.1.1  PARTIAL 45" in proc.stdout
    assert "partial_success=1/3" in proc.stdout
    assert "http_status=404" in proc.stdout
    assert "\tPARTIAL\t45\t" in history.read_text(encoding="utf-8")


def test_verify_nonzero_curl_cannot_produce_pass(tmp_path: Path) -> None:
    """curl 非零即使带有成功输出，也只能留下不完整证据。"""
    _sandbox, proc, history = _verify_sandbox(
        tmp_path,
        tries=3,
        time_rows="0.010000\n0.045000\n0.045000\n0.045000\n",
        http_rows="200\t0.010000\n200\t0.045000\n200\t0.045000\n200\t0.045000\n",
        curl_rc=28,
    )
    assert proc.returncode == 0, proc.stderr
    assert "1.1.1.1  PASS " not in proc.stdout
    assert "PARTIAL" in proc.stdout
    assert "curl_rc=28" in proc.stdout
    assert "PARTIAL" in history.read_text(encoding="utf-8")


