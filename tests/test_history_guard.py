"""历史记录守卫：入口不可用不能变成"这些 IP 都坏了"的证据。"""
import re
import subprocess
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "verify_vless.sh"
WANTED = ("declare -a HISTORY_BUFFER", "append_vless_history()",
          "flush_vless_history()", "prune_vless_history()")


def _extract() -> str:
    text = SCRIPT.read_text()
    blocks = re.findall(r"^declare -a HISTORY_BUFFER=\(\)[^\n]*", text, re.M)
    for name in WANTED[1:]:
        match = re.search(rf"^{re.escape(name)} \{{.*?^\}}", text, re.M | re.S)
        assert match, name
        blocks.append(match.group(0))
    assert len(blocks) == 4, blocks
    return "\n\n".join(blocks) + "\n"


def _run(tmp_path: Path, calls: list[tuple[str, str, str]], env_extra: dict | None = None):
    history = tmp_path / "history.tsv"
    history.write_text("")
    script = tmp_path / "lib.sh"
    script.write_text(_extract())
    body = [f'VLESS_HISTORY="{history}"', f'source "{script}"']
    for status, median, reason in calls:
        body.append(f"append_vless_history 198.51.100.7 {status} {median} {reason!r}")
    body.append("flush_vless_history")
    env = {"VLESS_HISTORY": str(history), "PATH": "/usr/local/bin:/usr/bin:/bin"}
    env.update(env_extra or {})
    proc = subprocess.run(["bash", "-c", "; ".join(body)], capture_output=True, text=True, env=env)
    return history.read_text().splitlines(), proc.stderr


def test_normal_run_is_recorded(tmp_path: Path) -> None:
    rows, _ = _run(tmp_path, [("PASS", "51", ""), ("PASS", "57", ""), ("FAIL", "0", "timeout")])
    assert len(rows) == 3
    assert rows[0].split("\t")[2] == "PASS"


def test_whole_run_failing_at_transport_layer_is_discarded(tmp_path: Path) -> None:
    calls = [("FAIL", "0", "timeout")] * 5
    rows, stderr = _run(tmp_path, calls)
    assert rows == []
    assert "entry looks unavailable" in stderr


def test_one_real_result_keeps_the_run(tmp_path: Path) -> None:
    calls = [("FAIL", "0", "timeout")] * 4 + [("PASS", "49", "")]
    rows, _ = _run(tmp_path, calls)
    assert len(rows) == 5


def test_small_batch_is_never_suppressed(tmp_path: Path) -> None:
    calls = [("FAIL", "0", "timeout")] * 4
    rows, _ = _run(tmp_path, calls)
    assert len(rows) == 4


def test_non_transport_failures_are_kept(tmp_path: Path) -> None:
    calls = [("FAIL", "0", "timeout")] * 4 + [("FAIL", "130", "slow_ttfb")]
    rows, _ = _run(tmp_path, calls)
    assert len(rows) == 5


def test_no_record_discards_everything(tmp_path: Path) -> None:
    rows, stderr = _run(tmp_path, [("PASS", "51", "")], {"VLESS_NO_RECORD": "1"})
    assert rows == []
    assert "VLESS_NO_RECORD" in stderr
