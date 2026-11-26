"""看门狗只读生产、零网络：这里用最小 config.sh 假身驱动它，验证两种发布模式的出口文案。"""
from __future__ import annotations

import os
import subprocess
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "publish_watchdog.sh"


def sandbox(tmp_path: Path, *, mode: str, divergence_hours: float = 5.0,
            converged: bool = False) -> dict[str, str]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    cfg = tmp_path / "config.sh"
    cfg.write_text(f'''CFST_DIR={tmp_path}
CFST_PUBLISH={mode}
RESULT_DIR={tmp_path}
APPLY_STATE={tmp_path}/.apply_state
BEST={tmp_path}/best_ips.txt
PUBLISH_TOP_N=3
read_publish_targets() {{ printf "%s\\n" '' 203.0.113.1 203.0.113.2 203.0.113.3; }}
compute_apply_state() {{ echo newstate; }}
''', encoding="utf-8")
    (tmp_path / ".apply_state").write_text("newstate\n" if converged else "oldstate\n")
    (tmp_path / "best_ips.txt").write_text("# fresh\n", encoding="utf-8")
    (tmp_path / "cron.log").write_text(
        "[2026-11-23 01:00:00] apply: DNS publish failed (rc=1)\n"
        "[2026-11-23 01:00:00] apply: push_to_misub failed\n", encoding="utf-8")
    state = tmp_path / ".publish_watchdog_state"
    if not converged:
        first = int(time.time()) - int(divergence_hours * 3600)
        state.write_text(f"{first} 0 oldstate\n", encoding="utf-8")
    return {
        "CFST_CONFIG": str(cfg),
        "PUBLISH_WATCHDOG_STATE": str(state),
        "PUBLISH_STALE_HOURS": "3",
        "PIPELINE_STALE_HOURS": "5",
        "ALERT_REPEAT_HOURS": "6",
    }


def run(env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["bash", str(SCRIPT)], capture_output=True, text=True,
                          env={**os.environ, **env}, timeout=60)


def test_dns_mode_does_not_talk_about_misub(tmp_path: Path) -> None:
    proc = run(sandbox(tmp_path, mode="dns"))
    assert proc.returncode == 0, proc.stderr
    assert "未落地" in proc.stdout
    assert "MiSub" not in proc.stdout
    assert "DNS" in proc.stdout
    assert "应发布 Top3" in proc.stdout


def test_misub_mode_keeps_its_wording(tmp_path: Path) -> None:
    proc = run(sandbox(tmp_path, mode="misub"))
    assert proc.returncode == 0, proc.stderr
    assert "MiSub" in proc.stdout


def test_converged_state_is_silent(tmp_path: Path) -> None:
    proc = run(sandbox(tmp_path, mode="dns", converged=True))
    assert proc.returncode == 0
    assert proc.stdout.strip() == ""


def test_recent_divergence_is_not_an_alert(tmp_path: Path) -> None:
    proc = run(sandbox(tmp_path, mode="dns", divergence_hours=1))
    assert proc.returncode == 0
    assert proc.stdout.strip() == ""


def test_failure_hint_matches_publish_mode(tmp_path: Path) -> None:
    dns = run(sandbox(tmp_path / "a", mode="dns"))
    assert "DNS publish failed" in dns.stdout
    assert "push_to_misub failed" not in dns.stdout
    misub = run(sandbox(tmp_path / "b", mode="misub"))
    assert "push_to_misub failed" in misub.stdout


def test_both_mode_names_both_channels(tmp_path: Path) -> None:
    proc = run(sandbox(tmp_path, mode="both"))
    assert proc.returncode == 0, proc.stderr
    assert "DNS 记录集 + MiSub" in proc.stdout


def test_both_mode_reports_either_channels_failure(tmp_path: Path) -> None:
    """两条通道都落地时，任一通道的最新失败都要能被指出来。"""
    env = sandbox(tmp_path, mode="both")
    dns_only = run(env)
    assert "push_to_misub failed" in dns_only.stdout

    (tmp_path / "cron.log").write_text(
        "[2026-11-23 02:00:00] apply: push_to_misub failed\n"
        "[2026-11-23 03:00:00] apply: DNS publish failed (rc=1)\n", encoding="utf-8")
    (tmp_path / ".publish_watchdog_state").write_text(
        f"{int(time.time()) - 5 * 3600} 0 oldstate\n", encoding="utf-8")
    dns_last = run(env)
    assert "DNS publish failed" in dns_last.stdout
