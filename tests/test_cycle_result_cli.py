from pathlib import Path
from datetime import timedelta
import os
import subprocess
import sys
import json
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import cycle_result as cr
from test_cycle_result_records import NOW

ROOT = Path(__file__).resolve().parents[1]


def test_cli_begin_accepts_spaces_and_close_skipped(tmp_path):
    store = tmp_path / "path with spaces"
    r = subprocess.run(
        [sys.executable, str(ROOT / "cycle_result.py"), "begin", "--store", str(store), "--mode", "fast"],
        capture_output=True,
        text=True,
    )
    assert r.returncode == 0, r.stderr
    path, identity = r.stdout.splitlines()
    assert Path(path).parent == store and Path(path).stem == "cycle-" + identity
    close = subprocess.run(
        [
            sys.executable,
            str(ROOT / "cycle_result.py"),
            "finish",
            "--record",
            path,
            "--rank-status",
            "skipped",
            "--application",
            "unknown",
            "--exit-code",
            "0",
        ],
        capture_output=True,
        text=True,
    )
    assert close.returncode == 0, close.stderr
    assert json.loads(Path(path).read_text())["state"] == "skipped"


def test_conflicting_finalize_refused_without_change(tmp_path):
    h = cr.begin_cycle(tmp_path / "records", "fast", now=NOW)
    args = dict(rank_status="skipped", application="unknown", exit_code=0, now=NOW)
    cr.finish_cycle(h, **args)
    before = h.path.read_bytes()
    cr.finish_cycle(h, **args)
    assert h.path.read_bytes() == before
    with pytest.raises(ValueError):
        cr.finish_cycle(h, **(args | dict(exit_code=1)))
    assert h.path.read_bytes() == before


def test_atomic_orphan_not_reclaimed_before_threshold(tmp_path):
    store = tmp_path / "records"
    cr.begin_cycle(store, "fast", now=NOW)
    fresh = store / ".cycle-fresh.json.atomic"
    fresh.write_text("partial")
    os.utime(fresh, ((NOW - timedelta(minutes=179)).timestamp(),) * 2)
    cr.maintain_records(store, now=NOW)
    assert fresh.exists()


def test_cli_error_does_not_echo_untrusted_payload(tmp_path):
    bad = tmp_path / "receipt"
    bad.write_text('{"sensitive_payload":"do-not-echo-value"}')
    r = subprocess.run(
        [sys.executable, str(ROOT / "cycle_result.py"), "receipt", "--path", str(bad)],
        capture_output=True,
        text=True,
    )
    assert r.returncode != 0 and "ValueError" in r.stderr
    assert "do-not-echo-value" not in r.stderr + r.stdout
