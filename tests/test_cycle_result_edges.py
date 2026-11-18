import json
import os
import signal
import subprocess
import time
from datetime import timedelta
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import cycle_result as cr
from test_cycle_result_records import NOW, receipt
from test_cycle_admission import sandbox
from test_cycle_shadow_run import _exe


def test_duplicate_json_field_is_not_trusted(tmp_path):
    store = tmp_path / "records"
    h = cr.begin_cycle(store, "fast", now=NOW)
    text = h.path.read_text().replace('"schema_version": 1', '"schema_version": 99, "schema_version": 1')
    h.path.write_text(text)
    report = cr.read_status(store, now=NOW)
    assert report["latest_attempt"]["state"] == "invalid" and report["errors"]


def test_record_time_cannot_disagree_with_identity(tmp_path):
    store = tmp_path / "records"
    h = cr.begin_cycle(store, "fast", now=NOW)
    data = json.loads(h.path.read_text())
    data["started_at"] = (NOW - timedelta(days=1)).isoformat()
    h.path.write_text(json.dumps(data))
    assert cr.read_status(store, now=NOW)["latest_attempt"]["state"] == "invalid"


def test_open_or_corrupt_record_makes_flow_unknown(tmp_path):
    store = tmp_path / "records"
    h = cr.begin_cycle(store, "fast", now=NOW)
    assert cr.read_status(store, now=NOW)["flow_7d"]["incomplete"] is True
    h.path.write_text("{")
    assert cr.read_status(store, now=NOW)["flow_7d"]["incomplete"] is True


def test_truncated_push_marker_is_not_confirmation(tmp_path):
    log = tmp_path / "fast.log"
    log.write_text("[2026-10-28 18:00:00] apply: pushed 3 IPs -> 10.0.0.1 10.0.0.2\n")
    assert cr.read_status(tmp_path / "records", now=NOW, legacy_paths=[log])["last_push"] is None


def test_application_confirmation_still_has_unknown_push(tmp_path):
    h = cr.begin_cycle(tmp_path / "records", "fast", now=NOW)
    result = cr.finish_cycle(
        h, rank_status="ok", receipt=receipt(), application="confirmed", exit_code=0, now=NOW
    )
    assert result["push_evidence"] == "unknown"


def test_sigkill_leaves_open_and_next_cycle_reclaims_only_old_temps(tmp_path):
    sb = sandbox(tmp_path)
    verifier = sb.sb / "verify_vless.sh"
    original = verifier.read_text()
    _exe(verifier, '#!/bin/bash\n: > "$STUB_OUT/hanging"\nexec sleep 60\n')
    proc = subprocess.Popen(
        [str(sb.sb / "cycle.sh"), "slow"],
        cwd=sb.sb,
        env=sb.env(),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    try:
        deadline = time.monotonic() + 10
        while not (sb.stub / "hanging").exists() and time.monotonic() < deadline and proc.poll() is None:
            time.sleep(0.02)
        assert (sb.stub / "hanging").exists(), "只等待本测试的假审计进程，不接触生产"
        os.killpg(proc.pid, signal.SIGKILL)
        assert proc.wait(timeout=5) == -signal.SIGKILL
    finally:
        if proc.poll() is None:
            os.killpg(proc.pid, signal.SIGKILL)
            proc.wait(timeout=5)
    store = sb.sb / "results/cycle-results"
    assert cr.read_status(store)["latest_attempt"]["state"] == "open"
    leftovers = [p for p in (sb.sb / "results").iterdir() if p.is_file() and p.name.startswith(".")]
    assert leftovers
    for p in leftovers:
        os.utime(p, (time.time() - 181 * 60,) * 2)
    _exe(verifier, original)
    result = sb.run("slow")
    assert result.returncode == 0, result.stderr
    assert not [p for p in (sb.sb / "results").iterdir() if p.is_file() and p.name.startswith(".")]
    assert cr.read_status(store)["latest_attempt"]["state"] == "completed"
