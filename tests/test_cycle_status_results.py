from datetime import datetime, timedelta
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import status
import cycle_result as cr
from test_status import _fixture, ROUND
from test_cycle_result_records import receipt

NOW = datetime(2026, 10, 28, 18)


def test_fast_only_push_is_detected(tmp_path, monkeypatch):
    _fixture(tmp_path, "20261028_140001.log", "")
    (tmp_path / "results/fast.log").write_text(
        "[2026-10-28 17:45:00] apply: pushed 3 IPs -> 10.0.0.1 10.0.0.2 10.0.0.3\n"
    )
    monkeypatch.setattr(status, "CFST", tmp_path)
    rep = status.collect(NOW)
    assert rep["last_publish"]["at"] == "2026-10-28 17:45:00"
    assert rep["last_publish"]["source"] == "fast.log"


def test_only_new_result_needs_no_old_slow_log(tmp_path, monkeypatch):
    (tmp_path / "config.sh").write_text("POOL_MAX=150\n")
    store = tmp_path / "results/cycle-results"
    h = cr.begin_cycle(store, "fast", now=NOW)
    cr.finish_cycle(h, rank_status="ok", receipt=receipt(), application="confirmed", exit_code=0, now=NOW)
    monkeypatch.setattr(status, "CFST", tmp_path)
    rep = status.collect(NOW)
    assert rep["cycle_result"]["latest_complete"]["id"] == h.path.stem.removeprefix("cycle-")
    assert rep["contender"]["pool"] == 10
    assert "最近尝试" in status.render(rep)
    json.dumps(rep)


def test_latest_failure_not_hidden_by_older_success(tmp_path, monkeypatch):
    (tmp_path / "config.sh").write_text("POOL_MAX=150\n")
    store = tmp_path / "results/cycle-results"
    a = cr.begin_cycle(store, "fast", now=NOW - timedelta(minutes=1))
    cr.finish_cycle(a, rank_status="ok", receipt=receipt(), application="confirmed", exit_code=0, now=NOW)
    b = cr.begin_cycle(store, "slow", now=NOW)
    cr.finish_cycle(b, rank_status="skipped", application="unknown", exit_code=1, now=NOW)
    monkeypatch.setattr(status, "CFST", tmp_path)
    rep = status.collect(NOW)
    assert rep["cycle_result"]["latest_attempt"]["state"] == "failed"
    assert rep["cycle_result"]["latest_complete"]["id"] == a.path.stem.removeprefix("cycle-")
    assert any("失败" in w for w in rep["warnings"])


def test_new_record_and_same_cycle_log_are_not_double_counted(tmp_path, monkeypatch):
    _fixture(tmp_path, "20261028_170001.log", "")
    store = tmp_path / "results/cycle-results"
    h = cr.begin_cycle(store, "slow", now=NOW - timedelta(minutes=59))
    cr.finish_cycle(
        h,
        rank_status="ok",
        receipt=receipt(),
        application="confirmed",
        exit_code=0,
        screened=20,
        admitted=8,
        now=NOW,
    )
    log = tmp_path / "results/20261028_170001.log"
    log.write_text(
        ROUND + "\n[2026-10-28 17:00:01] cycle-record: id=" + h.path.stem.removeprefix("cycle-") + "\n"
    )
    monkeypatch.setattr(status, "CFST", tmp_path)
    rep = status.collect(NOW)
    assert rep["flow_7d"]["admitted"] == 8 and rep["flow_7d"]["evicted"] == 2
