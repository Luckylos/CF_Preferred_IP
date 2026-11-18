import json
import os
from datetime import datetime, timedelta
from pathlib import Path
import sys
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import cycle_result as cr

NOW = datetime(2026, 10, 28, 18)


def receipt(**kw):
    fields = dict(
        at=NOW.isoformat(),
        pool=10,
        core=2,
        challengers=2,
        evicted=2,
        published=["10.0.0.1"],
        changed=True,
        guard="none",
        evaluated=4,
        waiting=6,
        quality_evicted=1,
        capacity_evicted=1,
        dry_run=False,
    )
    return cr.RankReceipt(**(fields | kw))


def done(handle, **kw):
    fields = dict(rank_status="ok", receipt=receipt(), application="confirmed", exit_code=0, now=NOW)
    return cr.finish_cycle(handle, **(fields | kw))


def test_begin_finish_is_atomic_business_record(tmp_path):
    h = cr.begin_cycle(tmp_path / "records", "slow", now=NOW)
    assert json.loads(h.path.read_text())["state"] == "open"
    before = cr.read_status(tmp_path / "records", now=NOW)
    assert before["latest_attempt"]["state"] == "open" and before["latest_complete"] is None
    result = done(h, audit=cr.assess_audit(10, 8), screened=3, admitted=2, warnings=["probe_failed"])
    assert result["state"] == "completed" and result["warnings"] == ["probe_failed"]
    report = cr.read_status(tmp_path / "records", now=NOW)
    assert report["latest_complete"]["id"] == result["id"]
    assert report["flow_7d"]["admitted"] == 2
    assert report["flow_7d"]["evicted"] == 2
    assert report["last_push"] is None, "changed与应用确认都不能伪造推送"


@pytest.mark.parametrize("guard", ["none", "no_evidence", "coverage", "systemic"])
def test_legal_guards_can_be_complete(tmp_path, guard):
    h = cr.begin_cycle(tmp_path / "records", "fast", now=NOW)
    done(h, receipt=receipt(guard=guard))
    assert cr.read_status(tmp_path / "records", now=NOW)["latest_complete"] is not None


@pytest.mark.parametrize(
    "kw,state",
    [
        (dict(rank_status="failed", receipt=None, exit_code=1), "failed"),
        (dict(application="unconfirmed", exit_code=1), "failed"),
        (dict(application="failed", exit_code=2), "failed"),
        (dict(rank_status="skipped", receipt=None, application="unknown"), "skipped"),
        (dict(receipt=None, rank_status="skipped", exit_code=75), "failed"),
    ],
)
def test_failed_or_skipped_is_latest_not_complete(tmp_path, kw, state):
    store = tmp_path / "records"
    first = cr.begin_cycle(store, "fast", now=NOW - timedelta(minutes=1))
    done(first)
    second = cr.begin_cycle(store, "slow", now=NOW)
    done(second, **kw)
    report = cr.read_status(store, now=NOW)
    assert report["latest_attempt"]["state"] == state
    assert report["latest_complete"]["id"] == first.path.stem.removeprefix("cycle-")


def test_unconfirmed_cannot_be_completed_even_rc_zero(tmp_path):
    h = cr.begin_cycle(tmp_path / "records", "fast", now=NOW)
    with pytest.raises(ValueError):
        done(h, application="unconfirmed")
    assert json.loads(h.path.read_text())["state"] == "open"


def test_dry_run_receipt_cannot_claim_real_completion(tmp_path):
    h = cr.begin_cycle(tmp_path / "records", "fast", now=NOW)
    with pytest.raises(ValueError):
        done(h, receipt=receipt(dry_run=True))


def test_late_slow_close_does_not_override_new_fast(tmp_path):
    store = tmp_path / "records"
    slow = cr.begin_cycle(store, "slow", now=NOW)
    fast = cr.begin_cycle(store, "fast", now=NOW + timedelta(seconds=1))
    done(fast, now=NOW + timedelta(seconds=2))
    done(slow, now=NOW + timedelta(seconds=3))
    r = cr.read_status(store, now=NOW + timedelta(seconds=4))
    assert r["latest_attempt"]["mode"] == "fast" and r["latest_complete"]["mode"] == "fast"


def test_shadow_does_not_mix_production(tmp_path):
    normal = cr.begin_cycle(tmp_path / "normal", "fast", now=NOW)
    done(normal)
    shadow = cr.begin_cycle(tmp_path / "shadow", "slow", shadow=True, now=NOW)
    done(shadow, application="shadow_skipped")
    assert cr.read_status(tmp_path / "normal", now=NOW)["latest_complete"]["shadow"] is False
    assert cr.read_status(tmp_path / "shadow", now=NOW)["latest_complete"]["shadow"] is True


@pytest.mark.parametrize(
    "mutation",
    [{"schema_version": 99}, {"state": "green"}, {"exit_code": True}, {"unexpected": "raw output"}],
)
def test_bad_new_record_is_visible_not_old_success(tmp_path, mutation):
    store = tmp_path / "records"
    old = cr.begin_cycle(store, "slow", now=NOW - timedelta(minutes=1))
    done(old)
    new = cr.begin_cycle(store, "fast", now=NOW)
    data = json.loads(new.path.read_text())
    data.update(mutation)
    new.path.write_text(json.dumps(data))
    r = cr.read_status(store, now=NOW)
    assert r["latest_attempt"]["state"] == "invalid"
    assert r["errors"] and r["latest_complete"]["id"] == old.path.stem.removeprefix("cycle-")


def test_invalid_json_and_unreadable_store_visible(tmp_path):
    store = tmp_path / "records"
    h = cr.begin_cycle(store, "fast", now=NOW)
    h.path.write_text("{")
    assert cr.read_status(store, now=NOW)["latest_attempt"]["state"] == "invalid"
    file = tmp_path / "not-dir"
    file.write_text("x")
    assert cr.read_status(file, now=NOW)["errors"]


def test_initial_and_final_write_errors_propagate(tmp_path, monkeypatch):
    def fail(*args, **kwargs):
        raise OSError("injected")

    store = tmp_path / "records"
    with monkeypatch.context() as m:
        m.setattr(cr, "atomic_write", fail)
        with pytest.raises(OSError):
            cr.begin_cycle(store, "slow", now=NOW)
    h = cr.begin_cycle(store, "slow", now=NOW)
    before = h.path.read_bytes()
    with monkeypatch.context() as m:
        m.setattr(cr, "atomic_write", fail)
        with pytest.raises(OSError):
            done(h)
    assert h.path.read_bytes() == before


def test_gc_keeps_latest_complete_and_own_namespace_only(tmp_path):
    store = tmp_path / "records"
    old = cr.begin_cycle(store, "slow", now=NOW - timedelta(days=10))
    done(old, now=NOW - timedelta(days=9))
    doomed = cr.begin_cycle(store, "fast", now=NOW - timedelta(days=8))
    other = store / "unrelated.json"
    other.write_text("secret-not-read")
    target = tmp_path / "foreign"
    target.write_text("untouched")
    link = store / "cycle-00000000000000000000-fast-1-1.json"
    link.symlink_to(target)
    temp = store / ".cycle-old.json.orphan"
    temp.write_text("partial")
    os.utime(temp, (NOW.timestamp() - 181 * 60,) * 2)
    fresh = cr.begin_cycle(store, "fast", now=NOW)
    cr.maintain_records(store, now=NOW)
    assert old.path.exists() and fresh.path.exists() and not doomed.path.exists()
    assert other.read_text() == "secret-not-read" and link.is_symlink() and target.read_text() == "untouched"
    assert not temp.exists()


def test_receipt_strict_schema_and_path_alias(tmp_path):
    r = receipt()
    p = tmp_path / "rank.json"
    r.write(p)
    assert cr.read_rank_receipt(p) == r
    with pytest.raises(ValueError):
        cr.preflight_receipt(p, [p])
    hard = tmp_path / "hard"
    os.link(p, hard)
    with pytest.raises(ValueError):
        cr.preflight_receipt(p, [hard])
    sym = tmp_path / "sym"
    sym.symlink_to(p)
    with pytest.raises(ValueError):
        cr.preflight_receipt(p, [sym])
    data = json.loads(p.read_text())
    data["changed"] = 1
    p.write_text(json.dumps(data))
    with pytest.raises(ValueError):
        cr.read_rank_receipt(p)


@pytest.mark.parametrize(
    "kw", [{"pool": True}, {"guard": "unknown"}, {"published": ["bad"]}, {"changed": 1}, {"evicted": 3}]
)
def test_bad_receipt_cannot_be_success(kw):
    with pytest.raises(ValueError):
        receipt(**kw)
