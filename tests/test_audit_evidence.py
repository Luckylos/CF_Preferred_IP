from datetime import datetime, timedelta

import pytest

from audit_evidence import bind, completed, record, summarize
from quality_evidence import Batch, Request


NOW = datetime(2026, 11, 26, 21, 4)
REFERENCE = "a" * 64
RUN = "test-cycle"
IPS = [f"192.0.2.{i}" for i in range(1, 21)]


def batch(ip, state="ok", ms=40, *, run=RUN, reference=REFERENCE, at=NOW):
    request = Request(state, ms if state == "ok" else None)
    return Batch(at, run, reference, ip, (request, request))


def audit(batches, ips=IPS):
    return summarize(batches, ips, RUN, REFERENCE, NOW - timedelta(minutes=20), NOW)


def test_coverage_counts_actual_attempts_and_deduplicates():
    batches = [batch(ip) for ip in IPS[:14]] + [batch(IPS[14], "timeout")]
    batches += [batch(ip, "xray_start_failed") for ip in IPS[15:]]
    result = audit([*batches, batches[0]], [*IPS, IPS[0]])
    assert (result.requested, result.returned, result.guard) == (20, 15, "coverage")


def test_old_run_cannot_complete_coverage():
    assert audit([batch(ip, run="stale") for ip in IPS]).guard == "no_evidence"


@pytest.mark.parametrize("extra", [
    batch("192.0.2.21"), batch(IPS[0], reference="b" * 64),
    batch(IPS[0], at=NOW - timedelta(minutes=21)),
])
def test_mismatched_landed_record_invalidates_round(extra):
    assert audit([batch(ip) for ip in IPS] + [extra]).guard == "no_evidence"


@pytest.mark.parametrize("ms, expected", [(150, "none"), (151, "systemic")])
def test_warm_p10_strict_boundary(ms, expected):
    assert audit([batch(ip, ms=ms) for ip in IPS[:10]], IPS[:10]).guard == expected


def test_failed_attempts_share_time_block():
    assert audit([batch(ip, "timeout" if i < 3 else "ok") for i, ip in enumerate(IPS[:5])], IPS[:5]).guard == "systemic"
    batches = [batch(ip, "timeout", at=NOW - timedelta(minutes=10)) for ip in IPS[:3]]
    batches += [batch(ip) for ip in IPS[3:5]]
    assert audit(batches, IPS[:5]).guard == "none"


def test_shared_failure_rate_counts_attempted_requests():
    from dataclasses import replace

    rows = [batch(ip) for ip in IPS[:5]]
    ok, timeout = Request("ok", 45), Request("timeout", None)
    partial = [replace(b, requests=(ok, ok, ok, timeout if i < 3 else ok)) for i, b in enumerate(rows)]
    assert audit(partial, IPS[:5]).guard == "none"
    heavy = [replace(b, requests=(timeout,) * 4 if i < 2 else (ok,)) for i, b in enumerate(rows)]
    assert audit(heavy, IPS[:5]).guard == "systemic"


def test_receipt_matches_landed_requests_and_cannot_rebind_observations(tmp_path):
    path = tmp_path / "observations"
    receipt = tmp_path / "receipt"
    now = datetime.now().replace(microsecond=0)
    ips = IPS[:2]
    rows = [f"{now.isoformat()}\t{ip}\t0\t200\t0.040\t0|1\t200\t0.040\t0" for ip in ips]
    bind(receipt, RUN, REFERENCE, ips)
    record(path, receipt, ips, RUN, REFERENCE, 1, rows)
    result = completed(path, receipt, ips, RUN, now, now)
    assert result.guard == "none" and result.returned == 2
    assert completed(path, receipt, IPS[:3], RUN, now, now).guard == "no_evidence"
    assert completed(path, receipt, ips, "another-run", now, now).guard == "no_evidence"
    original = path.read_bytes()
    bind(receipt, RUN, REFERENCE, ips)
    partial = completed(path, receipt, ips, RUN, now, now)
    assert partial.guard == "no_evidence" and len(partial.evidence) == 2
    with pytest.raises(ValueError, match="different observations"):
        record(path, receipt, ips, RUN, REFERENCE, 1, rows[:1])
    assert path.read_bytes() == original
    receipt.unlink()
    another_run = RUN + "-missing-plan"
    with pytest.raises(ValueError, match="plan missing"):
        record(path, receipt, ips, another_run, REFERENCE, 1, rows)
    assert not receipt.exists()
    assert "missing-plan" in path.read_text()
