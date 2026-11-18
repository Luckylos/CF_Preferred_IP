import pytest
from datetime import datetime, timezone
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import cycle_result as cr
from test_cycle_result_records import NOW


def test_coverage_ceiling_keeps_shell_integer_precision():
    requested = 10**18 + 1
    minimum = (requested * 80 + 99) // 100
    value = cr.assess_audit(requested, minimum - 1)
    assert value.minimum == minimum and value.guard == "coverage"


def test_unreadable_record_store_does_not_claim_exact_zero_flow(tmp_path):
    store = tmp_path / "file-not-directory"
    store.write_text("not a store")
    report = cr.read_status(store, now=NOW)
    assert report["errors"] and report["flow_7d"]["incomplete"] is True


@pytest.mark.parametrize("at", [datetime(1969, 1, 1), datetime(9999, 1, 1), NOW.replace(tzinfo=timezone.utc)])
def test_begin_rejects_unreadable_time_before_writing_record(tmp_path, at):
    with pytest.raises(ValueError):
        cr.begin_cycle(tmp_path / "records", "fast", now=at)
    assert not list((tmp_path / "records").glob("cycle-*.json"))
