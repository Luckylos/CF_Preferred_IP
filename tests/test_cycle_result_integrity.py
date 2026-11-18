from datetime import datetime
from pathlib import Path
import sys
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import cycle_result as cr

NOW = datetime(2026, 10, 28, 18)


def receipt():
    return cr.RankReceipt(NOW.isoformat(), 1, 1, 0, 0, ["10.0.0.1"], False, "none", 0, 1, 0, 0)


@pytest.mark.parametrize("forged", ["audit", "rank"])
def test_forged_values_rejected_before_durable_write(tmp_path, forged):
    h = cr.begin_cycle(tmp_path / "records", "fast", now=NOW)
    before = h.path.read_bytes()
    rank = receipt()
    audit = None
    if forged == "audit":
        audit = cr.AuditEvidence(10, 1, True, False, 80, 8, "none")
    else:
        rank.published.append("bad")
    with pytest.raises(ValueError):
        cr.finish_cycle(
            h, rank_status="ok", receipt=rank, audit=audit, application="confirmed", exit_code=0, now=NOW
        )
    assert h.path.read_bytes() == before


def test_mutated_receipt_is_not_written(tmp_path):
    r = receipt()
    r.published.append("bad")
    path = tmp_path / "receipt"
    with pytest.raises(ValueError):
        r.write(path)
    assert not path.exists()


def test_symlink_store_is_not_gc_destination_or_missing_success(tmp_path):
    foreign = tmp_path / "foreign"
    h = cr.begin_cycle(foreign, "fast", now=datetime(2020, 1, 1))
    store = tmp_path / "link"
    store.symlink_to(foreign, target_is_directory=True)
    with pytest.raises(ValueError):
        cr.maintain_records(store, now=NOW)
    assert h.path.exists()
    broken = tmp_path / "broken"
    broken.symlink_to(tmp_path / "missing")
    assert cr.read_status(broken, now=NOW)["errors"]
