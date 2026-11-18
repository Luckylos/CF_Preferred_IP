"""周期结果的业务interface：不使用真实网络、凭据或生产文件。"""

import sys
from pathlib import Path
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import cycle_result as cr


@pytest.mark.parametrize(
    "ok,systemic,requested,returned,percent,guard,minimum",
    [
        (False, True, 10, 1, 80, "no_evidence", 8),
        (True, True, 10, 1, 80, "systemic", 8),
        (True, False, 10, 7, 80, "coverage", 8),
        (True, False, 10, 8, 80, "none", 8),
        (True, False, 3, 2, 80, "coverage", 3),
        (True, False, 3, 3, 80, "none", 3),
        (True, False, 3, 2, 50, "none", 2),
        (True, False, 0, 0, 80, "none", 0),
        (True, False, None, None, 80, "none", None),
        (True, False, 10, None, 80, "none", 8),
        (True, False, 10, 0, 0, "none", 0),
    ],
)
def test_guard_legacy_priority_and_threshold(ok, systemic, requested, returned, percent, guard, minimum):
    e = cr.assess_audit(requested, returned, audit_ok=ok, systemic=systemic, percent=percent)
    assert (e.guard, e.minimum) == (guard, minimum)
    assert (e.requested, e.returned) == (requested, returned)


def test_audit_block_reader_and_read_error(tmp_path):
    path = tmp_path / "audit"
    path.write_text(
        "10.0.0.9 PASS\n=== AUDIT RESULTS ===\n 10.0.0.1 PASS\n 10.0.0.2 FAIL\n 999.0.0.1 FAIL\nfooter\n"
    )
    e = cr.assess_audit(3, audit_path=path)
    assert e.returned == 2 and e.guard == "coverage"
    with pytest.raises(IsADirectoryError):
        cr.assess_audit(3, audit_path=tmp_path)
    with pytest.raises(FileNotFoundError):
        cr.assess_audit(3, audit_path=tmp_path / "missing")


@pytest.mark.parametrize(
    "kwargs",
    [
        dict(percent=-1),
        dict(percent=101),
        dict(requested=-1),
        dict(returned=-1),
        dict(audit_ok=1),
        dict(systemic="1"),
    ],
)
def test_invalid_evidence_is_not_success(kwargs):
    with pytest.raises(ValueError):
        cr.assess_audit(**kwargs)
