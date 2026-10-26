"""质量和容量冷却隔离、到期及原子更新。"""
import importlib
from datetime import datetime, timedelta
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
NOW = datetime(2026, 10, 19, 12)


def test_capacity_expires_before_quality(tmp_path):
    module = importlib.import_module('cooldown')
    q, c = tmp_path/'quality', tmp_path/'capacity'
    module.record(q, ['198.51.100.15'], NOW-timedelta(hours=7), 24)
    module.record(c, ['198.51.100.16'], NOW-timedelta(hours=7), 6)
    assert module.active(q, NOW, 24) == {'198.51.100.15'}
    assert module.active(c, NOW, 6) == set()


def test_record_deduplicates_prunes_and_ignores_invalid_future(tmp_path):
    module = importlib.import_module('cooldown')
    path = tmp_path/'capacity'
    path.write_text('198.51.100.15\t2026-10-19 01:00:00\n198.51.100.16\t2026-10-20 01:00:00\ninvalid\t2026-10-19 10:00:00\n')
    module.record(path, ['198.51.100.17', '198.51.100.17'], NOW, 6)
    assert path.read_text() == '198.51.100.17\t2026-10-19 12:00:00\n'
    assert module.active(path, NOW, 6) == {'198.51.100.17'}


def test_empty_record_does_not_create_ledger(tmp_path):
    module = importlib.import_module('cooldown')
    path = tmp_path/'capacity'
    module.record(path, [], NOW, 6)
    assert not path.exists()


def test_invalid_duration_is_rejected_without_mutation(tmp_path):
    import pytest
    module = importlib.import_module('cooldown')
    path = tmp_path/'capacity'
    path.write_text('198.51.100.15\t2026-10-19 11:00:00\n')
    before = path.read_bytes()
    for hours in (0, -1, float('nan'), float('inf')):
        with pytest.raises(ValueError):
            module.record(path, ['198.51.100.16'], NOW, hours)
        assert path.read_bytes() == before
