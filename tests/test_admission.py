"""准入限额、元数据保留和等待不记失败。"""
import importlib
import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import rank

NOW = datetime(2026, 10, 19, 12)


def run(tmp_path, pool_size=4, maximum=5, outputs=None, queue=None):
    module = importlib.import_module('admission')
    paths = {k: tmp_path/k for k in ['pool', 'requested', 'passed', 'queue', 'blacklist']}
    saved = '2026-10-18 01:00:00'
    rows = [rank.Contender(f'10.0.0.{i}', '2026-10-16 12:00:00', '-', 'master', saved)
            for i in range(1, pool_size+1)]
    rank.write_contenders(paths['pool'], rows)
    paths['requested'].write_text('10.1.0.1\n10.1.0.2\n')
    paths['passed'].write_text(outputs if outputs is not None else '10.1.0.1\n10.1.0.2\n')
    paths['queue'].write_text(queue or '2026-10-19 10:00:00\t10.1.0.1\t0\t40\n2026-10-19 10:00:00\t10.1.0.2\t1\t41\n')
    admitted = module.process_screen(paths['pool'], paths['requested'], paths['passed'],
                                     paths['queue'], paths['blacklist'], NOW, maximum, 3)
    return paths, rows, admitted


def test_capacity_cap_and_metadata_preserved(tmp_path):
    paths, rows, admitted = run(tmp_path)
    actual = rank.read_contenders(paths['pool'])
    assert len(actual) == 5
    assert actual[:4] == rows
    assert admitted == ['10.1.0.1']
    assert actual[-1].evaluated_at == '-'
    assert paths['passed'].read_text() == '10.1.0.1\n'
    assert '10.1.0.2\t1\t41' in paths['queue'].read_text()
    assert not paths['blacklist'].exists()


def test_duplicate_unsolicited_invalid_screen_output_not_admitted(tmp_path):
    paths, _, admitted = run(tmp_path, outputs='10.1.0.1\n10.1.0.1\n10.9.9.9\n999.0.0.1\n')
    assert admitted == ['10.1.0.1']
    assert len(rank.read_contenders(paths['pool'])) == 5
    assert '10.1.0.2\t2\t41' in paths['queue'].read_text()


def test_full_pool_waiting_is_not_failure(tmp_path):
    paths, _, admitted = run(tmp_path, pool_size=5)
    assert admitted == []
    assert '10.1.0.2\t1\t41' in paths['queue'].read_text()
    assert not paths['blacklist'].exists()


def test_only_observed_failed_candidates_enter_quality_cooldown(tmp_path):
    paths, _, admitted = run(tmp_path, outputs='10.1.0.1\n', queue='2026-10-19 10:00:00\t10.1.0.2\t2\t41\n2026-10-19 10:00:00\t10.2.0.3\t2\t42\n')
    assert paths['blacklist'].read_text() == '10.1.0.2\t2026-10-19 12:00:00\n'
    assert '10.2.0.3\t2\t42' in paths['queue'].read_text()


def test_legacy_queue_rows_survive_when_waiting(tmp_path):
    raw = '2026-10-19 10:00:00\t10.2.0.3\n'
    paths, _, _ = run(tmp_path, queue=raw)
    assert paths['queue'].read_text() == raw
