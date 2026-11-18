"""发现与准入的真实 interface；断言持久文件，不复制整理算法。"""
from datetime import datetime
from pathlib import Path
import subprocess
import sys

import pytest
import admission
import rank

NOW = datetime(2026, 10, 28, 10)
ROOT = Path(__file__).resolve().parents[1]


def write(tmp_path, name, text=''):
    p = tmp_path / name
    p.write_text(text)
    return p


def maintain(tmp_path, text, **kwargs):
    queue = write(tmp_path, 'queue', text)
    result = admission.maintain_queue(queue, NOW, 24, kwargs.pop('limit', 180), **kwargs)
    return queue, result


def test_ttl_inclusive_and_legacy_four_column_contract(tmp_path):
    queue, counts = maintain(tmp_path,
        '2026-10-27 09:59:59\t10.100.0.1\t0\t40\n'
        '2026-10-27 10:00:00\t10.100.0.2\t2\t41.5\n'
        '2026-10-28 09:00:00\t10.100.0.3\n'
        '2026-10-28 09:01:00\t10.100.0.4\tbad\n')
    assert queue.read_text() == (
        '2026-10-27 10:00:00\t10.100.0.2\t2\t41.5\n'
        '2026-10-28 09:00:00\t10.100.0.3\t0\t\n'
        '2026-10-28 09:01:00\t10.100.0.4\t0\t\n')
    assert counts == (3, 1)


def test_existing_record_wins_over_repeated_discovery(tmp_path):
    incoming = write(tmp_path, 'incoming', '10.100.0.1\t5\n10.100.0.2\t31.5\n')
    queue, counts = maintain(tmp_path, '2026-10-28 08:00:00\t10.100.0.1\t2\t42\n',
                              incoming=incoming)
    assert queue.read_text() == ('2026-10-28 08:00:00\t10.100.0.1\t2\t42\n'
                                 '2026-10-28 10:00:00\t10.100.0.2\t0\t31.5\n')
    assert counts == (2, 2)


def test_newest_survives_capacity_then_disk_order_is_oldest_first(tmp_path):
    queue, _ = maintain(tmp_path,
        '2026-10-28 09:00:00\t10.100.0.3\t2\t43\n'
        '2026-10-28 07:00:00\t10.100.0.1\t0\t41\n'
        '2026-10-28 08:00:00\t10.100.0.2\t1\t42\n', limit=2)
    assert queue.read_text() == ('2026-10-28 08:00:00\t10.100.0.2\t1\t42\n'
                                 '2026-10-28 09:00:00\t10.100.0.3\t2\t43\n')


def test_equal_timestamp_uses_lexical_ip_order_not_numeric(tmp_path):
    queue, _ = maintain(tmp_path,
        '2026-10-28 09:00:00\t10.100.0.2\t0\t42\n'
        '2026-10-28 09:00:00\t10.100.0.10\t0\t40\n', limit=1)
    assert queue.read_text() == '2026-10-28 09:00:00\t10.100.0.10\t0\t40\n'


def test_exclusion_is_explicit_and_scanner_can_retain_existing_entry(tmp_path):
    original = '2026-10-28 09:00:00\t10.100.0.1\t1\t42\n'
    excluded = write(tmp_path, 'excluded', '10.100.0.1\n')
    queue, _ = maintain(tmp_path, original)
    assert queue.read_text() == original
    assert admission.maintain_queue(queue, NOW, 24, 180, excluded=excluded) == (0, 0)
    assert queue.read_text() == ''


def test_merge_retains_original_pruning_clock_but_uses_discovery_time(tmp_path):
    incoming = write(tmp_path, 'incoming', '10.100.0.2\t33\n')
    queue, _ = maintain(tmp_path, '2026-10-27 10:00:00\t10.100.0.1\t0\t40\n',
                          incoming=incoming, discovered_at=datetime(2026, 10, 28, 10, 2))
    assert queue.read_text() == ('2026-10-27 10:00:00\t10.100.0.1\t0\t40\n'
                                 '2026-10-28 10:02:00\t10.100.0.2\t0\t33\n')


def test_invalid_ip_and_duplicates_do_not_consume_slots(tmp_path):
    queue, _ = maintain(tmp_path,
        'comment\n2026-10-28 09:00:00\t999.0.0.1\t0\t40\n'
        '2026-10-28 09:00:00\t10.100.0.1\t2\t45\n'
        '2026-10-28 09:01:00\t10.100.0.1\t0\t20\n')
    assert queue.read_text() == '2026-10-28 09:00:00\t10.100.0.1\t2\t45\n'


def test_missing_queue_bootstraps_empty_targets(tmp_path):
    queue = tmp_path / 'queue'
    targets = tmp_path / 'targets'
    assert admission.maintain_queue(queue, NOW, 24, 180, targets=targets) == (0, 0)
    assert queue.read_text() == targets.read_text() == ''


def test_targets_contains_only_retained_ips(tmp_path):
    targets = tmp_path / 'targets'
    maintain(tmp_path, '2026-10-28 09:00:00\t10.100.0.1\t2\t45\n', targets=targets)
    assert targets.read_text() == '10.100.0.1\n'


@pytest.mark.parametrize('ttl,limit', [(0, 1), (float('nan'), 1), (float('inf'), 1), (24, 0)])
def test_invalid_maintenance_configuration_never_writes(tmp_path, ttl, limit):
    queue = write(tmp_path, 'queue', 'unchanged')
    with pytest.raises(ValueError):
        admission.maintain_queue(queue, NOW, ttl, limit)
    assert queue.read_text() == 'unchanged'


def test_maintenance_rejects_output_alias_before_writing(tmp_path):
    queue = write(tmp_path, 'queue', 'unchanged')
    with pytest.raises(ValueError):
        admission.maintain_queue(queue, NOW, 24, 180, targets=queue)
    assert queue.read_text() == 'unchanged'


def selection(tmp_path, text, size=0, maximum=3, budget=20, excluded=''):
    pool = tmp_path / 'pool'
    rank.write_contenders(pool, [rank.Contender(f'10.101.0.{i+1}', '-', '-', 'master') for i in range(size)])
    queue = write(tmp_path, 'queue', text)
    blocked = write(tmp_path, 'excluded', excluded)
    requested = tmp_path / 'requested'
    result = admission.select_candidates(pool, queue, blocked, requested, maximum, budget)
    return result, requested, queue


def test_select_caps_to_available_slots_excludes_known_and_cooldown(tmp_path):
    chosen, requested, queue = selection(tmp_path,
        '2026-10-28 09:00:00\t10.101.0.1\t0\t10\n'
        '2026-10-28 09:00:00\t10.100.0.1\t0\t41\n'
        '2026-10-28 09:00:00\t10.100.0.2\t0\t42\n'
        '2026-10-28 09:00:00\t10.100.0.3\t0\t43\n', size=2,
        excluded='10.100.0.1\n')
    assert chosen == ['10.100.0.2']
    assert requested.read_text() == '10.100.0.2\n'
    assert '10.100.0.3\t0\t43' in queue.read_text()


def test_select_prioritizes_failure_count_then_age_not_disk_order(tmp_path):
    chosen, _, _ = selection(tmp_path,
        '2026-10-27 09:00:00\t10.100.0.1\t2\t41\n'
        '2026-10-28 09:00:00\t10.100.0.2\t0\t42\n'
        '2026-10-28 08:00:00\t10.100.0.3\t0\t43\n')
    assert chosen == ['10.100.0.3', '10.100.0.2', '10.100.0.1']


def test_select_preserves_old_sort_tie_for_leading_zero_count(tmp_path):
    chosen, _, _ = selection(tmp_path,
        '2026-10-28 09:00:00\t10.100.0.1\t02\t41\n'
        '2026-10-28 08:00:00\t10.100.0.2\t2\t42\n')
    # Historical sort uses the date as key 2, then the full projected line.
    assert chosen == ['10.100.0.1', '10.100.0.2']


def test_full_pool_produces_empty_request_without_mutating_queue(tmp_path):
    original = '2026-10-28 09:00:00\t10.100.0.1\t1\t41\n'
    chosen, requested, queue = selection(tmp_path, original, size=3)
    assert chosen == []
    assert requested.read_text() == ''
    assert queue.read_text() == original


def test_select_honors_screen_max_and_deduplicates(tmp_path):
    chosen, _, _ = selection(tmp_path,
        '2026-10-28 09:00:00\t10.100.0.1\t0\t41\n' * 2 +
        '2026-10-28 09:00:00\t10.100.0.2\t0\t42\n', budget=1)
    assert chosen == ['10.100.0.1']


def test_maintain_cli_has_same_file_effects_as_python_interface(tmp_path):
    queue = write(tmp_path, 'queue', '2026-10-28 09:00:00\t10.100.0.1\t1\t41\n')
    result = subprocess.run([sys.executable, str(ROOT/'admission.py'), 'maintain',
        '--queue', str(queue), '--now', '2026-10-28 10:00:00', '--ttl-hours', '24', '--limit', '180'],
        capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == '1 1'
    assert queue.read_text().endswith('\t1\t41\n')
