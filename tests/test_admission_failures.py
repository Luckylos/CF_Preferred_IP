"""单文件持久化契约：故障必须可见；不伪装跨文件事务。"""
from datetime import datetime
from pathlib import Path

import pytest
import admission
import atomic_io
import cooldown
import rank

NOW = datetime(2026, 10, 28, 10)


def fixture_paths(tmp_path):
    paths = {name: tmp_path / name for name in ['pool', 'requested', 'passed', 'queue', 'quality']}
    paths['pool'].write_text('')
    paths['requested'].write_text('10.100.0.1\n10.100.0.2\n')
    paths['passed'].write_text('10.100.0.1\n10.100.0.9\n')
    paths['queue'].write_text('2026-10-28 09:00:00\t10.100.0.1\t0\t40\n'
                               '2026-10-28 09:00:00\t10.100.0.2\t2\t41\n'
                               '2026-10-28 09:00:00\t10.100.0.3\t0\t42\n')
    paths['quality'].write_text('')
    return paths


def apply(paths):
    return admission.process_screen(paths['pool'], paths['requested'], paths['passed'],
                                    paths['queue'], paths['quality'], NOW, 150, 3)


@pytest.mark.parametrize('failed_at', ['pool', 'quality', 'queue', 'passed'])
def test_each_write_failure_stops_later_writes_and_next_selection_uses_durable_state(
        tmp_path, monkeypatch, failed_at):
    paths = fixture_paths(tmp_path)
    before = {name: path.read_text() for name, path in paths.items()}
    attempted = []
    order = ['pool', 'quality', 'queue', 'passed']
    def fail(path, text):
        attempted.append(path.name)
        if path == paths[failed_at]:
            raise OSError('injected write failure')
        atomic_io.atomic_write(path, text)
    with monkeypatch.context() as patch:
        patch.setattr(admission, 'atomic_write', fail)
        patch.setattr(rank, 'atomic_write', fail)
        patch.setattr(cooldown, 'atomic_write', fail)
        with pytest.raises(OSError, match='injected'):
            apply(paths)
    index = order.index(failed_at)
    assert attempted == order[:index+1]
    for name in order[index:]:
        assert paths[name].read_text() == before[name]
    assert bool(rank.read_contenders(paths['pool'])) == (index > 0)
    assert ('10.100.0.2' in cooldown.active(paths['quality'], NOW, 24)) == (index > 1)
    # 不重放旧screen；从持久池与冷却重新选。已落盘的准入/冷却不能再被请求。
    excluded = tmp_path / 'excluded'
    excluded.write_text(''.join(ip+'\n' for ip in cooldown.active(paths['quality'], NOW, 24)))
    chosen = admission.select_candidates(paths['pool'], paths['queue'], excluded,
                                         tmp_path/'next-request', 150, 20)
    assert ('10.100.0.1' in chosen) == (index == 0)
    assert ('10.100.0.2' in chosen) == (index <= 1)
    assert '10.100.0.3' in chosen


def test_success_writes_in_contract_order_and_filters_actual_output(tmp_path, monkeypatch):
    paths = fixture_paths(tmp_path)
    order = []
    def observe(path, text):
        order.append(path.name)
        atomic_io.atomic_write(path, text)
    monkeypatch.setattr(admission, 'atomic_write', observe)
    monkeypatch.setattr(rank, 'atomic_write', observe)
    monkeypatch.setattr(cooldown, 'atomic_write', observe)
    assert apply(paths) == ['10.100.0.1']
    assert order == ['pool', 'quality', 'queue', 'passed']
    assert paths['passed'].read_text() == '10.100.0.1\n'
    assert paths['queue'].read_text() == '2026-10-28 09:00:00\t10.100.0.3\t0\t42\n'


@pytest.mark.parametrize('field', ['requested', 'passed', 'queue', 'quality'])
def test_unreadable_input_is_not_an_empty_success(tmp_path, field):
    paths = fixture_paths(tmp_path)
    directory = tmp_path / 'unreadable-as-file'
    directory.mkdir()
    paths[field] = directory
    before = paths['pool'].read_bytes()
    with pytest.raises(IsADirectoryError):
        apply(paths)
    assert paths['pool'].read_bytes() == before


@pytest.mark.parametrize('kind', ['same', 'symlink', 'hardlink'])
def test_process_rejects_state_output_aliases_before_any_write(tmp_path, kind):
    paths = fixture_paths(tmp_path)
    original = paths['queue'].read_bytes()
    alias = paths['queue'] if kind == 'same' else tmp_path/'alias'
    if kind == 'symlink':
        alias.symlink_to(paths['queue'])
    elif kind == 'hardlink':
        alias.hardlink_to(paths['queue'])
    paths['passed'] = alias
    with pytest.raises(ValueError, match='distinct'):
        apply(paths)
    assert paths['queue'].read_bytes() == original
    assert paths['pool'].read_text() == ''


@pytest.mark.parametrize('action', ['maintain', 'select'])
def test_queue_read_failure_never_overwrites_output(tmp_path, action):
    paths = fixture_paths(tmp_path)
    queue = tmp_path / 'directory'
    queue.mkdir()
    requested = tmp_path / 'output'
    requested.write_text('keep')
    with pytest.raises(IsADirectoryError):
        if action == 'maintain':
            admission.maintain_queue(queue, NOW, 24, 180, targets=requested)
        else:
            admission.select_candidates(paths['pool'], queue, paths['quality'], requested, 150, 20)
    assert requested.read_text() == 'keep'


@pytest.mark.parametrize('failed_at', ['queue', 'targets'])
def test_maintenance_write_failure_is_visible_and_does_not_rollback(tmp_path, monkeypatch, failed_at):
    queue = tmp_path / 'queue'
    original = '2026-10-28 09:00:00\t10.100.0.1\n'
    queue.write_text(original)
    targets = tmp_path/'targets'
    targets.write_text('keep')
    def fail(path, text):
        if path.name == failed_at:
            raise OSError('injected')
        atomic_io.atomic_write(path, text)
    monkeypatch.setattr(admission, 'atomic_write', fail)
    with pytest.raises(OSError, match='injected'):
        admission.maintain_queue(queue, NOW, 24, 180, targets=targets)
    assert queue.read_text() == (original if failed_at == 'queue' else original.rstrip('\n')+'\t0\t\n')
    assert targets.read_text() == 'keep'


def test_duplicate_requested_pass_is_admitted_once(tmp_path):
    paths = fixture_paths(tmp_path)
    paths['requested'].write_text('10.100.0.1\n10.100.0.1\n')
    assert apply(paths) == ['10.100.0.1']
    assert len(rank.read_contenders(paths['pool'])) == 1
