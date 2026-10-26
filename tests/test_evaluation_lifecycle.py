"""候选验证覆盖、持久状态和相对退出保护。"""
from dataclasses import replace
from datetime import datetime, timedelta
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import rank
from test_rank_policy import R, ranked

NOW = datetime(2026, 10, 19, 2)
CFG = rank.Config(pool_max=5, pool_target=2, trim_headroom=1)
IP = '192.0.2.12'


def samples(times, statuses=None):
    statuses = statuses or ['PASS'] * len(times)
    return [rank.Sample(datetime.fromisoformat(t), IP, status, 50, '')
            for t, status in zip(times, statuses)]


def completed(rows, *, first='2026-10-18 12:00:00', saved='-', neff=9, systemic=False, now=NOW):
    c = rank.Contender(IP, first, '-', 'screen', saved)
    st = replace(R(IP, .8).stats, n_eff=neff)
    baselines = {rank.bucket_key(s.ts, 10): rank.RoundInfo(50, systemic) for s in rows}
    return rank.complete_evaluations([c], rows, baselines, {IP: st}, now, CFG)


FULL = ['2026-10-18 20:00:00', '2026-10-18 22:00:00', '2026-10-19 00:00:00']


def test_full_night_completes_including_valid_failures():
    assert IP in completed(samples(FULL, ['PASS', 'FAIL', 'PARTIAL']))


@pytest.mark.parametrize('times', [
    ['2026-10-18 20:00:00', '2026-10-18 20:15:00', '2026-10-18 20:30:00'],
    ['2026-10-17 20:00:00', '2026-10-18 22:00:00', '2026-10-19 00:00:00'],
    ['2026-10-18 20:00:00', '2026-10-18 22:00:00'],
])
def test_short_or_mixed_nights_do_not_complete(times):
    assert completed(samples(times), first='2026-10-17 12:00:00') == {}


def test_evidence_before_admission_does_not_complete():
    assert completed(samples(FULL), first='2026-10-18 21:00:00') == {}


def test_systemic_rounds_do_not_count_as_coverage():
    assert completed(samples(FULL), systemic=True) == {}


def test_neff_must_reach_eight():
    assert completed(samples(FULL), neff=7.99) == {}


def test_completion_survives_expired_history_and_freshness():
    saved = '2026-10-10 01:00:00'
    assert completed([], first='2026-10-09 10:00:00', saved=saved, neff=0) == {IP: saved}


@pytest.mark.parametrize('saved', ['garbage', '2026-10-20 00:00:00'])
def test_invalid_or_future_marker_does_not_grant_protection_exit(saved):
    assert completed([], saved=saved) == {}


def test_four_column_read_five_column_roundtrip(tmp_path):
    path = tmp_path / 'contenders.tsv'
    path.write_text(f'{IP}\t2026-10-18 12:00:00\t-\tscreen\n')
    c = rank.read_contenders(path)[0]
    assert c.evaluated_at == '-'
    c = replace(c, evaluated_at='2026-10-19 01:00:00')
    rank.write_contenders(path, [c])
    assert rank.read_contenders(path) == [c]
    assert path.read_text().splitlines()[-1].split('\t')[-1] == c.evaluated_at


def row(ip, lcb, *, ready, fail=0, unreachable=0):
    r = R(ip, lcb, ucb=lcb+.01, n_eff=10, fail=fail, peak_ok=True, unreachable=unreachable)
    return replace(r, stats=replace(r.stats, evaluation_completed=ready))


@pytest.mark.parametrize('reason', ['unworthy', 'overflow'])
def test_pending_is_protected_from_relative_exits(reason):
    rows = [row('198.51.100.15', .95, ready=True), row('198.51.100.16', .94, ready=True),
            row(IP, .1, ready=False)]
    cfg = replace(CFG, pool_target=2 if reason == 'unworthy' else 60, pool_max=3)
    kept, removed = rank.evict(ranked(rows), cfg, 'none')
    assert IP in kept
    assert not any(ip == IP for ip, why in removed)


def test_completed_low_quality_can_exit():
    rows = [row('198.51.100.15', .95, ready=True), row('198.51.100.16', .94, ready=True),
            row(IP, .1, ready=True)]
    assert (IP, 'unworthy') in rank.evict(ranked(rows), CFG, 'none')[1]


@pytest.mark.parametrize('fail,unreachable,reason', [(1, 0, 'hard_fail'), (0, 3, 'unreachable')])
def test_pending_still_exits_for_strong_failure(fail, unreachable, reason):
    r = row(IP, .1, ready=False, fail=fail, unreachable=unreachable)
    assert (IP, reason) in rank.evict([r], CFG, 'none')[1]


def test_guard_keeps_completed_and_pending():
    rs = [row(IP, .1, ready=True, fail=1)]
    assert rank.evict(rs, CFG, 'systemic')[1] == []
