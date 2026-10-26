"""实际 CLI 将容量退出写入独立冷却，保留已完成验证元数据。"""
from datetime import datetime, timedelta
from pathlib import Path
import subprocess
import sys
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import rank


def test_overflow_does_not_enter_quality_blacklist(tmp_path):
    now = datetime(2026, 10, 19, 12)
    hist, pool, best, quality, capacity = [tmp_path/n for n in ['history', 'pool', 'best', 'quality', 'capacity']]
    ips = ['198.51.100.15', '198.51.100.16', '198.51.100.17']
    saved = '2026-10-18 01:00:00'
    rank.write_contenders(pool, [rank.Contender(ip, '2026-10-16 12:00:00', '-', 'screen', saved) for ip in ips])
    hist.write_text(''.join(f'{(now-timedelta(minutes=i*15)).strftime(rank.TS_FORMAT)}\t{ip}\tPASS\t50\t\n' for i in range(40) for ip in ips))
    r = subprocess.run([sys.executable, str(ROOT/'rank.py'), '--history', str(hist), '--contenders', str(pool),
                        '--best', str(best), '--blacklist', str(quality), '--capacity-cooldown', str(capacity),
                        '--now', now.strftime(rank.TS_FORMAT), '--pool-target', '1', '--pool-max', '3',
                        '--trim-headroom', '1', '--core-n', '1'], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    assert 'overflow' in r.stdout
    assert not quality.exists() or quality.read_text() == ''
    assert len(capacity.read_text().splitlines()) == 1
    assert len(rank.read_contenders(pool)) == 2
    assert all(c.evaluated_at == saved for c in rank.read_contenders(pool))


def test_cli_rejects_invalid_cooldown_before_writing(tmp_path):
    pool = tmp_path/'pool'
    pool.write_text('198.51.100.15\t2026-10-16 12:00:00\t-\tscreen\n')
    before = pool.read_bytes()
    base = [sys.executable, str(ROOT/'rank.py'), '--history', str(tmp_path/'history'),
            '--contenders', str(pool), '--best', str(tmp_path/'best'), '--blacklist', str(tmp_path/'quality'),
            '--now', '2026-10-19 12:00:00', '--dry-run']
    for args in (['--capacity-cooldown-hours', 'nan'], ['--capacity-cooldown-hours', '-1'],
                 ['--capacity-cooldown', str(tmp_path/'quality')]):
        proc = subprocess.run(base+args, capture_output=True, text=True)
        assert proc.returncode != 0
        assert pool.read_bytes() == before
