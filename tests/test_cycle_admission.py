"""慢周期的空位背压与失败/等待语义；全部网络和发布为本地桩。"""
from datetime import datetime
from test_cycle_shadow_run import Sandbox, VERIFY_STUB, _exe


def sandbox(tmp_path, maximum=5, rc=0):
    sb = Sandbox(tmp_path)
    (sb.sb/'contenders.tsv').write_bytes((sb.sb/'.shadow/contenders.tsv').read_bytes())
    cfg = sb.sb/'config.sh'
    cfg.write_text(cfg.read_text().replace('POOL_MAX=90', f'POOL_MAX={maximum}'))
    _exe(sb.sb/'apply.sh', '#!/bin/bash\nset -euo pipefail\nsource "$(dirname "$0")/config.sh"\ncompute_apply_state > "$APPLY_STATE"\n')
    old = '--screen) touch "$STUB_OUT/screen_called"; exit 0 ;;'
    new = '--screen) cp "$2" "$STUB_OUT/screen_input"; cat "$2" > "$3"; exit '+str(rc)+' ;;'
    assert old in VERIFY_STUB
    _exe(sb.sb/'verify_vless.sh', VERIFY_STUB.replace(old, new))
    stamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    (sb.sb/'discovered_ips.tsv').write_text(f'{stamp}\t10.1.0.1\t0\t40\n{stamp}\t10.1.0.2\t1\t41\n')
    return sb


def test_one_free_slot_screens_and_admits_one(tmp_path):
    sb = sandbox(tmp_path)
    r = sb.run('slow')
    assert r.returncode == 0, r.stderr+r.stdout
    assert (sb.stub/'screen_input').read_text().splitlines() == ['10.1.0.1']
    rows = [l for l in (sb.sb/'contenders.tsv').read_text().splitlines() if not l.startswith('#')]
    assert len(rows) == 5
    assert all(len(l.split('\t')) == 5 for l in rows)
    assert '10.1.0.2\t1\t41' in (sb.sb/'discovered_ips.tsv').read_text()


def test_full_pool_does_not_screen_or_increase_failures(tmp_path):
    sb = sandbox(tmp_path, maximum=4)
    r = sb.run('slow')
    assert r.returncode == 0, r.stderr+r.stdout
    assert not (sb.stub/'screen_input').exists()
    assert '10.1.0.2\t1\t41' in (sb.sb/'discovered_ips.tsv').read_text()


def test_failed_screen_run_never_admits_or_counts_as_failure(tmp_path):
    sb = sandbox(tmp_path, rc=75)
    r = sb.run('slow')
    assert r.returncode == 0, r.stderr+r.stdout
    rows = [l for l in (sb.sb/'contenders.tsv').read_text().splitlines() if not l.startswith('#')]
    assert len(rows) == 4
    assert '10.1.0.1\t0\t40' in (sb.sb/'discovered_ips.tsv').read_text()
    assert '10.1.0.2\t1\t41' in (sb.sb/'discovered_ips.tsv').read_text()


def test_capacity_cooldown_excluded_before_screen(tmp_path):
    sb = sandbox(tmp_path)
    stamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    (sb.sb/'.capacity_cooldown.tsv').write_text(f'10.1.0.1\t{stamp}\n')
    r = sb.run('slow')
    assert r.returncode == 0, r.stderr+r.stdout
    assert (sb.stub/'screen_input').read_text().splitlines() == ['10.1.0.2']
    assert '10.1.0.1' not in (sb.sb/'.screen_blacklist.tsv').read_text()
