import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from dns_selection import Choice
from publication_snapshot import Publication, migrate, project_legacy, read, write

ROOT = Path(__file__).resolve().parents[1]
A, B, C, D = ('192.0.2.1', '192.0.2.2', '192.0.2.3', '192.0.2.4')
MARKER = '# --- BEST_IPS (machine-readable, one IP per line) ---\n'


def test_migrate_round_trips_selection_and_hysteresis(tmp_path):
    best = tmp_path / 'best_ips.txt'
    best.write_text(MARKER + f'{A}\n{B}\n{C}\n{D}\n')
    from dns_selection import write as write_dns
    write_dns(tmp_path / '.dns_preference.json', Choice(B, C, '123-test', 'reference'))
    expected = Publication((A, B, C), Choice(B, C, '123-test', 'reference'))
    assert migrate(best, 3) == expected
    assert read(tmp_path / '.publish_desired.json') == expected
    with pytest.raises(FileExistsError):
        migrate(best, 3)


def test_project_legacy_uses_latest_targets_and_hysteresis(tmp_path):
    from dns_selection import read as read_dns

    best = tmp_path / 'best_ips.txt'
    best.write_text('# ranking\n' + MARKER + f'{A}\n{B}\n{C}\n{D}\n')
    path = tmp_path / '.publish_desired.json'
    choice = Choice(D, A, '124-test', 'reference')
    write(path, Publication((D, C, B), choice))
    (tmp_path / '.apply_state').write_text('confirmed\n')
    (tmp_path / '.apply_state.pending').write_text('pending\n')
    project_legacy(best, 3)
    assert best.read_text() == '# ranking\n' + MARKER + f'{D}\n{C}\n{B}\n'
    assert read_dns(tmp_path / '.dns_preference.json', '') == choice
    assert (tmp_path / '.apply_state').read_text() == 'confirmed\n'
    assert (tmp_path / '.apply_state.pending').read_text() == 'pending\n'


@pytest.mark.parametrize('members', [(D, B), (D, B, A, C)], ids=['2-of-3', '4-of-3'])
def test_project_legacy_cli_rejects_wrong_count_without_writing(tmp_path, members):
    from dns_selection import write as write_dns

    best = tmp_path / 'best_ips.txt'
    dns = tmp_path / '.dns_preference.json'
    snapshot = tmp_path / '.publish_desired.json'
    applied = tmp_path / '.apply_state'
    pending = tmp_path / '.apply_state.pending'
    best.write_text('# ranking\n' + MARKER + f'{A}\n{B}\n{C}\n{D}\n')
    write_dns(dns, Choice(A, C, '123-test', 'old-reference'))
    write(snapshot, Publication(members, Choice(D, A, '124-test', 'new-reference')))
    applied.write_bytes(b'confirmed\n')
    pending.write_bytes(b'pending\n')
    before = {path: path.read_bytes() for path in (best, dns, snapshot, applied, pending)}

    result = subprocess.run(
        [sys.executable, str(ROOT / 'publication_snapshot.py'), 'project-legacy', str(best), '3'],
        cwd=tmp_path, capture_output=True, text=True, timeout=10,
    )

    changed = [path.name for path, contents in before.items() if path.read_bytes() != contents]
    assert (result.returncode, changed) == (1, []), result.stderr
    assert 'publication snapshot does not contain the configured member count' in result.stderr


def test_interrupted_replacement_keeps_old_snapshot(tmp_path, monkeypatch):
    import atomic_io

    path = tmp_path / '.publish_desired.json'
    original = Publication((A, B, C), Choice(B, C, '123-test', 'reference'))
    write(path, original)
    before = path.read_bytes()

    def fail_replace(*_):
        raise OSError('interrupted replacement')

    monkeypatch.setattr(atomic_io.os, 'replace', fail_replace)
    with pytest.raises(OSError, match='interrupted replacement'):
        write(path, Publication((D, B, C), Choice(D)))
    assert path.read_bytes() == before
    assert read(path) == original


@pytest.fixture
def apply(tmp_path):
    for name in ('apply.sh', 'atomic_io.py', 'dns_selection.py', 'ip_validation.py', 'publication_snapshot.py'):
        shutil.copy2(ROOT / name, tmp_path)
    config = (ROOT / 'config.sh').read_text().replace('CFST_DIR=/opt/cfst', f'CFST_DIR={tmp_path}')
    (tmp_path / 'config.sh').write_text(config)
    (tmp_path / '.quality_evidence_enabled').touch()
    (tmp_path / 'misub.env').touch(mode=0o600)
    (tmp_path / 'push_to_misub.py').write_text(
        'import os\nfrom pathlib import Path\nBEST_IPS_FILE = "best_ips.txt"\n'
        'def main():\n'
        '    host = os.environ.get("CFST_NODE_HOST", "").strip()\n'
        '    Path("misub.log").write_text(host or Path(BEST_IPS_FILE).read_text())\n'
        '    raise SystemExit(int(os.environ.get("MISUB_RC", "0")))\n'
        'if __name__ == "__main__": main()\n'
    )
    (tmp_path / 'dns_publish.py').write_text(
        'import os, sys\nfrom pathlib import Path\n'
        'Path("dns.log").write_text(" ".join(sys.argv[2:]))\n'
        'if os.environ.get("REPLACE") == "1":\n'
        f'    Path("best_ips.txt").write_text({(MARKER + D + chr(10))!r})\n'
        '    Path("next.json").replace(".publish_desired.json")\n'
    )
    path = tmp_path / '.publish_desired.json'
    write(path, Publication((A, B, C), Choice(B)))
    (tmp_path / 'best_ips.txt').write_text(MARKER + f'{D}\n')
    env = dict(os.environ, MISUB_TOKEN_FILE=str(tmp_path / 'misub.env'), CFST_PUBLISH='both',
               CFST_DNS_TOP_N='1', APPLY_FORCE='1', APPLY_RETRY_ONLY='0')

    def run(command='bash ./apply.sh', **overrides):
        return subprocess.run(['bash', '-c', command], cwd=tmp_path, env=env | overrides,
                              capture_output=True, text=True, timeout=10)

    return run, path


def test_project_legacy_materializes_empty_active_without_losing_dns_state(tmp_path, apply):
    from dns_selection import read as read_dns

    run, path = apply
    choice = Choice('', D, '124-test', 'reference')
    write(path, Publication((A, B, C), choice))
    state = tmp_path / '.apply_state'
    pending = tmp_path / '.apply_state.pending'
    state.write_bytes(b'confirmed\n')
    pending.write_bytes(b'pending\n')
    before = path.read_bytes()
    snapshot = run('set -e; source ./config.sh; read_publish_targets; compute_apply_state')
    assert snapshot.returncode == 0, snapshot.stderr
    preferred, *members, fingerprint = snapshot.stdout.splitlines()
    assert (preferred, members) == ('', [A, B, C])
    assert fingerprint

    project_legacy(tmp_path / 'best_ips.txt', 3)

    # The legacy reader rejects empty active and falls back without the DNS history.
    assert read_dns(tmp_path / '.dns_preference.json', '') == Choice(A, D, '124-test', 'reference')
    legacy = run('set -e; source ./config.sh; preferred=$(dns_preference); members=$(publish_set); '
                 'printf "%s\\n" "$preferred" "$members"; compute_apply_state "$preferred" "$members"')
    assert legacy.returncode == 0, legacy.stderr
    assert legacy.stdout.splitlines() == [preferred or members[0], *members, fingerprint]
    assert path.read_bytes() == before
    assert state.read_bytes() == b'confirmed\n'
    assert pending.read_bytes() == b'pending\n'


def test_snapshot_misub_ignores_host_override_but_direct_push_keeps_it(tmp_path, apply):
    run, _ = apply
    host = 'override.example'
    direct = run('python3 ./push_to_misub.py', CFST_NODE_HOST=host)
    assert direct.returncode == 0, direct.stderr
    assert (tmp_path / 'misub.log').read_text() == host

    result = run(CFST_NODE_HOST=host)

    assert result.returncode == 0, result.stderr
    assert (tmp_path / 'misub.log').read_text() == MARKER + f'{A}\n{B}\n{C}\n'
    assert (tmp_path / 'dns.log').read_text() == B


def test_both_adapters_and_confirmation_share_snapshot_during_replacement(tmp_path, apply):
    run, path = apply
    old = run('source ./config.sh; compute_apply_state').stdout.strip()
    write(tmp_path / 'next.json', Publication((D, B, C), Choice(D)))
    result = run(REPLACE='1')
    assert result.returncode == 0, result.stderr
    assert (tmp_path / 'dns.log').read_text() == B
    assert (tmp_path / 'misub.log').read_text() == MARKER + f'{A}\n{B}\n{C}\n'
    assert (tmp_path / '.apply_state').read_text().strip() == old
    assert run('source ./config.sh; compute_apply_state').stdout.strip() != old
    assert read(path).members == (D, B, C)


def test_guard_cannot_retry_old_target_and_reversion_reconciles(tmp_path, apply):
    run, path = apply
    original = read(path)
    assert run().returncode == 0
    applied = (tmp_path / '.apply_state').read_bytes()
    write(path, Publication((D, B, C), Choice(D)))
    assert run(MISUB_RC='1').returncode == 1
    pending = tmp_path / '.apply_state.pending'
    failed = pending.read_bytes()
    write(path, original)
    assert run(APPLY_RETRY_ONLY='1').returncode == 0
    assert pending.read_bytes() == failed
    assert (tmp_path / 'dns.log').read_text() == D
    assert run().returncode == 0
    assert not pending.exists()
    assert (tmp_path / 'dns.log').read_text() == B
    assert (tmp_path / '.apply_state').read_bytes() == applied


def test_guard_preserves_pending_after_config_change(tmp_path, apply):
    run, _ = apply
    assert run(MISUB_RC='1').returncode == 1
    pending = tmp_path / '.apply_state.pending'
    before = pending.read_bytes()
    (tmp_path / 'dns.log').unlink()
    (tmp_path / 'misub.log').unlink()
    result = run(APPLY_RETRY_ONLY='1', CFST_DNS_TOP_N='2')
    assert result.returncode == 0, result.stderr
    assert pending.read_bytes() == before
    assert not (tmp_path / 'dns.log').exists()
    assert not (tmp_path / 'misub.log').exists()


@pytest.mark.parametrize('broken', [None, '{}', 'short'])
def test_invalid_snapshot_blocks_apply_without_reading_best(tmp_path, apply, broken):
    run, path = apply
    if broken is None:
        path.unlink()
    elif broken == 'short':
        write(path, Publication((A, B), Choice(B)))
    else:
        path.write_text(broken)
    result = run()
    assert result.returncode != 0
    assert not (tmp_path / '.apply_state.pending').exists()
    assert not (tmp_path / 'dns.log').exists()
    assert not (tmp_path / 'misub.log').exists()
