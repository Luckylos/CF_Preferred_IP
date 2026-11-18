"""实际shell/Python seam：本地测量桩，无网络与发布。"""
from datetime import datetime, timedelta

from test_batch1_boundaries import _scan_sandbox
from test_cycle_admission import sandbox


def stamp(hours=0):
    return (datetime.now()-timedelta(hours=hours)).strftime('%Y-%m-%d %H:%M:%S')


def test_scanner_stops_before_measurement_when_queue_module_fails(tmp_path):
    original = f'{stamp(1)}\t10.100.0.1\t2\t41\n'
    sb, result = _scan_sandbox(tmp_path, original,
        admission_override="raise RuntimeError('injected queue failure')\n")
    assert result.returncode != 0
    assert not (sb/'captured-target').exists()
    assert (sb/'discovered_ips.tsv').read_text() == original


def test_slow_cycle_stops_before_audit_when_queue_module_fails(tmp_path):
    sb = sandbox(tmp_path, maximum=4)
    original = (sb.sb/'discovered_ips.tsv').read_bytes()
    (sb.sb/'admission.py').write_text("raise RuntimeError('injected queue failure')\n")
    result = sb.run('slow')
    assert result.returncode != 0
    assert not sb.audit_inputs()
    assert (sb.sb/'discovered_ips.tsv').read_bytes() == original


def test_scanner_uses_all_target_sources_without_exposing_queue_format(tmp_path):
    sb, result = _scan_sandbox(tmp_path,
        f'{stamp(1)}\t10.100.0.1\t2\t41\n',
        scan_input='192.0.2.0/24\n', master='10.100.0.2\n',
        contenders=f'10.100.0.3\t{stamp(2)}\t-\tscreen\t-\n')
    assert result.returncode == 0, result.stderr
    assert set((sb/'captured-target').read_text().splitlines()) == {
        '192.0.2.0/24', '10.100.0.1', '10.100.0.2', '10.100.0.3'}


def test_scanner_merge_keeps_first_metadata_and_accepts_partial_timeout(tmp_path):
    original = f'{stamp(1)}\t10.100.0.1\t2\t41\n'
    sb, result = _scan_sandbox(tmp_path, original, cfst_rc=124,
        cfst_rows='10.100.0.1,4,4,0,5,0,ZZ\n10.100.0.2,4,4,0,33.5,0,ZZ')
    assert result.returncode == 0, result.stderr
    text = (sb/'discovered_ips.tsv').read_text()
    assert text.startswith(original)
    assert '\t10.100.0.2\t0\t33.5\n' in text
    assert 'keeping results' in result.stdout
    assert 'queued=2 lat_covered=2' in result.stdout


def test_scanner_reports_merge_failure_without_overwriting_existing_queue(tmp_path):
    original = f'{stamp(1)}\t10.100.0.1\t2\t41\n'
    wrapper = ("import sys\nfrom admission_real import main\n"
               "if '--incoming' in sys.argv: raise OSError('injected merge failure')\nmain()\n")
    sb, result = _scan_sandbox(tmp_path, original, admission_override=wrapper,
                              cfst_rows='10.100.0.2,4,4,0,33.5,0,ZZ')
    assert result.returncode != 0
    assert (sb/'discovered_ips.tsv').read_text() == original
