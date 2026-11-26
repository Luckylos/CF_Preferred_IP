import os
import shutil
import subprocess
from pathlib import Path

from dns_selection import Choice
from publication_snapshot import Publication, read, write

ROOT = Path(__file__).resolve().parents[1]
A, B, C = "192.0.2.1", "198.51.100.1", "203.0.113.1"


def test_dns_preference_has_its_own_fingerprint_and_failed_both_retries(tmp_path):
    for name in ("apply.sh", "atomic_io.py", "dns_selection.py", "ip_validation.py", "publication_snapshot.py"):
        shutil.copy2(ROOT / name, tmp_path)
    config = (ROOT / "config.sh").read_text().replace("CFST_DIR=/opt/cfst", f"CFST_DIR={tmp_path}")
    (tmp_path / "config.sh").write_text(config)
    best = tmp_path / "best_ips.txt"
    best.write_text(f"# --- BEST_IPS (machine-readable, one IP per line) ---\n{A}\n{B}\n{C}\n")
    secret = tmp_path / "misub.env"
    secret.touch(mode=0o600)
    (tmp_path / "dns_publish.py").write_text(
        "import sys\nfrom pathlib import Path\nPath('dns.log').write_text(sys.argv[2])\n"
    )
    (tmp_path / "push_to_misub.py").write_text(
        "import os\nfrom pathlib import Path\n"
        "BEST_IPS_FILE = 'best_ips.txt'\n"
        "def read_best_ips():\n"
        "    return Path(BEST_IPS_FILE).read_text().splitlines()[1:]\n"
        "def main():\n"
        "    Path('misub.log').write_text('\\n'.join(read_best_ips()) + '\\n')\n"
        "    raise SystemExit(int(os.environ.get('FAKE_MISUB_RC', '0')))\n"
        "if __name__ == '__main__':\n"
        "    main()\n"
    )
    (tmp_path / ".quality_evidence_enabled").touch(mode=0o600)
    env = dict(os.environ, CFST_PUBLISH="both", CFST_DNS_TOP_N="1",
               MISUB_TOKEN_FILE=str(secret), APPLY_FORCE="1", APPLY_RETRY_ONLY="0")
    env.pop("CFST_QUALITY_EVIDENCE", None)

    def run(command, **overrides):
        return subprocess.run(["bash", "-c", command], cwd=tmp_path, capture_output=True,
                              text=True, check=False, env={**env, **overrides}, timeout=10)

    def fingerprint():
        result = run("source ./config.sh; compute_apply_state")
        assert result.returncode == 0, result.stderr
        return result.stdout.strip()

    write(tmp_path / ".publish_desired.json", Publication((A, B, C), Choice(A)))
    old = fingerprint()
    applied = tmp_path / ".apply_state"
    applied.write_text(old + "\n")
    write(tmp_path / ".publish_desired.json", Publication((A, B, C), Choice(A, B, "batch-1")))
    assert fingerprint() == old
    write(tmp_path / ".publish_desired.json", Publication((A, B, C), Choice(B, last_batch="batch-2")))
    expected = fingerprint()
    assert expected != old
    assert run("env -u APPLY_RETRY_ONLY bash ./apply.sh").returncode == 0
    assert not (tmp_path / "dns.log").exists()
    assert not (tmp_path / "misub.log").exists()
    assert run("bash ./apply.sh", FAKE_MISUB_RC="1").returncode == 1
    assert applied.read_text().strip() == old
    assert not (tmp_path / ".apply_cooldown").exists()
    assert (tmp_path / "dns.log").read_text() == B
    pending = tmp_path / ".apply_state.pending"
    assert pending.read_text().strip() == expected
    saved = best.read_text()
    dns = tmp_path / "dns_publish.py"
    normal_dns = dns.read_text()
    dns.write_text(normal_dns + "Path('best_ips.txt').write_text(" + repr(saved.replace(A, "192.0.2.9")) + ")\n")
    outcome = run("env -u APPLY_RETRY_ONLY bash ./apply.sh")
    assert "192.0.2.9" in best.read_text()
    best.write_text(saved)
    dns.write_text(normal_dns)
    assert outcome.returncode == 0, outcome.stderr
    assert applied.read_text().strip() == expected
    assert (tmp_path / "misub.log").read_text() == f"{A}\n{B}\n{C}\n"

    write(tmp_path / ".publish_desired.json", Publication((A, B, C), Choice(C, last_batch="batch-3")))
    assert run("bash ./apply.sh", FAKE_MISUB_RC="1").returncode == 1
    assert (tmp_path / "dns.log").read_text() == C
    write(tmp_path / ".publish_desired.json", Publication((A, B, C), Choice(B, last_batch="batch-4")))
    assert fingerprint() == expected
    assert run("bash ./apply.sh", APPLY_RETRY_ONLY="1").returncode == 0
    assert pending.exists()
    assert (tmp_path / "dns.log").read_text() == C
    assert run("bash ./apply.sh").returncode == 0
    assert (tmp_path / "dns.log").read_text() == B

def test_cycle_passes_current_structured_audit_to_rank(tmp_path, monkeypatch):
    from test_cycle_shadow_run import LEGACY_BEST, LEGACY_PUBLISHED, Sandbox, _exe

    sb = Sandbox(tmp_path)
    for name in ("quality_evidence.py", "dns_selection.py"):
        shutil.copy2(ROOT / name, sb.sb)
    monkeypatch.setenv("CFST_QUALITY_EVIDENCE", "1")
    _exe(sb.sb / "verify_vless.sh", '''#!/usr/bin/env python3
import os
import sys
from datetime import datetime
from pathlib import Path
from audit_evidence import bind, record
from quality_evidence import reference_key
assert sys.argv[1] == "--audit"
ips = Path(sys.argv[2]).read_text().splitlines()
now = datetime.now().replace(microsecond=0)
ref = reference_key(["cycle-smoke"])
run = os.environ["VLESS_AUDIT_RUN"]
receipt = Path(os.environ["VLESS_REFERENCE_OUT"])
rows = [f"{now.isoformat()}\\t{ip}\\t" + "|".join(f"{i}\\t200\\t0.055\\t0" for i in range(4)) for ip in ips]
bind(receipt, run, ref, ips)
record(Path(os.environ["VLESS_HISTORY"] + ".requests.jsonl"), receipt, ips, run, ref, 3, rows)
print("=== AUDIT RESULTS ===")
for ip in ips:
    print(f"  {ip}  PASS 55")
''')
    result = sb.run("slow", "--shadow", timeout=15)
    assert result.returncode == 0, result.stderr + result.stdout
    assert "pool_in=4 guard=none" in result.stdout
    assert "warm=3/3" in result.stdout
    assert (sb.sb / "best_ips.txt").read_text() == LEGACY_BEST
    assert read(sb.sb / ".publish_desired.json").members == tuple(LEGACY_PUBLISHED)


def test_watchdog_triggers_when_independent_dns_target_is_down(tmp_path):
    from test_periphery_contract import _run_watchdog, _watchdog_sandbox

    sb = _watchdog_sandbox(tmp_path, "exit 75\n")
    config = sb / "config.sh"
    config.write_text(config.read_text() + "\nread_publish_targets() { printf '%s\\n' 198.51.100.1 1.1.1.1; }\n")
    timeout = sb / "bin" / "timeout"
    timeout.write_text('#!/bin/sh\n[ "$6" = "1.1.1.1" ]\n')
    result = _run_watchdog(sb)
    assert result.returncode == 75, result.stderr
    assert (sb / ".watchdog_state").read_text() == f"{B} 1\n"
    assert (sb / ".cycle_args").read_text() == "fast --emergency\n"


def test_emergency_audit_replaces_slots_without_increasing_probe_budget(tmp_path, monkeypatch):
    from test_cycle_admission import sandbox

    sb = sandbox(tmp_path)
    for name in ("quality_evidence.py", "dns_selection.py"):
        shutil.copy2(ROOT / name, sb.sb)
    publication = sb.sb / ".publish_desired.json"
    members = read(publication).members
    write(publication, Publication((members[0], B, *members[2:]), Choice(B)))
    tiers = sb.sb / ".tiers"
    tiers.mkdir()
    inputs = [f"192.0.2.{i}" for i in range(1, 21)]
    (tiers / "core.txt").write_text("\n".join(inputs[:10]) + "\n")
    (tiers / "challengers.txt").write_text("\n".join(inputs[10:]) + "\n")

    fingerprint = subprocess.check_output(["bash", "-c", "source ./config.sh; compute_apply_state"], cwd=sb.sb)
    (sb.sb / ".apply_state").write_bytes(fingerprint)
    result = sb.run("fast", timeout=15)
    assert result.returncode == 0, result.stderr + result.stdout
    assert sb.audit_inputs()[-1] == inputs

    (tiers / "core.txt").write_text("\n".join(inputs[:10]) + "\n")
    (tiers / "challengers.txt").write_text("\n".join(inputs[10:]) + "\n")
    monkeypatch.setenv("CFST_QUALITY_EVIDENCE", "1")
    monkeypatch.setenv("CFST_PUBLISH", "both")
    result = sb.run("fast", "--emergency", timeout=15)
    assert result.returncode == 0, result.stderr + result.stdout
    audited = sb.audit_inputs()[-1]
    assert len(audited) == len(set(audited)) == 20
    assert audited[0] == B

    (tiers / "core.txt").unlink()
    (tiers / "challengers.txt").unlink()
    result = sb.run("fast", "--emergency", timeout=15)
    assert result.returncode == 0, result.stderr + result.stdout
    assert len(sb.audit_inputs()) == 3
    assert sb.audit_inputs()[-1] == [B, "10.0.0.1", "10.0.0.9"]
