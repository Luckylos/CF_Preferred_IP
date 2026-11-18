import json
import shutil
from test_cycle_shadow_run import Sandbox, _exe
from test_cycle_admission import sandbox


def records(sb, shadow=False):
    base = sb.sb / ".shadow/cycle-results" if shadow else sb.sb / "results/cycle-results"
    return [json.loads(p.read_text()) for p in base.glob("cycle-*.json")]


def fault_module(sb, action):
    shutil.copy(sb.sb / "cycle_result.py", sb.sb / "cycle_result_real.py")
    (sb.sb / "cycle_result.py").write_text(
        "from cycle_result_real import *\nimport sys\n"
        'if __name__ == "__main__":\n'
        f'    if sys.argv[1] == {action!r}: raise OSError("injected record failure")\n'
        "    main()\n"
    )


def test_success_and_shadow_have_separate_records(tmp_path):
    sb = sandbox(tmp_path)
    r = sb.run("slow")
    assert r.returncode == 0, r.stderr
    data = records(sb)
    assert len(data) == 1
    assert data[0]["state"] == "completed" and data[0]["application"] == "confirmed"
    assert data[0]["admitted"] == 1 and data[0]["screened"] == 1
    assert data[0]["rank"]["published"]
    result = sb.run("fast", "--shadow")
    assert result.returncode == 0, result.stderr
    assert len(records(sb)) == 1
    shadow = records(sb, True)
    assert len(shadow) == 1 and shadow[0]["application"] == "shadow_skipped"


def test_begin_failure_stops_before_audit(tmp_path):
    sb = sandbox(tmp_path)
    fault_module(sb, "begin")
    before = (sb.sb / "contenders.tsv").read_bytes()
    result = sb.run("slow")
    assert result.returncode != 0
    assert not sb.audit_inputs() and (sb.sb / "contenders.tsv").read_bytes() == before


def test_finish_failure_does_not_replay_or_rollback_application(tmp_path):
    sb = sandbox(tmp_path)
    fault_module(sb, "finish")
    _exe(
        sb.sb / "apply.sh",
        '#!/bin/bash\nset -euo pipefail\nsource "$(dirname "$0")/config.sh"\necho x >> "$CFST_DIR/apply-count"\ncompute_apply_state > "$APPLY_STATE"\n',
    )
    result = sb.run("slow")
    assert result.returncode != 0
    assert (sb.sb / "apply-count").read_text().splitlines() == ["x"]
    assert (sb.sb / ".apply_state").read_text().strip()
    assert records(sb)[0]["state"] == "open"


def test_apply_nonzero_is_failed_even_rank_ok(tmp_path):
    sb = sandbox(tmp_path)
    _exe(sb.sb / "apply.sh", "#!/bin/bash\nexit 42\n")
    result = sb.run("slow")
    assert result.returncode == 42
    d = records(sb)[0]
    assert d["state"] == "failed" and d["rank_status"] == "ok" and d["application"] == "failed"


def test_no_tiers_is_recorded_skip(tmp_path):
    sb = Sandbox(tmp_path)
    result = sb.run("fast")
    assert result.returncode == 0
    d = records(sb)[0]
    assert d["state"] == "skipped" and d["rank"] is None


def test_screen_execution_failure_remains_nonfatal_and_visible(tmp_path):
    sb = sandbox(tmp_path, rc=75)
    result = sb.run("slow")
    assert result.returncode == 0, result.stderr
    d = records(sb)[0]
    assert d["state"] == "completed" and "screen_failed" in d["warnings"] and d["admitted"] == 0


def test_admission_error_after_pool_write_is_not_zero_admissions(tmp_path):
    sb = sandbox(tmp_path)
    shutil.copy(sb.sb / "admission.py", sb.sb / "admission_real.py")
    (sb.sb / "admission.py").write_text(
        'import admission_real as a\noriginal=a.process_screen\ndef bad(*args,**kwargs):\n    original(*args,**kwargs)\n    raise OSError("after durable admission")\na.process_screen=bad\na.main()\n'
    )
    result = sb.run("slow")
    assert result.returncode != 0
    d = records(sb)[0]
    assert d["admitted"] is None and "admission_unconfirmed" in d["warnings"]
    rows = [x for x in (sb.sb / "contenders.tsv").read_text().splitlines() if x and not x.startswith("#")]
    assert len(rows) == 5, "已经持久化的准入不得被伪回滚"
