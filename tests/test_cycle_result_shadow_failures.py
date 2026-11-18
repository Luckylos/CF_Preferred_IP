import json
import shutil
from test_cycle_shadow_run import Sandbox, _exe
from test_cycle_admission import sandbox


def test_shadow_no_tiers_stays_successful_skip(tmp_path):
    sb = Sandbox(tmp_path)
    result = sb.run("fast", "--shadow")
    assert result.returncode == 0, result.stderr
    rows = list((sb.sb / ".shadow/cycle-results").glob("cycle-*.json"))
    assert len(rows) == 1
    assert json.loads(rows[0].read_text())["state"] == "skipped"
    assert "shadow: legacy=" not in result.stdout, "未rank时保持原先无比较行的语义"


def test_shadow_rank_failure_preserves_original_exit_code(tmp_path):
    sb = Sandbox(tmp_path)
    shutil.copy(sb.sb / "rank.py", sb.sb / "rank_real.py")
    _exe(sb.sb / "rank.py", 'from rank_real import *\nif __name__ == "__main__": raise SystemExit(27)\n')
    result = sb.run("slow", "--shadow")
    assert result.returncode == 27, result.stderr
    row = next((sb.sb / ".shadow/cycle-results").glob("cycle-*.json"))
    data = json.loads(row.read_text())
    assert data["state"] == "failed" and data["rank_status"] == "failed" and data["exit_code"] == 27
    assert sb.markers() == set()


def test_human_summary_without_valid_receipt_cannot_apply(tmp_path):
    sb = sandbox(tmp_path)
    shutil.copy(sb.sb / "rank.py", sb.sb / "rank_real.py")
    _exe(
        sb.sb / "rank.py",
        'from rank_real import *\nif __name__ == "__main__": print("rank: pool=4 core=3 challengers=1 evicted=0 published=10.0.0.1 changed=1 guard=none")\n',
    )
    result = sb.run("slow")
    assert result.returncode != 0
    data = json.loads(next((sb.sb / "results/cycle-results").glob("cycle-*.json")).read_text())
    assert data["state"] == "failed" and data["rank_status"] == "failed"
    assert "apply_called" not in sb.markers()
