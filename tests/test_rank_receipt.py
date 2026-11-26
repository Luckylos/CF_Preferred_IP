from pathlib import Path
import os
import sys
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import rank
import cycle_result as cr
from test_rank_cli import make_env, base_args, run_rank, summary_of


@pytest.mark.parametrize("dry", [False, True])
def test_machine_receipt_agrees_with_original_summary(tmp_path, dry):
    env = make_env(tmp_path)
    output = tmp_path / "receipt.json"
    before = env["contenders"].read_bytes()
    result = run_rank(base_args(env) + ["--result-out", str(output)] + (["--dry-run"] if dry else []))
    assert result.returncode == 0, result.stderr
    receipt = cr.read_rank_receipt(output)
    assert receipt.summary() == result.stdout.rstrip().splitlines()[-1]
    assert receipt.dry_run is dry
    if dry:
        assert env["contenders"].read_bytes() == before


@pytest.mark.parametrize("kind", ["same", "symlink", "hardlink"])
def test_receipt_alias_refused_before_domain_write(tmp_path, kind):
    env = make_env(tmp_path)
    original = env["contenders"]
    out = original
    if kind != "same":
        out = tmp_path / "alias"
        if kind == "symlink":
            out.symlink_to(original)
        else:
            os.link(original, out)
    before = {p: p.read_bytes() for p in [env["history"], original]}
    result = run_rank(base_args(env) + ["--result-out", str(out)])
    assert result.returncode != 0
    assert all(p.read_bytes() == data for p, data in before.items())
    assert not env["best"].exists() and not env["tiers"].exists()


@pytest.mark.parametrize(
    "extra,guard",
    [
        (["--audit-ok", "0", "--systemic", "1"], "no_evidence"),
        (["--audit-ok", "1", "--systemic", "1"], "systemic"),
        (["--audit-requested", "4", "--audit-returned", "3"], "coverage"),
        (["--audit-requested", "4", "--audit-returned", "3", "--audit-min-coverage-percent", "75"], "none"),
        (["--audit-requested", "0", "--audit-returned", "0"], "none"),
    ],
)
def test_receipt_guard_preserves_cli_and_config(tmp_path, extra, guard):
    env = make_env(tmp_path, history="", pool_ips=["10.0.0.1"])
    out = tmp_path / "receipt"
    result = run_rank(base_args(env) + ["--result-out", str(out)] + extra)
    assert result.returncode == 0, result.stderr
    assert cr.read_rank_receipt(out).guard == guard
    assert summary_of(result.stdout)["guard"] == guard


def test_receipt_write_error_is_not_success(tmp_path, monkeypatch):
    env = make_env(tmp_path)
    out = tmp_path / "receipt"

    def fail(*args, **kwargs):
        raise OSError("receipt write injected")

    monkeypatch.setattr(cr, "atomic_write", fail)
    with pytest.raises(OSError):
        rank._run_cli(rank.build_parser().parse_args(base_args(env) + ["--result-out", str(out)]))
    assert not out.exists()
