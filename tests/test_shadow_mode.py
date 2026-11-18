"""Task 6：影子模式接入契约（切换前新链路只写 .shadow/，不发布）。"""
from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

CFST = Path(__file__).resolve().parents[1]
CYCLE = (CFST / "cycle.sh").read_text(encoding="utf-8")


def _shadow_region(code: str) -> str:
    regions = re.findall(r'^if \[ "\$SHADOW" = "1" \]; then\n(.*?)^fi$', code, re.S | re.M)
    assert regions, '缺少 if [ "$SHADOW" = "1" ]; then 区'
    hits = [r for r in regions if "SHADOW_DIR=" in r]
    assert hits, "缺少设置 SHADOW_DIR 的 SHADOW=1 区"
    return hits[0]


class TestCycleShadow:
    def test_no_dry_run(self) -> None:
        assert "--dry-run" not in CYCLE

    def test_shadow_redirects_state_to_shadow_dir(self) -> None:
        region = _shadow_region(CYCLE)
        for var in ("CONTENDERS=", "BEST=", "SCREEN_BLACKLIST=", "LEGACY_BEST="):
            assert var in region, var
        assert ".shadow" in region

    def test_rank_uses_variables_not_literal_paths(self) -> None:
        assert '--contenders "$CONTENDERS"' in CYCLE
        assert '--tiers-out "$TIERS_DIR"' in CYCLE
        assert 'CONTENDERS="$CFST_DIR/contenders.tsv"' not in CYCLE
        assert 'TIERS_DIR="$CFST_DIR/.tiers"' not in CYCLE

    def test_queue_housekeeping_skipped_in_shadow(self) -> None:
        i = CYCLE.index('admission.py" maintain')
        assert re.search(r'if \[ "\$SHADOW" = "0" \]', CYCLE[:i]), "队列整理必须由 SHADOW=0 门控"

    def test_shadow_line_contract(self) -> None:
        assert re.search(r'log "shadow: legacy=\$\w+ new=\$\w+ same=\$\w+"', CYCLE)


class TestMigrateShadowOut:
    def _env(self, tmp_path: Path) -> dict:
        return dict(os.environ, MIGRATE_ROOT=str(tmp_path), MIGRATE_LOCK=str(tmp_path / "lock"),
                    VLESS_HISTORY=str(tmp_path / "nohist.tsv"))

    def test_shadow_out_generates_without_renaming(self, tmp_path: Path) -> None:
        (tmp_path / "master_ips.txt").write_text("1.1.1.9\n1.1.1.10\n")
        (tmp_path / "probation_pool.tsv").write_text("2026-10-15 10:00:00\t1.1.1.11\t1\n")
        out = tmp_path / "cand.tsv"
        r = subprocess.run(["bash", str(CFST / "migrate.sh"), "--shadow-out", str(out)],
                           env=self._env(tmp_path), capture_output=True, text=True, cwd=tmp_path)
        assert r.returncode == 0, r.stderr
        ips = [l.split("\t")[0] for l in out.read_text().splitlines() if l and not l.startswith("#")]
        assert ips == ["1.1.1.9", "1.1.1.10", "1.1.1.11"]
        assert (tmp_path / "master_ips.txt").exists()
        assert not (tmp_path / "contenders.tsv").exists()
        assert not (tmp_path / "master_ips.txt.legacy").exists()
        assert not (tmp_path / "run.sh").exists()

    def test_shadow_out_ignores_lock(self, tmp_path: Path) -> None:
        (tmp_path / "master_ips.txt").write_text("1.1.1.9\n")
        lock = tmp_path / "lock"
        out = tmp_path / "cand.tsv"
        cmd = f'exec 9>"{lock}"; flock 9; bash "{CFST}/migrate.sh" --shadow-out "{out}"'
        r = subprocess.run(["bash", "-c", cmd], env=self._env(tmp_path), capture_output=True, text=True, cwd=tmp_path)
        assert r.returncode == 0, r.stderr
        assert out.exists()
