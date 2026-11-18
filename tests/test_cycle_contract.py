"""cycle.sh 结构契约（Contender Pool 计划 Task 4）。

只做源码结构断言（if/fi 配对 + 子串），绝不执行 cycle.sh（会触发 xray/网络/推送）。
解析手法同 tests/test_systemic_guard.py：剥整行注释后按 `if ...; then` / `fi`
深度配对；awk 程序内的 `if (...)` 不以 `; then` 结尾，不参与计数。
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

CFST_DIR = Path(__file__).resolve().parents[1]
CYCLE_SH = CFST_DIR / "cycle.sh"

RANK_THRESHOLD_FLAGS = {
    "--half-life-hours": "RANK_HALF_LIFE_HOURS",
    "--floor-ms": "RANK_FLOOR_MS",
    "--z": "RANK_Z",
    "--sigma0": "RANK_SIGMA0",
    "--peak-weight": "RANK_PEAK_WEIGHT",
    "--peak-min-samples": "RANK_PEAK_MIN_SAMPLES",
    "--trim-headroom": "VLESS_SCREEN_MAX",
    "--core-n": "CORE_N",
    "--pool-target": "POOL_TARGET",
    "--pool-max": "POOL_MAX",
    "--publish-min-neff": "PUBLISH_MIN_NEFF",
    "--publish-margin": "PUBLISH_MARGIN",
    "--top-n": "SCORE_TOP_N",
    "--publish-top-n": "PUBLISH_TOP_N",
    "--hard-max-fail": "VLESS_HARD_MAX_FAIL",
    "--peak-hours": "RANK_PEAK_HOURS",
}
RANK_EVIDENCE_FLAGS = (
    "--history", "--contenders", "--best", "--blacklist", "--now",
    "--audit-requested", "--audit-returned", "--systemic", "--audit-ok", "--tiers-out",
)

SYSTEMIC_GUARD_RE = re.compile(r'^if \[ "\$SYSTEMIC_ROUND" = "1" \]; then$')
SLOW_ONLY_RE = re.compile(r'^if \[ "\$MODE" = "slow" \]; then$')
APPLY_GUARD_RE = re.compile(r'^if \[ "\$SHADOW" = "0" \]; then$')
SHADOW_GUARD_RE = re.compile(r'^if \[ "\$SHADOW" = "1" \]; then$')
IF_THEN_RE = re.compile(r"^if .*;\s*then$")


def code_lines(path: Path) -> str:
    return "\n".join(
        ln for ln in path.read_text(encoding="utf-8").splitlines()
        if not ln.lstrip().startswith("#")
    )


def regions(code: str, head: re.Pattern[str]) -> list[tuple[int, int]]:
    """每个匹配 head 的 `if ...; then` 到配对 fi 的行区间（含 elif 分支）。"""
    lines = code.splitlines()
    found: list[tuple[int, int]] = []
    for start, raw in enumerate(lines):
        if not head.match(raw.strip()):
            continue
        depth, end = 1, len(lines) - 1
        for cursor in range(start + 1, len(lines)):
            stripped = lines[cursor].strip()
            if IF_THEN_RE.match(stripped):
                depth += 1
            elif stripped == "fi":
                depth -= 1
                if depth == 0:
                    end = cursor
                    break
        found.append((start, end))
    return found


def inside(regs: list[tuple[int, int]], target: int) -> bool:
    return any(start < target <= end for start, end in regs)


def line_indices(code: str, needle: str) -> list[int]:
    return [i for i, ln in enumerate(code.splitlines()) if needle in ln]


def first_index(code: str, needle: str) -> int:
    hits = line_indices(code, needle)
    assert hits, f"cycle.sh 缺少 {needle!r}"
    return hits[0]


def rank_invocation(code: str) -> str:
    """从 `python3 .../rank.py` 起收集反斜杠续行，得到整条调用。"""
    lines = code.splitlines()
    cursor = first_index(code, 'rank.py"')
    block = [lines[cursor]]
    while lines[cursor].rstrip().endswith("\\") and cursor + 1 < len(lines):
        cursor += 1
        block.append(lines[cursor])
    return "\n".join(block)


class TestShellContract:
    def test_bash_syntax_parses(self) -> None:
        assert CYCLE_SH.exists(), "cycle.sh 尚未创建"
        proc = subprocess.run(["bash", "-n", str(CYCLE_SH)],
                              capture_output=True, text=True, check=False)
        assert proc.returncode == 0, proc.stderr

    def test_strict_mode_lock_and_tmpfiles(self) -> None:
        code = code_lines(CYCLE_SH)
        assert "set -euo pipefail" in code
        assert 'source "$(dirname "$0")/config.sh"' in code
        assert 'exec 9>"$CFST_LOCK"' in code
        assert "flock -n 9 || exit 75" in code
        assert re.search(r'mktemp "\$RESULT_DIR/\.', code)
        assert re.search(r"^trap .*EXIT", code, re.M)

    def test_usage_accepts_slow_fast_and_flags(self) -> None:
        code = code_lines(CYCLE_SH)
        assert "slow|fast" in code and "--emergency" in code and "--shadow" in code


class TestSystemicGuard:
    def test_screen_is_skipped_on_systemic_round(self) -> None:
        code = code_lines(CYCLE_SH)
        regs = regions(code, SYSTEMIC_GUARD_RE)
        assert regs, "缺少 systemic 守卫区"
        assert inside(regs, first_index(code, 'verify_vless.sh" --screen'))

    def test_verdict_computed_before_guard(self) -> None:
        code = code_lines(CYCLE_SH)
        assign = first_index(code, "SYSTEMIC_ROUND=$(python3")
        for start, _end in regions(code, SYSTEMIC_GUARD_RE):
            assert assign < start


class TestFastPath:
    def test_screen_probe_queue_tidy_and_log_cleanup_are_slow_only(self) -> None:
        code = code_lines(CYCLE_SH)
        slow = regions(code, SLOW_ONLY_RE)
        assert slow, '缺少 `if [ "$MODE" = "slow" ]; then` 区'
        for needle in ('verify_vless.sh" --screen', 'probe.sh" --all',
                       'admission.py" maintain', 'find "$RESULT_DIR"'):
            hits = line_indices(code, needle)
            assert hits, f"缺少 {needle!r}"
            for idx in hits:
                assert inside(slow, idx), f"{needle!r} 不在 slow-only 区内"

    def test_fast_reads_tiers_union_or_exits_zero(self) -> None:
        code = code_lines(CYCLE_SH)
        assert "core.txt" in code and "challengers.txt" in code and ".tiers" in code
        idx = first_index(code, "core.txt")
        after = "\n".join(code.splitlines()[idx:idx + 12])
        assert "exit 0" in after, "tiers 文件不存在时 fast 必须 exit 0"
        assert "!seen[$0]++" in code, "core ∪ challengers 需去重"

    def test_emergency_only_marks_log(self) -> None:
        code = code_lines(CYCLE_SH)
        assert "EMERGENCY=1" in code
        hits = line_indices(code, "$EMERGENCY")
        assert hits, "emergency 标记必须进入日志行"
        for idx in hits:
            ln = code.splitlines()[idx].lstrip()
            assert ln.startswith(("echo", "printf", "if", "elif", "FLAGS", "CYCLE")), ln


class TestRankAndApply:
    def test_rank_runs_before_apply(self) -> None:
        code = code_lines(CYCLE_SH)
        assert first_index(code, 'rank.py"') < first_index(code, 'apply.sh"')

    def test_apply_is_gated_by_shadow_zero(self) -> None:
        code = code_lines(CYCLE_SH)
        regs = regions(code, APPLY_GUARD_RE)
        assert regs, '缺少 `if [ "$SHADOW" = "0" ]; then` 区'
        assert inside(regs, first_index(code, 'apply.sh"'))
        assert inside(regs, first_index(code, "compute_apply_state"))

    def test_shadow_redirects_state_instead_of_dry_run(self) -> None:
        # 影子 = 状态重定向到 .shadow/（rank 正常写入以保留粘性在任者），而非 --dry-run。
        code = code_lines(CYCLE_SH)
        regs = regions(code, SHADOW_GUARD_RE)
        assert regs, '缺少 `if [ "$SHADOW" = "1" ]; then` 区'
        assert "--dry-run" not in code
        assert inside(regs, first_index(code, 'CONTENDERS="$SHADOW_DIR/contenders.tsv"'))
        assert inside(regs, first_index(code, 'BEST="$SHADOW_DIR/best_ips.txt"'))

    def test_apply_failure_exits_nonzero(self) -> None:
        code = code_lines(CYCLE_SH)
        assert "APPLY_FORCE=1" in code
        assert 'exit "$apply_rc"' in code
        assert "apply state mismatch" in code

    def test_rank_invocation_passes_all_thresholds_and_evidence(self) -> None:
        call = rank_invocation(code_lines(CYCLE_SH))
        for flag, var in RANK_THRESHOLD_FLAGS.items():
            assert re.search(rf'{re.escape(flag)} "\$\{{{var}:\?', call), \
                f'rank 调用缺少 {flag} "${{{var}:?...}}"'
        for flag in RANK_EVIDENCE_FLAGS:
            assert flag in call, f"rank 调用缺少 {flag}"
        assert '--contenders "$CONTENDERS"' in call
        assert '--tiers-out "$TIERS_DIR"' in call
        # 16 个阈值 + --tiers-out = 契约要求的 17 个参数
        assert len(RANK_THRESHOLD_FLAGS) + 1 == 17

    def test_rank_failure_is_fail_closed(self) -> None:
        code = code_lines(CYCLE_SH)
        assert 'exit "$rank_rc"' in code


class TestScreenAdmission:
    def test_screen_pass_appends_to_contenders_not_probation(self) -> None:
        code = code_lines(CYCLE_SH)
        assert "probation_pool" not in code
        assert 'admission.py" --contenders "$CONTENDERS"' in code
        assert 'CONTENDERS="${CONTENDERS:-$CFST_DIR/contenders.tsv}"' in code
        screen = first_index(code, 'verify_vless.sh" --screen')
        append = first_index(code, 'admission.py" --contenders')
        assert screen < append

    def test_pool_max_gate_exists(self) -> None:
        code = code_lines(CYCLE_SH)
        gate = [i for i, ln in enumerate(code.splitlines())
                if ln.strip().startswith("elif") and "POOL_MAX" in ln]
        assert gate, "缺少 POOL_MAX 门控 elif 分支"
        assert inside(regions(code, SYSTEMIC_GUARD_RE), gate[0])
        assert "${POOL_MAX:?" in code


class TestLegacyRemoved:
    def test_no_legacy_pipeline_calls(self) -> None:
        code = code_lines(CYCLE_SH)
        for legacy in ('pool.py"', 'score.py"', "probation_pool.py", "probation.py",
                       '"$MASTER"', "$MASTER_STATE", "$PROBATION_POOL"):
            assert legacy not in code, f"cycle.sh 不得再引用 {legacy}"


class TestAuditAndLogging:
    def test_audit_returned_counts_ipv4_rows_in_results_block(self, tmp_path) -> None:
        from cycle_result import assess_audit
        path=tmp_path/'audit'
        path.write_text('10.0.0.9 PASS\n=== AUDIT RESULTS ===\n10.0.0.1 PASS\n10.0.0.2 FAIL\nnoise\n')
        evidence=assess_audit(2,audit_path=path)
        assert evidence.returned==2 and evidence.guard=='none'
        assert 'cycle_result.py" audit --path "$AUDIT_OUT"' in code_lines(CYCLE_SH)

    def test_audit_credential_failure_marks_no_evidence(self) -> None:
        code = code_lines(CYCLE_SH)
        assert "AUDIT_OK=0" in code
        assert re.search(r"^\s*2\)\s", code, re.M), "rc 2（凭据缺失）必须单独记日志"

    def test_summary_line_and_log_targets(self) -> None:
        """结束行 `cycle: mode=.. guard=.. rank=ok|failed|skipped`（status.py 解析），
        rank 摘要行 `rank: pool=...` 另以时间戳前缀原样入日志。"""
        code = code_lines(CYCLE_SH)
        assert 'log "cycle: mode=$MODE$flags guard=$GUARD rank=$RANK_STATUS"' in code
        assert 'log "$RANK_SUMMARY"' in code
        assert 'LOG="$RESULT_DIR/$TS.log"' in code
        assert "LOG=/dev/stdout" in code, "fast 写 stdout，由 cron 重定向"
