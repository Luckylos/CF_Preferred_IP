"""切片1：系统性劣化守卫 — 共因故障轮不得转化为 IP 级处罚。

背景（2026-08-26 04:00 实测事件）：
本地出口/上游整体劣化一轮，42 个 master 中 39 个 PASS 但 median 集中到
346-414ms（p10=380ms），仅 3 个 IP 仍在 ~45ms。当轮把 40 条 ttfb_slow 记到
单个 IP 头上，并污染 37 个 non-master 候选的 24h 证据窗口；配合
PROBATION_MAX_SLOW=0 与 PROBATION_FAIL_LIMIT=3，会在持续故障下批量拉黑。

判据选择的实测依据（/root/.hermes/tmp/cfst-analysis/p10_verify.py，8319 行
历史、84 轮）：
  - master-only PASS p10 正常区间 min=43.0 p50=45.0 p90=47.0 max(次高)=48.5
  - 事件轮 p10=380.0，分离度 7.8x
  - 阈值 80/100/120/150/200/250/300ms 全部只命中同一轮 → 判据极不敏感
  - floor(最小值)不可用：事件轮 floor 仍为 45ms（3 个 IP 未受影响），
    只有 p10 这类抗离群分位数才能表达「主体劣化」

为什么不是 median：median 在半数 IP 劣化时才动，太晚；p10 表达的是
「连最快的一批都慢了」，正是共因故障的指纹，且对单 IP 劣化免疫。
"""

from __future__ import annotations

import importlib.util
import re
import subprocess
import sys
from pathlib import Path

CFST_DIR = Path(__file__).resolve().parents[1]
MODULE_PATH = CFST_DIR / "systemic.py"
CYCLE_SH = CFST_DIR / "cycle.sh"
CONFIG_SH = CFST_DIR / "config.sh"

SPEC = importlib.util.spec_from_file_location("systemic", MODULE_PATH)
assert SPEC and SPEC.loader, f"systemic.py 尚未实现: {MODULE_PATH}"
systemic = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = systemic
SPEC.loader.exec_module(systemic)


def audit_text(rows: list[tuple[str, str, int]]) -> str:
    """构造 verify_vless.sh --audit 的输出格式。"""
    lines = ["preamble noise line", "=== AUDIT RESULTS ==="]
    for ip, status, median in rows:
        suffix = " (timeout)" if status == "FAIL" and median == 0 else ""
        lines.append(f"  {ip} {status} {median}{suffix}")
    return "\n".join(lines) + "\n"


def ip_at(index: int) -> str:
    return f"10.0.{index // 254}.{index % 254 + 1}"


def rows_uniform(count: int, status: str, median: int, start: int = 0) -> list[tuple[str, str, int]]:
    return [(ip_at(start + i), status, median) for i in range(count)]


def code_lines(path: Path) -> str:
    """剥掉整行注释：注释里出现变量名是合法的（解释设计），不算接线。"""
    return "\n".join(
        ln for ln in path.read_text(encoding="utf-8").splitlines()
        if not ln.lstrip().startswith("#")
    )


GUARD_RE = re.compile(r'^if \[ "\$SYSTEMIC_ROUND" = "1" \]; then$')


def guard_regions(code: str) -> list[tuple[int, int]]:
    """定位每个 `if [ "$SYSTEMIC_ROUND" = "1" ]; then` 到其配对 fi 的行区间。

    只做 if/fi 深度配对 —— run.sh 全文是 `if ...; then` / `elif` / `fi` 风格，
    单行 case 不参与计数。必须真正配对，否则「文件里出现过 SYSTEMIC」这种
    宽松匹配会让接线测试假绿。
    """
    lines = code.splitlines()
    regions: list[tuple[int, int]] = []
    for start, raw in enumerate(lines):
        if not GUARD_RE.match(raw.strip()):
            continue
        depth = 1
        end = len(lines) - 1
        for cursor in range(start + 1, len(lines)):
            stripped = lines[cursor].strip()
            if stripped.startswith("if "):
                depth += 1
            elif stripped == "fi":
                depth -= 1
                if depth == 0:
                    end = cursor
                    break
        regions.append((start, end))
    return regions


# ─────────────────────────────────────────────────────────────────
# 判据本体：evaluate()
# ─────────────────────────────────────────────────────────────────

class TestSystemicVerdict:
    """Given 一轮 master audit 证据 / When 计算判据 / Then 是否共因劣化。"""

    def test_uniformly_degraded_round_is_flagged_systemic(self) -> None:
        """事件轮指纹：主体劣化到 ~350ms，少数 IP 仍快 → 必须判 systemic。

        复刻 2026-08-26 04:00 形态：39 PASS 中仅 3 个 ~45ms。
        """
        rows = (
            rows_uniform(3, "PASS", 45)
            + rows_uniform(36, "PASS", 360, start=3)
        )
        flagged, reason = systemic.evaluate(
            systemic.parse_audit(audit_text(rows)),
            p10_threshold_ms=150,
            min_samples=10,
        )
        assert flagged is True, reason
        assert "p10=" in reason

    def test_single_slow_ip_does_not_trigger_the_guard(self) -> None:
        """一个 IP 真慢是 IP 级证据，必须照常累计退役，不能被守卫吞掉。"""
        rows = rows_uniform(41, "PASS", 45) + [(ip_at(99), "PASS", 900)]
        flagged, reason = systemic.evaluate(
            systemic.parse_audit(audit_text(rows)),
            p10_threshold_ms=150,
            min_samples=10,
        )
        assert flagged is False, reason

    def test_half_the_pool_degrading_is_still_ip_level_evidence(self) -> None:
        """半数劣化仍不算共因：p10 表达「连最快一批都慢了」。

        这是与 median 判据的关键差异 —— median 在此处会误报。
        """
        rows = rows_uniform(21, "PASS", 45) + rows_uniform(21, "PASS", 400, start=21)
        flagged, reason = systemic.evaluate(
            systemic.parse_audit(audit_text(rows)),
            p10_threshold_ms=150,
            min_samples=10,
        )
        assert flagged is False, reason

    def test_fastest_ips_surviving_do_not_mask_a_systemic_round(self) -> None:
        """floor(最小值)判据在事件轮失效的回归防护。

        事件轮实测 floor 仍为 45ms，若用 min() 会漏判；p10 必须仍然命中。
        """
        rows = (
            rows_uniform(3, "PASS", 45)
            + rows_uniform(30, "PASS", 395, start=3)
            + rows_uniform(6, "FAIL", 0, start=33)
        )
        records = systemic.parse_audit(audit_text(rows))
        assert min(m for _ip, st, m in records if st == "PASS") == 45
        flagged, _reason = systemic.evaluate(
            records, p10_threshold_ms=150, min_samples=10
        )
        assert flagged is True

    def test_thin_evidence_is_not_flagged_so_small_pools_still_retire(self) -> None:
        """样本不足时 p10 无意义：必须 fail-open 回落到正常处罚路径。

        否则 master 池小于 min_samples 时守卫会永久冻结退役。
        """
        rows = rows_uniform(4, "PASS", 800)
        flagged, reason = systemic.evaluate(
            systemic.parse_audit(audit_text(rows)),
            p10_threshold_ms=150,
            min_samples=10,
        )
        assert flagged is False
        assert "insufficient" in reason

    def test_all_fail_round_is_left_to_the_existing_pool_guard(self) -> None:
        """全 FAIL 无 median 可用：本守卫不表态，交给 pool.py 既有全池守卫。"""
        rows = rows_uniform(42, "FAIL", 0)
        flagged, reason = systemic.evaluate(
            systemic.parse_audit(audit_text(rows)),
            p10_threshold_ms=150,
            min_samples=10,
        )
        assert flagged is False
        assert "insufficient" in reason

    def test_threshold_is_inclusive_boundary(self) -> None:
        """阈值语义固定为「严格超过才判」，避免边界轮反复翻转。"""
        at_threshold = rows_uniform(20, "PASS", 150)
        just_over = rows_uniform(20, "PASS", 151)
        assert systemic.evaluate(
            systemic.parse_audit(audit_text(at_threshold)), 150, 10
        )[0] is False
        assert systemic.evaluate(
            systemic.parse_audit(audit_text(just_over)), 150, 10
        )[0] is True

    def test_failed_probes_do_not_enter_the_percentile(self) -> None:
        """FAIL 的 median=0 若混入分位数会把 p10 拉到 0，永久压住守卫。"""
        rows = rows_uniform(20, "FAIL", 0) + rows_uniform(20, "PASS", 400, start=20)
        records = systemic.parse_audit(audit_text(rows))
        flagged, reason = systemic.evaluate(records, 150, 10)
        assert flagged is True, reason


class TestAuditParsing:
    """解析必须与 run.sh:76-86 / probation_pool.py:243-253 的既有契约一致。"""

    def test_only_lines_after_the_results_marker_are_parsed(self) -> None:
        text = (
            "  1.2.3.4 PASS 45\n"           # marker 之前：噪声，忽略
            "=== AUDIT RESULTS ===\n"
            "  5.6.7.8 PASS 46\n"
        )
        assert systemic.parse_audit(text) == [("5.6.7.8", "PASS", 46)]

    def test_timeout_rows_keep_zero_median(self) -> None:
        text = "=== AUDIT RESULTS ===\n  1.2.3.4 FAIL 0 (timeout)\n"
        assert systemic.parse_audit(text) == [("1.2.3.4", "FAIL", 0)]

    def test_non_ip_lines_are_ignored(self) -> None:
        text = (
            "=== AUDIT RESULTS ===\n"
            "  summary: 3 passed\n"
            "  1.2.3.4 PASS 45\n"
            "  not-an-ip PASS 45\n"
        )
        assert systemic.parse_audit(text) == [("1.2.3.4", "PASS", 45)]


class TestPercentile:
    """p10 必须与标定脚本 p10_verify.py 同一算法，否则阈值不可迁移。"""

    def test_linear_interpolation_matches_calibration(self) -> None:
        assert systemic.percentile([45.0, 45.0], 0.10) == 45.0
        assert systemic.percentile([10.0, 20.0], 0.50) == 15.0
        assert systemic.percentile([100.0], 0.10) == 100.0

    def test_percentile_ignores_position_of_outliers(self) -> None:
        fast_tail = [45.0] * 40 + [900.0, 900.0]
        assert systemic.percentile(sorted(fast_tail), 0.10) == 45.0


# ─────────────────────────────────────────────────────────────────
# CLI 契约：run.sh 靠 stdout 单 token 取判定
# ─────────────────────────────────────────────────────────────────

class TestCliContract:
    def _run(self, tmp_path: Path, rows: list[tuple[str, str, int]]) -> subprocess.CompletedProcess[str]:
        audit = tmp_path / "audit.txt"
        audit.write_text(audit_text(rows), encoding="utf-8")
        return subprocess.run(
            [
                sys.executable, str(MODULE_PATH),
                "--audit", str(audit),
                "--p10-threshold", "150",
                "--min-samples", "10",
            ],
            capture_output=True, text=True, check=False,
        )

    def test_systemic_round_prints_one_on_stdout(self, tmp_path: Path) -> None:
        proc = self._run(tmp_path, rows_uniform(20, "PASS", 400))
        assert proc.returncode == 0, proc.stderr
        assert proc.stdout.strip() == "1"
        assert "p10=" in proc.stderr

    def test_healthy_round_prints_zero_on_stdout(self, tmp_path: Path) -> None:
        proc = self._run(tmp_path, rows_uniform(20, "PASS", 45))
        assert proc.returncode == 0, proc.stderr
        assert proc.stdout.strip() == "0"

    def test_missing_audit_file_fails_open_to_normal_round(self, tmp_path: Path) -> None:
        """守卫自身故障不得冻结退役，也不得让 run.sh 因 set -e 崩掉。"""
        proc = subprocess.run(
            [
                sys.executable, str(MODULE_PATH),
                "--audit", str(tmp_path / "nope.txt"),
                "--p10-threshold", "150",
                "--min-samples", "10",
            ],
            capture_output=True, text=True, check=False,
        )
        assert proc.returncode == 0, proc.stderr
        assert proc.stdout.strip() == "0"


# ─────────────────────────────────────────────────────────────────
# 处罚入口接线：三条路径都必须被守卫覆盖
# ─────────────────────────────────────────────────────────────────

class TestPunishmentPathsAreGuarded:
    """cycle.sh（2026-10-15 取代 run.sh）里仍存在的处罚入口：

      C. 发现队列快筛 fc++ → VLESS_SCREEN_MAX_FAIL → 黑名单（systemic 轮跳过）
    旧入口 A（pool.py 退役）与 B（probation recheck）已由 rank.py 取代：
    cycle.sh 把判定以 --systemic 传给 rank.py，守卫轮不淘汰（见 tests/test_rank_cli.py）。
    """

    def setup_method(self) -> None:
        self.code = code_lines(CYCLE_SH)

    def test_config_declares_the_calibrated_thresholds(self) -> None:
        config = CONFIG_SH.read_text(encoding="utf-8")
        assert re.search(r"^MASTER_SYSTEMIC_P10_MS=\d+", config, re.M),             "阈值必须在 config.sh 单点声明"
        assert re.search(r"^MASTER_SYSTEMIC_MIN_SAMPLES=\d+", config, re.M)

    def test_guard_runs_before_rank_and_screen(self) -> None:
        verdict = self.code.index("systemic.py")
        assert verdict < self.code.index("rank.py"), "判定必须早于 rank.py"
        assert verdict < self.code.index('--screen "$SCREEN_IN"'), "C: 必须早于发现队列快筛"

    def test_rank_receives_the_verdict(self) -> None:
        assert '--systemic "$SYSTEMIC_ROUND"' in self.code

    def test_entry_c_discovery_screen_is_skipped(self) -> None:
        """C：systemic 轮不快筛新候选 —— 否则连撞 3 轮就被拉黑 24h。"""
        lines = self.code.splitlines()
        target = next(i for i, ln in enumerate(lines) if 'verify_vless.sh" --screen' in ln)
        assert any(start < target <= end for start, end in guard_regions(self.code)),             "C: 发现队列快筛未被守卫门控"

    def test_guard_verdict_is_computed_before_every_guarded_region(self) -> None:
        lines = self.code.splitlines()
        assign = next(i for i, ln in enumerate(lines) if ln.strip().startswith("SYSTEMIC_ROUND="))
        regions = guard_regions(self.code)
        assert regions, "cycle.sh 应有 systemic 守卫区"
        for start, _end in regions:
            assert assign < start, "守卫区出现在判定赋值之前"


class TestShellSyntax:
    def test_cycle_sh_parses(self) -> None:
        proc = subprocess.run(
            ["bash", "-n", str(CYCLE_SH)], capture_output=True, text=True, check=False
        )
        assert proc.returncode == 0, proc.stderr

    def test_config_sh_parses(self) -> None:
        proc = subprocess.run(
            ["bash", "-n", str(CONFIG_SH)], capture_output=True, text=True, check=False
        )
        assert proc.returncode == 0, proc.stderr
