"""P1：latency scan 的 cfst 参数契约与超时分级。

固化两件实测事实：
1. 下载测速必须用 -dd 真正禁用。`-dn 0` 不禁用（-dn 是数量，不是开关），会落回
   默认队列 10 个 IP × 最长 -dt 10s ≈ 100s 恒定开销，撞满 SCAN_TIMEOUT=90。
   实测同目标集：-dn 0 为 113.4s，-dd 为 13.5s。
2. RC=124 且已有输出时，本轮结果必须保留而非丢弃。
"""
from __future__ import annotations

import pathlib
import re
import subprocess
import unittest

CFST_DIR = pathlib.Path(__file__).resolve().parent.parent
SCAN = CFST_DIR / "scan_latency.sh"
CONFIG = CFST_DIR / "config.sh"


def code_lines(path: pathlib.Path) -> str:
    """去掉整行注释，只留可执行内容 —— 注释里提到 -dn 是合法的（解释为何不用它）。"""
    return "\n".join(
        ln for ln in path.read_text().splitlines() if not ln.lstrip().startswith("#")
    )


class CfstDownloadFlagTests(unittest.TestCase):
    """下载测速开关是 P1 的全部内容，必须精确。"""

    def setUp(self) -> None:
        self.code = code_lines(SCAN)

    def test_download_speedtest_is_disabled_with_dd(self) -> None:
        self.assertRegex(
            self.code, re.compile(r"^\s*-dd\b", re.M), "必须用 -dd 禁用下载测速"
        )

    def test_dn_is_never_passed(self) -> None:
        """-dn 任何取值都会进入下载阶段；0 不是「关闭」的意思。"""
        self.assertNotRegex(
            self.code,
            re.compile(r"^\s*-dn\b", re.M),
            "不得再传 -dn —— 它是数量而非开关",
        )

    def test_dt_is_not_relied_on(self) -> None:
        """既然整段跳过，就不该再靠调小 -dt 来遮掩问题。"""
        self.assertNotRegex(
            self.code, re.compile(r"^\s*-dt\b", re.M), "禁用下载后无需 -dt"
        )

    def test_latency_column_contract_unchanged(self) -> None:
        """-dd 改变排序，但不改列序；下游仍按第 5 列取平均延迟。"""
        self.assertRegex(
            self.code,
            r"NR > 1 && \$5 \+ 0 > 0 && \$5 \+ 0 < L",
            "仍应从 CSV 第 5 列读平均延迟",
        )

    def test_timeout_budget_is_kept_as_safety_net(self) -> None:
        """余量变大不是放宽超时的理由。"""
        self.assertRegex(self.code, r'--kill-after="\$\{SCAN_TIMEOUT_GRACE\}s"')
        self.assertRegex(self.code, r'"\$\{SCAN_TIMEOUT\}s"')
        self.assertRegex(CONFIG.read_text(), re.compile(r"^SCAN_TIMEOUT=90\b", re.M))


class FullCoverageTests(unittest.TestCase):
    """分片方案已作废：每轮必须全量覆盖，且不留持久游标状态。"""

    def setUp(self) -> None:
        self.code = code_lines(SCAN)

    def test_no_sharding_state(self) -> None:
        for token in ("SCAN_SHARDS", "SCAN_SHARD_CURSOR", "SHARD_INDEX", "SHARD_TOTAL"):
            self.assertNotIn(token, self.code, f"分片方案已作废，不应有 {token}")
        self.assertNotIn("SCAN_SHARDS", CONFIG.read_text())

    def test_all_three_target_sources_are_scanned_every_round(self) -> None:
        """master（在用）+ 队列（待筛）+ ip_ranges（发现面）缺一不可。"""
        block = self.code[self.code.index("{") : self.code.index('> "$TARGET"')]
        self.assertIn('"$MASTER"', block)
        self.assertIn('"$QUEUE_TMP"', block)  # module输出的已验证队列IP集合
        self.assertIn('"$SCAN"', block)

    def test_comment_lines_are_filtered_from_target_file(self) -> None:
        """cfst -f 会把 '#' 当 CIDR 解析报错，过滤必须保留。"""
        block = self.code[self.code.index("{") : self.code.index('> "$TARGET"')]
        self.assertEqual(
            block.count("grep -vE '^[[:space:]]*(#|$)'"),
            2,
            "master 与 ip_ranges 都需过滤注释与空行",
        )

    def test_targets_are_deduplicated(self) -> None:
        self.assertIn("awk '!seen[$0]++'", self.code)


class PartialTimeoutTests(unittest.TestCase):
    """超时但已有产出的轮次，结果必须留下 —— 与分片无关的独立缺陷。"""

    def setUp(self) -> None:
        self.text = SCAN.read_text()

    def _rc124_block(self) -> str:
        start = self.text.index('if [ "$RC" -eq 124 ]')
        end = self.text.index('if [ ! -s "$OUT" ]')
        return "\n".join(
            ln
            for ln in self.text[start:end].splitlines()
            if not ln.lstrip().startswith("#")
        )

    def test_partial_results_are_not_discarded(self) -> None:
        block = self._rc124_block()
        partial = block[: block.index("else")]
        self.assertIn("partial", partial)
        self.assertNotIn("exit", partial, "partial 分支不得退出，结果要继续入队")

    def test_dead_round_exits_cleanly(self) -> None:
        block = self._rc124_block()
        dead = block[block.index("else") :]
        self.assertIn("dead", dead)
        self.assertIn("exit 0", dead, "零产出轮次应正常退出，不作为错误")

    def test_generic_error_branch_excludes_124(self) -> None:
        """曾经的缺陷：RC=124 走完 partial 后又被通用分支 exit 124 丢弃。"""
        self.assertIn(
            'if [ "$RC" -ne 0 ] && [ "$RC" -ne 124 ]; then',
            self.text,
            "通用错误分支必须排除 124，否则 partial 结果仍会被丢",
        )


class ShellSyntaxTests(unittest.TestCase):
    def test_scripts_parse(self) -> None:
        for name in ("scan_latency.sh", "config.sh", "run.sh", "verify_vless.sh"):
            with self.subTest(script=name):
                r = subprocess.run(
                    ["bash", "-n", str(CFST_DIR / name)],
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(r.returncode, 0, r.stderr)


if __name__ == "__main__":
    unittest.main()


class ContenderExclusionTests(unittest.TestCase):
    """Contender pool（2026-10-15）：排除集 = contenders.tsv ∪ master_ips.txt（过渡期）。"""

    def setUp(self) -> None:
        self.code = code_lines(SCAN)

    def test_known_set_reads_contenders_first_column_and_master(self) -> None:
        start = self.code.index("known_ip_set() {")
        body = self.code[start:self.code.index("\n}", start)]
        self.assertIn('"$CONTENDERS"', body)
        self.assertIn('"$MASTER"', body)
        self.assertIn("ip_validation.py", body, "仍须经 ip_validation.py --filter 过滤")

    def test_new_candidate_filter_uses_known_set(self) -> None:
        self.assertIn('known_ip_set "$MASTER_SET"', self.code)
        self.assertRegex(self.code, r'-v master="\$MASTER_SET"')

    def test_target_block_still_filters_comments_exactly_twice(self) -> None:
        """contenders 行不得复用 master/ip_ranges 的注释过滤 grep（契约计数为 2）。"""
        block = self.code[self.code.index("{") : self.code.index('> "$TARGET"')]
        self.assertEqual(block.count("grep -vE '^[[:space:]]*(#|$)'"), 2)
        self.assertIn('"$CONTENDERS"', block)
