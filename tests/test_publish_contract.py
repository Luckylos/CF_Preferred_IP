"""P3.1：发布契约（方案 C）—— `.apply_state` 只跟踪实际发布的 Top3。

修复的缺陷：`score.py` 输出 Top5，`apply.sh` 与 `run.sh` 各自按 `SCORE_TOP_N=5`
计算 `.apply_state`，而 `push_to_misub.py` 的 `TOP_N=3` 只发布 Top3。
后果是 **rank4/rank5 变化就触发一次无意义的生产重推**（删改 6 个节点 +
下游全量重新订阅），而这两个位次根本没有被发布。

方案 C 的两条硬约束：

1. 状态只跟踪发布集（`PUBLISH_TOP_N`），候补集（`SCORE_TOP_N`）不参与推送触发。
2. 状态公式必须是**单一真相源**。`run.sh` 与 `apply.sh` 曾各持一份拷贝，
   任一处漏改都会让两侧哈希永久不等，`run.sh` 每轮 fail-closed exit 1。
   因此这里既断言行为，也断言公式在树里只存在一处。
"""

from __future__ import annotations

import pathlib
import re
import subprocess
import unittest

CFST_DIR = pathlib.Path(__file__).resolve().parent.parent
CONFIG = CFST_DIR / "config.sh"
APPLY = CFST_DIR / "apply.sh"
RUN = CFST_DIR / "cycle.sh"   # 2026-10-15：慢/快周期编排，取代 run.sh
VERIFY = CFST_DIR / "verify_vless.sh"
PUSHER = CFST_DIR / "push_to_misub.py"
README = CFST_DIR / "README.md"


def code_lines(path: pathlib.Path) -> str:
    """去掉整行注释 —— 注释里提到旧变量名是合法的（解释为何不再用它）。"""
    return "\n".join(
        ln for ln in path.read_text().splitlines() if not ln.lstrip().startswith("#")
    )


class PublishContractDeclarationTests(unittest.TestCase):
    """发布位数必须显式、可配置，且与真正的发布者一致。"""

    def test_config_declares_publish_top_n(self) -> None:
        self.assertRegex(
            code_lines(CONFIG),
            re.compile(r"^\s*PUBLISH_TOP_N=(\d+)", re.M),
            "config.sh 必须显式声明 PUBLISH_TOP_N（发布位数）",
        )

    def test_publish_top_n_agrees_with_the_pusher(self) -> None:
        """跨语言漂移会精确地重建 P3.1 缺陷：状态跟踪 N 位、实际发布 M 位。"""
        shell = re.search(r"^\s*PUBLISH_TOP_N=(\d+)", code_lines(CONFIG), re.M)
        python = re.search(r"^TOP_N\s*=\s*(\d+)", PUSHER.read_text(), re.M)
        self.assertIsNotNone(shell, "config.sh 缺 PUBLISH_TOP_N")
        self.assertIsNotNone(python, "push_to_misub.py 缺 TOP_N")
        assert shell is not None and python is not None
        self.assertEqual(
            shell.group(1),
            python.group(1),
            "PUBLISH_TOP_N 必须与 push_to_misub.py 的 TOP_N 相等，否则状态跟踪的位数"
            "与实际发布的位数不一致（正是 P3.1 要消除的缺陷）",
        )


class SingleSourceOfTruthTests(unittest.TestCase):
    """状态公式只能有一份。两份拷贝是 P3.1 明确要消除的重复策略边界。"""

    def test_state_formula_lives_in_exactly_one_file(self) -> None:
        """md5sum 状态公式必须只在共用函数里出现一次。"""
        holders = [
            path.name
            for path in (CONFIG, APPLY, RUN)
            if re.search(r"md5sum", code_lines(path))
        ]
        self.assertEqual(
            holders,
            [CONFIG.name],
            f"状态公式应只存在于 config.sh 的共用函数中，实际出现在 {holders}",
        )

    def test_template_hash_is_not_recomputed_by_callers(self) -> None:
        """push_to_misub.py 的模板哈希也属于公式的一部分，不得在调用方重算。"""
        for path in (APPLY, RUN):
            self.assertNotRegex(
                code_lines(path),
                re.compile(r"sha256sum.*push_to_misub\.py"),
                f"{path.name} 不得自行计算模板哈希，应调用共用函数",
            )

    def test_both_callers_use_the_shared_function(self) -> None:
        for path in (APPLY, RUN):
            self.assertRegex(
                code_lines(path),
                re.compile(r"compute_apply_state", re.M),
                f"{path.name} 必须通过 compute_apply_state 取状态",
            )

    def test_callers_do_not_slice_best_ips_for_state(self) -> None:
        """取发布集也必须走共用函数，否则 head -n 的位数会再次漂移。"""
        for path in (APPLY, RUN):
            self.assertNotRegex(
                code_lines(path),
                re.compile(r"head -n \"\$SCORE_TOP_N\""),
                f"{path.name} 不得再按 SCORE_TOP_N 截取状态输入",
            )


class CandidateVerificationScopeTests(unittest.TestCase):
    """回归护栏：收窄发布集不等于收窄候选验证集。"""

    def test_verify_vless_still_defaults_to_score_top_n(self) -> None:
        """候补集（rank4/rank5）仍需 VLESS 数据，否则它们永远进不了发布位。"""
        self.assertRegex(
            code_lines(VERIFY),
            re.compile(r"head -n \"\$SCORE_TOP_N\""),
            "verify_vless.sh 默认输入必须保持 SCORE_TOP_N（Top5），"
            "候补集需要持续的 VLESS 样本",
        )


class StateBehaviourTests(unittest.TestCase):
    """真正的验收：在沙箱里调用共用函数，逐维度证明状态键的敏感度。"""

    TOP5 = ["1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4", "5.5.5.5"]

    def _sandbox(self, tmp: pathlib.Path, ips: list[str], template: str = "v1",
                 secret: str = "MISUB_TOKEN=deadbeef") -> None:
        best = tmp / "best_ips.txt"
        best.write_text(
            "# scored\n# --- BEST_IPS (machine-readable) ---\n" + "\n".join(ips) + "\n"
        )
        (tmp / "push_to_misub.py").write_text(f"# template {template}\n")
        secrets = tmp / "secrets"
        secrets.mkdir(exist_ok=True)
        env = secrets / "misub.env"
        env.write_text(secret + "\n")
        env.chmod(0o600)

    def _state(self, ips: list[str], template: str = "v1",
               secret: str = "MISUB_TOKEN=deadbeef",
               drop_secret: bool = False) -> str:
        """source 真实 config.sh，覆盖路径到沙箱，调用共用函数。"""
        import tempfile

        with tempfile.TemporaryDirectory() as raw:
            tmp = pathlib.Path(raw)
            self._sandbox(tmp, ips, template, secret)
            if drop_secret:
                (tmp / "secrets" / "misub.env").unlink()
            script = f"""
set -euo pipefail
VLESS_SECRET_FILE={tmp}/secrets/vless.env
source {CONFIG} 2>/dev/null || true
CFST_DIR={tmp}
BEST={tmp}/best_ips.txt
MISUB_TOKEN_FILE={tmp}/secrets/misub.env
compute_apply_state
"""
            proc = subprocess.run(
                ["/usr/bin/bash", "-c", script],
                capture_output=True,
                text=True,
                timeout=30,
            )
            self.assertEqual(
                proc.returncode,
                0,
                f"compute_apply_state 执行失败: {proc.stderr.strip()}",
            )
            return proc.stdout.strip()

    def test_publish_set_change_changes_state(self) -> None:
        base = self._state(self.TOP5)
        moved = self._state(["9.9.9.9", "2.2.2.2", "3.3.3.3", "4.4.4.4", "5.5.5.5"])
        self.assertNotEqual(base, moved, "发布位 IP 变化必须触发推送")

    def test_publish_set_reorder_changes_state(self) -> None:
        """rank1/2/3 映射到 CM/CM2/CM3，顺序本身就是契约。"""
        base = self._state(self.TOP5)
        swapped = self._state(["2.2.2.2", "1.1.1.1", "3.3.3.3", "4.4.4.4", "5.5.5.5"])
        self.assertNotEqual(base, swapped, "发布位顺序变化必须触发推送")

    def test_candidate_only_change_does_not_change_state(self) -> None:
        """P3.1 的核心：rank4/rank5 变化不得触发生产重推。"""
        base = self._state(self.TOP5)
        candidates_moved = self._state(
            ["1.1.1.1", "2.2.2.2", "3.3.3.3", "8.8.8.8", "7.7.7.7"]
        )
        self.assertEqual(
            base,
            candidates_moved,
            "rank4/rank5 未被发布，其变化不得触发推送（P3.1 修复目标）",
        )

    def test_candidate_count_change_does_not_change_state(self) -> None:
        """候补集缩短/延长同样不影响发布集。"""
        base = self._state(self.TOP5)
        fewer = self._state(["1.1.1.1", "2.2.2.2", "3.3.3.3"])
        self.assertEqual(base, fewer, "候补集数量变化不得触发推送")

    def test_template_change_changes_state(self) -> None:
        base = self._state(self.TOP5)
        retemplated = self._state(self.TOP5, template="v2")
        self.assertNotEqual(base, retemplated, "推送模板变化必须触发重推")

    def test_secret_rotation_changes_state(self) -> None:
        base = self._state(self.TOP5)
        rotated = self._state(self.TOP5, secret="MISUB_TOKEN=cafebabe")
        self.assertNotEqual(base, rotated, "Token 轮换必须触发重推")

    def test_missing_secret_is_marked_not_fatal_in_the_formula(self) -> None:
        """run.sh 用 secret=missing 参与比对；公式本身不能因缺文件崩掉。

        缺凭据的 fail-closed 归调用方（apply.sh 显式 exit 1），不归公式。
        """
        state = self._state(self.TOP5, drop_secret=True)
        self.assertRegex(state, r"^[0-9a-f]{32}$", "缺凭据时公式仍须给出确定状态")
        self.assertNotEqual(
            state,
            self._state(self.TOP5),
            "缺凭据的状态不得与正常状态相同",
        )

    def test_state_is_deterministic(self) -> None:
        self.assertEqual(self._state(self.TOP5), self._state(self.TOP5))


class ApplyGuardTests(unittest.TestCase):
    """收敛公式不得削弱 apply.sh 既有的 fail-closed 行为。"""

    def test_apply_still_fails_closed_on_missing_secret(self) -> None:
        code = code_lines(APPLY)
        self.assertRegex(
            code,
            re.compile(r"MISUB_TOKEN_FILE.*|PUSH_SECRET_FILE"),
            "apply.sh 仍须解析凭据文件路径",
        )
        self.assertRegex(
            code, re.compile(r"exit 1", re.M), "apply.sh 缺凭据时仍须 exit 1"
        )

    def test_maintenance_gate_survives(self) -> None:
        self.assertRegex(
            code_lines(APPLY),
            re.compile(r"\.push_disabled"),
            "P0 维护闸门不得在 P3.1 收敛中丢失",
        )


class DocContractTests(unittest.TestCase):
    """README 曾声称 preflight 验证「完整 Top5」，实测只验证发布集。"""

    def test_readme_does_not_claim_top5_preflight(self) -> None:
        self.assertNotRegex(
            README.read_text(),
            re.compile(r"验证完整 Top5"),
            "README 不得声称 preflight 覆盖 Top5 —— 实测覆盖发布集（Top3）",
        )


if __name__ == "__main__":
    unittest.main()
