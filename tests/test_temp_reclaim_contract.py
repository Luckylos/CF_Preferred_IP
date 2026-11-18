#!/usr/bin/env python3
"""资源回收契约：被 SIGKILL 打断的临时产物必须能被兜底清扫。

背景（2026-10-17 资源审计）：
- verify_vless.sh 的 EXIT/HUP/INT/TERM trap 在正常退出与 SIGTERM/SIGHUP 下都会清理
  临时目录，但 SIGKILL/OOM/断电不会触发 trap；实测 /dev/shm/cfst 里积压了 13 个
  9 月的 verify.* 目录（含 VLESS UUID），因为机器连续运行 27 天、tmpfs 从未清空。
- cycle.sh / scan_latency.sh 的临时文件是点号前缀（.audit.* / .rank.* / .lat_* 等），
  不以 .log/.csv 结尾，因此既有的 7 天保留规则永远命中不了它们；一旦泄漏即永久残留。

契约：只清理本脚本自己的命名空间，且有年龄下限（一次运行最长约 11 分钟，3 小时足够
安全），绝不误删活跃文件或无关文件。
"""
from __future__ import annotations

import fnmatch
import os
import re
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

CFST = Path("/opt/cfst")
VERIFY = CFST / "verify_vless.sh"
CYCLE = CFST / "cycle.sh"
SCAN = CFST / "scan_latency.sh"

OLD = 4 * 3600          # 早于兜底阈值（3h）


def _aged(p: Path, seconds: float) -> None:
    t = time.time() - seconds
    os.utime(p, (t, t))


def _run(cmd: str) -> None:
    subprocess.run(["bash", "-c", cmd], check=False, capture_output=True, text=True)


def _sample_name(mktemp_path: str) -> str:
    """mktemp '$RESULT_DIR/.audit.XXXXXX' -> 具体文件名 .audit.ZZZZZZ"""
    return Path(mktemp_path.strip('"')).name.replace("XXXXXX", "ZZZZZZ")


class _Base(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="cfst_reclaim_")
        self.base = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()


class VerifyTmpfsSweepTests(_Base):
    """verify_vless.sh 启动时必须清扫历史遗留的 verify.* 目录。"""

    def _sweep_line(self) -> str:
        m = re.search(r"find\s+\"\$VERIFY_TMPDIR_BASE\"[^\n]*", VERIFY.read_text())
        self.assertIsNotNone(m, "verify_vless.sh 缺少 tmpfs 遗留目录兜底清扫")
        return m.group(0)

    def test_sweep_targets_only_verify_dirs_with_age_guard(self) -> None:
        line = self._sweep_line()
        self.assertIn("-name 'verify.*'", line, "必须限定 verify.* 命名空间")
        self.assertIn("-type d", line, "只清理目录")
        m = re.search(r"-mmin\s+\+(\d+)", line)
        self.assertIsNotNone(m, "必须有年龄下限，避免删到本次运行的目录")
        self.assertGreaterEqual(int(m.group(1)), 60)
        self.assertIn("-exec rm -rf", line)

    def test_removes_old_dirs_keeps_fresh_and_unrelated(self) -> None:
        line = self._sweep_line().replace('"$VERIFY_TMPDIR_BASE"', f'"{self.base}"')
        old_dir = self.base / "verify.OLDAAA"
        old_dir.mkdir()
        (old_dir / "xray_0.json").write_text("{}")
        _aged(old_dir, OLD)
        fresh = self.base / "verify.FRESH1"
        fresh.mkdir()
        unrelated = self.base / "other.OLD"
        unrelated.mkdir()
        _aged(unrelated, OLD)
        old_file = self.base / "verify.FILE99"       # 同名文件：-type d 不得删
        old_file.write_text("x")
        _aged(old_file, OLD)

        _run(line)

        self.assertFalse(old_dir.exists(), "应删除超龄的 verify.* 目录")
        self.assertTrue(fresh.exists(), "不得删除本次运行的新目录")
        self.assertTrue(unrelated.exists(), "只清理 verify.* 命名空间")
        self.assertTrue(old_file.exists(), "不得删除同名文件")


class CycleDotTempSweepTests(_Base):
    """cycle.sh 必须兜底清扫泄漏的点号临时文件（mktemp 产物）。"""

    def _sweep_cmd(self) -> str:
        m = re.search(
            r"find\s+\"\$RESULT_DIR\"\s+-maxdepth\s+1\s+-type\s+f[\s\S]*?-delete",
            CYCLE.read_text())
        self.assertIsNotNone(m, "cycle.sh 缺少点号临时文件兜底清扫")
        return re.sub(r"\\\s*\n\s*", " ", m.group(0))

    def test_covers_every_mktemp_template_used_by_scripts(self) -> None:
        cmd = self._sweep_cmd()
        globs = re.findall(r"-name\s+'([^']+)'", cmd)
        self.assertTrue(globs, "清扫必须用 -name 限定前缀")
        self.assertIn("-type f", cmd, "只清理文件")
        m = re.search(r"-mmin\s+\+(\d+)", cmd)
        self.assertIsNotNone(m, "必须有年龄下限")
        self.assertGreaterEqual(int(m.group(1)), 60)
        for src in (CYCLE, SCAN):
            for tmpl in re.findall(r"mktemp\s+(\"\$RESULT_DIR/[^\"]+\")", src.read_text()):
                name = _sample_name(tmpl)
                self.assertTrue(any(fnmatch.fnmatch(name, g) for g in globs),
                                f"{src.name} 的临时名 {name} 未被兜底清扫覆盖")

    def test_removes_old_dot_temps_keeps_fresh_logs_and_dotfiles(self) -> None:
        cmd = self._sweep_cmd().replace('"$RESULT_DIR"', f'"{self.base}"')
        leaked = [self.base / n for n in (".audit.ab12", ".rank.cd34", ".lat_target.ef56",
                                          ".discovered.gh78", ".contenders.ij90")]
        for f in leaked:
            f.write_text("x")
            _aged(f, OLD)
        fresh = self.base / ".audit.NEW99"
        fresh.write_text("x")
        a_log = self.base / "20261017_120001.log"      # 7 天规则管辖，本清扫不得碰
        a_log.write_text("x")
        _aged(a_log, OLD)
        dotfile = self.base / ".gitignore"
        dotfile.write_text("x")
        _aged(dotfile, OLD)

        _run(cmd)

        for f in leaked:
            self.assertFalse(f.exists(), f"应删除超龄临时文件 {f.name}")
        self.assertTrue(fresh.exists(), "不得删除本次运行的新临时文件")
        self.assertTrue(a_log.exists(), "不得删除 .log 保留文件")
        self.assertTrue(dotfile.exists(), "不得删除无关点号文件")


if __name__ == "__main__":
    unittest.main()
