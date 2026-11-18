#!/usr/bin/env python3
"""P4 测试：xray 临时配置含 VLESS UUID，必须放 tmpfs 且不可被他人读。

历史缺陷：临时目录建在 /opt/cfst，xray_*.json 权限 0644，且被
timeout --kill-after 的 SIGKILL 终止时 EXIT trap 不执行，实测泄漏
10 个目录 / 178 个文件。
"""
from __future__ import annotations

import re
import subprocess
import unittest
from pathlib import Path

CFST = Path("/opt/cfst")
VERIFY = CFST / "verify_vless.sh"
CONFIG = CFST / "config.sh"


class TempDirLocationTests(unittest.TestCase):
    def test_temp_base_is_on_tmpfs(self) -> None:
        cfg = CONFIG.read_text()
        self.assertIn('VERIFY_TMPDIR_BASE="${VERIFY_TMPDIR_BASE:-/dev/shm/cfst}"', cfg,
                      "临时目录必须默认落在 tmpfs")

    def test_tmpfs_base_is_actually_a_tmpfs_mount(self) -> None:
        """/dev/shm 必须真是 tmpfs，否则迁移没有意义（重启不清空）。"""
        r = subprocess.run(["findmnt", "-no", "FSTYPE", "/dev/shm"],
                           capture_output=True, text=True)
        self.assertEqual(r.stdout.strip(), "tmpfs")

    def test_verify_script_no_longer_writes_temp_dirs_into_repo(self) -> None:
        text = VERIFY.read_text()
        self.assertNotIn('mktemp -d "$CFST_DIR/.verify_vless', text,
                         "临时目录不得再建在仓库目录（会落盘/进备份）")
        self.assertIn('mktemp -d "$VERIFY_TMPDIR_BASE/verify.XXXXXX"', text)

    def test_temp_base_and_dir_are_owner_only(self) -> None:
        text = VERIFY.read_text()
        self.assertIn('chmod 700 "$VERIFY_TMPDIR_BASE"', text)
        self.assertIn('chmod 700 "$TMPDIR_VERIFY"', text)


class ConfigPermissionTests(unittest.TestCase):
    """xray 配置内嵌 VLESS_UUID，创建时就必须是 0600。"""

    def test_config_is_chmodded_before_the_uuid_is_written(self) -> None:
        text = VERIFY.read_text()
        chmod_at = text.index('chmod 600 "$config"')
        heredoc_at = text.index('cat > "$config" <<EOF')
        self.assertLess(chmod_at, heredoc_at,
                        "必须先 chmod 600 再写入，否则存在 0644 窗口")

    def test_config_placeholder_is_created_empty_first(self) -> None:
        text = VERIFY.read_text()
        self.assertIn(': > "$config"\n    chmod 600 "$config"', text)

    def test_uuid_is_written_into_that_config(self) -> None:
        """确认被保护的正是含 UUID 的文件，而不是别的临时文件。"""
        text = VERIFY.read_text()
        opener = 'cat > "$config" <<EOF'
        start = text.index(opener) + len(opener)
        body = text[start:text.index("\nEOF\n", start)]
        self.assertIn("${VLESS_UUID}", body, "该文件确实含 UUID")


class LeakHygieneTests(unittest.TestCase):
    def test_no_stale_temp_dirs_remain_in_repo(self) -> None:
        leaked = [p for p in CFST.glob(".verify_vless.*") if p.is_dir()]
        self.assertEqual(leaked, [], f"仓库内仍有泄漏的临时目录: {leaked}")

    def test_no_xray_configs_left_on_disk(self) -> None:
        stale = list(CFST.glob(".verify_vless.*/xray_*.json"))
        self.assertEqual(stale, [], f"磁盘上仍有含 UUID 的残留配置: {stale}")

    def test_lock_file_is_preserved(self) -> None:
        """.verify_vless.lock 是活跃 flock 目标，清理时不能误删。"""
        self.assertTrue((CFST / ".verify_vless.lock").exists(),
                        "锁文件被误删会破坏并发互斥")

    def test_cleanup_runs_on_exit_and_signals(self) -> None:
        text = VERIFY.read_text()
        self.assertIn("trap cleanup_all EXIT", text)
        for sig in ("HUP", "INT", "TERM"):
            self.assertIn(f"' {sig}", text.replace("on_signal", "on_signal"),
                          f"缺少 {sig} 处理")

    def test_cleanup_removes_the_temp_dir(self) -> None:
        text = VERIFY.read_text()
        self.assertIn('rm -rf "$TMPDIR_VERIFY"', text)


class SecretHygieneTests(unittest.TestCase):
    """UUID 来自 0600 secret 文件，不得硬编码。"""

    def test_uuid_is_not_hardcoded(self) -> None:
        text = VERIFY.read_text()
        uuid_re = re.compile(
            r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
            r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
        self.assertEqual(uuid_re.findall(text), [],
                         "源码中不得出现字面 UUID")

    def test_secrets_file_is_owner_only(self) -> None:
        secret = CFST / "secrets" / "vless.env"
        if secret.exists():
            self.assertEqual(oct(secret.stat().st_mode)[-3:], "600")


if __name__ == "__main__":
    unittest.main()
