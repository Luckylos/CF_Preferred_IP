"""共享原子写 helper 的 owner 契约与行为回归。

背景（历史）：pool.py 与 probation_pool.py 曾各自定义了一份字节级完全相同的
atomic_write（mkstemp → fdopen → flush → fsync → os.replace，异常时清理
临时文件并原样传播）。两份实现漂移会让崩溃安全语义在其中一处被静默改坏。
本文件先以 owner identity 探针固定「两处必须是同一实现」，再冻结该实现的
用户可观察行为：成功落盘、os.replace 失败时旧字节保留且不留临时文件。

所有断言只使用临时 sandbox，不访问网络，也不修改 /opt/cfst 运行态文件。
"""
from __future__ import annotations

import os
import sys
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def test_shared_atomic_write_owner() -> None:
    """Given 所有状态写入方（rank.py 等）, Then 它们的 atomic_write 必须是 atomic_io 的同一函数对象。

    2026-10-15 Task 10 之前这里对比 pool.py / probation_pool.py；两者随旧链路删除，
    现在由 rank.py 承担状态写入，契约不变：禁止各自复制一份实现。
    """
    import atomic_io
    import rank
    import admission
    import cooldown

    assert admission.atomic_write is atomic_io.atomic_write
    assert cooldown.atomic_write is atomic_io.atomic_write
    assert rank.atomic_write is atomic_io.atomic_write, (
        "rank.atomic_write 必须复用 atomic_io.atomic_write，否则崩溃安全语义会漂移"
    )


def test_atomic_write_persists_text(tmp_path: Path) -> None:
    """Given 目标路径, When atomic_write 写入文本, Then 内容原样落盘。"""
    import atomic_io

    target = tmp_path / "state.tsv"
    atomic_io.atomic_write(target, "line-1\nline-2\n")

    assert target.read_text(encoding="utf-8") == "line-1\nline-2\n"
    # 落盘后不得残留同前缀临时文件。
    leftovers = [p.name for p in tmp_path.iterdir() if p.name != "state.tsv"]
    assert leftovers == [], f"意外残留临时文件: {leftovers}"


def test_atomic_write_preserves_old_bytes_on_replace_failure(tmp_path: Path) -> None:
    """Given 已有旧内容, When os.replace 失败, Then 旧字节保留且不留临时文件。"""
    import atomic_io

    target = tmp_path / "state.tsv"
    target.write_text("OLD\n", encoding="utf-8")

    def boom(source: str | os.PathLike[str], destination: str | os.PathLike[str]) -> None:
        raise OSError("simulated replace failure")

    with patch.object(atomic_io.os, "replace", side_effect=boom):
        try:
            atomic_io.atomic_write(target, "NEW\n")
        except OSError as exc:
            assert "simulated replace failure" in str(exc)
        else:
            raise AssertionError("atomic_write 必须把 os.replace 的失败原样抛出")

    assert target.read_text(encoding="utf-8") == "OLD\n", "写入失败必须保留旧字节"
    leftovers = [p.name for p in tmp_path.iterdir() if p.name != "state.tsv"]
    assert leftovers == [], f"失败路径必须清理临时文件, 残留: {leftovers}"
