#!/usr/bin/env python3
"""原子写入的单一真相源。

崩溃安全契约：同目录 mkstemp → 写入 → flush → fsync → os.replace 原子替换；
任何异常都清理临时文件并原样传播（不吞异常、不改 mode 语义）。同一份实现
被 rank.py 等所有状态写入方复用，避免多处各自维护导致语义漂移。
"""
from __future__ import annotations

import os
import tempfile
from pathlib import Path


def atomic_write(path: Path, text: str) -> None:
    fd, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent, text=True)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(name, path)
    except BaseException:
        try:
            os.unlink(name)
        except FileNotFoundError:
            pass
        raise
