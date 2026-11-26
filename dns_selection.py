"""Select a DNS address independently of MiSub member order."""
from __future__ import annotations

import json
import re
import sys
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path

from atomic_io import atomic_write
from ip_validation import is_valid_ipv4


@dataclass(frozen=True)
class Choice:
    active: str
    challenger: str = ""
    last_batch: str = ""
    reference: str = ""


def read(path: Path, default: str) -> Choice:
    try:
        candidate = Choice(**json.loads(path.read_text(encoding="utf-8")))
        if (is_valid_ipv4(candidate.active) and isinstance(candidate.last_batch, str)
                and (candidate.challenger == "" or is_valid_ipv4(candidate.challenger))):
            return candidate
    except (FileNotFoundError, TypeError, ValueError):
        pass
    return Choice(default)


def write(path: Path, choice: Choice) -> None:
    atomic_write(path, json.dumps(asdict(choice)) + "\n")


def batch_order(identity: str) -> str:
    prefix, separator, suffix = identity.partition("-")
    if separator and prefix.isdecimal():
        return f"{int(prefix):020d}-{suffix}"
    return identity


def choose(previous: Choice, published: list[str], eligible: set[str], rejected: set[str],
           ranked: list[str], batch: str) -> Choice:
    if not batch or batch_order(batch) <= batch_order(previous.last_batch):
        return previous
    safe = set(published) & eligible
    winner = next((ip for ip in ranked if ip in safe), "")
    if not winner or winner == previous.active:
        return Choice(previous.active, last_batch=batch)
    if (previous.active in rejected or previous.active not in published
            or previous.challenger == winner):
        return Choice(winner, last_batch=batch)
    return Choice(previous.active, winner, batch)


def current_batch(value: str, started_ns: int | None, now: datetime) -> str:
    if started_ns is None or not re.fullmatch(r"[0-9]{19}-[0-9]+", value):
        return ""
    ts = int(value.split("-", 1)[0])
    return value if started_ns <= ts < (int(now.timestamp()) + 1) * 10**9 else ""


if __name__ == "__main__":
    print(read(Path(sys.argv[1]), "").active)
