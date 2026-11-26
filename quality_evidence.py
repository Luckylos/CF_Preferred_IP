"""Raw VLESS observations and time-specific engineering budgets."""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
import sys
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path

from atomic_io import atomic_write
from ip_validation import is_valid_ipv4


@dataclass(frozen=True)
class Request:
    state: str
    ttfb: float | None


@dataclass(frozen=True)
class Batch:
    ts: datetime
    run: str
    path: str
    ip: str
    requests: tuple[Request, ...]


@dataclass(frozen=True)
class Window:
    attempts: int = 0
    successes: int = 0
    fail: float | None = None
    tail: float | None = None
    heavy_tail: float | None = None
    median: float | None = None
    p90: float | None = None
    p95: float | None = None


@dataclass(frozen=True)
class Quality:
    state: str
    n_eff: float
    covered: frozenset[int]
    unresolved: int
    offpeak: Window
    peak: Window
    usable: tuple[Batch, ...]
    last_attempt: datetime | None = None


def reference_key(parts: list[str]) -> str:
    return hashlib.sha256(json.dumps([1, *parts], separators=(",", ":")).encode()).hexdigest()


def load_batches(path: Path, now: datetime, key: str | None = None) -> list[Batch]:
    batches = []
    try:
        handle = path.open(encoding="utf-8")
    except FileNotFoundError:
        return batches
    cutoff = now - timedelta(days=7)
    with handle:
        for line in handle:
            try:
                ts, run, ref, ip, requests = json.loads(line)
                when = datetime.fromisoformat(ts)
                if (not cutoff <= when <= now or not is_valid_ipv4(ip)
                        or not isinstance(run, str) or not re.fullmatch(r"[a-f0-9]{64}", ref)
                        or (key is not None and ref != key) or not 2 <= len(requests) <= 33):
                    continue
                parsed = []
                for state, ms in requests:
                    if not re.fullmatch(r"ok|not_started|xray_start_failed|unresolved|timeout|http_[0-9]{3}|curl_[0-9]+", state):
                        raise ValueError("invalid request state")
                    if ms is not None and (not math.isfinite(ms) or ms <= 0):
                        raise ValueError("invalid TTFB")
                    if state == "ok" and ms is None:
                        raise ValueError("missing successful TTFB")
                    parsed.append(Request(state, ms))
                batches.append(Batch(when, run, ref, ip, tuple(parsed)))
            except (TypeError, ValueError):
                continue
    return batches


def store_batches(path: Path, batches: list[Batch], now: datetime) -> None:
    cutoff = now - timedelta(days=7)
    retained = {(b.run, b.path, b.ip): b for b in load_batches(path, now) + batches
                if cutoff <= b.ts <= now}
    rows = (json.dumps([b.ts.isoformat(), b.run, b.path, b.ip,
                        [[r.state, r.ttfb] for r in b.requests]], separators=(",", ":"))
            for b in retained.values())
    atomic_write(path, "".join(row + "\n" for row in rows))


def phase(ts: datetime) -> int:
    return 0 if ts.hour < 20 else 1 if ts.hour < 22 else 2


def time_block(ts: datetime) -> datetime:
    return ts.replace(minute=ts.minute // 10 * 10, second=0, microsecond=0)


def parse_transfers(raw: str, warm_count: int) -> tuple[Request, ...]:
    requests = [Request("not_started", None)] * (warm_count + 1)
    if raw == "xray_start_failed":
        requests[0] = Request("xray_start_failed", None)
        return tuple(requests)
    for line in raw.splitlines():
        try:
            index, code, seconds, ret = line.split("\t")
            i, code, ret = int(index), int(code), int(ret)
            ms = float(seconds) * 1000
        except ValueError:
            continue
        if not 0 <= i <= warm_count:
            continue
        ttfb = ms if math.isfinite(ms) and ms > 0 else None
        if ret:
            state = "timeout" if ret == 28 else f"curl_{ret}"
        elif not 200 <= code < 300:
            state = f"http_{code}" if code else "unresolved"
        else:
            state = "ok" if ttfb is not None else "unresolved"
        requests[i] = Request(state, ttfb)
    return tuple(requests)


def _loss(warm: tuple[Request, ...], tail: int, heavy: int):
    attempted = [r for r in warm if r.state != "not_started"]
    values = [r.ttfb for r in attempted if r.state == "ok" and r.ttfb is not None]
    fail = 1 - len(values) / len(attempted) if attempted else None
    ratios = (fail, *(sum(ms > limit for ms in values) / len(values) if values else None
                      for limit in (tail, heavy)))
    return len(attempted), values, ratios


UNATTEMPTED = {"not_started", "xray_start_failed"}


def shared_failure_blocks(batches):
    attempts = defaultdict(list)
    for batch in batches:
        attempted = [r.state != "ok" for r in batch.requests if r.state not in UNATTEMPTED]
        if attempted:
            attempts[batch.path, batch.run, time_block(batch.ts)].append((batch.ip, attempted))
    return {key for key, rows in attempts.items()
            if len({ip for ip, _ in rows}) >= 5
            and 2 * sum(sum(failed) for _, failed in rows) >= sum(len(failed) for _, failed in rows)}


def assess(batches: list[Batch], ip: str, path: str, now: datetime) -> Quality:
    cutoff = now - timedelta(days=7)
    batches = list({(b.run, b.ip): b for b in batches if b.path == path and cutoff <= b.ts <= now}.values())
    healthy: dict[tuple[str, datetime], set[str]] = defaultdict(set)
    for b in batches:
        limits = (120, 200) if phase(b.ts) else (80, 150)
        _, _, ratios = _loss(b.requests[1:], *limits)
        if b.requests[0].state == "ok" and ratios == (0, 0, 0):
            healthy[b.run, time_block(b.ts)].add(b.ip)
    shared = shared_failure_blocks(batches)
    selected = [b for b in batches if b.ip == ip]
    valid: list[tuple[Batch, int, float, list[float], tuple]] = []
    unresolved = []
    connect_failures = []
    for b in selected:
        peak = bool(phase(b.ts))
        attempts, values, ratios = _loss(b.requests[1:], *((120, 200) if peak else (80, 150)))
        peers = healthy[b.run, time_block(b.ts)] - {ip}
        if (b.path, b.run, time_block(b.ts)) in shared:
            peers = set()
        first_state = b.requests[0].state
        if first_state not in {"ok", "not_started", "unresolved", "xray_start_failed"} and peers:
            connect_failures.append(b)
        if (first_state != "ok" or not attempts or any(r.state == "unresolved" for r in b.requests[1:])
                or (any(ratios) and not peers)):
            unresolved.append(b)
            continue
        weight = 2 ** (-(now - b.ts).total_seconds() / 86400)
        valid.append((b, attempts, weight, values, ratios))
    weight_by_block: dict[datetime, float] = {}
    for b, _, weight, _, _ in valid:
        block = time_block(b.ts)
        weight_by_block[block] = max(weight_by_block.get(block, 0), weight)
    n_eff = sum(weight_by_block.values())
    covered = frozenset(phase(b.ts) for b, *_ in valid if phase(b.ts) and now - b.ts <= timedelta(hours=48))
    recent = any(phase(b.ts) and now - b.ts < timedelta(hours=24) for b, *_ in valid)
    enough = n_eff >= 8 and len(weight_by_block) >= 8 and covered == {1, 2} and recent
    passes = True
    repeated = False
    windows = []
    for peak in (False, True):
        group = [row for row in valid if bool(phase(row[0].ts)) == peak]
        results = []
        for col, limit in enumerate((.01, .05, .01)):
            metrics = [(b, w, ratios[col]) for b, _, w, _, ratios in group if ratios[col] is not None]
            rate = (sum(w * x for _, w, x in metrics) / sum(w for _, w, _ in metrics)
                    if metrics else None)
            results.append(rate)
            if rate is None or rate > limit:
                passes = False
                repeated |= len({time_block(b.ts) for b, _, x in metrics if x > limit}) >= 2
        values = sorted(x for _, _, _, v, _ in group for x in v)
        quantiles = [values[math.ceil(q * len(values)) - 1] if values else None for q in (.5, .9, .95)]
        windows.append(Window(sum(n for _, n, *_ in group), len(values), *results, *quantiles))
    state = "pending"
    # Recovery does not relabel an earlier ambiguous request as successful.
    clean_blocks = {(bool(phase(b.ts)), time_block(b.ts)) for b, _, _, _, ratios in valid
                    if ratios == (0, 0, 0) and healthy[b.run, time_block(b.ts)] - {ip}}

    def recovered(b):
        return sum(peak == bool(phase(b.ts)) and block > time_block(b.ts)
                   for peak, block in clean_blocks) >= 2

    bad_connect_blocks = {time_block(b.ts) for b in connect_failures if not recovered(b)}
    if len(bad_connect_blocks) >= 2 or (enough and repeated):
        state = "ineligible"
    elif enough and passes and all(recovered(b) for b in unresolved):
        state = "eligible"
    last_attempt = max((b.ts for b in selected
                        if any(r.state not in {"not_started", "xray_start_failed"}
                               for r in b.requests)), default=None)
    return Quality(state, n_eff, covered, len(unresolved), *windows, tuple(b for b, *_ in valid), last_attempt)


def main() -> None:
    parser = argparse.ArgumentParser()
    subs = parser.add_subparsers(dest="command", required=True)
    subs.add_parser("reference")
    record = subs.add_parser("record")
    record.add_argument("path", type=Path)
    record.add_argument("key")
    record.add_argument("run")
    record.add_argument("warm_count", type=int, choices=range(1, 33))
    args = parser.parse_args()
    if args.command == "reference":
        print(reference_key(sys.stdin.read().split("\0")))
        return
    batches = []
    for line in sys.stdin:
        ts, ip, raw = line.rstrip("\n").split("\t", 2)
        if not is_valid_ipv4(ip):
            raise ValueError("invalid address in observation input")
        batches.append(Batch(datetime.fromisoformat(ts), args.run, args.key, ip,
                             parse_transfers(raw.replace("|", "\n"), args.warm_count)))
    if batches:
        store_batches(args.path, batches, datetime.now())


if __name__ == "__main__":
    main()
