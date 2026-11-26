#!/usr/bin/env python3
"""Bind one cycle's planned audit to its persisted request observations."""
from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime
import hashlib
import json
from pathlib import Path
import re
from statistics import median, quantiles
import sys

from atomic_io import atomic_write
from ip_validation import is_valid_ipv4
from quality_evidence import (Batch, UNATTEMPTED, load_batches, parse_transfers,
                              shared_failure_blocks, store_batches)


@dataclass(frozen=True)
class Audit:
    requested: int
    returned: int
    guard: str
    reference: str = ""
    evidence: tuple[Batch, ...] = ()


def targets(ips):
    result = sorted(set(ips))
    if any(not is_valid_ipv4(ip) for ip in result):
        raise ValueError("invalid audit target")
    return result


def summarize(batches, ips, run, reference, started, now, *, percent=80,
              p10_ms=150, min_samples=10):
    planned = set(targets(ips))
    current = {}
    for batch in batches:
        if batch.run != run:
            continue
        if (batch.path != reference or batch.ip not in planned
                or not started <= batch.ts <= now
                or (batch.ip in current and current[batch.ip] != batch)):
            return Audit(len(planned), 0, "no_evidence")
        current[batch.ip] = batch
    if not current:
        return Audit(len(planned), 0, "no_evidence")

    returned = 0
    warm_medians = []
    for batch in current.values():
        if not any(request.state not in UNATTEMPTED for request in batch.requests):
            continue
        returned += 1
        warm = batch.requests[1:]
        if warm and all(request.state == "ok" for request in warm):
            warm_medians.append(median(request.ttfb for request in warm))

    if (len(warm_medians) >= max(2, min_samples)
            and quantiles(warm_medians, n=10, method="inclusive")[0] > p10_ms
            or shared_failure_blocks(current.values())):
        guard = "systemic"
    elif 100 * returned < len(planned) * percent:
        guard = "coverage"
    else:
        guard = "none"
    return Audit(len(planned), returned, guard, reference)


def digest(batches):
    rows = sorted((b.ip, b.ts.isoformat(), [[r.state, r.ttfb] for r in b.requests]) for b in batches)
    return hashlib.sha256(json.dumps(rows, separators=(",", ":")).encode()).hexdigest()


def bind(receipt, run, reference, ips):
    if not run or not re.fullmatch(r"[a-f0-9]{64}", reference):
        raise ValueError("invalid audit identity")
    plan = {"run": run, "reference": reference, "targets": targets(ips)}
    atomic_write(receipt, json.dumps(plan) + "\n")


def record(path, receipt, ips, run, reference, count, rows):
    planned = targets(ips)
    plan = {"run": run, "reference": reference, "targets": planned}
    try:
        bound = json.loads(receipt.read_text()) == plan
    except (OSError, ValueError):
        bound = False
    batches = []
    observed = set()
    for line in rows:
        ts, ip, raw = line.rstrip("\n").split("\t", 2)
        if ip not in planned or ip in observed:
            raise ValueError("unexpected or duplicate audit target")
        observed.add(ip)
        batches.append(Batch(datetime.fromisoformat(ts), run, reference, ip,
                             parse_transfers(raw.replace("|", "\n"), count)))
    now = datetime.now()
    previous = {b.ip: b for b in load_batches(path, now) if b.run == run}
    if previous and previous != {b.ip: b for b in batches}:
        raise ValueError("audit identity already owns different observations")
    store_batches(path, batches, now)
    if not bound:
        raise ValueError("audit plan missing or differs from probe input")
    atomic_write(receipt, json.dumps({**plan, "observations": digest(batches)}) + "\n")


def completed(path, receipt, ips, run, started, now, **policy):
    planned = targets(ips)
    missing = Audit(len(planned), 0, "no_evidence")
    try:
        entries = json.loads(receipt.read_text())
        ref = entries["reference"]
        if (entries["run"] != run or entries["targets"] != planned
                or not re.fullmatch(r"[a-f0-9]{64}", ref)):
            return missing
        batches = load_batches(path, now)
        current = [b for b in batches if b.run == run]
        result = summarize(current, planned, run, ref, started, now, **policy)
        if result.guard == "no_evidence":
            return missing
        evidence = tuple(b for b in batches if b.path == ref)
        if digest(current) != entries.get("observations"):
            return Audit(len(planned), 0, "no_evidence", ref, evidence)
        return Audit(result.requested, result.returned, result.guard, ref, evidence)
    except (OSError, ValueError, TypeError, KeyError):
        return missing


def main():
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    binder = commands.add_parser("bind")
    binder.add_argument("receipt", type=Path)
    binder.add_argument("run")
    binder.add_argument("reference")
    binder.add_argument("targets", nargs="+")
    writer = commands.add_parser("record")
    reader = commands.add_parser("facts")
    for command in (writer, reader):
        command.add_argument("observations", type=Path)
        command.add_argument("receipt", type=Path)
        command.add_argument("run")
    writer.add_argument("reference")
    writer.add_argument("count", type=int, choices=range(1, 33))
    writer.add_argument("targets", nargs="+")
    reader.add_argument("targets", type=Path)
    reader.add_argument("started_ns", type=int)
    reader.add_argument("percent", type=int)
    reader.add_argument("p10_ms", type=int)
    reader.add_argument("min_samples", type=int)
    args = parser.parse_args()
    if args.command == "bind":
        bind(args.receipt, args.run, args.reference, args.targets)
        return
    if args.command == "record":
        record(args.observations, args.receipt, args.targets, args.run,
               args.reference, args.count, sys.stdin)
        return
    # Probe timestamps currently have one-second resolution.
    started = datetime.fromtimestamp(args.started_ns // 10**9)
    result = completed(args.observations, args.receipt, args.targets.read_text().split(),
                       args.run, started, datetime.now(), percent=args.percent,
                       p10_ms=args.p10_ms, min_samples=args.min_samples)
    print(result.guard, result.requested, result.returned, result.reference or "-")


if __name__ == "__main__":
    main()
