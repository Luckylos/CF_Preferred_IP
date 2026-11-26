#!/usr/bin/env python3
"""周期事实和证据的单一解释处；不执行探测、排名或应用，不读取凭据。"""

from __future__ import annotations

from dataclasses import dataclass, asdict, fields
import argparse
import statistics
import sys
import json
import os
import re
import time
from datetime import datetime, timedelta
from pathlib import Path

from ip_validation import is_valid_ipv4
from atomic_io import atomic_write


GUARDS = {"none", "no_evidence", "systemic", "coverage"}


def _count(value: object, optional: bool = False) -> None:
    if optional and value is None:
        return
    if type(value) is not int or value < 0:
        raise ValueError("invalid nonnegative count")


@dataclass(frozen=True)
class AuditEvidence:
    requested: int | None
    returned: int | None
    audit_ok: bool
    systemic: bool
    percent: int
    minimum: int | None
    guard: str


def assess_audit(
    requested: int | None = None,
    returned: int | None = None,
    *,
    audit_ok: bool = True,
    systemic: bool = False,
    percent: int = 80,
    audit_path: Path | None = None,
) -> AuditEvidence:
    _count(requested, optional=True)
    _count(returned, optional=True)
    if type(audit_ok) is not bool or type(systemic) is not bool:
        raise ValueError("audit flags must be booleans")
    if type(percent) is not int or not 0 <= percent <= 100:
        raise ValueError("coverage percent must be 0..100")
    if audit_path is not None:
        if returned is not None:
            raise ValueError("provide audit rows or returned count, not both")
        in_block = False
        returned = 0
        for line in audit_path.read_text().splitlines():
            if line.startswith("=== AUDIT RESULTS"):
                in_block = True
                continue
            fields = line.split()
            if in_block and fields and is_valid_ipv4(fields[0]):
                returned += 1
    minimum = (requested * percent + 99) // 100 if requested is not None else None
    if not audit_ok:
        guard = "no_evidence"
    elif systemic:
        guard = "systemic"
    elif requested is not None and requested > 0 and returned is not None and returned < minimum:
        guard = "coverage"
    else:
        guard = "none"
    return AuditEvidence(requested, returned, audit_ok, systemic, percent, minimum, guard)


def _at(value: str) -> datetime:
    if type(value) is not str:
        raise ValueError("invalid timestamp")
    result = datetime.fromisoformat(value)
    if result.tzinfo is not None:
        raise ValueError("timestamps use the local log clock")
    return result


@dataclass(frozen=True)
class RankReceipt:
    at: str
    pool: int
    core: int
    challengers: int
    evicted: int
    published: list[str]
    changed: bool
    guard: str
    evaluated: int
    waiting: int
    quality_evicted: int
    capacity_evicted: int
    dry_run: bool = False

    def __post_init__(self):
        _at(self.at)
        for key in (
            "pool",
            "core",
            "challengers",
            "evicted",
            "evaluated",
            "waiting",
            "quality_evicted",
            "capacity_evicted",
        ):
            _count(getattr(self, key))
        if type(self.changed) is not bool or type(self.dry_run) is not bool or self.guard not in GUARDS:
            raise ValueError("invalid rank flags")
        if type(self.published) is not list or not all(
            type(ip) is str and is_valid_ipv4(ip) for ip in self.published
        ):
            raise ValueError("invalid publication")
        if (
            len(set(self.published)) != len(self.published)
            or self.pool != self.evaluated + self.waiting
            or self.evicted != self.quality_evicted + self.capacity_evicted
        ):
            raise ValueError("inconsistent rank counts")

    def data(self) -> dict:
        return dict(schema_version=1, kind="rank", **asdict(self))

    def write(self, path: Path) -> None:
        preflight_receipt(path, [])
        _receipt(self.data())
        atomic_write(path, json.dumps(self.data(), ensure_ascii=False, allow_nan=False) + "\n")

    def summary(self) -> str:
        return (
            f"rank: pool={self.pool} core={self.core} challengers={self.challengers} evicted={self.evicted} "
            f"published={','.join(self.published)} changed={int(self.changed)} guard={self.guard} "
            f"evaluated={self.evaluated} waiting={self.waiting} "
            f"quality_evicted={self.quality_evicted} capacity_evicted={self.capacity_evicted}"
        )


def _json_load(text: str):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON field")
            result[key] = value
        return result

    def reject_constant(value):
        raise ValueError("nonfinite JSON value")

    return json.loads(text, object_pairs_hook=unique, parse_constant=reject_constant)


def _receipt(data: dict) -> RankReceipt:
    keys = {f.name for f in fields(RankReceipt)}
    if (
        type(data) is not dict
        or set(data) != keys | {"schema_version", "kind"}
        or type(data["schema_version"]) is not int
        or data["schema_version"] != 1
        or data["kind"] != "rank"
    ):
        raise ValueError("unsupported or malformed rank receipt")
    return RankReceipt(**{k: data[k] for k in keys})


def read_rank_receipt(path: Path) -> RankReceipt:
    return _receipt(_json_load(path.read_text()))


def preflight_receipt(path: Path, inputs: list[Path]) -> None:
    if path.is_symlink() or path.is_dir():
        raise ValueError("invalid receipt output path")
    for other in inputs:
        if path.resolve() == other.resolve() or (path.exists() and other.exists() and path.samefile(other)):
            raise ValueError("receipt and state/input paths must be distinct")


@dataclass(frozen=True)
class CycleHandle:
    path: Path


_NAME = re.compile(r"cycle-([0-9]{20}-(?:slow|fast)-[0-9]+-[0-9]+)\.json\Z")
_STATES = {"open", "completed", "failed", "skipped"}
_APPLICATIONS = {"unknown", "confirmed", "not_required", "shadow_skipped", "unconfirmed", "failed"}
_WARNINGS = {"probe_failed", "screen_failed", "interrupted", "admission_unconfirmed"}
_KEYS = {
    "schema_version",
    "kind",
    "id",
    "mode",
    "shadow",
    "started_at",
    "ended_at",
    "state",
    "exit_code",
    "audit",
    "rank",
    "rank_status",
    "application",
    "screened",
    "admitted",
    "warnings",
    "push_evidence",
}


def _complete(data: dict) -> bool:
    return (
        data["state"] == "completed"
        and data["exit_code"] == 0
        and data["rank_status"] == "ok"
        and data["rank"] is not None
        and not data["rank"]["dry_run"]
        and data["application"] in ({"shadow_skipped"} if data["shadow"] else {"confirmed", "not_required"})
    )


def _read_cycle(path: Path) -> dict:
    match = _NAME.fullmatch(path.name)
    if not match or path.is_symlink() or path.stat().st_uid != os.getuid():
        raise ValueError("invalid cycle record path")
    data = _json_load(path.read_text())
    return _validate_cycle(data, match[1])


def _validate_cycle(data: dict, identity: str) -> dict:
    if (
        type(data) is not dict
        or set(data) != _KEYS
        or type(data["schema_version"]) is not int
        or data["schema_version"] != 1
        or data["kind"] != "cycle"
    ):
        raise ValueError("unsupported or malformed cycle record")
    if (
        data["id"] != identity
        or data["mode"] not in {"slow", "fast"}
        or data["mode"] != data["id"].split("-")[1]
        or type(data["shadow"]) is not bool
    ):
        raise ValueError("invalid cycle identity")
    if int(_at(data["started_at"]).timestamp() * 1_000_000_000) != int(identity.split("-")[0]):
        raise ValueError("record time and identity disagree")
    if data["push_evidence"] != "unknown":
        raise ValueError("push requires separately attributable evidence")
    if (
        data["state"] not in _STATES
        or data["rank_status"] not in {"ok", "failed", "skipped"}
        or data["application"] not in _APPLICATIONS
    ):
        raise ValueError("invalid cycle outcome")
    _count(data["screened"])
    _count(data["admitted"], optional=True)
    if type(data["warnings"]) is not list or not all(
        type(x) is str and x in _WARNINGS for x in data["warnings"]
    ):
        raise ValueError("invalid cycle warning")
    if data["audit"] is not None:
        audit = data["audit"]
        if type(audit) is not dict or set(audit) != {f.name for f in fields(AuditEvidence)}:
            raise ValueError("invalid audit evidence")
        expected = assess_audit(
            audit["requested"],
            audit["returned"],
            audit_ok=audit["audit_ok"],
            systemic=audit["systemic"],
            percent=audit["percent"],
        )
        if audit != asdict(expected):
            raise ValueError("inconsistent audit evidence")
    if data["rank"] is not None:
        _receipt(data["rank"])
    if data["state"] == "open":
        if data["ended_at"] is not None or data["exit_code"] is not None or data["rank"] is not None:
            raise ValueError("open record has a terminal result")
    else:
        _at(data["ended_at"])
        _count(data["exit_code"])
        if data["rank_status"] == "ok" and data["rank"] is None:
            raise ValueError("rank result missing")
        if data["state"] == "completed" and not _complete(data):
            raise ValueError("incomplete success")
        if data["state"] == "failed" and data["exit_code"] == 0:
            raise ValueError("failure requires nonzero exit")
        if data["state"] == "skipped" and (data["rank_status"] != "skipped" or data["exit_code"] != 0):
            raise ValueError("inconsistent skip")
    return data


def begin_cycle(store: Path, mode: str, *, shadow: bool = False, now: datetime | None = None) -> CycleHandle:
    if mode not in {"slow", "fast"} or type(shadow) is not bool or store.is_symlink() or "\n" in str(store):
        raise ValueError("invalid cycle destination or mode")
    at = now or datetime.now()
    identity = f"{int(at.timestamp() * 1_000_000_000):020d}-{mode}-{os.getpid()}-{time.monotonic_ns()}"
    store.mkdir(mode=0o700, parents=True, exist_ok=True)
    if store.stat().st_uid != os.getuid():
        raise ValueError("foreign record directory")
    path = store / f"cycle-{identity}.json"
    if not _NAME.fullmatch(path.name):
        raise ValueError("cycle timestamp outside supported range")
    if path.exists() or path.is_symlink():
        raise FileExistsError("cycle identity already exists")
    data = dict(
        schema_version=1,
        kind="cycle",
        id=identity,
        mode=mode,
        shadow=shadow,
        started_at=at.isoformat(),
        ended_at=None,
        state="open",
        exit_code=None,
        audit=None,
        rank=None,
        rank_status="skipped",
        application="unknown",
        screened=0,
        admitted=0,
        warnings=[],
        push_evidence="unknown",
    )
    _validate_cycle(data, identity)
    atomic_write(path, json.dumps(data, ensure_ascii=False, allow_nan=False) + "\n")
    return CycleHandle(path)


def finish_cycle(
    handle: CycleHandle,
    *,
    rank_status: str,
    application: str,
    exit_code: int,
    receipt: RankReceipt | None = None,
    audit: AuditEvidence | None = None,
    screened: int = 0,
    admitted: int | None = 0,
    warnings=(),
    now: datetime | None = None,
) -> dict:
    previous = _read_cycle(handle.path)
    data = dict(
        previous,
        rank_status=rank_status,
        application=application,
        exit_code=exit_code,
        rank=receipt.data() if receipt is not None else None,
        audit=asdict(audit) if audit is not None else None,
        screened=screened,
        admitted=admitted,
        warnings=list(warnings),
    )
    data["state"] = "failed" if exit_code else ("skipped" if rank_status == "skipped" else "completed")
    data["ended_at"] = previous["ended_at"] or (now or datetime.now()).isoformat()
    # Validate the same business constraints before replacing the durable open record.
    if data["state"] == "completed" and (receipt is None or receipt.dry_run or not _complete(data)):
        raise ValueError("cannot confirm completed cycle")
    _count(exit_code)
    _count(screened)
    _count(admitted, optional=True)
    if (
        rank_status not in {"ok", "failed", "skipped"}
        or application not in _APPLICATIONS
        or not all(w in _WARNINGS for w in warnings)
    ):
        raise ValueError("invalid cycle outcome")
    if rank_status == "ok" and receipt is None:
        raise ValueError("rank result missing")
    _validate_cycle(data, previous["id"])
    if previous["state"] != "open":
        if data != previous:
            raise ValueError("conflicting cycle finalization")
        return previous
    atomic_write(handle.path, json.dumps(data, ensure_ascii=False, allow_nan=False) + "\n")
    return data


def _scan(store: Path) -> tuple[list[dict], list[str]]:
    records, errors = [], []
    if store.is_symlink():
        return records, ["cycle records: ValueError"]
    if not store.exists():
        return records, errors
    try:
        if store.is_symlink():
            raise ValueError("symlink record directory")
        paths = list(store.iterdir())
    except (OSError, ValueError) as e:
        return records, [f"cycle records: {type(e).__name__}"]
    for path in paths:
        match = _NAME.fullmatch(path.name)
        if not match:
            continue
        try:
            data = _read_cycle(path)
        except (OSError, ValueError, TypeError, KeyError) as e:
            errors.append(f"{path.name}: {type(e).__name__}")
            data = dict(id=match[1], state="invalid", source=str(path))
        data["_path"] = str(path)
        records.append(data)
    return sorted(records, key=lambda d: d["id"], reverse=True), errors


def read_status(store: Path, *, now: datetime | None = None, legacy_paths=()) -> dict:
    now = now or datetime.now()
    records, errors = _scan(store)
    complete = next((r for r in records if r["state"] != "invalid" and _complete(r)), None)
    flow = dict(
        rounds=0, screened=0, admitted=0, evicted=0, quality_evicted=0, capacity_evicted=0, incomplete=False
    )
    cutoff = now - timedelta(days=7)
    for data in records:
        if data["state"] in {"invalid", "open"}:
            if datetime.fromtimestamp(int(data["id"].split("-")[0]) / 1_000_000_000) >= cutoff:
                flow["incomplete"] = True
            continue
        if _at(data["started_at"]) < cutoff:
            continue
        flow["rounds"] += 1
        flow["screened"] += data["screened"]
        if data["admitted"] is None:
            flow["incomplete"] = True
        else:
            flow["admitted"] += data["admitted"]
        if data["rank_status"] == "ok" and data["rank"] is not None:
            for key in ("evicted", "quality_evicted", "capacity_evicted"):
                flow[key] += data["rank"][key]
        elif data["rank_status"] == "failed":
            flow["incomplete"] = True
    legacy, last_push, legacy_errors = _legacy_observations(legacy_paths, {r["id"] for r in records}, cutoff)
    for key in ("rounds", "screened", "admitted", "evicted", "quality_evicted", "capacity_evicted"):
        flow[key] += legacy[key]
    flow["incomplete"] |= legacy["incomplete"] or bool(errors) or bool(legacy_errors)
    return dict(
        latest_attempt=records[0] if records else None,
        latest_complete=complete,
        errors=errors + legacy_errors,
        flow_7d=flow,
        last_push=last_push,
        records=records,
    )


def maintain_records(store: Path, *, now: datetime | None = None) -> None:
    now = now or datetime.now()
    if store.is_symlink() or (store.exists() and store.stat().st_uid != os.getuid()):
        raise ValueError("invalid maintenance directory")
    report = read_status(store, now=now)
    if not store.exists():
        return
    keep = {r["id"] for r in [report["latest_attempt"], report["latest_complete"]] if r is not None}
    for path in store.iterdir():
        if path.is_symlink() or not path.is_file() or path.stat().st_uid != os.getuid():
            continue
        match = _NAME.fullmatch(path.name)
        if match:
            stamp = datetime.fromtimestamp(int(match[1].split("-")[0]) / 1_000_000_000)
            if match[1] not in keep and stamp < now - timedelta(days=7):
                path.unlink()
        elif (
            path.name.startswith(".cycle-")
            and ".json." in path.name
            and path.stat().st_mtime < now.timestamp() - 180 * 60
        ):
            path.unlink()


TS_FMT = "%Y-%m-%d %H:%M:%S"
IP_RE = r"(?:\d{1,3}\.){3}\d{1,3}"


def parse_round(text: str) -> dict:
    """解析一轮 cycle.sh slow 日志：池审计分布、audit evidence、rank 摘要、快筛、发布。"""
    audit_part = text.split("audit evidence:")[0]
    meds = [int(x) for x in re.findall(r"PASS \(median=(\d+)ms\)", audit_part)]
    per_ip = {
        m.group(1): int(m.group(2))
        for m in re.finditer(rf"verify_vless: ({IP_RE}) PASS \(median=(\d+)ms\)", audit_part)
    }
    out: dict = {"audit_ttfb": per_ip}
    if meds:
        s = sorted(meds)
        out["ttfb_p50"] = statistics.median(s)
        out["ttfb_p90"] = s[min(len(s) - 1, int(len(s) * 0.9))]
        out["ttfb_max"] = s[-1]
    m = re.search(r"verify_vless: (\d+)/(\d+) IPs passed, (\d+) failed", audit_part)
    out["unreachable"] = int(m.group(3)) if m else 0
    m = re.search(r"audit evidence: returned=(\d+)/(\d+) .*audit_ok=([01]) systemic=([01]) guard=(\S+)", text)
    if m:
        out.update(
            returned=int(m.group(1)), requested=int(m.group(2)), audit_ok=m.group(3) == "1", guard=m.group(5)
        )
    out["systemic"] = "systemic guard: systemic" in text
    rank = None
    for line in text.splitlines():
        rank = parse_rank_line(line) or rank
    if rank:
        out.update(pool=rank["pool"], evicted=rank["evicted"])
    m = re.search(r"discovery screen: candidates=(\d+)", text)
    out["screened"] = int(m.group(1)) if m else 0
    m = re.search(r"discovery screen: screen_pass=(\d+)", text)
    out["screen_pass"] = int(m.group(1)) if m else 0
    out["pool_full"] = "discovery screen skipped: pool full" in text
    m = re.search(rf"apply: pushed \d+ IPs -> ((?:{IP_RE}\s*)+)", text)
    out["pushed"] = m.group(1).split() if m else []
    return out


def _ts_of(line: str) -> datetime | None:
    m = re.match(r"\[(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)\]", line)
    return datetime.strptime(m.group(1), TS_FMT) if m else None


def parse_rank_line(line: str) -> dict | None:
    """解析 rank.py 摘要行（契约见模块 docstring）；非 rank 行返回 None。"""
    m = re.search(
        r"rank: pool=(\d+) core=(\d+) challengers=(\d+) evicted=(\d+) published=(\S*) changed=([01]) guard=(\S+)",
        line,
    )
    if not m:
        return None
    parsed = {
        "pool": int(m.group(1)),
        "core": int(m.group(2)),
        "challengers": int(m.group(3)),
        "evicted": int(m.group(4)),
        "published": re.findall(IP_RE, m.group(5)),
        "changed": m.group(6) == "1",
        "guard": m.group(7),
    }
    for key in ("evaluated", "waiting", "quality_evicted", "capacity_evicted"):
        extra = re.search(rf"\b{key}=(\d+)", line)
        if extra:
            parsed[key] = int(extra.group(1))
    return parsed


def parse_cycle_line(line: str) -> dict | None:
    """解析 cycle.sh 行 `cycle: mode=... guard=... rank=...`，键值对顺序不敏感。"""
    m = re.search(r"cycle: ((?:\w+=\S+\s*)+)", line)
    if not m:
        return None
    return dict(kv.split("=", 1) for kv in m.group(1).split())


def _last_tagged(path: Path, parser) -> tuple[datetime | None, dict | None]:
    """文件中最后一条能被 parser 解析的行及其时间戳。"""
    if not path.exists():
        return None, None
    for raw in reversed(path.read_text(encoding="utf-8", errors="replace").splitlines()):
        d = parser(raw)
        if d is not None:
            return _ts_of(raw), d
    return None, None


def collect_contender(results: Path, latest_slow: Path | None, now: datetime) -> dict | None:
    """汇总 fast.log 与最近一轮 slow 日志的 rank/cycle 行；两者都没有 rank 行时返回 None（未启用）。"""
    fast = results / "fast.log"
    cands = []
    for p in (fast, latest_slow):
        if p is None:
            continue
        ts, r = _last_tagged(p, parse_rank_line)
        if r is not None:
            cands.append((ts or datetime.min, r, p))
    if not cands:
        return None
    ts, r, src = max(cands, key=lambda c: c[0])
    fast_ts = None
    for parser in (parse_rank_line, parse_cycle_line):
        t, d = _last_tagged(fast, parser)
        if d is not None and t is not None and (fast_ts is None or t > fast_ts):
            fast_ts = t
    cycle_ts, cycle = _last_tagged(fast, parse_cycle_line)
    if latest_slow is not None:
        t2, c2 = _last_tagged(latest_slow, parse_cycle_line)
        if c2 is not None and (cycle is None or (t2 or datetime.min) > (cycle_ts or datetime.min)):
            cycle = c2
    return {
        **r,
        "at": ts.strftime(TS_FMT) if ts else None,
        "source": src.name,
        "fast_age_min": int((now - fast_ts).total_seconds() // 60) if fast_ts else None,
        "last_cycle": cycle,
    }


def last_match(paths: list[Path], pattern: str) -> tuple[datetime | None, str]:
    """跨 cron.log 轮转文件找最后一条匹配，返回 (时间, 行)。"""
    rx = re.compile(pattern)
    for p in paths:  # 调用方按新→旧传入
        if not p.exists():
            continue
        for raw in reversed(p.read_text(encoding="utf-8", errors="replace").splitlines()):
            if rx.search(raw):
                m = re.match(r"\[(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)\]", raw)
                return (datetime.strptime(m.group(1), TS_FMT) if m else None), raw
    return None, ""


def _legacy_observations(paths, covered_ids: set[str], cutoff: datetime):
    flow = dict(
        rounds=0, screened=0, admitted=0, evicted=0, quality_evicted=0, capacity_evicted=0, incomplete=False
    )
    push, errors = None, []
    for path in dict.fromkeys(paths):
        try:
            if path.is_symlink():
                raise ValueError("symlink log source")
            text = path.read_text(encoding="utf-8", errors="replace")
            for line in text.splitlines():
                match = re.search(rf"apply: pushed (\d+) IPs -> ((?:{IP_RE}[ \t]*)+)$", line)
                if match:
                    stamp = _ts_of(line)
                    ips = match[2].split()
                    if (
                        stamp is not None
                        and int(match[1]) == len(ips) == len(set(ips))
                        and all(is_valid_ipv4(ip) for ip in ips)
                    ):
                        entry = dict(at=stamp.strftime(TS_FMT), ips=ips, source=path.name)
                        if push is None or (entry["at"], entry["source"]) > (push["at"], push["source"]):
                            push = entry
            # 旧slow一文件一轮；新slow用明确ID去重。旧fast没有可靠准入轮次，不补造。
            if not re.fullmatch(r"20\d{6}_\d{6}\.log", path.name):
                continue
            if datetime.strptime(path.stem, "%Y%m%d_%H%M%S") < cutoff:
                continue
            ids = set(re.findall(r"cycle-record: id=(\S+)", text))
            if ids & covered_ids:
                continue
            flow["rounds"] += 1
            values = parse_round(text)
            if "pool" not in values:
                continue
            flow["screened"] += values.get("screened", 0)
            flow["admitted"] += values.get("screen_pass", 0)
            flow["evicted"] += values.get("evicted", 0)
            ranks = [v for line in text.splitlines() if (v := parse_rank_line(line)) is not None]
            if ranks:
                r = ranks[-1]
                for key in ("quality_evicted", "capacity_evicted"):
                    if key in r:
                        flow[key] += r[key]
                if r["evicted"] and "quality_evicted" not in r:
                    flow["incomplete"] = True
        except (OSError, ValueError, TypeError) as e:
            errors.append(f"legacy {path.name}: {type(e).__name__}")
    return flow, push, errors


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    begin = sub.add_parser("begin")
    begin.add_argument("--store", type=Path, required=True)
    begin.add_argument("--mode", choices=["slow", "fast"], required=True)
    begin.add_argument("--shadow", action="store_true")
    audit = sub.add_parser("audit")
    audit.add_argument("--path", type=Path, required=True)
    audit.add_argument("--requested", type=int, required=True)
    audit.add_argument("--ok", type=int, choices=[0, 1], required=True)
    audit.add_argument("--systemic", type=int, choices=[0, 1], required=True)
    audit.add_argument("--percent", type=int, default=80)
    rank = sub.add_parser("receipt")
    rank.add_argument("--path", type=Path, required=True)
    field = rank.add_mutually_exclusive_group()
    field.add_argument("--published", action="store_true")
    field.add_argument("--guard", action="store_true")
    finish = sub.add_parser("finish")
    finish.add_argument("--record", type=Path, required=True)
    finish.add_argument("--rank-receipt", type=Path)
    finish.add_argument("--rank-status", choices=["ok", "failed", "skipped"], required=True)
    finish.add_argument("--application", choices=sorted(_APPLICATIONS), required=True)
    finish.add_argument("--exit-code", type=int, required=True)
    finish.add_argument("--screened", type=int, default=0)
    finish.add_argument("--admitted", type=int, default=0)
    finish.add_argument("--warning", choices=sorted(_WARNINGS), action="append", default=[])
    finish.add_argument("--requested", type=int)
    finish.add_argument("--returned", type=int)
    finish.add_argument("--audit-ok", type=int, choices=[0, 1])
    finish.add_argument("--systemic", type=int, choices=[0, 1], default=0)
    finish.add_argument("--percent", type=int, default=80)
    args = parser.parse_args(argv)
    if args.action == "begin":
        handle = begin_cycle(args.store, args.mode, shadow=args.shadow)
        maintain_records(args.store)
        print(handle.path)
        print(handle.path.stem.removeprefix("cycle-"))
    elif args.action == "audit":
        e = assess_audit(
            args.requested,
            audit_ok=bool(args.ok),
            systemic=bool(args.systemic),
            percent=args.percent,
            audit_path=args.path,
        )
        print(e.returned, e.minimum, e.guard)
    elif args.action == "receipt":
        value = read_rank_receipt(args.path)
        if args.published:
            print(" ".join(value.published))
        elif args.guard:
            print(value.guard)
        else:
            print(value.summary())
    else:
        r = (
            read_rank_receipt(args.rank_receipt)
            if args.rank_status == "ok" and args.rank_receipt is not None
            else None
        )
        e = (
            assess_audit(
                args.requested,
                args.returned,
                audit_ok=bool(args.audit_ok),
                systemic=bool(args.systemic),
                percent=args.percent,
            )
            if args.audit_ok is not None
            else None
        )
        finish_cycle(
            CycleHandle(args.record),
            rank_status=args.rank_status,
            application=args.application,
            exit_code=args.exit_code,
            receipt=r,
            audit=e,
            screened=args.screened,
            admitted=None if args.admitted == -1 else args.admitted,
            warnings=args.warning,
        )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, TypeError, KeyError) as error:
        # 只报告类别与阶段，避免将原始输入/异常内容写进日志。
        print(
            f"cycle-result-error: stage={sys.argv[1] if len(sys.argv) > 1 else 'arguments'} category={type(error).__name__}",
            file=sys.stderr,
        )
        raise SystemExit(1)
