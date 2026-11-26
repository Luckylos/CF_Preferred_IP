"""发布 = 单个域名的一组 A 记录；所有外部写入都可通过注入的 transport 观察。"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

SPEC = importlib.util.spec_from_file_location(
    "dns_publish_contract", Path(__file__).resolve().parents[1] / "dns_publish.py"
)
assert SPEC and SPEC.loader
dns = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = dns
SPEC.loader.exec_module(dns)

ZONE = "zone-1"
NAME = "preferred.example.com"
OLD = ["198.51.100.1", "198.51.100.2", "198.51.100.3"]
NEW = ["203.0.113.7", "203.0.113.8", "203.0.113.9"]


class FakeCloudflare:
    """Cloudflare DNS API 的最小子集：只保留 reconcile 真正依赖的语义。"""

    def __init__(self, records: list[dict[str, object]] | None = None) -> None:
        self.records = {str(r["id"]): dict(r) for r in records or []}
        self.calls: list[tuple[str, str]] = []
        self.fail_on: str | None = None
        self.created = 0

    def request(self, method: str, path: str, body: dict[str, object] | None = None):
        self.calls.append((method, path))
        if self.fail_on and self.fail_on in f"{method} {path}":
            raise RuntimeError("cloudflare unavailable")
        if method == "GET" and path.startswith("/zones/"):
            return {"success": True, "result": [dict(r) for r in self.records.values()]}
        if method == "POST":
            self.created += 1
            record = {"id": f"rec-{self.created}", "proxied": False,
                      "ttl": 60, **dict(body or {})}
            self.records[str(record["id"])] = record
            return {"success": True, "result": dict(record)}
        if method == "PATCH":
            record_id = path.rsplit("/", 1)[-1]
            self.records[record_id].update(dict(body or {}))
            return {"success": True, "result": dict(self.records[record_id])}
        if method == "DELETE":
            self.records.pop(path.rsplit("/", 1)[-1], None)
            return {"success": True, "result": {"id": "deleted"}}
        raise AssertionError(f"unexpected {method} {path}")

    def writes(self) -> list[tuple[str, str]]:
        return [c for c in self.calls if c[0] != "GET"]


def record(index: int, content: str, *, proxied: bool = False, ttl: int = 60) -> dict[str, object]:
    return {"id": f"old-{index}", "type": "A", "name": NAME, "content": content,
            "proxied": proxied, "ttl": ttl}


def resolver(value: list[str] | Exception):
    def resolve(name: str) -> list[str]:
        assert name == NAME
        if isinstance(value, Exception):
            raise value
        return list(value)
    return resolve


def reconcile(cloud: FakeCloudflare, desired: list[str], *, resolve=None, **kwargs):
    kwargs.setdefault("sleep", lambda seconds: None)
    return dns.reconcile(zone_id=ZONE, name=NAME, desired=desired, request=cloud.request,
                         resolve=resolve or resolver(desired), **kwargs)


def test_unchanged_set_performs_no_writes() -> None:
    cloud = FakeCloudflare([record(i, ip) for i, ip in enumerate(OLD, 1)])
    receipt = reconcile(cloud, OLD)
    assert receipt.changed is False and cloud.writes() == []


def test_changed_set_replaces_the_addresses_without_an_empty_window() -> None:
    cloud = FakeCloudflare([record(i, ip) for i, ip in enumerate(OLD, 1)])
    receipt = reconcile(cloud, NEW)
    assert receipt.changed is True
    assert receipt.previous == sorted(OLD)
    assert sorted(r["content"] for r in cloud.records.values()) == sorted(NEW)
    assert all(r["proxied"] is False and r["ttl"] == 60 for r in cloud.records.values())
    deletes = [c for c in cloud.calls if c[0] == "DELETE"]
    assert deletes and cloud.calls.index(("POST", "/zones/zone-1/dns_records")) < cloud.calls.index(deletes[0])


def test_overlapping_addresses_are_kept_not_recreated() -> None:
    cloud = FakeCloudflare([record(i, ip) for i, ip in enumerate(OLD, 1)])
    reconcile(cloud, [OLD[0], NEW[0], NEW[1]])
    contents = sorted(r["content"] for r in cloud.records.values())
    assert contents == sorted([OLD[0], NEW[0], NEW[1]])
    assert not any(c[0] == "DELETE" and c[1].endswith("old-1") for c in cloud.calls)


def test_proxied_record_is_forced_to_dns_only() -> None:
    cloud = FakeCloudflare([record(1, OLD[0], proxied=True, ttl=1)])
    reconcile(cloud, [OLD[0]])
    (row,) = cloud.records.values()
    assert row["proxied"] is False and row["ttl"] == 60


def test_rejected_resolution_restores_the_previous_set() -> None:
    cloud = FakeCloudflare([record(i, ip) for i, ip in enumerate(OLD, 1)])
    with pytest.raises(RuntimeError, match="did not resolve"):
        reconcile(cloud, NEW, resolve=resolver(OLD))
    assert sorted(r["content"] for r in cloud.records.values()) == sorted(OLD)
    assert not any(c[0] == "DELETE" and c[1].endswith("old-1") for c in cloud.calls)


def test_resolver_failure_is_not_treated_as_success() -> None:
    cloud = FakeCloudflare([record(i, ip) for i, ip in enumerate(OLD, 1)])
    with pytest.raises(RuntimeError, match="could not verify"):
        reconcile(cloud, NEW, resolve=resolver(OSError("dns down")))
    assert sorted(r["content"] for r in cloud.records.values()) == sorted(OLD)


def test_upstream_failure_leaves_the_previous_set_serving() -> None:
    cloud = FakeCloudflare([record(i, ip) for i, ip in enumerate(OLD, 1)])
    cloud.fail_on = "POST"
    with pytest.raises(RuntimeError):
        reconcile(cloud, NEW)
    assert sorted(r["content"] for r in cloud.records.values()) == sorted(OLD)


def test_empty_or_invalid_desired_refuses_before_any_call() -> None:
    cloud = FakeCloudflare()
    with pytest.raises(ValueError):
        reconcile(cloud, [])
    with pytest.raises(ValueError):
        reconcile(cloud, ["not-an-ip"])
    with pytest.raises(ValueError):
        reconcile(cloud, [NEW[0], NEW[0]])
    assert cloud.calls == []


def test_propagation_delay_is_awaited_instead_of_rolled_back() -> None:
    cloud = FakeCloudflare([record(i, ip) for i, ip in enumerate(OLD, 1)])
    answers = [[], [], NEW]

    def resolve(name: str) -> list[str]:
        return answers.pop(0) if answers else list(NEW)

    receipt = reconcile(cloud, NEW, resolve=resolve)
    assert receipt.changed is True
    assert sorted(r["content"] for r in cloud.records.values()) == sorted(NEW)
    assert all(not rid.startswith("old-") for rid in cloud.records)


def test_never_observing_the_new_set_still_rolls_back() -> None:
    cloud = FakeCloudflare([record(i, ip) for i, ip in enumerate(OLD, 1)])
    with pytest.raises(RuntimeError, match="did not resolve"):
        reconcile(cloud, NEW, resolve=lambda name: OLD, attempts=3)
    assert sorted(r["content"] for r in cloud.records.values()) == sorted(OLD)


def live_resolver(cloud: FakeCloudflare, *, stale: list[str] | None = None):
    """DoH 读的是"现网实际记录"，不是写入意图；stale 模拟删除尚未传播。"""
    def resolve(name: str) -> list[str]:
        assert name == NAME
        contents = {str(r["content"]) for r in cloud.records.values() if r.get("name") == NAME}
        return sorted(contents | set(stale or []))
    return resolve


def test_stale_extra_record_does_not_block_publication() -> None:
    """期望 3 条、实到 4 条（多一条旧记录）时，校验必须先放行再删除，而不是判失败。"""
    cloud = FakeCloudflare([record(1, NEW[0]), record(2, OLD[0]), record(3, OLD[1])])
    receipt = reconcile(cloud, NEW, resolve=live_resolver(cloud))
    assert receipt.changed is True
    assert sorted(r["content"] for r in cloud.records.values()) == sorted(NEW)


def test_delete_propagation_failure_restores_the_previous_set() -> None:
    cloud = FakeCloudflare([record(1, NEW[0]), record(2, OLD[0])])
    with pytest.raises(RuntimeError, match="did not resolve"):
        reconcile(cloud, NEW, resolve=live_resolver(cloud, stale=[OLD[0]]))
    assert sorted(r["content"] for r in cloud.records.values()) == sorted([NEW[0], OLD[0]])


def test_dry_run_reports_the_plan_without_writing() -> None:
    cloud = FakeCloudflare([record(i, ip) for i, ip in enumerate(OLD, 1)])
    receipt = reconcile(cloud, NEW, dry_run=True)
    assert receipt.changed is True and receipt.dry_run is True
    assert cloud.writes() == []
    assert sorted(r["content"] for r in cloud.records.values()) == sorted(OLD)


def test_desired_addresses_are_published_in_a_stable_order() -> None:
    cloud = FakeCloudflare()
    receipt = reconcile(cloud, [NEW[2], NEW[0], NEW[1]])
    assert receipt.applied == sorted(NEW)
    assert sorted(c["content"] for c in cloud.records.values()) == sorted(NEW)
