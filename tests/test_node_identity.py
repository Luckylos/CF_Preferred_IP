"""节点身份归 MiSub：发布时只换地址，凭据/参数/显示名原样保留。"""
from __future__ import annotations

import importlib.util
import sys
import urllib.parse
from pathlib import Path

import pytest

SPEC = importlib.util.spec_from_file_location(
    "push_identity", Path(__file__).resolve().parents[1] / "push_to_misub.py"
)
assert SPEC and SPEC.loader
push = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = push
SPEC.loader.exec_module(push)

OLD_IP = "198.51.100.1"
NEW_IP = "203.0.113.7"
HT_UUID = "00000000-0000-4000-8000-000000000003"
HK_UUID = "00000000-0000-4000-8000-000000000004"
QUERY = "encryption=none&security=tls&sni=ht-relay.example.com&type=xhttp&path=%2Fargo&mode=auto"


def node(name: str, uuid: str, host: str = OLD_IP, query: str = QUERY) -> "push.ManagedNode":
    url = f"vless://{uuid}@{host}:443?{query}#{urllib.parse.quote(name)}"
    return push.ManagedNode(id=f"id-{name}", name=name, url=url)


def test_region_connection_reads_the_credential_from_the_node() -> None:
    region = next(r for r in push.REGIONS if r["key"] == "HT")
    managed = {f"{region['prefix']} CM": node("🇭🇰 HT Example CM", HT_UUID)}
    query, uuid = push.region_connection(region, managed)
    assert uuid == HT_UUID and query == QUERY


def test_region_connection_reports_absence_so_templates_can_bootstrap() -> None:
    """一个节点都没有时返回 None，让新建节点走模板兜底（而不是整条流水线中断）。"""
    region = next(r for r in push.REGIONS if r["key"] == "HT")
    assert push.region_connection(region, {}) is None


def test_desired_urls_preserve_each_regions_own_credential(monkeypatch) -> None:
    """回归：过去用一个全局 uuid 重建所有节点，会把 HT 的正确凭据覆盖掉。"""
    ips = [NEW_IP, "203.0.113.8", "203.0.113.9"]
    monkeypatch.setattr(push, "read_best_ips", lambda: ips)
    monkeypatch.setattr(push, "run_region_preflight", lambda *a, **k: None)
    managed = {}
    for region in push.REGIONS:
        uuid = HT_UUID if region["key"] == "HT" else HK_UUID
        for suffix in push.SUFFIXES:
            name = f"{region['prefix']} {suffix}"
            managed[name] = node(name, uuid)

    desired = push._prepare_desired_urls(managed)
    assert set(desired) == set(managed)
    for name, url in desired.items():
        region = next(r for r in push.REGIONS if name.startswith(r["prefix"]))
        expected_uuid = HT_UUID if region["key"] == "HT" else HK_UUID
        parts = urllib.parse.urlsplit(url)
        assert parts.username == expected_uuid, name
        assert parts.hostname in ips, name


def test_desired_urls_change_only_the_address(monkeypatch) -> None:
    """节点上的一切（凭据/传输参数/显示名）都属于 MiSub；CFST 只替换地址。"""
    ips = [NEW_IP, "203.0.113.8", "203.0.113.9"]
    monkeypatch.setattr(push, "read_best_ips", lambda: ips)
    monkeypatch.setattr(push, "run_region_preflight", lambda *a, **k: None)
    custom = "type=ws&sni=node-own.example.com&path=%2Fkeep&ed=2560"
    managed = {}
    for region in push.REGIONS:
        uuid = HT_UUID if region["key"] == "HT" else HK_UUID
        for suffix in push.SUFFIXES:
            name = f"{region['prefix']} {suffix}"
            managed[name] = node(name, uuid, query=custom)

    desired = push._prepare_desired_urls(managed)
    for name, url in desired.items():
        parts = urllib.parse.urlsplit(url)
        original = urllib.parse.urlsplit(managed[name].url)
        assert parts.query == custom, name
        assert parts.fragment == original.fragment, name
        assert parts.username == original.username, name
        assert parts.hostname in ips, name


def test_preflight_uses_the_template_entry_with_the_node_credential(monkeypatch) -> None:
    """迁入口时验证的是目标入口；凭据仍取节点自己的那个 uuid。"""
    ips = [NEW_IP, "203.0.113.8", "203.0.113.9"]
    monkeypatch.setattr(push, "read_best_ips", lambda: ips)
    seen = []

    def fake_preflight(region, candidates, *, query=None, uuid=None):
        seen.append((region["key"], query, uuid))

    monkeypatch.setattr(push, "run_region_preflight", fake_preflight)
    managed = {}
    for region in push.REGIONS:
        uuid = HT_UUID if region["key"] == "HT" else HK_UUID
        for suffix in push.SUFFIXES:
            name = f"{region['prefix']} {suffix}"
            managed[name] = node(name, uuid, query="type=ws&sni=stale.example.com")
    push._prepare_desired_urls(managed)

    assert [entry[0] for entry in seen] == [r["key"] for r in push.REGIONS]
    for key, query, uuid in seen:
        region = next(r for r in push.REGIONS if r["key"] == key)
        assert query == region["query"], key
        assert uuid == (HT_UUID if key == "HT" else HK_UUID), key


def test_swap_address_refuses_a_url_without_credentials() -> None:
    with pytest.raises(RuntimeError):
        push.swap_address("https://example.com/", NEW_IP)
    with pytest.raises(RuntimeError):
        push.swap_address("vless://example.com:443?x=1", NEW_IP)
