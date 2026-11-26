#!/usr/bin/env python3
"""把发布集写成单个域名的 A 记录：DNS 只做指针，节点地址不再变。

契约：
  - desired 为空、重复或非法时不发起任何外部调用。
  - 已一致时零写入。
  - 先写新值、再用公共解析器回读确认，确认成功后才删除多余记录；
    任何一步失败都恢复到调用前的地址集合，绝不留下空记录集。
  - 只写 A 记录，且强制 DNS-only（proxied=false）：橙云会让解析返回 CF 自己的
    地址，选优 IP 就失效了。
"""
from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from ip_validation import is_valid_ipv4

API = "https://api.cloudflare.com/client/v4"
TOKEN_FILE = Path("/root/.config/credentials/cloudflare.env")
TOKEN_KEY = "CLOUDFLARE_API_TOKEN"
ZONE_ID = "00000000000000000000000000000000"      # example.com
RECORD_NAME = "preferred.example.com"
TTL = 60
DOH = "https://1.1.1.1/dns-query"


@dataclass(frozen=True)
class Receipt:
    changed: bool
    applied: list[str]
    previous: list[str]
    dry_run: bool = False


def _normalise(desired: list[str]) -> list[str]:
    if not desired:
        raise ValueError("refusing to publish an empty address set")
    if len(set(desired)) != len(desired):
        raise ValueError("duplicate address in publish set")
    for ip in desired:
        if not is_valid_ipv4(ip):
            raise ValueError(f"invalid IPv4 in publish set: {ip!r}")
    return sorted(desired)


def _records(request, zone_id: str, name: str) -> list[dict]:
    query = urllib.parse.urlencode({"type": "A", "name": name, "per_page": 100})
    payload = request("GET", f"/zones/{zone_id}/dns_records?{query}")
    return [r for r in payload["result"] if r.get("type") == "A"]


def _await_resolution(resolve, name: str, wanted: list[str], attempts: int,
                      delay: float, sleep, *, exact: bool = True) -> list[str]:
    """DNS 写入后回读需要等传播；只有全部尝试都失败才算失败。

    exact=False 用于"新记录都可见即可"的阶段：此时旧记录还没删，回读必然多出来。
    """
    observed: list[str] = []
    for attempt in range(attempts):
        if attempt:
            sleep(delay)
        try:
            observed = sorted(set(resolve(name)))
        except Exception as exc:
            if attempt == attempts - 1:
                raise RuntimeError(f"could not verify {name}: {exc}") from exc
            continue
        if observed == wanted or (not exact and set(wanted) <= set(observed)):
            return observed
    return observed


def reconcile(*, zone_id: str, name: str, desired: list[str], request, resolve,
              ttl: int = TTL, dry_run: bool = False, attempts: int = 8,
              delay: float = 5.0, sleep=time.sleep) -> Receipt:
    wanted = _normalise(desired)
    current = _records(request, zone_id, name)
    previous = sorted(r["content"] for r in current)
    dns_only = all(not r.get("proxied") and r.get("ttl") == ttl for r in current)
    if previous == wanted and dns_only:
        return Receipt(changed=False, applied=wanted, previous=previous)
    if dry_run:
        return Receipt(changed=True, applied=wanted, previous=previous, dry_run=True)

    creative = Path(f"/zones/{zone_id}/dns_records")
    keep = {r["content"]: r for r in current if r["content"] in wanted}
    created: list[str] = []
    patched: list[dict] = []
    deleted: list[dict] = []
    try:
        for ip in wanted:
            body = {"type": "A", "name": name, "content": ip, "ttl": ttl, "proxied": False}
            row = keep.get(ip)
            if row is None:
                payload = request("POST", str(creative), body)
                created.append(payload["result"]["id"])
            elif row.get("proxied") or row.get("ttl") != ttl:
                patched.append({"id": row["id"], "proxied": row.get("proxied"), "ttl": row.get("ttl")})
                request("PATCH", f"/zones/{zone_id}/dns_records/{row['id']}",
                        {"proxied": False, "ttl": ttl})

        observed = _await_resolution(resolve, name, wanted, attempts, delay, sleep, exact=False)
        if not set(wanted) <= set(observed):
            raise RuntimeError(
                f"{name} did not resolve to the published set: expected {wanted}, got {observed}"
            )
        for row in current:
            if row["content"] not in wanted:
                request("DELETE", f"/zones/{zone_id}/dns_records/{row['id']}")
                deleted.append({"content": row["content"], "ttl": row.get("ttl"),
                                "proxied": row.get("proxied")})
        observed = _await_resolution(resolve, name, wanted, attempts, delay, sleep)
        if observed != wanted:
            raise RuntimeError(
                f"{name} did not resolve to the published set: expected {wanted}, got {observed}"
            )
    except BaseException:
        _rollback(request, zone_id, name, created, patched, deleted, ttl)
        raise
    return Receipt(changed=True, applied=wanted, previous=previous)


def _rollback(request, zone_id: str, name: str, created: list[str], patched: list[dict],
              deleted: list[dict], ttl: int) -> None:
    """尽力恢复；不掩盖原始异常（调用方负责报告）。先补回被删的，再撤掉新建的。"""
    for row in deleted:
        try:
            request("POST", f"/zones/{zone_id}/dns_records",
                    {"type": "A", "name": name, "content": row["content"],
                     "ttl": row.get("ttl") or ttl, "proxied": False})
        except Exception:
            pass
    for record_id in created:
        try:
            request("DELETE", f"/zones/{zone_id}/dns_records/{record_id}")
        except Exception:
            pass
    for row in patched:
        try:
            request("PATCH", f"/zones/{zone_id}/dns_records/{row['id']}",
                    {"proxied": row["proxied"], "ttl": row["ttl"]})
        except Exception:
            pass


# ── 生产适配器 ────────────────────────────────────────────────────────────
def _token() -> str:
    if not TOKEN_FILE.is_file():
        raise RuntimeError(f"cloudflare credentials missing: {TOKEN_FILE}")
    if TOKEN_FILE.stat().st_mode & 0o077:
        raise RuntimeError(f"cloudflare credentials must be 0600: {TOKEN_FILE}")
    for line in TOKEN_FILE.read_text().splitlines():
        key, sep, value = line.partition("=")
        if sep and key.strip() == TOKEN_KEY:
            token = value.strip().strip("'\"")
            if token:
                return token
    raise RuntimeError("CLOUDFLARE_API_TOKEN not found in credentials file")


def api_request(method: str, path: str, body: dict | None = None) -> dict:
    data = json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request(
        API + path, data=data, method=method,
        headers={"Authorization": f"Bearer {_token()}", "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            payload = json.load(response)
    except urllib.error.HTTPError as exc:      # 4xx/5xx 带 CF 错误体，保留状态码
        raise RuntimeError(f"cloudflare {method} {path} failed: HTTP {exc.code}") from exc
    if not payload.get("success"):
        errors = payload.get("errors") or []
        raise RuntimeError(f"cloudflare {method} {path} refused: {errors}")
    return payload


def resolve_doh(name: str) -> list[str]:
    query = f"{DOH}?name={urllib.parse.quote(name)}&type=A"
    request = urllib.request.Request(query, headers={"accept": "application/dns-json"})
    with urllib.request.urlopen(request, timeout=15) as response:
        payload = json.load(response)
    if payload.get("Status") != 0:
        raise RuntimeError(f"public resolver returned status {payload.get('Status')} for {name}")
    return [a["data"] for a in payload.get("Answer", []) if a.get("type") == 1]


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    dry_run = "--dry-run" in args
    args = [a for a in args if a != "--dry-run"]
    if not args or args[0] not in {"apply", "status"}:
        print("usage: dns_publish.py apply|status [--dry-run] [ip ...]", file=sys.stderr)
        return 2
    if args[0] == "status":
        rows = _records(api_request, ZONE_ID, RECORD_NAME)
        print(json.dumps({"name": RECORD_NAME, "addresses": sorted(r["content"] for r in rows)}))
        return 0
    desired = [a for a in args[1:] if not a.startswith("-")]
    if not desired:
        print("dns_publish: no addresses given", file=sys.stderr)
        return 2
    try:
        receipt = reconcile(zone_id=ZONE_ID, name=RECORD_NAME, desired=desired,
                            request=api_request, resolve=resolve_doh, dry_run=dry_run)
    except Exception as exc:
        print(json.dumps({"error": str(exc), "name": RECORD_NAME}))
        return 1
    print(json.dumps({"name": RECORD_NAME, "changed": receipt.changed,
                      "addresses": receipt.applied, "previous": receipt.previous,
                      "dry_run": receipt.dry_run}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
