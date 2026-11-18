#!/usr/bin/env python3
"""Faithful fake of the MiSub External Management API.

Modelled on upstream source (github.com/imzyb/MiSub), NOT on REST intuition.
The previous harness assumed ``DELETE /manual-nodes/:id`` removes one profile
reference by ID. That assumption produced a false green while production lost
6 profile references on 2026-08-24 12:07.

Upstream facts reproduced here, with the source location of each:

``functions/storage-adapter.js``
  - ``D1_COLLECTION_CACHE_TTL_MS = 30 * 1000`` (line 21).
  - ``getAllSubscriptions()`` / ``getAllProfiles()`` read through
    ``readCachedD1Collection()`` (lines 412-437), a 30s TTL cache held in a
    module-level ``WeakMap`` keyed by the D1 binding.
  - ``getSubscriptionById()`` / ``getProfileById()`` issue direct SQL and are
    always fresh (lines 354, 398).
  - ``putSubscription()`` / ``putProfile()`` are whole-row ``INSERT OR REPLACE``
    and invalidate the collection cache *of the isolate that performed them*
    (lines 453-475).

``functions/modules/external-manual-nodes-handler.js``
  - ``DELETE /manual-nodes/:id`` (lines 156-162) does
    ``deleteSubscriptionById(id)`` then ``removeManualNodeIdFromProfiles()``.
  - ``removeManualNodeIdFromProfiles()`` (lines 42-53) reads
    ``getAllProfiles()`` -- THE CACHED COLLECTION -- and for every profile that
    lists the id writes ``putProfile({...profile, manualNodes: without(id)})``.
    That is a whole-row write of a possibly stale snapshot, so it silently
    reverts every reference added since the snapshot was taken. This is the
    12:07 outage.
  - ``PATCH /manual-nodes/:id`` (lines 134-154) reads ``getManualNodeById()``
    (fresh) and writes ``putSubscription()``. It never touches profiles, so it
    cannot clobber a profile.

``functions/modules/external-profiles-handler.js``
  - ``PATCH /profiles/:id`` (lines 172-196) reads ``getProfileById()`` (fresh),
    validates through ``validateProfileReferences()`` -> ``getAllSubscriptions()``
    -- CACHED -- and writes ``putProfile()``. A stale subscriptions snapshot
    yields HTTP 400 ``manual_node_id_not_found``. That is the 02:03 outage.

Cloudflare Workers serves requests from multiple isolates, each with its own
module scope and therefore its own collection cache; a write in isolate A does
not invalidate isolate B's cache. ``isolate_router`` models that. Correctness
must not depend on which isolate serves which request, so tests drive several
routings.
"""

from __future__ import annotations

import itertools
import time
from copy import deepcopy
from typing import Any, Callable

# storage-adapter.js:21
D1_COLLECTION_CACHE_TTL_SECONDS = 30.0

# external-api-mappers.js: a manual node is any non-http(s) supported protocol.
MANUAL_NODE_PROTOCOLS = (
    "vless://",
    "vmess://",
    "trojan://",
    "ss://",
    "ssr://",
    "hysteria://",
    "hysteria2://",
    "hy2://",
    "tuic://",
    "anytls://",
)


def is_manual_node(item: dict[str, Any]) -> bool:
    url = str(item.get("url") or "").strip()
    if url.startswith(("http://", "https://")):
        return False
    return url.startswith(MANUAL_NODE_PROTOCOLS)


class _Isolate:
    """One Worker isolate: its own 30s TTL collection cache over a shared DB."""

    def __init__(self, name: str, clock: Callable[[], float], ttl: float) -> None:
        self.name = name
        self._clock = clock
        self._ttl = ttl
        self._cache: dict[str, tuple[float, list[dict[str, Any]]]] = {}

    def read_collection(
        self, table: str, loader: Callable[[], list[dict[str, Any]]]
    ) -> list[dict[str, Any]]:
        now = self._clock()
        entry = self._cache.get(table)
        if entry is not None and now - entry[0] < self._ttl:
            return deepcopy(entry[1])
        data = loader()
        self._cache[table] = (now, deepcopy(data))
        return deepcopy(data)

    def invalidate(self, table: str) -> None:
        self._cache.pop(table, None)

    def prime(self, table: str, loader: Callable[[], list[dict[str, Any]]]) -> None:
        """Populate the cache now, the way any earlier read request would."""
        self.read_collection(table, loader)


class FakeMiSub:
    """Drop-in replacement for push_to_misub.api_request.

    Patch with ``patch.object(push, "api_request", fake.request)``.
    """

    def __init__(
        self,
        *,
        subscriptions: list[dict[str, Any]] | None = None,
        profiles: list[dict[str, Any]] | None = None,
        isolate_router: Callable[[str, str], str] | None = None,
        clock: Callable[[], float] | None = None,
        ttl: float = D1_COLLECTION_CACHE_TTL_SECONDS,
    ) -> None:
        self.subs: dict[str, dict[str, Any]] = {}
        self.profiles: dict[str, dict[str, Any]] = {}
        for index, item in enumerate(subscriptions or []):
            node = dict(item)
            node.setdefault("enabled", True)
            node.setdefault("sortIndex", index + 1)
            self.subs[str(node["id"])] = node
        for index, item in enumerate(profiles or []):
            profile = dict(item)
            profile.setdefault("subscriptions", [])
            profile.setdefault("manualNodes", [])
            profile.setdefault("sortIndex", index + 1)
            self.profiles[str(profile["id"])] = profile

        self._ttl = ttl
        self._clock = clock or time.monotonic
        self._isolates: dict[str, _Isolate] = {}
        self._router = isolate_router or (lambda method, path: "iso-0")

        self.calls: list[tuple[str, str]] = []
        self.errors: list[str] = []
        self._ids = itertools.count(1)

    # ---- infrastructure -------------------------------------------------

    def isolate(self, name: str) -> _Isolate:
        if name not in self._isolates:
            self._isolates[name] = _Isolate(name, self._clock, self._ttl)
        return self._isolates[name]

    def prime_profiles_cache(self, isolate: str) -> None:
        """Simulate an isolate that already served a profiles list read."""
        self.isolate(isolate).prime("profiles", self._load_profiles)

    def prime_subscriptions_cache(self, isolate: str) -> None:
        self.isolate(isolate).prime("subscriptions", self._load_subscriptions)

    def _load_subscriptions(self) -> list[dict[str, Any]]:
        return sorted(
            (deepcopy(node) for node in self.subs.values()),
            key=lambda node: node.get("sortIndex") or 0,
        )

    def _load_profiles(self) -> list[dict[str, Any]]:
        return sorted(
            (deepcopy(profile) for profile in self.profiles.values()),
            key=lambda profile: profile.get("sortIndex") or 0,
        )

    # storage-adapter.js:453-475 -- whole-row write, invalidate own isolate.
    def _put_subscription(self, iso: _Isolate, node: dict[str, Any]) -> None:
        self.subs[str(node["id"])] = deepcopy(node)
        iso.invalidate("subscriptions")

    def _put_profile(self, iso: _Isolate, profile: dict[str, Any]) -> None:
        self.profiles[str(profile["id"])] = deepcopy(profile)
        iso.invalidate("profiles")

    # ---- DTO mappers (external-api-mappers.js) --------------------------

    @staticmethod
    def _node_dto(node: dict[str, Any]) -> dict[str, Any]:
        return {
            "id": node["id"],
            "name": node.get("name", ""),
            "url": node.get("url", ""),
            "enabled": node.get("enabled", True),
        }

    @staticmethod
    def _profile_dto(profile: dict[str, Any]) -> dict[str, Any]:
        return {
            "id": profile["id"],
            "name": profile.get("name", ""),
            "enabled": profile.get("enabled", True),
            "subscriptionIds": list(profile.get("subscriptions") or []),
            "manualNodeIds": list(profile.get("manualNodes") or []),
        }

    # ---- helpers --------------------------------------------------------

    @staticmethod
    def _ok(data: Any) -> dict[str, Any]:
        return {"success": True, "data": data}

    def _fail(self, method: str, path: str, code: str, status: int) -> dict[str, Any]:
        self.errors.append(f"{method} {path} -> HTTP {status} ({code})")
        return {
            "success": False,
            "error": {"status": status, "code": code},
        }

    @staticmethod
    def _dedupe(values: Any) -> list[str]:
        seen: dict[str, None] = {}
        for value in values or []:
            if isinstance(value, str) and value:
                seen.setdefault(value, None)
        return list(seen)

    # ---- router ---------------------------------------------------------

    def request(
        self, method: str, path: str, data: Any = None
    ) -> dict[str, Any] | None:
        """Same contract as push_to_misub.api_request."""
        self.calls.append((method, path))
        route = path.split("?", 1)[0].rstrip("/")
        iso = self.isolate(self._router(method, path))

        if route == "/manual-nodes":
            if method == "GET":
                nodes = [n for n in iso.read_collection("subscriptions", self._load_subscriptions)
                         if is_manual_node(n)]
                return self._ok([self._node_dto(n) for n in nodes])
            if method == "POST":
                name = str((data or {}).get("name") or "").strip()
                url = str((data or {}).get("url") or "").strip()
                if not name:
                    return self._fail(method, path, "manual_node_name_required", 400)
                if not url:
                    return self._fail(method, path, "manual_node_url_required", 400)
                if not is_manual_node({"url": url}):
                    return self._fail(method, path, "invalid_manual_node_url", 400)
                node = {
                    "id": f"node_{next(self._ids):08d}",
                    "name": name,
                    "url": url,
                    "enabled": True,
                    "sortIndex": len(self.subs) + 1,
                }
                self._put_subscription(iso, node)
                return self._ok(self._node_dto(node))
            return self._fail(method, path, "method_not_allowed", 405)

        if route.startswith("/manual-nodes/"):
            node_id = route.split("/", 2)[2]
            # getManualNodeById -> direct SQL, always fresh.
            current = self.subs.get(node_id)
            if current is None or not is_manual_node(current):
                return self._fail(method, path, "manual_node_not_found", 404)

            if method == "GET":
                return self._ok(self._node_dto(current))

            if method == "PATCH":
                updated = dict(current)
                payload = data or {}
                if "name" in payload:
                    updated["name"] = str(payload["name"] or "").strip()
                if "url" in payload:
                    updated["url"] = str(payload["url"] or "").strip()
                if not updated.get("name"):
                    return self._fail(method, path, "manual_node_name_required", 400)
                if not updated.get("url"):
                    return self._fail(method, path, "manual_node_url_required", 400)
                if not is_manual_node(updated):
                    return self._fail(method, path, "invalid_manual_node_url", 400)
                # Only the subscription row is written. Profiles are untouched.
                self._put_subscription(iso, updated)
                return self._ok(self._node_dto(updated))

            if method == "DELETE":
                del self.subs[node_id]
                iso.invalidate("subscriptions")
                # removeManualNodeIdFromProfiles: reads the CACHED collection
                # and writes back whole rows. This is the clobber.
                affected: list[str] = []
                snapshot = iso.read_collection("profiles", self._load_profiles)
                for profile in snapshot:
                    refs = profile.get("manualNodes") or []
                    if node_id not in refs:
                        continue
                    updated = dict(profile)
                    updated["manualNodes"] = [r for r in refs if r != node_id]
                    self._put_profile(iso, updated)
                    affected.append(profile["id"])
                return self._ok(
                    {"deleted": True, "id": node_id, "removedFromProfiles": affected}
                )

            return self._fail(method, path, "method_not_allowed", 405)

        if route == "/profiles":
            if method == "GET":
                profiles = iso.read_collection("profiles", self._load_profiles)
                return self._ok([self._profile_dto(p) for p in profiles])
            return self._fail(method, path, "method_not_allowed", 405)

        if route.startswith("/profiles/"):
            profile_id = route.split("/", 2)[2]
            # getProfileById -> direct SQL, always fresh.
            current = self.profiles.get(profile_id)
            if current is None:
                return self._fail(method, path, "profile_not_found", 404)

            if method == "GET":
                return self._ok(self._profile_dto(current))

            if method == "PATCH":
                payload = data or {}
                updated = dict(current)
                if "manualNodeIds" in payload:
                    manual_ids = self._dedupe(payload["manualNodeIds"])
                    # validateProfileReferences -> getAllSubscriptions (CACHED)
                    known = {
                        n["id"]: n
                        for n in iso.read_collection("subscriptions", self._load_subscriptions)
                    }
                    for ref in manual_ids:
                        node_for_ref: dict[str, Any] | None = known.get(ref)
                        if node_for_ref is None:
                            return self._fail(
                                method, path, "manual_node_id_not_found", 400
                            )
                        if not is_manual_node(node_for_ref):
                            return self._fail(
                                method, path, "invalid_profile_reference", 400
                            )
                    updated["manualNodes"] = manual_ids
                if "subscriptionIds" in payload:
                    updated["subscriptions"] = self._dedupe(payload["subscriptionIds"])
                self._put_profile(iso, updated)
                return self._ok(self._profile_dto(updated))

            return self._fail(method, path, "method_not_allowed", 405)

        return self._fail(method, path, "not_found", 404)

    # ---- assertions helpers for tests ----------------------------------

    def profile_refs(self, profile_id: str) -> list[str]:
        """Authoritative DB state, bypassing every cache."""
        return list(self.profiles[profile_id].get("manualNodes") or [])

    def managed_by_name(self, names: set[str]) -> dict[str, dict[str, Any]]:
        return {
            node["name"]: node
            for node in self.subs.values()
            if node.get("name") in names
        }
