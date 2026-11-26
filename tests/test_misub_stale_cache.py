#!/usr/bin/env python3
"""Regression tests for the MiSub stale-collection-cache outages.

Two production outages, both caused by upstream's read-modify-write over a 30s
TTL collection cache (see tests/misub_fake_api.py for the source citations):

  02:03  PATCH /profiles validated new refs against a stale subscriptions
         snapshot and returned HTTP 400 manual_node_id_not_found.
  12:07  DELETE /manual-nodes wrote back a stale profiles snapshot, silently
         reverting the 6 references the preceding bind had just added.
         missing_profile=6, user-servable nodes fell from 8 to 2.

The old fake API modelled DELETE as "remove exactly this id from the live
profile", which is not what upstream does. That is why the previous adversarial
suite was green while production broke.
"""

from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

TESTS_DIR = Path(__file__).resolve().parent
if str(TESTS_DIR) not in sys.path:
    sys.path.insert(0, str(TESTS_DIR))

from misub_fake_api import FakeMiSub  # noqa: E402

MODULE_PATH = TESTS_DIR.parents[0] / "push_to_misub.py"
SPEC = importlib.util.spec_from_file_location("push_to_misub", MODULE_PATH)
assert SPEC and SPEC.loader
push = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = push
SPEC.loader.exec_module(push)

PROFILE_ID = "00000000-0000-4000-8000-000000000005"
UUID = "00000000-0000-4000-8000-000000000002"
OLD_IPS = ["9.9.9.1", "9.9.9.2", "9.9.9.3"]
NEW_IPS = ["104.18.0.107", "104.21.47.37", "104.18.34.253"]

MANAGED_NAMES = [
    f"{region['prefix']} {suffix}"
    for region in push.REGIONS
    for suffix in push.SUFFIXES
]


def managed_name_to_region(name: str) -> dict:
    for region in push.REGIONS:
        if name.startswith(region["prefix"]):
            return region
    raise AssertionError(name)


def build_production_fake(**kwargs) -> FakeMiSub:
    """2 preserved unmanaged nodes + one managed node per name on the OLD ips.

    This is the shape of the real profile: CFST Example = 2 preserved + one per CFST name.
    """
    subscriptions = [
        {"id": "preserved-jp-1", "name": "🇯🇵 JP AZ 01", "url": "vless://x@jp1.example:443#JP1"},
        {"id": "preserved-jp-2", "name": "🇯🇵 JP AZ 02", "url": "vless://x@jp2.example:443#JP2"},
    ]
    managed_ids: list[str] = []
    with patch.object(push, "get_vless_uuid", return_value=UUID):
        for index, name in enumerate(MANAGED_NAMES):
            region = managed_name_to_region(name)
            suffix = name.rsplit(" ", 1)[1]
            node_id = f"managed-{index}"
            managed_ids.append(node_id)
            subscriptions.append(
                {
                    "id": node_id,
                    "name": name,
                    "url": push.build_vless_url(region, OLD_IPS[push.SUFFIXES.index(suffix)], suffix),
                }
            )
    profiles = [
        {
            "id": PROFILE_ID,
            "name": push.PROFILE_NAME,
            "subscriptions": [],
            "manualNodes": ["preserved-jp-1", "preserved-jp-2", *managed_ids],
        }
    ]
    return FakeMiSub(subscriptions=subscriptions, profiles=profiles, **kwargs)


def run_push(fake: FakeMiSub, ips: list[str] | None = None):
    """Drive the real execution seam against the faithful fake, in private storage."""
    with tempfile.TemporaryDirectory() as directory:
        push.execute_push(
            prepare=lambda managed: expected_urls(list(ips or NEW_IPS)),
            request=fake.request,
            pending_path=Path(directory) / "pending.json",
            sleep=lambda seconds: None,
        )

def expected_urls(ips: list[str]) -> dict[str, str]:
    with patch.object(push, "get_vless_uuid", return_value=UUID):
        return push.expected_managed_urls(ips)


class HarnessFidelityTests(unittest.TestCase):
    """The fake must match upstream behaviour, or every result below is void."""

    def test_delete_removes_the_ref_from_every_profile(self) -> None:
        """Mirrors upstream tests/unit/external-manual-nodes-handler.test.js."""
        fake = FakeMiSub(
            subscriptions=[
                {"id": "node-1", "name": "HK 01", "url": "vless://u@e.com:443#HK01"},
                {"id": "node-2", "name": "SG 01", "url": "trojan://p@e.com:443#SG01"},
            ],
            profiles=[
                {"id": "profile-1", "name": "Main", "manualNodes": ["node-1"]},
                {"id": "profile-2", "name": "Backup", "manualNodes": ["node-1", "node-2"]},
            ],
        )

        response = fake.request("DELETE", "/manual-nodes/node-1")

        assert response is not None
        self.assertEqual(response["data"]["removedFromProfiles"], ["profile-1", "profile-2"])
        self.assertEqual(fake.profile_refs("profile-1"), [])
        self.assertEqual(fake.profile_refs("profile-2"), ["node-2"])

    def test_patch_manual_node_never_writes_profiles(self) -> None:
        """PATCH /manual-nodes touches only the subscription row (source: handler 134-154).

        This is the property the fix relies on: an in-place URL update cannot
        clobber a profile, because it never calls putProfile at all.
        """
        fake = build_production_fake()
        before = fake.profile_refs(PROFILE_ID)
        # Prime a stale profiles snapshot; a PATCH must not write it back.
        fake.prime_profiles_cache("iso-0")

        response = fake.request(
            "PATCH", "/manual-nodes/managed-0", {"url": "vless://u@1.2.3.4:443#x"}
        )

        assert response is not None
        self.assertTrue(response["success"])
        self.assertEqual(fake.profile_refs(PROFILE_ID), before)
        self.assertEqual(fake.subs["managed-0"]["url"], "vless://u@1.2.3.4:443#x")

    def test_stale_profiles_snapshot_write_back_loses_concurrent_refs(self) -> None:
        """The 12:07 mechanism, isolated: DELETE reverts refs added after the snapshot."""
        fake = build_production_fake()
        # An isolate serves a list read and caches the profiles collection.
        fake.prime_profiles_cache("iso-stale")
        # Someone else adds a reference (fresh single-profile read + write).
        fake.profiles[PROFILE_ID]["manualNodes"] = ["preserved-jp-1", "brand-new-ref"]

        fake._router = lambda method, path: "iso-stale"
        fake.request("DELETE", "/manual-nodes/managed-0")

        self.assertNotIn(
            "brand-new-ref",
            fake.profile_refs(PROFILE_ID),
            "upstream writes back the stale snapshot, so the new ref is lost",
        )


class StaleCacheOutageTests(unittest.TestCase):
    """End-to-end: push must survive both stale-cache hazards without data loss."""

    def _assert_healthy_final_state(self, fake: FakeMiSub, ips: list[str]) -> None:
        refs = fake.profile_refs(PROFILE_ID)
        self.assertIn("preserved-jp-1", refs, "preserved node must stay in the profile")
        self.assertIn("preserved-jp-2", refs, "preserved node must stay in the profile")

        managed = fake.managed_by_name(set(MANAGED_NAMES))
        self.assertEqual(
            len(managed), len(MANAGED_NAMES),
            "exactly one node per managed name must exist",
        )
        for name, node in managed.items():
            self.assertIn(
                node["id"], refs,
                f"managed node {name} must be referenced by the profile",
            )
        self.assertEqual(
            {node["name"]: node["url"] for node in managed.values()},
            expected_urls(ips),
            "every managed node must carry the current Top3 URL",
        )
        self.assertEqual(
            len(refs), 2 + len(MANAGED_NAMES),
            "profile must end with 2 preserved + every managed node",
        )

    def test_survives_delete_phase_with_stale_profiles_cache(self) -> None:
        """The 12:07 outage.

        The isolate that serves the profile list read is not the isolate that
        serves the profile write, so the write does not invalidate the reader's
        cache. Any delete routed back to the reader writes back a pre-bind
        snapshot. Correctness must not depend on that routing.
        """
        def router(method: str, path: str) -> str:
            if path.startswith("/profiles") and method == "PATCH":
                return "iso-writer"
            return "iso-reader"

        fake = build_production_fake(isolate_router=router, clock=lambda: 0.0)

        run_push(fake)

        self._assert_healthy_final_state(fake, NEW_IPS)

    def test_survives_stale_subscriptions_cache_during_profile_write(self) -> None:
        """The 02:03 outage.

        PATCH /profiles validates refs against getAllSubscriptions(), which is
        cached. An isolate holding a pre-create snapshot rejects the new ids with
        HTTP 400 manual_node_id_not_found. Push must not lose the live set.
        """
        def router(method: str, path: str) -> str:
            if path.startswith("/profiles"):
                return "iso-writer"
            return "iso-reader"

        fake = build_production_fake(isolate_router=router, clock=lambda: 0.0)
        # iso-writer served an earlier read and cached subscriptions as they were
        # before this run created anything.
        fake.prime_subscriptions_cache("iso-writer")

        try:
            run_push(fake)
        except RuntimeError:
            # Fail-closed is acceptable; silent data loss is not.
            pass

        refs = fake.profile_refs(PROFILE_ID)
        self.assertIn("preserved-jp-1", refs)
        self.assertIn("preserved-jp-2", refs)
        managed_refs = [r for r in refs if r in {n["id"] for n in fake.subs.values()
                                                 if n.get("name") in set(MANAGED_NAMES)}]
        self.assertEqual(
            len(managed_refs), len(MANAGED_NAMES),
            "the profile must still reference a full managed set, never a partial profile",
        )

    def test_correct_under_every_isolate_routing(self) -> None:
        """Routing is Cloudflare's choice, so no routing may break the result."""
        routings = {
            "single-isolate": lambda method, path: "iso-0",
            "reader-writer-split": lambda method, path: (
                "iso-writer" if (method == "PATCH" and path.startswith("/profiles")) else "iso-reader"
            ),
            "delete-on-its-own": lambda method, path: (
                "iso-del" if method == "DELETE" else "iso-main"
            ),
            "round-robin": lambda method, path: f"iso-{hash((method, path)) % 3}",
        }
        for label, router in routings.items():
            with self.subTest(routing=label):
                fake = build_production_fake(isolate_router=router, clock=lambda: 0.0)
                run_push(fake)
                self._assert_healthy_final_state(fake, NEW_IPS)


class SteadyStateContractTests(unittest.TestCase):
    """The steady state must avoid the dangerous routes entirely."""

    def test_steady_state_performs_no_delete_and_no_profile_write(self) -> None:
        """When the managed set is already correct and bound, only URLs change.

        DELETE /manual-nodes and PATCH /profiles are the only two routes that can
        corrupt the profile. The recurring 2-hourly push must use neither.
        """
        fake = build_production_fake(clock=lambda: 0.0)

        run_push(fake)

        deletes = [c for c in fake.calls if c[0] == "DELETE"]
        profile_writes = [c for c in fake.calls if c[0] == "PATCH" and c[1].startswith("/profiles")]
        self.assertEqual(deletes, [], "steady state must not delete any node")
        self.assertEqual(profile_writes, [], "steady state must not rewrite the profile")

    def test_steady_state_keeps_node_ids_stable(self) -> None:
        """In-place update keeps client-visible node identity stable."""
        fake = build_production_fake(clock=lambda: 0.0)
        before = fake.profile_refs(PROFILE_ID)

        run_push(fake)

        self.assertEqual(fake.profile_refs(PROFILE_ID), before,
                         "profile references must be untouched in the steady state")

    def test_missing_managed_node_is_recreated_and_bound(self) -> None:
        """Bootstrap / self-heal: a missing node must be created and bound."""
        fake = build_production_fake(clock=lambda: 0.0)
        victim = fake.subs.pop("managed-3")
        fake.profiles[PROFILE_ID]["manualNodes"] = [
            r for r in fake.profile_refs(PROFILE_ID) if r != "managed-3"
        ]

        run_push(fake)

        managed = fake.managed_by_name(set(MANAGED_NAMES))
        self.assertEqual(len(managed), len(MANAGED_NAMES))
        recreated = managed[victim["name"]]
        self.assertIn(recreated["id"], fake.profile_refs(PROFILE_ID))
        self.assertEqual(recreated["url"], expected_urls(NEW_IPS)[victim["name"]])

    def test_duplicate_unreferenced_node_is_reclaimed(self) -> None:
        """A leaked duplicate from a failed run must not survive."""
        fake = build_production_fake(clock=lambda: 0.0)
        fake.subs["leaked"] = {
            "id": "leaked",
            "name": MANAGED_NAMES[0],
            "url": "vless://u@9.9.9.9:443#leak",
            "enabled": True,
            "sortIndex": 99,
        }

        run_push(fake)

        self.assertNotIn("leaked", fake.subs, "unreferenced duplicate must be reclaimed")
        self.assertEqual(len(fake.managed_by_name(set(MANAGED_NAMES))), len(MANAGED_NAMES))
        self._assert_refs_complete(fake)

    def _assert_refs_complete(self, fake: FakeMiSub) -> None:
        refs = fake.profile_refs(PROFILE_ID)
        self.assertEqual(len(refs), 2 + len(MANAGED_NAMES))
        for node in fake.managed_by_name(set(MANAGED_NAMES)).values():
            self.assertIn(node["id"], refs)


if __name__ == "__main__":
    unittest.main()
