#!/usr/bin/env python3
"""Regression tests for CFST -> MiSub replacement semantics."""

from __future__ import annotations

import importlib.util
import io
import json
import sys
import unittest
import urllib.error
from collections import Counter
from email.message import Message
from pathlib import Path
from typing import TYPE_CHECKING
from unittest.mock import patch

MODULE_PATH = Path(__file__).resolve().parents[1] / "push_to_misub.py"
SPEC = importlib.util.spec_from_file_location("push_to_misub", MODULE_PATH)
assert SPEC and SPEC.loader
push = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = push
SPEC.loader.exec_module(push)

TEST_UUID = "00000000-0000-4000-8000-000000000000"
push.__dict__["get_vless_uuid"] = lambda: TEST_UUID

if TYPE_CHECKING:
    # The module is loaded by path at runtime, so `push` is a plain variable and
    # `push.ManagedNode` cannot be resolved as a type. Import the symbol
    # statically for annotations only; `from __future__ import annotations`
    # keeps every annotation a string, so nothing is imported at runtime.
    from push_to_misub import ManagedNode


def managed_node(node_id: str, name: str, url: str = "vless://example") -> ManagedNode:
    return push.ManagedNode(node_id, name, url)


class PushToMiSubTests(unittest.TestCase):
    def test_http_error_preserves_provider_error_code_and_message(self) -> None:
        body = json.dumps(
            {
                "success": False,
                "error": {
                    "code": "manual_node_id_not_found",
                    "message": "Manual node stale-id not found",
                },
            }
        ).encode()
        error = urllib.error.HTTPError(
            "https://example.invalid/api",
            400,
            "Bad Request",
            Message(),
            io.BytesIO(body),
        )

        with (
            patch.object(push.urllib.request, "urlopen", side_effect=error),
            patch.object(push, "get_misub_token", return_value="test-token"),
            patch("sys.stderr", new_callable=io.StringIO) as stderr,
        ):
            self.assertIsNone(push.api_request("PATCH", "/profiles/profile-1", {}))

        self.assertIn("HTTP 400", stderr.getvalue())
        self.assertIn("manual_node_id_not_found", stderr.getvalue())
        self.assertIn("Manual node stale-id not found", stderr.getvalue())

    def test_transient_transport_error_is_retried(self) -> None:
        response = io.BytesIO(json.dumps({"success": True, "data": []}).encode())

        class FakeResponse:
            def __enter__(self) -> "FakeResponse":
                return self

            def __exit__(self, *_args: object) -> None:
                return None

            def read(self) -> bytes:
                return response.getvalue()

        with (
            patch.object(
                push.urllib.request,
                "urlopen",
                side_effect=[urllib.error.URLError("timeout"), FakeResponse()],
            ) as urlopen,
            patch.object(push, "get_misub_token", return_value="test-token"),
            patch.object(push, "API_ATTEMPTS", 2),
            patch("sys.stderr", new_callable=io.StringIO),
        ):
            result = push.api_request("GET", "/manual-nodes")

        self.assertEqual(result, {"success": True, "data": []})
        self.assertEqual(urlopen.call_count, 2)

    def test_read_best_ips_limits_push_to_three_even_when_score_outputs_five(self) -> None:
        content = """# ranking report
# --- BEST_IPS (machine-readable, do not edit below) ---
1.1.1.1
2.2.2.2
3.3.3.3
4.4.4.4
5.5.5.5
"""
        with patch("builtins.open", unittest.mock.mock_open(read_data=content)):
            self.assertEqual(push.read_best_ips(), ["1.1.1.1", "2.2.2.2", "3.3.3.3"])

    def test_final_state_requires_exactly_one_node_per_managed_name(self) -> None:
        expected_names = [
            f"{region['prefix']} {suffix}"
            for region in push.REGIONS
            for suffix in push.SUFFIXES
        ]
        nodes = [managed_node(f"node-{index}", name) for index, name in enumerate(expected_names)]
        counts = Counter(node.name for node in nodes)

        self.assertEqual(len(nodes), len(push.REGIONS) * push.TOP_N)
        self.assertEqual(set(counts.values()), {1})

    def test_cfst_manages_hk_and_sg_but_preserves_jp_nodes(self) -> None:
        self.assertEqual(
            {region["prefix"] for region in push.REGIONS},
            {"🇭🇰 HK Senior", "🇸🇬 SG Legend"},
        )
        self.assertNotIn("🇯🇵 JP AZ", push.CFST_NODE_PREFIXES)

    def test_sg_nodes_use_the_known_working_legend_template(self) -> None:
        sg = next(region for region in push.REGIONS if region["prefix"] == "🇸🇬 SG Legend")
        with patch.object(push, "get_vless_uuid", return_value="00000000-0000-4000-8000-000000000000"):
            url = push.build_vless_url(sg, "104.21.37.203", "CM")

        self.assertIn("sni=sglegend.example.com", url)
        self.assertIn("host=sglegend.example.com", url)
        self.assertIn("path=%2Fargo%3Fed%3D2560", url)
        self.assertNotIn("sgorigin.example.com", url)
        self.assertNotIn("%2Forigin", url)

    def test_parse_audit_results_returns_status_for_each_expected_ip(self) -> None:
        output = """=== AUDIT RESULTS ===
  104.21.37.203  PASS 61
  172.64.146.192  FAIL 0 (timeout)
"""

        self.assertEqual(
            push.parse_audit_results(output, ["104.21.37.203", "172.64.146.192"]),
            {
                "104.21.37.203": push.AuditResult("PASS", "61"),
                "172.64.146.192": push.AuditResult("FAIL", "0 (timeout)"),
            },
        )

    def test_region_preflight_rejects_any_ip_that_did_not_pass(self) -> None:
        region = {"key": "SG", "prefix": "🇸🇬 SG Legend"}
        with self.assertRaisesRegex(RuntimeError, "SG.*172\\.64\\.146\\.192"):
            push.assert_region_preflight_passed(
                region,
                ["104.21.37.203", "172.64.146.192"],
                {
                    "104.21.37.203": push.AuditResult("PASS", "61"),
                    "172.64.146.192": push.AuditResult("FAIL", "0 (timeout)"),
                },
            )

    def test_preflight_failure_happens_before_any_misub_state_read_or_delete(self) -> None:
        with (
            patch.object(push, "read_best_ips", return_value=["1.1.1.1", "2.2.2.2", "3.3.3.3"]),
            patch.object(push, "run_all_region_preflights", side_effect=RuntimeError("SG preflight failed")),
            patch.object(push, "list_managed_nodes") as list_managed,
            patch.object(push, "delete_nodes") as delete_nodes,
        ):
            with self.assertRaisesRegex(RuntimeError, "SG preflight failed"):
                push.main()

        list_managed.assert_not_called()
        delete_nodes.assert_not_called()


class ReconcileSafetyTests(unittest.TestCase):
    """A push must never delete a node it can reuse.

    Upstream MiSub reads collections through a 30s TTL cache and writes whole
    rows back, so DELETE /manual-nodes and PATCH /profiles can both write a
    stale snapshot. The 12:07 outage was exactly that: six references committed
    by a bind were reverted by the deletes that followed it. These tests pin the
    ordering and reuse properties that keep those routes off the hot path.
    """

    IPS = ["1.1.1.1", "2.2.2.2", "3.3.3.3"]

    def _managed_names(self) -> list[str]:
        return [
            f"{region['prefix']} {suffix}"
            for region in push.REGIONS
            for suffix in push.SUFFIXES
        ]

    def _expected_urls(self, ips: list[str]) -> dict[str, str]:
        with patch.object(push, "get_vless_uuid", return_value="00000000-0000-4000-8000-000000000000"):
            return push.expected_managed_urls(ips)

    def _existing(self) -> list[ManagedNode]:
        """The managed set as a healthy steady state leaves it."""
        urls = self._expected_urls(self.IPS)
        return [
            managed_node(f"live-{index}", name, urls[name])
            for index, name in enumerate(self._managed_names())
        ]

    def _per_id(
        self, nodes: list[ManagedNode], unmanaged: dict[str, str] | None = None
    ) -> dict[str, ManagedNode]:
        """MiSub's authoritative per-id view: the real name and url of every id.

        Every classification below comes from the per-id read, so a fake that
        answers all ids with one placeholder name would describe a state MiSub
        can never be in and would hide the node reuse the design exists for.
        Ids absent from the mapping resolve to None, which is a genuine ghost.
        """
        by_id = {node.id: node for node in nodes}
        for node_id, name in (unmanaged or {}).items():
            by_id[node_id] = managed_node(node_id, name)
        return by_id

    def test_all_deletes_precede_every_profile_write(self) -> None:
        """The 12:07 ordering invariant.

        A delete makes upstream write back a possibly stale profiles snapshot, so
        no delete may follow a bind. Ordering it the other way round is what
        reverted the six references in production.
        """
        existing = self._existing()
        duplicates = [
            managed_node(f"dupe-{index}", node.name, node.url)
            for index, node in enumerate(existing)
        ]
        events: list[str] = []
        profile = {
            "id": "p1",
            "name": push.PROFILE_NAME,
            "manualNodeIds": [node.id for node in existing],
        }

        with (
            patch.object(push, "read_best_ips", return_value=self.IPS),
            patch.object(push, "run_all_region_preflights"),
            patch.object(push, "list_managed_nodes", return_value=existing + duplicates),
            patch.object(push, "list_profiles", return_value=[profile]),
            patch.object(push, "get_profile_refs",
                         side_effect=lambda _pid: [node.id for node in existing]),
            patch.object(push, "get_manual_node",
                         side_effect=self._per_id(existing + duplicates).get),
            patch.object(push, "delete_nodes",
                         side_effect=lambda nodes, phase: events.append(f"delete:{len(nodes)}")),
            patch.object(push, "bind_profile_refs",
                         side_effect=lambda *_args: events.append("bind")),
            patch.object(push, "verify_final_state"),
        ):
            push.main()

        self.assertEqual(events, [f"delete:{len(duplicates)}"],
                         "duplicates are reclaimed and no bind is needed")
        self.assertNotIn("bind", events[: events.index(f"delete:{len(duplicates)}")],
                         "no profile write may precede a delete")

    def test_steady_state_neither_deletes_nor_creates(self) -> None:
        """The recurring case: same names, same urls, already bound.

        Nothing may be created or deleted, so client-visible node identity is
        stable and neither profile-clobbering route is touched.
        """
        existing = self._existing()
        profile = {
            "id": "p1",
            "name": push.PROFILE_NAME,
            "manualNodeIds": [node.id for node in existing],
        }

        with (
            patch.object(push, "read_best_ips", return_value=self.IPS),
            patch.object(push, "run_all_region_preflights"),
            patch.object(push, "list_managed_nodes", return_value=existing),
            patch.object(push, "list_profiles", return_value=[profile]),
            patch.object(push, "get_profile_refs",
                         side_effect=lambda _pid: [node.id for node in existing]),
            patch.object(push, "get_manual_node", side_effect=self._per_id(existing).get),
            patch.object(push, "delete_nodes") as delete_nodes,
            patch.object(push, "create_managed_node") as create_node,
            patch.object(push, "update_managed_node_url") as update_url,
            patch.object(push, "bind_profile_refs") as bind_refs,
            patch.object(push, "verify_final_state"),
        ):
            push.main()

        delete_nodes.assert_not_called()
        create_node.assert_not_called()
        update_url.assert_not_called()
        bind_refs.assert_not_called()

    def test_ip_change_updates_urls_in_place_without_deleting(self) -> None:
        """A new Top3 changes URLs only, via the route that cannot touch profiles."""
        existing = self._existing()
        new_ips = ["4.4.4.4", "5.5.5.5", "6.6.6.6"]
        expected_urls = self._expected_urls(new_ips)
        updated: list[tuple[str, str]] = []
        profile = {
            "id": "p1",
            "name": push.PROFILE_NAME,
            "manualNodeIds": [node.id for node in existing],
        }

        def fake_update(node: ManagedNode, url: str) -> ManagedNode:
            updated.append((node.name, url))
            return push.ManagedNode(node.id, node.name, url)

        with (
            patch.object(push, "read_best_ips", return_value=new_ips),
            patch.object(push, "run_all_region_preflights"),
            patch.object(push, "list_managed_nodes", return_value=existing),
            patch.object(push, "list_profiles", return_value=[profile]),
            patch.object(push, "get_profile_refs",
                         side_effect=lambda _pid: [node.id for node in existing]),
            patch.object(push, "get_manual_node", side_effect=self._per_id(existing).get),
            patch.object(push, "update_managed_node_url", side_effect=fake_update),
            patch.object(push, "delete_nodes") as delete_nodes,
            patch.object(push, "create_managed_node") as create_node,
            patch.object(push, "bind_profile_refs") as bind_refs,
            patch.object(push, "verify_final_state"),
        ):
            push.main()

        delete_nodes.assert_not_called()
        create_node.assert_not_called()
        bind_refs.assert_not_called()
        self.assertEqual(
            sorted(updated),
            sorted((name, expected_urls[name]) for name in self._managed_names()),
            "every managed node must be re-pointed at the new Top3",
        )

    def test_unreferenced_node_is_reused_not_recreated(self) -> None:
        """The 12:07 aftermath: nodes existed but the profile had lost them.

        Recovery must rebind the existing nodes. Deleting and recreating them
        would churn client identity for no reason.
        """
        existing = self._existing()
        bound: list[list[str]] = []
        profile = {"id": "p1", "name": push.PROFILE_NAME, "manualNodeIds": ["keep-jp"]}

        with (
            patch.object(push, "read_best_ips", return_value=self.IPS),
            patch.object(push, "run_all_region_preflights"),
            patch.object(push, "list_managed_nodes", return_value=existing),
            patch.object(push, "list_profiles", return_value=[profile]),
            patch.object(push, "get_profile_refs",
                         side_effect=[["keep-jp"], ["keep-jp"]]),
            patch.object(push, "get_manual_node",
                         side_effect=self._per_id(existing, {"keep-jp": "🇯🇵 JP AZ 01"}).get),
            patch.object(push, "delete_nodes") as delete_nodes,
            patch.object(push, "create_managed_node") as create_node,
            patch.object(push, "bind_profile_refs",
                         side_effect=lambda _pid, ids: bound.append(list(ids))),
            patch.object(push, "verify_final_state"),
        ):
            push.main()

        delete_nodes.assert_not_called()
        create_node.assert_not_called()
        self.assertEqual(
            bound,
            [["keep-jp", *[node.id for node in existing]]],
            "the profile is repaired with the existing node ids",
        )

    def test_duplicate_prefers_the_referenced_node(self) -> None:
        """Keeping the referenced copy means the repair needs no profile write."""
        referenced = managed_node("kept", "🇭🇰 HK Senior CM")
        duplicate = managed_node("leaked", "🇭🇰 HK Senior CM")

        keep, reclaim = push.select_managed_by_name(
            [duplicate, referenced], {"kept"}, {"🇭🇰 HK Senior CM"}
        )

        self.assertEqual(keep["🇭🇰 HK Senior CM"].id, "kept")
        self.assertEqual([node.id for node in reclaim], ["leaked"])

    def test_node_with_an_unwanted_name_is_reclaimed(self) -> None:
        """A managed name no longer in the desired set must not linger."""
        wanted = managed_node("wanted", "🇭🇰 HK Senior CM")
        retired = managed_node("retired", "🇭🇰 HK Senior CM9")

        keep, reclaim = push.select_managed_by_name(
            [wanted, retired], {"wanted", "retired"}, {"🇭🇰 HK Senior CM"}
        )

        self.assertEqual(list(keep), ["🇭🇰 HK Senior CM"])
        self.assertEqual([node.id for node in reclaim], ["retired"])

    def test_foreign_profile_reference_is_preserved_not_deleted(self) -> None:
        """A node another profile references is kept, and the push still succeeds.

        Referencing CFST-managed nodes from other profiles is an intended setup,
        so reclaim must skip those nodes instead of failing the whole run.
        """
        existing = self._existing()
        profile = {
            "id": "p1",
            "name": push.PROFILE_NAME,
            "manualNodeIds": [node.id for node in existing],
        }
        other = {"id": "p2", "name": "Other", "manualNodeIds": [existing[0].id]}

        with (
            patch.object(push, "read_best_ips", return_value=self.IPS),
            patch.object(push, "run_all_region_preflights"),
            patch.object(push, "list_managed_nodes", return_value=existing),
            patch.object(push, "list_profiles", return_value=[profile, other]),
            patch.object(push, "get_profile_refs",
                         return_value=[node.id for node in existing]),
            patch.object(push, "get_manual_node", side_effect=self._per_id(existing).get),
            patch.object(push, "delete_nodes") as delete_nodes,
            patch.object(push, "create_managed_node") as create_node,
            patch.object(push, "bind_profile_refs") as bind_refs,
            patch.object(push, "verify_final_state"),
        ):
            push.main()

        delete_nodes.assert_not_called()
        create_node.assert_not_called()
        bind_refs.assert_not_called()

    def test_foreign_reference_skips_only_the_referenced_reclaim(self) -> None:
        """Unreferenced duplicates are still reclaimed; referenced ones are kept."""
        existing = self._existing()
        leaked = managed_node("leaked", "🇭🇰 HK Senior CM")
        profile = {
            "id": "p1",
            "name": push.PROFILE_NAME,
            "manualNodeIds": [node.id for node in existing],
        }
        other = {"id": "p2", "name": "Other", "manualNodeIds": [existing[0].id]}
        all_nodes = [*existing, leaked]
        deleted: list[str] = []

        def fake_delete(nodes, phase):
            deleted.extend(node.id for node in nodes)

        with (
            patch.object(push, "read_best_ips", return_value=self.IPS),
            patch.object(push, "run_all_region_preflights"),
            patch.object(push, "list_managed_nodes", return_value=all_nodes),
            patch.object(push, "list_profiles", return_value=[profile, other]),
            patch.object(push, "get_profile_refs",
                         return_value=[node.id for node in existing]),
            patch.object(push, "get_manual_node", side_effect=self._per_id(all_nodes).get),
            patch.object(push, "delete_nodes", side_effect=fake_delete),
            patch.object(push, "create_managed_node") as create_node,
            patch.object(push, "bind_profile_refs") as bind_refs,
            patch.object(push, "verify_final_state"),
        ):
            push.main()

        self.assertEqual(deleted, ["leaked"])
        create_node.assert_not_called()
        bind_refs.assert_not_called()

    def test_bind_refuses_ids_that_do_not_resolve(self) -> None:
        """A bind may only be attempted with ids confirmed by a fresh per-id read.

        Otherwise the retry loop would keep re-sending a genuinely missing id and
        report a stale-cache symptom for a real inconsistency.
        """
        with (
            patch.object(push, "get_manual_node", return_value=None),
            patch.object(push, "api_request") as api_request,
        ):
            with self.assertRaisesRegex(RuntimeError, "do not resolve by id"):
                push.bind_profile_refs("p1", ["ghost"])

        api_request.assert_not_called()

    def test_bind_retries_a_stale_snapshot_rejection(self) -> None:
        """The 02:03:42 mode: a stale isolate rejects a brand-new id.

        The snapshot expires inside the 30s TTL, so a bounded retry is correct.
        """
        refs = ["a", "b"]
        with (
            patch.object(push, "get_manual_node",
                         side_effect=lambda node_id: managed_node(node_id, "x")),
            patch.object(push, "api_request",
                         side_effect=[None, {"success": True}]) as api_request,
            patch.object(push, "get_profile_refs", return_value=refs),
            patch.object(push.time, "sleep") as sleep,
            patch("sys.stderr", new_callable=io.StringIO),
        ):
            push.bind_profile_refs("p1", refs)

        self.assertEqual(api_request.call_count, 2)
        self.assertEqual(sleep.call_count, 1, "must back off once before retrying")

    def test_bind_is_fail_closed_when_the_profile_never_converges(self) -> None:
        """A PATCH that reports success but does not stick must not pass."""
        refs = ["a", "b"]
        with (
            patch.object(push, "get_manual_node",
                         side_effect=lambda node_id: managed_node(node_id, "x")),
            patch.object(push, "api_request", return_value={"success": True}),
            patch.object(push, "get_profile_refs", return_value=["a"]),
            patch.object(push.time, "sleep"),
            patch("sys.stderr", new_callable=io.StringIO),
        ):
            with self.assertRaisesRegex(RuntimeError, "could not bind"):
                push.bind_profile_refs("p1", refs)

    def test_node_visibility_retry_recovers_from_delayed_propagation(self) -> None:
        """POST can return an id before PATCH /profiles can resolve it."""
        created = [managed_node("new-1", "🇭🇰 HK Senior CM")]

        with (
            patch.object(push, "get_manual_node",
                         side_effect=[None, created[0]]),
            patch.object(push.time, "sleep") as sleep,
            patch("sys.stderr", new_callable=io.StringIO),
        ):
            push.wait_for_node_visibility(created)

        self.assertEqual(sleep.call_count, 1, "must back off once before succeeding")

    def test_node_visibility_failure_is_fail_closed(self) -> None:
        created = [managed_node("new-1", "🇭🇰 HK Senior CM")]
        with (
            patch.object(push, "get_manual_node", return_value=None),
            patch.object(push.time, "sleep"),
            patch("sys.stderr", new_callable=io.StringIO),
        ):
            with self.assertRaisesRegex(RuntimeError, "not visible"):
                push.wait_for_node_visibility(created)

    def _nodes_by_id(
        self, nodes: list[ManagedNode], unmanaged: tuple[str, str] = ("live-jp", "🇯🇵 JP AZ 01")
    ) -> dict[str, ManagedNode]:
        """A per-id view of MiSub: authoritative name and url for every node."""
        by_id = {node.id: node for node in nodes}
        by_id[unmanaged[0]] = managed_node(unmanaged[0], unmanaged[1])
        return by_id

    def test_managed_ref_missing_from_the_cached_list_is_reused(self) -> None:
        """GET /manual-nodes is a cached collection and can omit a live node.

        Real-API acceptance hit exactly this: the whole managed set was invisible
        in the cached list, so six duplicates were created for nodes that already
        existed. Reuse is the entire point of the design, so classification has
        to come from the per-id read, which is authoritative. Here the profile is
        already correct, so a run must do nothing at all.
        """
        existing = self._existing()
        hidden, listed = existing[0], existing[1:]
        refs = ["live-jp", *[node.id for node in existing]]
        profile = {"id": "p1", "name": push.PROFILE_NAME, "manualNodeIds": refs}
        by_id = self._nodes_by_id(existing)

        with (
            patch.object(push, "read_best_ips", return_value=self.IPS),
            patch.object(push, "run_all_region_preflights"),
            patch.object(push, "list_managed_nodes", return_value=listed),
            patch.object(push, "list_profiles", return_value=[profile]),
            patch.object(push, "get_profile_refs", return_value=refs),
            patch.object(push, "get_manual_node", side_effect=by_id.get),
            patch.object(push, "create_managed_node") as create_node,
            patch.object(push, "update_managed_node_url") as update_url,
            patch.object(push, "delete_nodes") as delete_nodes,
            patch.object(push, "bind_profile_refs") as bind_refs,
            patch.object(push, "verify_final_state") as verify,
        ):
            push.main()

        create_node.assert_not_called()
        update_url.assert_not_called()
        delete_nodes.assert_not_called()
        bind_refs.assert_not_called()
        verified_ids = [node.id for node in verify.call_args.args[2].values()]
        self.assertIn(hidden.id, verified_ids,
                      "the node absent from the cached list must be reused, not replaced")

    def test_ghost_entry_in_the_cached_list_is_never_deleted(self) -> None:
        """The cached list can also still show an already-deleted node.

        Reclaiming it would DELETE an id that no longer exists, and delete_nodes
        is fail-closed, so a stale cache entry would abort an otherwise healthy
        push. It must be ignored instead.
        """
        existing = self._existing()
        ghost = managed_node("ghost", existing[0].name, existing[0].url)
        refs = ["live-jp", *[node.id for node in existing]]
        profile = {"id": "p1", "name": push.PROFILE_NAME, "manualNodeIds": refs}
        by_id = self._nodes_by_id(existing)

        with (
            patch.object(push, "read_best_ips", return_value=self.IPS),
            patch.object(push, "run_all_region_preflights"),
            patch.object(push, "list_managed_nodes", return_value=existing + [ghost]),
            patch.object(push, "list_profiles", return_value=[profile]),
            patch.object(push, "get_profile_refs", return_value=refs),
            patch.object(push, "get_manual_node", side_effect=by_id.get),
            patch.object(push, "create_managed_node") as create_node,
            patch.object(push, "delete_nodes") as delete_nodes,
            patch.object(push, "bind_profile_refs") as bind_refs,
            patch.object(push, "verify_final_state"),
        ):
            push.main()

        delete_nodes.assert_not_called()
        create_node.assert_not_called()
        bind_refs.assert_not_called()

    def test_stale_profile_reference_is_dropped_not_rebound(self) -> None:
        """A ref that no longer resolves must not be carried into the bind.

        Rebinding a dead id is exactly what upstream rejects with
        manual_node_id_not_found.
        """
        existing = self._existing()
        bound: list[list[str]] = []
        profile = {
            "id": "p1",
            "name": push.PROFILE_NAME,
            "manualNodeIds": ["live-jp", "dead-jp", *[node.id for node in existing]],
        }

        # dead-jp is absent from the per-id view, so it resolves to None: the
        # only way MiSub reports an id that no longer exists.
        by_id = self._per_id(existing, {"live-jp": "🇯🇵 JP AZ 01"})

        with (
            patch.object(push, "read_best_ips", return_value=self.IPS),
            patch.object(push, "run_all_region_preflights"),
            patch.object(push, "list_managed_nodes", return_value=existing),
            patch.object(push, "list_profiles", return_value=[profile]),
            patch.object(push, "get_profile_refs",
                         return_value=["live-jp", "dead-jp", *[n.id for n in existing]]),
            patch.object(push, "get_manual_node", side_effect=by_id.get),
            patch.object(push, "delete_nodes"),
            patch.object(push, "bind_profile_refs",
                         side_effect=lambda _pid, ids: bound.append(list(ids))),
            patch.object(push, "verify_final_state"),
        ):
            push.main()

        self.assertEqual(len(bound), 1, "the wrong reference set must be repaired")
        self.assertNotIn("dead-jp", bound[0])
        self.assertEqual(bound[0][0], "live-jp")
        self.assertEqual(bound[0][1:], [node.id for node in existing])


if __name__ == "__main__":
    unittest.main()
