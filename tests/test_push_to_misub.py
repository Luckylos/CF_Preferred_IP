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

TEST_UUID = "00000000-0000-4000-8000-000000000002"
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

    def test_cfst_manages_hk_sg_and_tamago_but_preserves_jp_nodes(self) -> None:
        self.assertEqual(
            {region["prefix"] for region in push.REGIONS},
            {"🇭🇰 HK Example", "🇸🇬 SG Example", "🇭🇰 HT Example"},
        )
        self.assertNotIn("🇯🇵 JP AZ", push.CFST_NODE_PREFIXES)

    def test_sg_nodes_use_the_known_working_legend_template(self) -> None:
        sg = next(region for region in push.REGIONS if region["prefix"] == "🇸🇬 SG Example")
        with patch.object(push, "get_vless_uuid", return_value="00000000-0000-4000-8000-000000000002"):
            url = push.build_vless_url(sg, "104.21.37.203", "CM")

        self.assertIn("sni=sg-relay.example.com", url)
        self.assertIn("host=sg-relay.example.com", url)
        self.assertIn("path=%2Fargo%3Fed%3D2560", url)
        self.assertNotIn("sgorigin.example.com", url)
        self.assertNotIn("%2Forigin", url)

    def test_tamago_nodes_use_the_tamago_endpoint(self) -> None:
        tamago = next(region for region in push.REGIONS if region["prefix"] == "🇭🇰 HT Example")
        with patch.object(push, "get_vless_uuid", return_value="00000000-0000-4000-8000-000000000002"):
            url = push.build_vless_url(tamago, "104.21.37.203", "CM")

        self.assertIn("sni=ht-relay.example.com", url)
        self.assertIn("host=ht-relay.example.com", url)
        self.assertIn("type=xhttp", url)
        self.assertIn("path=%2Fargo&", url)
        self.assertIn("mode=auto", url)
        self.assertIn("fp=chrome", url)
        self.assertNotIn("hk-relay.example.com", url)
        self.assertNotIn("ed%3D2560", url)

    def test_pushing_only_substitutes_the_ip(self) -> None:
        for region in push.REGIONS:
            with patch.object(push, "get_vless_uuid", return_value="00000000-0000-4000-8000-000000000002"):
                first = push.build_vless_url(region, "1.1.1.1", "CM")
                second = push.build_vless_url(region, "2.2.2.2", "CM")
                other_suffix = push.build_vless_url(region, "1.1.1.1", "CM2")
            self.assertEqual(first.replace("1.1.1.1", "<ip>"), second.replace("2.2.2.2", "<ip>"))
            self.assertEqual(first.split("#")[0], other_suffix.split("#")[0])
            self.assertIn(f"?{region['query']}#", first)

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
        region = {"key": "SG", "prefix": "🇸🇬 SG Example"}
        with self.assertRaisesRegex(RuntimeError, "SG.*172\\.64\\.146\\.192"):
            push.assert_region_preflight_passed(
                region,
                ["104.21.37.203", "172.64.146.192"],
                {
                    "104.21.37.203": push.AuditResult("PASS", "61"),
                    "172.64.146.192": push.AuditResult("FAIL", "0 (timeout)"),
                },
            )


class ManagedSelectionTests(unittest.TestCase):
    """Pin the remaining pure selection contract; execution lives in test_push_execution."""

    def test_duplicate_prefers_the_referenced_node(self) -> None:
        """Keeping the referenced copy means the repair needs no profile write."""
        referenced = managed_node("kept", "🇭🇰 HK Example CM")
        duplicate = managed_node("leaked", "🇭🇰 HK Example CM")

        keep, reclaim = push.select_managed_by_name(
            [duplicate, referenced], {"kept"}, {"🇭🇰 HK Example CM"}
        )

        self.assertEqual(keep["🇭🇰 HK Example CM"].id, "kept")
        self.assertEqual([node.id for node in reclaim], ["leaked"])

    def test_node_with_an_unwanted_name_is_reclaimed(self) -> None:
        """A managed name no longer in the desired set must not linger."""
        wanted = managed_node("wanted", "🇭🇰 HK Example CM")
        retired = managed_node("retired", "🇭🇰 HK Example CM9")

        keep, reclaim = push.select_managed_by_name(
            [wanted, retired], {"wanted", "retired"}, {"🇭🇰 HK Example CM"}
        )

        self.assertEqual(list(keep), ["🇭🇰 HK Example CM"])
        self.assertEqual([node.id for node in reclaim], ["retired"])



if __name__ == "__main__":
    unittest.main()
