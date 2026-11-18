#!/usr/bin/env python3
"""Regression tests for fail-closed VLESS publish preflight recovery."""

from __future__ import annotations

import importlib.util
import io
import tempfile
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

TESTS_DIR = Path(__file__).resolve().parent
MODULE_PATH = TESTS_DIR.parent / "push_to_misub.py"
SPEC = importlib.util.spec_from_file_location("push_to_misub_preflight", MODULE_PATH)
assert SPEC and SPEC.loader
push = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = push
SPEC.loader.exec_module(push)


class AuditResultParsingTests(unittest.TestCase):
    def test_parser_preserves_safe_detail_and_marks_missing_as_unknown(self) -> None:
        output = """
=== AUDIT RESULTS ===
  1.1.1.1  PASS 48
  2.2.2.2  FAIL 0 (timeout)
  3.3.3.3  PARTIAL 203 (partial_success=2/3 failed=1)
"""

        results = push.parse_audit_results(
            output, ["1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4"]
        )

        self.assertEqual(results["1.1.1.1"].status, "PASS")
        self.assertEqual(results["1.1.1.1"].detail, "48")
        self.assertEqual(results["2.2.2.2"].status, "FAIL")
        self.assertEqual(results["2.2.2.2"].detail, "0 (timeout)")
        self.assertEqual(results["3.3.3.3"].status, "PARTIAL")
        self.assertEqual(
            results["3.3.3.3"].detail,
            "203 (partial_success=2/3 failed=1)",
        )
        self.assertEqual(results["4.4.4.4"].status, "UNKNOWN")
        self.assertEqual(results["4.4.4.4"].detail, "missing audit result")


class RecoveryPredicateTests(unittest.TestCase):
    def test_recovery_requires_exactly_two_complete_passes(self) -> None:
        self.assertTrue(
            push.recovery_passed(
                [push.AuditResult("PASS", "58"), push.AuditResult("PASS", "53")]
            )
        )
        self.assertFalse(push.recovery_passed([push.AuditResult("PASS", "58")]))
        self.assertFalse(
            push.recovery_passed(
                [push.AuditResult("PASS", "58"), push.AuditResult("PARTIAL", "203")]
            )
        )
        self.assertFalse(
            push.recovery_passed(
                [push.AuditResult("PASS", "58"), push.AuditResult("UNKNOWN", "timeout")]
            )
        )


class PreflightSafetyTests(unittest.TestCase):
    def test_region_preflight_requires_audit_result_objects_to_be_pass(self) -> None:
        region = {"key": "HK"}
        results = {
            "1.1.1.1": push.AuditResult("PASS", "48"),
            "2.2.2.2": push.AuditResult("FAIL", "0 (timeout)"),
        }

        with self.assertRaisesRegex(RuntimeError, r"HK region preflight failed: 2\.2\.2\.2=FAIL"):
            push.assert_region_preflight_passed(region, ["1.1.1.1", "2.2.2.2"], results)

    def test_transient_failure_recovers_only_after_two_same_template_passes(self) -> None:
        region = {"key": "HK"}
        ips = ["1.1.1.1", "2.2.2.2"]
        calls: list[tuple[str, list[str], str]] = []
        outcomes = iter(
            [
                (
                    {
                        ip: push.AuditResult("PASS", "48")
                        for ip in ips[:1]
                    }
                    | {ips[1]: push.AuditResult("FAIL", "0 (timeout)")},
                    True,
                ),
                ({ips[1]: push.AuditResult("PASS", "58")}, True),
                ({ips[1]: push.AuditResult("PASS", "53")}, True),
            ]
        )

        def fake_audit(region_arg, ips_arg, _temp_path, attempt):
            calls.append((region_arg["key"], list(ips_arg), attempt))
            return next(outcomes)

        with tempfile.TemporaryDirectory() as raw:
            verifier = Path(raw) / "verify_vless.sh"
            verifier.write_text("#!/bin/sh\n")
            with (
                patch.object(push, "VERIFY_SCRIPT", verifier),
                patch.object(push, "_run_region_audit", side_effect=fake_audit),
                patch("sys.stdout", new_callable=io.StringIO) as stdout,
            ):
                push.run_region_preflight(region, ips)

        self.assertEqual(calls[0][0], "HK")
        self.assertEqual(calls[0][1], ips)
        self.assertEqual(calls[1][0], calls[2][0], "retries must keep the same template")
        self.assertEqual(calls[1][1], [ips[1]])
        self.assertEqual(calls[2][1], [ips[1]])
        self.assertIn("transient-recovered", stdout.getvalue())

    def test_recovery_failure_remains_fail_closed(self) -> None:
        region = {"key": "SG"}
        ip = "2.2.2.2"
        outcomes = iter(
            [
                ({ip: push.AuditResult("FAIL", "0 (timeout)")}, True),
                ({ip: push.AuditResult("PASS", "111")}, True),
                ({ip: push.AuditResult("PARTIAL", "182 (partial_success=2/3")}, True),
            ]
        )

        with tempfile.TemporaryDirectory() as raw:
            verifier = Path(raw) / "verify_vless.sh"
            verifier.write_text("#!/bin/sh\n")
            with (
                patch.object(push, "VERIFY_SCRIPT", verifier),
                patch.object(push, "_run_region_audit", side_effect=lambda *args: next(outcomes)),
            ):
                with self.assertRaisesRegex(RuntimeError, r"SG region preflight failed: 2\.2\.2\.2=FAIL"):
                    push.run_region_preflight(region, [ip])

    def test_main_does_not_call_misub_when_preflight_fails(self) -> None:
        with (
            patch.object(push, "read_best_ips", return_value=["1.1.1.1", "2.2.2.2", "3.3.3.3"]),
            patch.object(push, "run_all_region_preflights", side_effect=RuntimeError("preflight failed")),
            patch.object(push, "api_request") as api_request,
        ):
            with self.assertRaisesRegex(RuntimeError, "preflight failed"):
                push.main()
        api_request.assert_not_called()


if __name__ == "__main__":
    unittest.main()
