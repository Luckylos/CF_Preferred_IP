"""Batch 4 MiSub reconcile contracts.

These scenarios exercise the production ``push_to_misub.main`` path against the
faithful local fake API.  They deliberately do not call MiSub or read any
production credential.  The desired contracts are observable at the profile,
manual-node, and HTTP-request boundaries:

* a failed per-ID read is UNKNOWN, not a confirmed missing node;
* a fresh foreign-profile reference blocks reclaim;
* a multi-PATCH failure leaves a durable, secret-free pending marker and a later
  run can converge;
* an ambiguous POST response is not blindly retried without provider idempotency.
"""

from __future__ import annotations

import importlib.util
import io
import json
import sys
import unittest
import urllib.error
import urllib.request
from email.message import Message
from pathlib import Path
from typing import Any, Self
from unittest.mock import patch

TESTS_DIR = Path(__file__).resolve().parent
if str(TESTS_DIR) not in sys.path:
    sys.path.insert(0, str(TESTS_DIR))

from misub_fake_api import FakeMiSub

MODULE_PATH = TESTS_DIR.parent / "push_to_misub.py"
SPEC = importlib.util.spec_from_file_location("push_to_misub_batch4", MODULE_PATH)
assert SPEC and SPEC.loader
push = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = push
SPEC.loader.exec_module(push)

PROFILE_ID = "profile-target"
TEST_UUID = "00000000-0000-4000-8000-000000000002"
OLD_IPS = ["9.9.9.1", "9.9.9.2", "9.9.9.3"]
NEW_IPS = ["104.18.0.107", "104.21.47.37", "104.18.34.253"]
MANAGED_NAMES = [
    f"{region['prefix']} {suffix}"
    for region in push.REGIONS
    for suffix in push.SUFFIXES
]


def _region_for_name(name: str) -> dict[str, object]:
    for region in push.REGIONS:
        if name.startswith(str(region["prefix"])):
            return region
    raise AssertionError(name)


def _build_fake(**kwargs: Any) -> FakeMiSub:
    subscriptions: list[dict[str, object]] = [
        {
            "id": "preserved-jp-1",
            "name": "🇯🇵 JP AZ 01",
            "url": "vless://x@jp1.example:443#JP1",
        },
        {
            "id": "preserved-jp-2",
            "name": "🇯🇵 JP AZ 02",
            "url": "vless://x@jp2.example:443#JP2",
        },
    ]
    with patch.object(push, "get_vless_uuid", return_value=TEST_UUID):
        for index, name in enumerate(MANAGED_NAMES):
            suffix = name.rsplit(" ", 1)[1]
            subscriptions.append(
                {
                    "id": f"managed-{index}",
                    "name": name,
                    "url": push.build_vless_url(
                        _region_for_name(name),
                        OLD_IPS[push.SUFFIXES.index(suffix)],
                        suffix,
                    ),
                }
            )
    managed_ids = [f"managed-{index}" for index in range(len(MANAGED_NAMES))]
    profiles = [
        {
            "id": PROFILE_ID,
            "name": push.PROFILE_NAME,
            "manualNodes": ["preserved-jp-1", "preserved-jp-2", *managed_ids],
        }
    ]
    return FakeMiSub(subscriptions=subscriptions, profiles=profiles, **kwargs)


def _lookup_execution():
    # Pin the irreducible FOUND/MISSING/UNKNOWN contract below the execution seam.
    return push._PushExecution(lambda: {}, push.api_request, Path("unused-pending.json"), lambda seconds: None)


class ReadStateContractTests(unittest.TestCase):


    def test_authoritative_404_is_missing_but_transport_failure_is_unknown(self) -> None:
        """Only an explicit 404 may authorize dropping a stale id."""
        with patch.object(
            push,
            "api_request",
            return_value={
                "success": False,
                "error": {"status": 404, "code": "manual_node_not_found"},
            },
        ):
            self.assertIsNone(_lookup_execution().get_manual_node("missing"))

        with (
            patch.object(push, "api_request", return_value=None),
            self.assertRaisesRegex(RuntimeError, r"(?i)unknown|temporary"),
        ):
            _lookup_execution().get_manual_node("uncertain")

    def test_error_matrix_is_unknown_except_for_authoritative_404(self) -> None:
        """400/429/5xx and malformed node data must never mean ``MISSING``."""
        cases: list[tuple[str, dict[str, Any] | None]] = [
            (
                "400",
                {"success": False, "error": {"status": 400, "code": "bad_request"}},
            ),
            (
                "429",
                {"success": False, "error": {"status": 429, "code": "rate_limited"}},
            ),
            (
                "500",
                {"success": False, "error": {"status": 500, "code": "server_error"}},
            ),
            (
                "503",
                {"success": False, "error": {"status": 503, "code": "unavailable"}},
            ),
            ("transport failure", None),
            ("malformed node", {"success": True, "data": {"id": "uncertain"}}),
        ]
        for label, response in cases:
            with (
                self.subTest(case=label),
                patch.object(push, "api_request", return_value=response),
            ):
                outcome = _lookup_execution().lookup_manual_node("uncertain")
                self.assertIs(outcome.state, push.NodeLookupState.UNKNOWN)
                with self.assertRaises(push.UnknownNodeLookup):
                    _lookup_execution().get_manual_node("uncertain")


    def test_retryable_read_exhaustion_is_unknown_and_bounded(self) -> None:
        """GET 503 retries are bounded, then become UNKNOWN rather than missing."""
        calls: list[urllib.request.Request] = []

        def urlopen(
            request: urllib.request.Request, timeout: float
        ) -> object:
            calls.append(request)
            raise urllib.error.HTTPError(
                request.full_url,
                503,
                "unavailable",
                Message(),
                io.BytesIO(b"{\"error\":{\"code\":\"unavailable\"}}"),
            )

        with (
            patch.object(push.urllib.request, "urlopen", side_effect=urlopen),
            patch.object(push, "get_misub_token", return_value="test-token"),
            patch.object(push, "API_ATTEMPTS", 3),
            patch.object(push.time, "sleep"),
            patch("sys.stderr", new_callable=io.StringIO),
        ):
            response = push.api_request("GET", "/manual-nodes/uncertain")

        self.assertIsNone(response)
        self.assertEqual(len(calls), 3)

    def test_timeout_is_bounded_and_malformed_json_is_unknown(self) -> None:
        """Transport timeout retries are bounded; malformed JSON never becomes found."""
        timeout_calls: list[urllib.request.Request] = []

        def timeout_urlopen(
            request: urllib.request.Request, timeout: float
        ) -> object:
            timeout_calls.append(request)
            raise TimeoutError("simulated read timeout")

        with (
            patch.object(push.urllib.request, "urlopen", side_effect=timeout_urlopen),
            patch.object(push, "get_misub_token", return_value="test-token"),
            patch.object(push, "API_ATTEMPTS", 3),
            patch.object(push.time, "sleep"),
            patch("sys.stderr", new_callable=io.StringIO),
        ):
            timeout_response = push.api_request("GET", "/manual-nodes/uncertain")

        self.assertIsNone(timeout_response)
        self.assertEqual(len(timeout_calls), 3)

        class MalformedResponse:
            def __enter__(self) -> Self:
                return self

            def __exit__(self, *_args: object) -> None:
                return None

            def read(self) -> bytes:
                return b"not-json"

        malformed_calls: list[urllib.request.Request] = []

        def malformed_urlopen(
            request: urllib.request.Request, timeout: float
        ) -> MalformedResponse:
            malformed_calls.append(request)
            return MalformedResponse()

        with (
            patch.object(push.urllib.request, "urlopen", side_effect=malformed_urlopen),
            patch.object(push, "get_misub_token", return_value="test-token"),
            patch("sys.stderr", new_callable=io.StringIO),
        ):
            malformed_response = push.api_request("GET", "/manual-nodes/uncertain")

        self.assertIsNone(malformed_response)
        self.assertEqual(len(malformed_calls), 1)


class PostIdempotencyContractTests(unittest.TestCase):
    def test_response_loss_does_not_blindly_retry_post(self) -> None:
        """Given provider commit then connection loss, Then client sends one POST only."""
        calls: list[object] = []
        commits: list[dict[str, object]] = []

        class FakeResponse:
            def __enter__(self) -> Self:
                return self

            def __exit__(self, *_args: object) -> None:
                return None

            def read(self) -> bytes:
                return json.dumps(
                    {"success": True, "data": {"id": "created-after-retry"}}
                ).encode()

        def urlopen(request: urllib.request.Request, timeout: float) -> FakeResponse:
            calls.append(request)
            raw_data = request.data
            if not isinstance(raw_data, bytes):
                raise TypeError("test request body is not bytes")
            body = json.loads(raw_data.decode())
            commits.append(body)
            if len(calls) == 1:
                raise urllib.error.URLError("connection reset after provider commit")
            return FakeResponse()

        with (
            patch.object(push.urllib.request, "urlopen", side_effect=urlopen),
            patch.object(push, "get_misub_token", return_value="test-token"),
            patch.object(push, "API_ATTEMPTS", 3),
            patch("sys.stderr", new_callable=io.StringIO),
        ):
            result = push.api_request(
                "POST",
                "/manual-nodes",
                {"name": "🇭🇰 HK Example CM", "url": "vless://safe@example"},
            )

        self.assertIsNone(result, "ambiguous POST must fail closed without idempotency")
        self.assertEqual(len(calls), 1)
        self.assertEqual(len(commits), 1)


if __name__ == "__main__":
    unittest.main()
