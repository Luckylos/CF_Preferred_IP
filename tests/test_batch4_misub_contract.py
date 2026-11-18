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
import tempfile
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
TEST_UUID = "00000000-0000-4000-8000-000000000000"
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


def _run_push(
    fake: FakeMiSub,
    *,
    pending_path: Path | None = None,
) -> None:
    pending_patch = (
        patch.object(push, "PENDING_RECONCILE_FILE", pending_path, create=True)
        if pending_path is not None
        else patch.object(push, "PENDING_RECONCILE_FILE", None, create=True)
    )
    with (
        pending_patch,
        patch.object(push, "api_request", side_effect=fake.request),
        patch.object(push, "read_best_ips", return_value=list(NEW_IPS)),
        patch.object(push, "run_all_region_preflights"),
        patch.object(push, "get_vless_uuid", return_value=TEST_UUID),
        patch.object(push.time, "sleep"),
        patch("sys.stdout", new_callable=io.StringIO),
        patch("sys.stderr", new_callable=io.StringIO),
    ):
        push.main()


class ReadStateContractTests(unittest.TestCase):
    def test_transport_failure_is_unknown_and_does_not_change_profile(self) -> None:
        """Given a transient JP read failure, Then profile refs stay byte-for-byte equal."""
        fake = _build_fake()
        before = fake.profile_refs(PROFILE_ID)
        original_request = fake.request

        def request(method: str, path: str, data: object = None):
            if path == "/manual-nodes/preserved-jp-1":
                return None
            return original_request(method, path, data)

        with (
            patch.object(push, "api_request", side_effect=request),
            patch.object(push, "read_best_ips", return_value=list(NEW_IPS)),
            patch.object(push, "run_all_region_preflights"),
            patch.object(push, "get_vless_uuid", return_value=TEST_UUID),
            patch.object(push.time, "sleep"),
            patch("sys.stdout", new_callable=io.StringIO),
            patch("sys.stderr", new_callable=io.StringIO),
            self.assertRaisesRegex(RuntimeError, r"(?i)unknown|temporary|refus"),
        ):
            push.main()

        self.assertEqual(fake.profile_refs(PROFILE_ID), before)
        self.assertEqual(
            [call for call in fake.calls if call == ("PATCH", f"/profiles/{PROFILE_ID}")],
            [],
        )

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
            self.assertIsNone(push.get_manual_node("missing"))

        with (
            patch.object(push, "api_request", return_value=None),
            self.assertRaisesRegex(RuntimeError, r"(?i)unknown|temporary"),
        ):
            push.get_manual_node("uncertain")

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
                outcome = push.lookup_manual_node("uncertain")
                self.assertIs(outcome.state, push.NodeLookupState.UNKNOWN)
                with self.assertRaises(push.UnknownNodeLookup):
                    push.get_manual_node("uncertain")

    def test_each_unknown_read_preserves_profile_and_blocks_writes(self) -> None:
        """Every ambiguous read must stop reconcile before DELETE or profile PATCH."""
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
            ("malformed node", {"success": True, "data": {"id": "preserved-jp-1"}}),
        ]
        with tempfile.TemporaryDirectory() as raw_tmp:
            pending = Path(raw_tmp) / "pending.json"
            for label, failure in cases:
                with self.subTest(case=label):
                    fake = _build_fake()
                    before = fake.profile_refs(PROFILE_ID)
                    original_request = fake.request

                    def request(
                        method: str,
                        path: str,
                        data: object = None,
                        *,
                        ambiguous: dict[str, Any] | None = failure,
                        base_request=original_request,
                    ):
                        if path == "/manual-nodes/preserved-jp-1":
                            return ambiguous
                        return base_request(method, path, data)

                    with (
                        patch.object(push, "PENDING_RECONCILE_FILE", pending, create=True),
                        patch.object(push, "api_request", side_effect=request),
                        patch.object(push, "read_best_ips", return_value=list(NEW_IPS)),
                        patch.object(push, "run_all_region_preflights"),
                        patch.object(push, "get_vless_uuid", return_value=TEST_UUID),
                        patch.object(push.time, "sleep"),
                        patch("sys.stdout", new_callable=io.StringIO),
                        patch("sys.stderr", new_callable=io.StringIO),
                        self.assertRaisesRegex(RuntimeError, r"(?i)unknown|refus"),
                    ):
                        push.main()

                    self.assertEqual(fake.profile_refs(PROFILE_ID), before)
                    self.assertEqual(
                        [
                            call
                            for call in fake.calls
                            if call[0] == "DELETE"
                            or (call[0] == "PATCH" and call[1].startswith("/profiles/"))
                        ],
                        [],
                    )

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


class ForeignReferenceContractTests(unittest.TestCase):
    def test_fresh_foreign_reference_is_preserved_when_cached_row_omits_it(self) -> None:
        """Given a stale foreign collection row, the referenced node is kept, not deleted.

        Referencing managed nodes from another profile is an intended setup, so
        the push proceeds and only the referenced node is spared from reclaim.
        """
        with patch.object(push, "get_vless_uuid", return_value=TEST_UUID):
            old_urls = push.expected_managed_urls(OLD_IPS)
        existing = [
            push.ManagedNode(
                f"managed-{index}",
                name,
                old_urls[name],
            )
            for index, name in enumerate(MANAGED_NAMES)
        ]
        duplicate = push.ManagedNode(
            "foreign-duplicate",
            MANAGED_NAMES[0],
            old_urls[MANAGED_NAMES[0]],
        )
        target_refs = [node.id for node in existing]
        profile_rows = [
            {
                "id": PROFILE_ID,
                "name": push.PROFILE_NAME,
                "manualNodeIds": target_refs,
            },
            {
                "id": "foreign-profile",
                "name": "Other user",
                # Cached collection is stale and omits the live duplicate ref.
                "manualNodeIds": [],
            },
        ]
        by_id = {node.id: node for node in [*existing, duplicate]}

        def fresh_refs(profile_id: str) -> list[str]:
            if profile_id == "foreign-profile":
                return [duplicate.id]
            return list(target_refs)

        with (
            patch.object(push, "read_best_ips", return_value=list(NEW_IPS)),
            patch.object(push, "run_all_region_preflights"),
            patch.object(push, "list_managed_nodes", return_value=[*existing, duplicate]),
            patch.object(push, "list_profiles", return_value=profile_rows),
            patch.object(push, "get_profile_refs", side_effect=fresh_refs),
            patch.object(push, "get_manual_node", side_effect=by_id.get),
            patch.object(push, "delete_nodes") as delete_nodes,
            patch.object(
                push,
                "update_managed_node_url",
                side_effect=lambda node, url: push.ManagedNode(node.id, node.name, url),
            ),
            patch.object(push, "bind_profile_refs"),
            patch.object(push, "verify_final_state"),
        ):
            push.main()

        deleted = [node.id for call in delete_nodes.call_args_list for node in call.args[0]]
        self.assertNotIn(duplicate.id, deleted, "the node another profile references must not be deleted")

    def test_unknown_foreign_profile_read_blocks_reclaim(self) -> None:
        """An unavailable foreign profile read must be a safety stop."""
        fake = _build_fake()
        with patch.object(push, "get_vless_uuid", return_value=TEST_UUID):
            duplicate_url = push.build_vless_url(
                _region_for_name(MANAGED_NAMES[0]), OLD_IPS[0], "CM"
            )
        fake.subs["foreign-duplicate"] = {
            "id": "foreign-duplicate",
            "name": MANAGED_NAMES[0],
            "url": duplicate_url,
            "enabled": True,
            "sortIndex": 99,
        }
        fake.profiles["foreign-profile"] = {
            "id": "foreign-profile",
            "name": "Other user",
            "manualNodes": [],
        }
        before = fake.profile_refs(PROFILE_ID)
        original_request = fake.request

        def request(method: str, path: str, data: object = None):
            if path == "/profiles/foreign-profile":
                return None
            return original_request(method, path, data)

        with (
            patch.object(push, "api_request", side_effect=request),
            patch.object(push, "read_best_ips", return_value=list(NEW_IPS)),
            patch.object(push, "run_all_region_preflights"),
            patch.object(push, "get_vless_uuid", return_value=TEST_UUID),
            patch.object(push.time, "sleep"),
            patch("sys.stdout", new_callable=io.StringIO),
            patch("sys.stderr", new_callable=io.StringIO),
            self.assertRaisesRegex(RuntimeError, r"(?i)fresh-read|reclaim"),
        ):
            push.main()

        self.assertEqual(fake.profile_refs(PROFILE_ID), before)
        self.assertNotIn(
            ("DELETE", "/manual-nodes/foreign-duplicate"),
            fake.calls,
        )


class PartialPatchRecoveryTests(unittest.TestCase):
    def test_nth_patch_failure_leaves_secret_free_pending_and_next_run_converges(
        self,
    ) -> None:
        """Given Nth PATCH fails, Then pending is observable and retry converges."""
        with tempfile.TemporaryDirectory() as raw_tmp:
            self._run_nth_patch_failure_scenario(Path(raw_tmp) / "pending.json")

    def _run_nth_patch_failure_scenario(self, pending: Path) -> None:
        """Execute the two-run partial PATCH scenario in a private directory."""
        fake = _build_fake()
        original_request = fake.request
        patch_count = 0
        fail_once = True

        def request(method: str, path: str, data: object = None):
            nonlocal patch_count
            if method == "PATCH" and path.startswith("/manual-nodes/"):
                patch_count += 1
                if fail_once and patch_count == 2:
                    return None
            return original_request(method, path, data)

        with (
            patch.object(push, "api_request", side_effect=request),
            patch.object(push, "read_best_ips", return_value=list(NEW_IPS)),
            patch.object(push, "run_all_region_preflights"),
            patch.object(push, "get_vless_uuid", return_value=TEST_UUID),
            patch.object(push.time, "sleep"),
            patch.object(push, "PENDING_RECONCILE_FILE", pending, create=True),
            patch("sys.stdout", new_callable=io.StringIO),
            patch("sys.stderr", new_callable=io.StringIO),
            self.assertRaises(RuntimeError),
        ):
            push.main()

        self.assertTrue(pending.exists(), "a partial external reconcile needs a durable marker")
        pending_text = pending.read_text(encoding="utf-8")
        pending_data = json.loads(pending_text)
        self.assertEqual(pending_data["version"], 1)
        self.assertNotIn(TEST_UUID, pending_text, "pending state must not persist the VLESS UUID")
        self.assertNotIn("desired_urls", pending_data, "pending state must not persist credential-bearing URLs")

        fail_once = False
        with (
            patch.object(push, "api_request", side_effect=request),
            patch.object(push, "read_best_ips", return_value=list(NEW_IPS)),
            patch.object(push, "run_all_region_preflights"),
            patch.object(push, "get_vless_uuid", return_value=TEST_UUID),
            patch.object(push.time, "sleep"),
            patch.object(push, "PENDING_RECONCILE_FILE", pending, create=True),
            patch("sys.stdout", new_callable=io.StringIO),
            patch("sys.stderr", new_callable=io.StringIO),
        ):
            push.main()

        self.assertFalse(pending.exists(), "successful final verification must clear pending state")
        managed = [node for node in fake.subs.values() if push.is_managed_name(str(node.get("name", "")))]
        with patch.object(push, "get_vless_uuid", return_value=TEST_UUID):
            expected_urls = push.expected_managed_urls(NEW_IPS)
        self.assertEqual(
            {str(node["name"]): str(node["url"]) for node in managed},
            expected_urls,
        )
        self.assertEqual(len(fake.profile_refs(PROFILE_ID)), 8)


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
                {"name": "🇭🇰 HK Senior CM", "url": "vless://safe@example"},
            )

        self.assertIsNone(result, "ambiguous POST must fail closed without idempotency")
        self.assertEqual(len(calls), 1)
        self.assertEqual(len(commits), 1)

    def test_response_loss_does_not_create_duplicate_across_cached_retry(self) -> None:
        """A committed POST hidden by collection cache must not be issued twice."""
        now = [0.0]
        fake = _build_fake(
            isolate_router=lambda method, path: (
                "iso-writer" if method == "POST" else "iso-reader"
            ),
            clock=lambda: now[0],
        )
        missing_id = "managed-0"
        missing_name = next(
            name for name in MANAGED_NAMES if fake.subs[missing_id]["name"] == name
        )
        fake.subs.pop(missing_id)
        fake.profiles[PROFILE_ID]["manualNodes"] = [
            node_id for node_id in fake.profile_refs(PROFILE_ID) if node_id != missing_id
        ]
        original_request = fake.request
        post_count = 0

        def request(method: str, path: str, data: object = None):
            nonlocal post_count
            if method == "POST" and path == "/manual-nodes":
                post_count += 1
                response = original_request(method, path, data)
                if post_count == 1:
                    # The provider committed, but the client lost the response.
                    return None
                return response
            return original_request(method, path, data)

        def run_once(pending: Path) -> None:
            with (
                patch.object(push, "PENDING_RECONCILE_FILE", pending, create=True),
                patch.object(push, "api_request", side_effect=request),
                patch.object(push, "read_best_ips", return_value=list(NEW_IPS)),
                patch.object(push, "run_all_region_preflights"),
                patch.object(push, "get_vless_uuid", return_value=TEST_UUID),
                patch.object(push.time, "sleep"),
                patch("sys.stdout", new_callable=io.StringIO),
                patch("sys.stderr", new_callable=io.StringIO),
            ):
                push.main()

        with tempfile.TemporaryDirectory() as raw_tmp:
            pending = Path(raw_tmp) / "pending.json"
            with self.assertRaises(RuntimeError):
                run_once(pending)
            self.assertTrue(pending.exists())

            # The reader isolate still serves its pre-create collection snapshot;
            # the pending create must fail closed rather than POST again.
            with self.assertRaisesRegex(RuntimeError, r"(?i)duplicate|pending"):
                run_once(pending)

            # Once the collection TTL has elapsed, the committed node becomes
            # discoverable and the same pending run can converge without POST.
            now[0] = 31.0
            run_once(pending)

        same_name = [
            node for node in fake.subs.values() if node.get("name") == missing_name
        ]
        self.assertEqual(
            len(same_name),
            1,
            "a response-loss retry must converge to one managed node, not two POST commits",
        )
        self.assertEqual(post_count, 1)


if __name__ == "__main__":
    unittest.main()
