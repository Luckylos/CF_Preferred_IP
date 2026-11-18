#!/usr/bin/env python3
"""The egress guard in conftest.py is itself load-bearing, so it is tested.

A RED run of this suite once called push.main() without patching
create_managed_node and created 12 real manual nodes in production MiSub. The
guard exists so that accident is structurally impossible. A guard nobody
verifies is worse than none, because it invites trust it has not earned.
"""

from __future__ import annotations

import importlib.util
import io
import socket
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

import conftest

MODULE_PATH = Path(__file__).resolve().parents[1] / "push_to_misub.py"
SPEC = importlib.util.spec_from_file_location("push_to_misub", MODULE_PATH)
assert SPEC and SPEC.loader
push = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = push
SPEC.loader.exec_module(push)


class NetworkGuardTests(unittest.TestCase):
    def test_remote_connect_is_blocked(self) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.addCleanup(sock.close)

        with self.assertRaises(conftest.NetworkBlocked):
            sock.connect(("104.18.0.107", 443))

    def test_loopback_stays_allowed(self) -> None:
        """Local tooling must keep working; the guard is not a blanket ban."""
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.addCleanup(listener.close)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)

        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.addCleanup(client.close)
        client.connect(listener.getsockname())

    def test_api_request_does_not_swallow_the_guard(self) -> None:
        """The property that makes the guard work at all.

        api_request() catches URLError/OSError and returns None, so an
        OSError-derived guard would be absorbed and the run would look like a
        harmless API failure. NetworkBlocked is a RuntimeError precisely so an
        unpatched helper aborts the test loudly.
        """
        self.assertFalse(issubclass(conftest.NetworkBlocked, OSError))

        with (
            patch.object(push, "get_misub_token", return_value="test-token"),
            patch("sys.stderr", new_callable=io.StringIO),
        ):
            with self.assertRaises(conftest.NetworkBlocked):
                push.api_request("GET", "/manual-nodes")

    def test_unpatched_main_cannot_reach_the_live_api(self) -> None:
        """The exact accident: one helper left unpatched, everything else real."""
        with (
            patch.object(push, "read_best_ips", return_value=["1.1.1.1", "2.2.2.2", "3.3.3.3"]),
            patch.object(push, "run_all_region_preflights"),
            patch.object(push, "get_misub_token", return_value="test-token"),
            patch("sys.stderr", new_callable=io.StringIO),
        ):
            with self.assertRaises(conftest.NetworkBlocked):
                push.main()

    def test_executing_a_networking_script_is_blocked(self) -> None:
        """verify_vless.sh opens its own sockets, so the guard stops the process."""
        with self.assertRaises(conftest.NetworkBlocked):
            subprocess.run([str(MODULE_PATH.with_name("verify_vless.sh")), "--screen"])

    def test_shell_syntax_check_stays_allowed(self) -> None:
        """`bash -n` parses without executing, so it cannot open a socket."""
        result = subprocess.run(
            ["bash", "-n", str(MODULE_PATH.with_name("verify_vless.sh"))],
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
