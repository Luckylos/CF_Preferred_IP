"""Session-wide egress choke for the test suite.

A unit test that forgets to patch one MiSub helper must not be able to reach the
live API. That is not hypothetical: a RED run of this suite called push.main()
without patching create_managed_node and created 12 real manual nodes in
production MiSub, plus a leftover profile. Relying on every test to remember
every patch is what failed, so egress is blocked in-process instead.

Scope, deliberately narrow:

  * socket.connect / connect_ex to a non-local address is blocked. That is the
    single choke point every MiSub API call passes through (urllib -> socket).
  * subprocess is blocked ONLY for the scripts that do their own networking
    (verify_vless.sh, xray). Several tests in this suite legitimately shell out
    to local tools (awk, findmnt, bash -n, jq), so a blanket process block would
    break real coverage without adding safety: a child process has its own
    address space and never passes through the socket guard above anyway.

The failure is deliberately a RuntimeError and NOT an OSError: api_request()
swallows OSError/URLError and returns None, so an OSError-derived guard would be
absorbed and would hide the very accident this exists to prevent.

There is no opt-out. Real-API acceptance runs as a standalone script outside
pytest, so nothing in this suite has a legitimate reason to reach the network.
"""

from __future__ import annotations

import socket
import subprocess
from pathlib import Path
from typing import Any

# AF_UNIX never leaves the host, and local tooling may legitimately use it.
_LOCAL_FAMILIES = {getattr(socket, "AF_UNIX", None)} - {None}
_LOCAL_HOSTS = {"127.0.0.1", "::1", "localhost"}

# Scripts that open their own sockets, so an in-process guard cannot see them.
_NETWORK_SCRIPTS = ("verify_vless.sh", "xray")


class NetworkBlocked(RuntimeError):
    """Raised when a test tries to reach the network."""


def _fail(what: str) -> NetworkBlocked:
    return NetworkBlocked(
        f"blocked {what} during tests: a MiSub helper was left unpatched. "
        "Patch the helper (api_request, create_managed_node, delete_nodes, "
        "bind_profile_refs, run_all_region_preflights, ...) instead of letting "
        "the test reach the live API."
    )


def _is_local(address: Any) -> bool:
    host = address[0] if isinstance(address, tuple) and address else address
    return isinstance(host, str) and host in _LOCAL_HOSTS


_real_connect = socket.socket.connect
_real_connect_ex = socket.socket.connect_ex
_real_popen_init = subprocess.Popen.__init__


def _guard_connect(self: socket.socket, address: Any) -> Any:
    if self.family in _LOCAL_FAMILIES or _is_local(address):
        return _real_connect(self, address)
    raise _fail(f"connect to {address!r}")


def _guard_connect_ex(self: socket.socket, address: Any) -> Any:
    if self.family in _LOCAL_FAMILIES or _is_local(address):
        return _real_connect_ex(self, address)
    raise _fail(f"connect_ex to {address!r}")


def _is_syntax_check_only(parts: list[str]) -> bool:
    """`bash -n script` parses without executing, so it cannot open a socket.

    Several tests assert the shell scripts parse. Naming a network script in
    argv is therefore not evidence that anything will run.
    """
    if not parts:
        return False
    shell = Path(parts[0]).name
    return shell in {"bash", "sh", "dash", "zsh"} and "-n" in parts[1:]


def _guard_popen(self: subprocess.Popen, *args: Any, **kwargs: Any) -> None:
    argv = kwargs.get("args", args[0] if args else "")
    parts = [argv] if isinstance(argv, str) else [str(part) for part in argv]
    flat = " ".join(parts)
    if not _is_syntax_check_only(parts) and any(
        script in flat for script in _NETWORK_SCRIPTS
    ):
        raise _fail(f"subprocess {flat!r}")
    _real_popen_init(self, *args, **kwargs)


socket.socket.connect = _guard_connect  # type: ignore[method-assign]
socket.socket.connect_ex = _guard_connect_ex  # type: ignore[method-assign]
subprocess.Popen.__init__ = _guard_popen  # type: ignore[method-assign]
