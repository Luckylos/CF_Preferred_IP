#!/usr/bin/env python3
"""Push CFST best IPs to MiSub by updating managed nodes in place.

MiSub's storage layer reads collections through a 30s TTL cache and writes whole
rows back (functions/storage-adapter.js). Two of its routes therefore perform a
read-modify-write over a possibly stale snapshot, and each one caused a
production incident:

  DELETE /manual-nodes/:id  calls removeManualNodeIdFromProfiles(), which reads
      the CACHED profiles collection and writes back whole profile rows. Any
      profile reference added since that snapshot is silently reverted.
      On 2026-08-24 12:07 this reverted the 6 references the preceding bind had
      just committed: missing_profile=6, servable nodes fell from 8 to 2.

  PATCH /profiles/:id  validates incoming ids through getAllSubscriptions(),
      also CACHED. An isolate holding a pre-create snapshot rejects brand-new
      node ids with HTTP 400 manual_node_id_not_found, as seen at 02:03:42.

Both hazards are avoided by never replacing a node that already exists:

    reclaim unreferenced duplicates -> update managed URLs in place -> bind
    only when the reference set is actually wrong -> verify from fresh reads

PATCH /manual-nodes/:id reads by id (direct SQL, always fresh) and writes only
the subscription row, so it can never clobber a profile. In the steady state the
managed node ids and the profile reference set are already correct, so a routine
run issues no DELETE and no PATCH /profiles at all: it touches neither route
that can corrupt the profile, and client-visible node identity stays stable.

Deletes are confined to reclaiming unreferenced duplicates, and they all run
BEFORE any profile write, so a stale snapshot write-back has no committed
reference to revert. A node that another profile references is preserved rather
than reclaimed: referencing managed nodes from other profiles is an intended
setup, so its presence neither blocks the push nor makes the node a delete
candidate. Every verification reads per-id endpoints rather than the cached
collections, because only per-id reads are guaranteed fresh.

JP nodes are intentionally unmanaged here and remain in the profile as manually
maintained nodes.
"""

import ast
import functools
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, NotRequired, Protocol, TypedDict

from ip_validation import is_valid_ipv4

MISUB_BASE = "https://subscription.example.com/api/ext/v1"
DEFAULT_MISUB_TOKEN_FILE = "/opt/cfst/secrets/misub.env"
BEST_IPS_FILE = "/opt/cfst/best_ips.txt"
PENDING_RECONCILE_FILE = Path(
    os.environ.get(
        "MISUB_PENDING_RECONCILE_FILE",
        str(Path(BEST_IPS_FILE).with_name(".misub-reconcile-pending.json")),
    )
)
VERIFY_SCRIPT = Path(__file__).with_name("verify_vless.sh")
TOP_N = 3
CFST_NODE_SUFFIXES = {"CM", "CM2", "CM3"}
CFST_NODE_PREFIXES = {"🇭🇰 HK Example", "🇸🇬 SG Example"}
PROFILE_NAME = "CFST Example"
API_ATTEMPTS = 3
API_TIMEOUT_SECONDS = 30
VERIFY_TIMEOUT_SECONDS = 180
PREFLIGHT_RECOVERY_ATTEMPTS = 2
RETRYABLE_HTTP_STATUS = {429, 500, 502, 503, 504}
# MiSub can acknowledge a created node before its ID resolves in PATCH /profiles.
NODE_VISIBILITY_ATTEMPTS = 4
NODE_VISIBILITY_DELAY_SECONDS = 2.0
# A stale isolate snapshot expires within the 30s collection TTL, so a bounded
# retry is enough to ride out a manual_node_id_not_found rejection.
BIND_ATTEMPTS = 4
BIND_RETRY_DELAY_SECONDS = 5.0

CONFIG_FILE = Path(
    os.environ.get("CFST_CONFIG_FILE", str(Path(__file__).with_name("config.sh")))
)


class Region(TypedDict):
    prefix: str
    key: str
    query: str
    audit_key: str
    sni: str
    host: str
    path: str
    fp: str
    alpn: str
    legacy_insecure_flags: NotRequired[bool]


# QUERY is the subscription URL parameter string: pushing only substitutes the IP.
# AUDIT_KEY names the template whose NODE_* values verify_vless.sh probes with.
_TEMPLATE_FIELDS = (
    "KEY",
    "NAME_PREFIX",
    "QUERY",
    "AUDIT_KEY",
    "SNI",
    "HOST",
    "PATH",
    "FP",
    "ALPN",
    "LEGACY_INSECURE_FLAGS",
)
_TEMPLATE_ASSIGNMENT = re.compile(
    r"^\s*(CFST_TEMPLATE_(?:HK|SG|HT)_(?:KEY|NAME_PREFIX|QUERY|AUDIT_KEY|SNI|HOST|PATH|FP|ALPN|LEGACY_INSECURE_FLAGS))\s*=(.*)$"
)


def _parse_template_scalar(name: str, raw_value: str) -> str:
    value = raw_value.strip()
    if not value:
        raise RuntimeError(f"template config has empty {name}: {CONFIG_FILE}")
    if value[0] in {"'", '"'}:
        quote = value[0]
        closing = value.rfind(quote)
        suffix = value[closing + 1 :].strip()
        if closing == 0 or (suffix and not suffix.startswith("#")):
            raise RuntimeError(f"template config has invalid {name}: {CONFIG_FILE}")
        literal = value[: closing + 1]
        try:
            parsed = ast.literal_eval(literal)
        except (SyntaxError, ValueError) as exc:
            raise RuntimeError(f"template config has invalid {name}: {CONFIG_FILE}") from exc
        if not isinstance(parsed, str):
            raise RuntimeError(f"template config has invalid {name}: {CONFIG_FILE}")
        return parsed
    value = value.split("#", 1)[0].strip()
    if not re.fullmatch(r"[A-Za-z0-9_.:/?=-]+", value):
        raise RuntimeError(f"template config has invalid {name}: {CONFIG_FILE}")
    return value


def _read_template_values() -> dict[str, str]:
    try:
        text = CONFIG_FILE.read_text(encoding="utf-8")
    except OSError as exc:
        raise RuntimeError(f"cannot read template config: {CONFIG_FILE}") from exc

    values: dict[str, str] = {}
    for line in text.splitlines():
        match = _TEMPLATE_ASSIGNMENT.match(line)
        if not match:
            continue
        name = match.group(1)
        if name in values:
            raise RuntimeError(f"template config duplicates {name}: {CONFIG_FILE}")
        values[name] = _parse_template_scalar(name, match.group(2))
    return values


def _load_template_regions() -> list[Region]:
    values = _read_template_values()
    regions: list[Region] = []
    for key in ("HK", "SG", "HT"):
        prefix = f"CFST_TEMPLATE_{key}_"
        missing = [field for field in _TEMPLATE_FIELDS if f"{prefix}{field}" not in values]
        if missing:
            missing_names = ", ".join(f"{prefix}{field}" for field in missing)
            raise RuntimeError(f"template config is missing {missing_names}: {CONFIG_FILE}")

        template_key = values[f"{prefix}KEY"]
        if template_key != key:
            raise RuntimeError(f"template config key mismatch for {key}: {CONFIG_FILE}")
        name_prefix = values[f"{prefix}NAME_PREFIX"]
        query = values[f"{prefix}QUERY"]
        audit_key = values[f"{prefix}AUDIT_KEY"]
        sni = values[f"{prefix}SNI"]
        host = values[f"{prefix}HOST"]
        path = values[f"{prefix}PATH"]
        fp = values[f"{prefix}FP"]
        alpn = values[f"{prefix}ALPN"]
        legacy = values[f"{prefix}LEGACY_INSECURE_FLAGS"]
        if not name_prefix or any(char in name_prefix for char in "\r\n"):
            raise RuntimeError(f"template config has invalid {prefix}NAME_PREFIX: {CONFIG_FILE}")
        if not query or any(char.isspace() for char in query) or any(
            char in query for char in "#?"
        ):
            raise RuntimeError(f"template config has invalid {prefix}QUERY: {CONFIG_FILE}")
        if "type=" not in query:
            raise RuntimeError(f"template config has invalid {prefix}QUERY: {CONFIG_FILE}")
        if audit_key not in {"HK", "SG", "HT"}:
            raise RuntimeError(f"template config has invalid {prefix}AUDIT_KEY: {CONFIG_FILE}")
        if not re.fullmatch(r"[A-Za-z0-9.-]+", sni) or not re.fullmatch(r"[A-Za-z0-9.-]+", host):
            raise RuntimeError(f"template config has invalid {prefix}SNI/HOST: {CONFIG_FILE}")
        if not path.startswith("/") or any(char in path for char in "\r\n"):
            raise RuntimeError(f"template config has invalid {prefix}PATH: {CONFIG_FILE}")
        if not fp or any(char.isspace() for char in fp) or any(char in fp for char in "\r\n"):
            raise RuntimeError(f"template config has invalid {prefix}FP: {CONFIG_FILE}")
        if any(char in alpn for char in "\r\n"):
            raise RuntimeError(f"template config has invalid {prefix}ALPN: {CONFIG_FILE}")
        if legacy not in {"0", "1"}:
            raise RuntimeError(f"template config has invalid {prefix}LEGACY_INSECURE_FLAGS: {CONFIG_FILE}")

        region: Region = {
            "prefix": name_prefix,
            "key": template_key,
            "query": query,
            "audit_key": audit_key,
            "sni": sni,
            "host": host,
            "path": path,
            "fp": fp,
            "alpn": alpn,
            "legacy_insecure_flags": legacy == "1",
        }
        regions.append(region)
    return regions


REGIONS: list[Region] = _load_template_regions()
SUFFIXES: list[str] = ["CM", "CM2", "CM3"]
CFST_NODE_SUFFIXES = set(SUFFIXES)
CFST_NODE_PREFIXES = {region["prefix"] for region in REGIONS}


@dataclass(frozen=True)
class ManagedNode:
    id: str
    name: str
    url: str


class NodeLookupState(str, Enum):
    FOUND = "FOUND"
    MISSING = "MISSING"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class NodeLookup:
    state: NodeLookupState
    node: ManagedNode | None = None
    reason: str = ""


class UnknownNodeLookup(RuntimeError):
    """A node read failed without authoritative evidence that it is absent."""


@dataclass(frozen=True)
class NodeResolution:
    found: dict[str, ManagedNode]
    missing: set[str]
    unknown: dict[str, str]


@dataclass(frozen=True)
class AuditResult:
    """Safe, credential-free result emitted by one VLESS audit entry."""

    status: str
    detail: str = ""

    def summary(self) -> str:
        return " ".join(part for part in (self.status, self.detail) if part).strip()


DEFAULT_VLESS_SECRET_FILE = "/opt/cfst/secrets/vless.env"


@functools.lru_cache(maxsize=1)
def get_vless_uuid() -> str:
    """Load the node VLESS UUID from a mode-restricted env file.

    Same contract as get_misub_token(): the credential stays out of source and
    out of the broad cron environment, and the path stays overrideable through
    VLESS_SECRET_FILE for tests or a staged deployment.
    """
    path = Path(os.environ.get("VLESS_SECRET_FILE", DEFAULT_VLESS_SECRET_FILE))
    try:
        mode = stat.S_IMODE(path.stat().st_mode)
    except OSError as exc:
        raise RuntimeError(f"VLESS secret file is unavailable: {path}") from exc
    if mode & 0o077:
        raise RuntimeError(f"VLESS secret file must be private (0600 or stricter): {path}")

    values: list[str] = []
    try:
        for raw_line in path.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("VLESS_UUID="):
                value = line.partition("=")[2].strip()
                if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
                    value = value[1:-1]
                values.append(value)
    except OSError as exc:
        raise RuntimeError(f"VLESS secret file cannot be read: {path}") from exc

    if len(values) != 1 or not values[0]:
        raise RuntimeError(
            f"VLESS secret file must contain exactly one non-empty VLESS_UUID: {path}"
        )
    return values[0]

def get_misub_token() -> str:
    """Load the MiSub token from a mode-restricted env file.

    The token is intentionally not kept in the source or inherited from the
    broad cron environment.  The path remains overrideable for a test or a
    staged deployment through MISUB_TOKEN_FILE.
    """
    path = Path(os.environ.get("MISUB_TOKEN_FILE", DEFAULT_MISUB_TOKEN_FILE))
    try:
        mode = stat.S_IMODE(path.stat().st_mode)
    except OSError as exc:
        raise RuntimeError(f"MiSub token file is unavailable: {path}") from exc
    if mode & 0o077:
        raise RuntimeError(f"MiSub token file must be private (0600 or stricter): {path}")

    values: list[str] = []
    try:
        for raw_line in path.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("MISUB_TOKEN="):
                value = line.partition("=")[2].strip()
                if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
                    value = value[1:-1]
                values.append(value)
    except OSError as exc:
        raise RuntimeError(f"MiSub token file cannot be read: {path}") from exc

    if len(values) != 1 or not values[0]:
        raise RuntimeError(f"MiSub token file must contain exactly one non-empty MISUB_TOKEN: {path}")
    return values[0]


def api_request(method: str, path: str, data: Any = None) -> dict[str, Any] | None:
    body = json.dumps(data).encode() if data is not None else None
    for attempt in range(1, API_ATTEMPTS + 1):
        req = urllib.request.Request(f"{MISUB_BASE}{path}", data=body, method=method)
        req.add_header("Authorization", f"Bearer {get_misub_token()}")
        req.add_header("Content-Type", "application/json")
        req.add_header("User-Agent", "Mozilla/5.0 MiSub-Push/2.0")
        try:
            with urllib.request.urlopen(req, timeout=API_TIMEOUT_SECONDS) as resp:
                result = json.loads(resp.read())
                if not isinstance(result, dict):
                    raise TypeError("non-object JSON response")
                return result
        except urllib.error.HTTPError as exc:
            try:
                payload = json.loads(exc.read())
            except ValueError:
                payload = None
            detail = ""
            if isinstance(payload, dict):
                provider_error = payload.get("error")
                if isinstance(provider_error, dict):
                    code = str(provider_error.get("code", "")).strip()
                    message = str(provider_error.get("message", "")).strip()
                    detail = ": ".join(value for value in (code, message) if value)
            suffix = f" ({detail})" if detail else ""
            print(f"  API error {method} {path}: HTTP {exc.code}{suffix}", file=sys.stderr)
            if exc.code == 404:
                error_payload: dict[str, Any] = {"status": exc.code}
                if detail:
                    error_payload["detail"] = detail
                return {"success": False, "error": error_payload}
            if method.upper() == "POST" or (
                exc.code not in RETRYABLE_HTTP_STATUS or attempt == API_ATTEMPTS
            ):
                return None
        except (urllib.error.URLError, TimeoutError) as exc:
            print(f"  API error {method} {path}: {exc}", file=sys.stderr)
            if method.upper() == "POST" or attempt == API_ATTEMPTS:
                return None
        except (TypeError, ValueError) as exc:
            print(f"  API error {method} {path}: {exc}", file=sys.stderr)
            return None
        print(f"  Retrying {method} {path} ({attempt + 1}/{API_ATTEMPTS})", file=sys.stderr)
    return None


def require_success(response: dict[str, Any] | None, operation: str) -> dict[str, Any]:
    if not response or response.get("success") is not True:
        raise RuntimeError(f"MiSub operation failed: {operation}")
    return response


def read_best_ips() -> list[str]:
    ips: list[str] = []
    with open(BEST_IPS_FILE, encoding="utf-8") as handle:
        in_machine_block = False
        for raw_line in handle:
            line = raw_line.strip()
            if "BEST_IPS (machine-readable" in line:
                in_machine_block = True
                continue
            if in_machine_block:
                if line.startswith("#") or not line:
                    break
                if not is_valid_ipv4(line):
                    raise RuntimeError(f"invalid IPv4 in best_ips.txt: {line!r}")
                ips.append(line)
    if len(ips) < TOP_N:
        raise RuntimeError(f"only {len(ips)} IPs in best_ips.txt, need {TOP_N}")
    return ips[:TOP_N]


_HOSTNAME = re.compile(r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$")


def node_address(target: str) -> str:
    """节点地址既可以是优选 IP，也可以是稳定域名（DNS 只做指针）。"""
    if is_valid_ipv4(target):
        return target
    if _HOSTNAME.match(target):
        return target
    raise RuntimeError(f"invalid node address: {target!r}")


def swap_address(url: str, address: str) -> str:
    """只替换节点地址：凭据、传输参数、显示名全部保留。

    这些字段属于 MiSub 里那个节点；重建整条 URL 会覆盖它（HT 的 uuid 就与 HK/SG 不同）。
    """
    parts = urllib.parse.urlsplit(url)
    if parts.scheme != "vless" or not parts.username or not parts.hostname:
        raise RuntimeError(f"cannot read a vless node url: {url!r}")
    netloc = f"{parts.username}@{node_address(address)}"
    if parts.port:
        netloc += f":{parts.port}"
    return urllib.parse.urlunsplit((parts.scheme, netloc, parts.path, parts.query, parts.fragment))


def node_connection(url: str) -> tuple[str, str]:
    """(query, uuid) —— 用来按节点自己的凭据做 preflight。"""
    parts = urllib.parse.urlsplit(url)
    if parts.scheme != "vless" or not parts.username:
        raise RuntimeError(f"node url carries no vless credential: {url!r}")
    return parts.query, parts.username


def region_connection(region: Mapping[str, Any], managed: Mapping[str, "ManagedNode"]) -> tuple[str, str] | None:
    """该地区现有节点里的凭据；一个都没有时返回 None（交给模板兜底用于新建）。"""
    for suffix in SUFFIXES:
        node = managed.get(f"{region['prefix']} {suffix}")
        if node is not None:
            return node_connection(node.url)
    return None


def expected_managed_names() -> set[str]:
    return {f"{region['prefix']} {suffix}" for region in REGIONS for suffix in SUFFIXES}


def build_vless_url(region: Mapping[str, Any], ip: str, suffix: str) -> str:
    address = node_address(ip)
    query = region["query"]
    if not query or any(char.isspace() for char in query):
        raise RuntimeError(f"invalid vless query for region {region['key']}: {query!r}")
    name = f"{region['prefix']} {suffix}"
    return f"vless://{get_vless_uuid()}@{address}:443?{query}#{urllib.parse.quote(name)}"


def parse_audit_results(output: str, expected_ips: list[str]) -> dict[str, AuditResult]:
    """Extract status and safe timing/reason details from an audit block."""
    expected = set(expected_ips)
    results: dict[str, AuditResult] = {}
    in_results = False
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if line == "=== AUDIT RESULTS ===":
            in_results = True
            continue
        if not in_results:
            continue
        fields = line.split()
        if len(fields) >= 2 and fields[0] in expected:
            results[fields[0]] = AuditResult(
                status=fields[1].upper(),
                detail=" ".join(fields[2:]),
            )
    return {
        ip: results.get(ip, AuditResult("UNKNOWN", "missing audit result"))
        for ip in expected_ips
    }


def recovery_passed(results: Sequence[AuditResult]) -> bool:
    """Require exactly two complete PASS results before transient recovery."""
    return len(results) == PREFLIGHT_RECOVERY_ATTEMPTS and all(
        result.status == "PASS" for result in results
    )


def assert_region_preflight_passed(
    region: Mapping[str, Any], ips: list[str], results: Mapping[str, AuditResult]
) -> None:
    failed = [
        ip for ip in ips
        if results.get(ip, AuditResult("UNKNOWN", "missing audit result")).status != "PASS"
    ]
    if failed:
        region_key = str(region.get("key") or region.get("prefix") or "unknown")
        detail = ", ".join(
            f"{ip}={results.get(ip, AuditResult('UNKNOWN', 'missing audit result')).summary()}"
            for ip in failed
        )
        raise RuntimeError(f"{region_key} region preflight failed: {detail}")


def _run_region_audit(
    region: Region, ips: list[str], temp_path: Path, attempt: str,
    *, query: str | None = None, uuid: str | None = None,
) -> tuple[dict[str, AuditResult], bool]:
    """Run one isolated verifier invocation without touching production history."""
    input_path = temp_path / f"ips-{attempt}.txt"
    history_path = temp_path / f"history-{attempt}.tsv"
    input_path.write_text("\n".join(ips) + "\n", encoding="utf-8")
    env = os.environ.copy()
    env["VLESS_TEMPLATE"] = str(region.get("audit_key") or region["key"])
    env["VLESS_HISTORY"] = str(history_path)
    # 用节点自己的凭据/参数探测：HT 那条隧道用的是另一个 uuid。
    if query:
        env["VLESS_TEMPLATE_QUERY"] = query
    if uuid:
        env["VLESS_TEMPLATE_UUID"] = uuid
    try:
        completed = subprocess.run(
            [str(VERIFY_SCRIPT), "--audit", str(input_path)],
            cwd=str(VERIFY_SCRIPT.parent),
            env=env,
            capture_output=True,
            text=True,
            timeout=VERIFY_TIMEOUT_SECONDS,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return {
            ip: AuditResult("TIMEOUT", "verifier timeout") for ip in ips
        }, False
    except OSError as exc:
        return {
            ip: AuditResult("UNKNOWN", f"verifier start failed: {type(exc).__name__}")
            for ip in ips
        }, False

    # 75 = 验证器正被其它周期占用。这不是候选 IP 的失败证据，不能记成 FAIL，
    # 也不能把整轮推送判死；交给下一轮重试即可。
    if completed.returncode == 75:
        raise RuntimeError(
            f"VLESS verifier busy (rc=75); deferring preflight for {region.get('key')}"
        )

    output = f"{completed.stdout or ''}\n{completed.stderr or ''}"
    results = parse_audit_results(output, ips)
    return results, completed.returncode == 0


def run_region_preflight(region: Region, ips: list[str], *,
                         query: str | None = None, uuid: str | None = None) -> None:
    """Verify every candidate with the exact credentials/params the node uses."""
    if not VERIFY_SCRIPT.is_file():
        raise RuntimeError(f"VLESS verifier is unavailable: {VERIFY_SCRIPT}")

    with tempfile.TemporaryDirectory(prefix=".misub-preflight-", dir=VERIFY_SCRIPT.parent) as temp_dir:
        temp_path = Path(temp_dir)
        region_key = str(region["key"])
        initial_results, initial_ok = _run_region_audit(
            region, ips, temp_path, "initial", query=query, uuid=uuid
        )
        failed = (
            ips
            if not initial_ok
            else [ip for ip in ips if initial_results[ip].status != "PASS"]
        )
        if not failed:
            print(f"  Preflight {region_key}: {len(ips)}/{len(ips)} PASS")
            return

        print(
            f"  Preflight {region_key} initial: "
            + "; ".join(f"{ip}={initial_results[ip].summary()}" for ip in failed)
        )
        unresolved: list[str] = []
        for index, ip in enumerate(failed):
            recovery_results: list[AuditResult] = []
            recovery_ok: list[bool] = []
            for attempt in range(1, PREFLIGHT_RECOVERY_ATTEMPTS + 1):
                results, command_ok = _run_region_audit(
                    region, [ip], temp_path, f"recovery-{index}-{attempt}",
                    query=query, uuid=uuid,
                )
                result = results[ip]
                recovery_results.append(result)
                recovery_ok.append(command_ok)
                print(
                    f"  Preflight {region_key} recovery: {ip} "
                    f"attempt={attempt} {result.summary()}"
                )
            if recovery_passed(recovery_results) and all(recovery_ok):
                print(
                    f"  Preflight {region_key} recovery: {ip} transient-recovered"
                )
            else:
                unresolved.append(ip)

        if unresolved:
            detail = ", ".join(
                f"{ip}={initial_results[ip].summary()}" for ip in unresolved
            )
            raise RuntimeError(f"{region_key} region preflight failed: {detail}")
        print(f"  Preflight {region_key}: {len(ips)}/{len(ips)} PASS (recovered)")


def run_all_region_preflights(ips: list[str]) -> None:
    for region in REGIONS:
        run_region_preflight(region, ips)


def is_managed_name(name: str) -> bool:
    if " " not in name:
        return False
    prefix, suffix = name.rsplit(" ", 1)
    return prefix in CFST_NODE_PREFIXES and suffix in CFST_NODE_SUFFIXES


def find_profile(profiles: list[dict[str, Any]]) -> dict[str, Any]:
    matches = [profile for profile in profiles if profile.get("name") == PROFILE_NAME]
    if len(matches) != 1:
        raise RuntimeError(f"expected exactly one profile named {PROFILE_NAME!r}, got {len(matches)}")
    return matches[0]


def profile_node_ids(profile: dict[str, Any]) -> list[str]:
    values = profile.get("manualNodeIds") or []
    if not isinstance(values, list) or not all(isinstance(value, str) for value in values):
        raise RuntimeError(f"profile {profile.get('name', '<unknown>')} manualNodeIds is invalid")
    return values


def select_managed_by_name(
    all_managed: list[ManagedNode], referenced_ids: set[str], desired_names: set[str],
    protected_ids: set[str] | None = None,
) -> tuple[dict[str, ManagedNode], list[ManagedNode]]:
    """Pick the surviving node for each managed name.

    Reusing an existing node is what avoids the delete that corrupts profiles, so
    a node is kept whenever its name is still wanted. A previous failed run can
    leave several nodes sharing one name; the one the profile already references
    wins, because updating it in place costs no profile write at all.

    Everything else is returned for reclaim: duplicates, and nodes whose managed
    name is no longer in the desired set. Reclaiming is the only delete this
    module performs, and it always runs before any profile write.

    protected_ids are nodes another profile references; they are kept in place
    rather than reclaimed, because deleting them would break that other profile.
    """
    protected = protected_ids or set()
    groups: dict[str, list[ManagedNode]] = {}
    for node in all_managed:
        groups.setdefault(node.name, []).append(node)

    keep: dict[str, ManagedNode] = {}
    reclaim: list[ManagedNode] = []
    for name, nodes in groups.items():
        if name not in desired_names:
            reclaim.extend(node for node in nodes if node.id not in protected)
            continue
        preferred = next((node for node in nodes if node.id in referenced_ids), nodes[0])
        keep[name] = preferred
        reclaim.extend(node for node in nodes if node.id != preferred.id and node.id not in protected)
    return keep, reclaim


def validate_replacement(nodes: list[ManagedNode]) -> None:
    expected_names = [f"{region['prefix']} {suffix}" for region in REGIONS for suffix in SUFFIXES]
    actual_names = [node.name for node in nodes]
    if len(nodes) != len(expected_names) or sorted(actual_names) != sorted(expected_names):
        raise RuntimeError("replacement node set is incomplete, duplicated, or has unexpected names")
    if len({node.id for node in nodes}) != len(nodes):
        raise RuntimeError("replacement node ids are not unique")


def expected_managed_urls(ips: list[str]) -> dict[str, str]:
    return {
        f"{region['prefix']} {suffix}": build_vless_url(region, ip, suffix)
        for region in REGIONS
        for ip, suffix in zip(ips, SUFFIXES, strict=True)
    }


def _pending_reconcile_path(path: Path | None = None) -> Path:
    if path is None:
        path = PENDING_RECONCILE_FILE
    if not isinstance(path, Path):
        raise TypeError("pending reconcile path is invalid")
    return path


def write_pending_reconcile(
    managed: dict[str, ManagedNode], desired_urls: dict[str, str], phase: str,
    *, path: Path | None = None,
) -> None:
    """Persist a secret-free marker before the first external mutation."""
    path = _pending_reconcile_path(path)
    payload = {
        "version": 1,
        "phase": phase,
        "managed": [
            {
                "name": name,
                "node_id": managed[name].id if name in managed else None,
            }
            for name in desired_urls
        ],
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", dir=str(path.parent), text=True
    )
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, ensure_ascii=False, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, path)
    except Exception:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise


def load_pending_reconcile(*, path: Path | None = None) -> dict[str, Any] | None:
    """Load and validate a prior incomplete reconcile marker."""
    path = _pending_reconcile_path(path)
    if not path.exists():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise RuntimeError(f"pending reconcile marker is unreadable: {path}") from exc
    if not isinstance(payload, dict) or payload.get("version") != 1:
        raise RuntimeError(f"pending reconcile marker is invalid: {path}")
    phase = payload.get("phase")
    if phase not in {"reclaim", "create", "update", "bind"}:
        raise RuntimeError(f"pending reconcile marker is invalid: {path}")
    managed = payload.get("managed")
    if not isinstance(managed, list) or not all(isinstance(item, dict) for item in managed):
        raise RuntimeError(f"pending reconcile marker is invalid: {path}")
    return payload


def pending_reconcile_exists() -> bool:
    """Validate and report a prior incomplete reconcile marker."""
    return load_pending_reconcile() is not None


def clear_pending_reconcile(*, path: Path | None = None) -> None:
    """Remove the marker only after fresh final-state verification succeeds."""
    path = _pending_reconcile_path(path)
    try:
        path.unlink()
    except FileNotFoundError:
        return
    except OSError as exc:
        raise RuntimeError(f"could not clear pending reconcile marker: {path}") from exc


def expected_published_urls(host: str) -> dict[str, str]:
    """所有受管理节点共用同一个发布入口；节点地址因此不再随 IP 变化。"""
    return {f"{region['prefix']} {suffix}": build_vless_url(region, host, suffix)
            for region in REGIONS for suffix in SUFFIXES}


def _prepare_desired_urls(managed: Mapping[str, "ManagedNode"]) -> dict[str, str]:
    """目标状态 = 每个受管节点指向某个优选 IP；其余一切沿用节点自己。

    preflight 与最终 URL 都取自节点现有凭据，因此 CFST 不会把地区专属的 uuid
    覆盖成全局默认值（HT 与 HK/SG 用的是不同 uuid）。
    """
    ips = read_best_ips()
    print(f"Top {TOP_N} IPs: {', '.join(ips)}")

    credentials = {region["key"]: region_connection(region, managed) for region in REGIONS}
    print("\n[0/5] Verifying candidates against each region's target entry...")
    for region in REGIONS:
        # 凭据取节点自己的（各隧道 uuid 不同）；入口参数取模板——那是我们要迁到的路径。
        node_conn = credentials[region["key"]]
        uuid = node_conn[1] if node_conn else get_vless_uuid()
        if node_conn and node_conn[0] != region["query"]:
            print(f"  {region['key']}: node parameters differ from the template; "
                  "verifying the template entry (align the node to switch over)")
        run_region_preflight(region, ips, query=region["query"], uuid=uuid)

    desired: dict[str, str] = {}
    for region in REGIONS:
        for ip, suffix in zip(ips, SUFFIXES, strict=True):
            name = f"{region['prefix']} {suffix}"
            address = node_address(ip)
            node = managed.get(name)
            if node is not None:
                # 节点自己的一切（凭据、传输参数、显示名）都属于 MiSub，CFST 只换地址。
                desired[name] = swap_address(node.url, address)
                continue
            query, uuid = credentials[region["key"]] or (region["query"], get_vless_uuid())
            desired[name] = f"vless://{uuid}@{address}:443?{query}#{urllib.parse.quote(name)}"
    return desired


class PushRequest(Protocol):
    """The existing transport seam, including its optional JSON body."""

    def __call__(
        self, method: str, path: str, data: Any = None
    ) -> dict[str, Any] | None: ...


@dataclass
class _PushExecution:
    """Private implementation; callers and tests use execute_push."""

    prepare: Callable[[], dict[str, str]]
    request: PushRequest
    pending_path: Path
    sleep: Callable[[float], None]

    def list_managed_nodes(self) -> list[ManagedNode]:
        response = require_success(self.request("GET", "/manual-nodes?pageSize=200"), "list manual nodes")
        data = response.get("data")
        if not isinstance(data, list):
            raise RuntimeError("manual-nodes response data is not a list")
        result: list[ManagedNode] = []
        for node in data:
            if not isinstance(node, dict):
                continue
            name, node_id, url = str(node.get("name", "")), node.get("id"), node.get("url")
            if is_managed_name(name) and isinstance(node_id, str) and isinstance(url, str):
                result.append(ManagedNode(node_id, name, url))
        return result

    def list_profiles(self) -> list[dict[str, Any]]:
        response = require_success(self.request("GET", "/profiles"), "list profiles")
        profiles = response.get("data")
        if not isinstance(profiles, list) or not all(isinstance(profile, dict) for profile in profiles):
            raise RuntimeError("profiles response data is not a list of objects")
        return profiles

    def other_profile_refs(self,
        profiles: list[dict[str, Any]], target_profile: dict[str, Any], old_managed_ids: set[str]
    ) -> dict[str, set[str]]:
        """Find managed nodes referenced by other profiles using fresh profile reads.

        The collection returned by ``GET /profiles`` is only a discovery snapshot.
        Each foreign profile is read again by id before a node can be reclaimed. Any
        failed or malformed fresh read is an unknown safety condition, not evidence
        that the profile has no references.
        """
        target_id = target_profile.get("id")
        refs: dict[str, set[str]] = {}
        for profile in profiles:
            profile_id = profile.get("id")
            if profile_id == target_id:
                continue
            if not isinstance(profile_id, str) or not profile_id:
                raise RuntimeError("foreign profile has no valid id; refusing to reclaim")
            try:
                ids = set(self.get_profile_refs(profile_id)) & old_managed_ids
            except Exception as exc:
                raise RuntimeError(
                    f"could not fresh-read other profile {profile_id}; refusing to reclaim"
                ) from exc
            if ids:
                name = str(profile.get("name") or profile_id)
                refs[name] = ids
        return refs

    def lookup_manual_node(self, node_id: str) -> NodeLookup:
        """Return an explicit FOUND, MISSING, or UNKNOWN per-id read outcome."""
        response = self.request("GET", f"/manual-nodes/{node_id}")
        if response is None:
            return NodeLookup(NodeLookupState.UNKNOWN, reason="API read failed or was exhausted")
        if response.get("success") is not True:
            error = response.get("error")
            status = error.get("status") if isinstance(error, dict) else None
            if status == 404:
                return NodeLookup(NodeLookupState.MISSING, reason="authoritative HTTP 404")
            return NodeLookup(NodeLookupState.UNKNOWN, reason=f"API read returned status {status!r}")
        node = response.get("data")
        if not isinstance(node, dict):
            return NodeLookup(NodeLookupState.UNKNOWN, reason="API read returned invalid node data")
        found_id, name, url = node.get("id"), node.get("name"), node.get("url")
        if not (isinstance(found_id, str) and isinstance(name, str) and isinstance(url, str)):
            return NodeLookup(NodeLookupState.UNKNOWN, reason="API read returned malformed node data")
        if found_id != node_id:
            return NodeLookup(NodeLookupState.UNKNOWN, reason="API read returned a different node id")
        return NodeLookup(NodeLookupState.FOUND, ManagedNode(found_id, name, url))

    def get_manual_node(self, node_id: str) -> ManagedNode | None:
        """Read one node by id, raising when absence is not authoritative.

        Upstream getManualNodeById() issues direct SQL, so a per-id read is always
        fresh. Collection reads (GET /manual-nodes) go through the 30s TTL cache and
        must never be used as verification evidence. ``None`` now means only an
        authoritative HTTP 404; all other failures raise ``UnknownNodeLookup``.
        """
        outcome = self.lookup_manual_node(node_id)
        if outcome.state is NodeLookupState.FOUND:
            assert outcome.node is not None
            return outcome.node
        if outcome.state is NodeLookupState.MISSING:
            return None
        raise UnknownNodeLookup(f"manual node {node_id} lookup UNKNOWN: {outcome.reason}")

    def resolve_nodes_by_id(self, node_ids: list[str]) -> NodeResolution:
        """Resolve ids without turning an uncertain read into a missing node."""
        found: dict[str, ManagedNode] = {}
        missing: set[str] = set()
        unknown: dict[str, str] = {}
        for node_id in node_ids:
            try:
                node = self.get_manual_node(node_id)
            except UnknownNodeLookup as exc:
                unknown[node_id] = str(exc)
                continue
            if node is None:
                missing.add(node_id)
            else:
                found[node_id] = node
        return NodeResolution(found=found, missing=missing, unknown=unknown)

    def get_profile_refs(self, profile_id: str) -> list[str]:
        """Read a profile's manual node references.

        Upstream getProfileById() issues direct SQL, so this is fresh even when a
        cached GET /profiles list would still show a pre-write snapshot.
        """
        response = require_success(
            self.request("GET", f"/profiles/{profile_id}"), f"read profile {profile_id}"
        )
        data = response.get("data")
        if not isinstance(data, dict):
            raise RuntimeError(f"profile {profile_id} response data is not an object")
        return profile_node_ids(data)

    def create_managed_node(self, name: str, url: str) -> ManagedNode:
        response = require_success(
            self.request("POST", "/manual-nodes", {"name": name, "url": url}),
            f"create {name}",
        )
        node = response.get("data")
        if not isinstance(node, dict) or not isinstance(node.get("id"), str):
            raise RuntimeError(f"create {name} returned no node id")
        return ManagedNode(node["id"], name, str(node.get("url", "")))

    def update_managed_node_url(self, node: ManagedNode, url: str) -> ManagedNode:
        """Update a node's URL in place.

        This is the route that makes the whole design safe: upstream
        PATCH /manual-nodes/:id reads the node by id and writes only that
        subscription row. It never calls putProfile(), so it cannot revert a profile
        reference no matter which isolate serves it or how stale that isolate's
        cached collections are.
        """
        response = require_success(
            self.request("PATCH", f"/manual-nodes/{node.id}", {"url": url}),
            f"update {node.name}",
        )
        data = response.get("data")
        if not isinstance(data, dict) or data.get("url") != url:
            raise RuntimeError(f"MiSub did not return the updated url for {node.name}")
        return ManagedNode(node.id, node.name, url)

    def delete_nodes(self, nodes: list[ManagedNode], phase: str) -> None:
        for node in nodes:
            response = self.request("DELETE", f"/manual-nodes/{node.id}")
            if not response or response.get("success") is not True:
                raise RuntimeError(f"{phase}: delete {node.name} failed")
            print(f"  Deleted ({phase}): {node.name}")

    def wait_for_node_visibility(self, nodes: list[ManagedNode]) -> None:
        """Block until every id resolves through a per-id read.

        A newly created node can be acknowledged by POST before PATCH /profiles can
        resolve it (02:03:42, HTTP 400 manual_node_id_not_found). Per-id reads are
        used because they hit direct SQL; a cached collection read could report a
        node as missing long after it exists, or as present after deletion.
        """
        pending = list(nodes)
        for attempt in range(1, NODE_VISIBILITY_ATTEMPTS + 1):
            pending = [node for node in pending if self.get_manual_node(node.id) is None]
            if not pending:
                if nodes:
                    print(f"  All {len(nodes)} new node(s) are visible")
                return
            if attempt < NODE_VISIBILITY_ATTEMPTS:
                print(
                    f"  {len(pending)} new node(s) not visible yet; "
                    f"retrying ({attempt + 1}/{NODE_VISIBILITY_ATTEMPTS})",
                    file=sys.stderr,
                )
                self.sleep(NODE_VISIBILITY_DELAY_SECONDS)
        raise RuntimeError(
            f"new nodes are not visible via the MiSub API after "
            f"{NODE_VISIBILITY_ATTEMPTS} attempts: {len(pending)} missing"
        )

    def bind_profile_refs(self, profile_id: str, manual_node_ids: list[str]) -> None:
        """Write the profile reference set, then verify it with a fresh read.

        Two failure modes are handled explicitly:

        A stale subscriptions snapshot in the serving isolate makes upstream reject
        brand-new ids with HTTP 400 manual_node_id_not_found (02:03:42). Retrying is
        the correct response: the snapshot is at most 30s old, and a retry may also be
        served by a different isolate. Every id is confirmed resolvable by a fresh
        per-id read first, so a retry loop cannot mask a genuinely missing node.

        The value echoed back by PATCH is not accepted as proof, because it is built
        from the request rather than re-read. Verification is a separate per-id read.
        """
        missing = [
            node_id for node_id in manual_node_ids if self.get_manual_node(node_id) is None
        ]
        if missing:
            raise RuntimeError(
                f"refusing to bind: {len(missing)} node id(s) do not resolve by id"
            )

        for attempt in range(1, BIND_ATTEMPTS + 1):
            response = self.request(
                "PATCH", f"/profiles/{profile_id}", {"manualNodeIds": manual_node_ids}
            )
            if response and response.get("success") is True:
                observed = self.get_profile_refs(profile_id)
                if observed == manual_node_ids:
                    return
                reason = f"profile still shows {len(observed)} of {len(manual_node_ids)} refs"
            else:
                reason = "PATCH /profiles was rejected"
            if attempt < BIND_ATTEMPTS:
                print(
                    f"  bind attempt {attempt} failed ({reason}); "
                    f"retrying ({attempt + 1}/{BIND_ATTEMPTS})",
                    file=sys.stderr,
                )
                self.sleep(BIND_RETRY_DELAY_SECONDS)
        raise RuntimeError(
            f"could not bind {len(manual_node_ids)} profile refs after {BIND_ATTEMPTS} attempts"
        )

    def verify_final_state(self,
        profile_id: str, expected_profile_ids: list[str], managed: dict[str, ManagedNode],
        desired_urls: dict[str, str],
    ) -> None:
        """Verify the outcome through fresh per-id reads only.

        GET /manual-nodes and GET /profiles both serve the 30s TTL cached collection,
        so they can report a pre-write snapshot and turn a real failure green. Only
        per-id reads hit direct SQL, so only per-id reads are evidence.
        """
        final_refs = self.get_profile_refs(profile_id)
        if final_refs != expected_profile_ids:
            missing = [ref for ref in expected_profile_ids if ref not in final_refs]
            extra = [ref for ref in final_refs if ref not in expected_profile_ids]
            raise RuntimeError(
                "profile references do not match the reconciled node set: "
                f"missing={len(missing)} extra={len(extra)} "
                f"order_match={final_refs == expected_profile_ids}"
            )
        for name, url in desired_urls.items():
            node = self.get_manual_node(managed[name].id)
            if node is None:
                raise RuntimeError(f"managed node {name} does not resolve by id after reconcile")
            if node.name != name or node.url != url:
                raise RuntimeError(f"managed node {name} does not carry the current Top{TOP_N} url")

    def run(self) -> None:
        print("=== MiSub CM Node Push (in-place reconcile) ===")
        pending_record = load_pending_reconcile(path=self.pending_path)
        pending_written = pending_record is not None
        pending_phase = pending_record.get("phase") if pending_record else None
        if pending_written:
            print(f"  Resuming a pending reconcile recorded at {self.pending_path}")

        def mark_pending(phase: str) -> None:
            nonlocal pending_written
            if pending_written:
                return
            write_pending_reconcile(managed, desired_urls, phase, path=self.pending_path)
            pending_written = True

        print("\n[1/5] Reading current MiSub state...")
        all_managed = self.list_managed_nodes()
        profiles = self.list_profiles()
        profile = find_profile(profiles)
        profile_id = profile.get("id")
        if not isinstance(profile_id, str):
            raise RuntimeError("profile has no id")

        # Per-id read: the cached /profiles collection can lag the real profile by up
        # to 30s, and every decision below depends on the true reference set.
        live_refs = self.get_profile_refs(profile_id)

        # The cached node list is a discovery hint only; the profile's own references
        # are the other source of candidates, because a live managed node can be
        # missing from that list entirely. Resolving every candidate by id gives the
        # authoritative name for each one, so nothing is classified from cached data.
        candidates = list(dict.fromkeys([node.id for node in all_managed] + live_refs))
        resolution = self.resolve_nodes_by_id(candidates)
        if resolution.unknown:
            details = "; ".join(
                f"{node_id}: {reason}" for node_id, reason in resolution.unknown.items()
            )
            raise RuntimeError(
                f"manual node lookup is UNKNOWN; refusing reconciliation: {details}"
            )
        resolved = resolution.found
        known_managed = [node for node in resolved.values() if is_managed_name(node.name)]
        managed_ids = {node.id for node in known_managed}
        ghosts = len(resolution.missing)
        if ghosts:
            print(f"  Ignoring {ghosts} node id(s) that no longer resolve")

        foreign = self.other_profile_refs(profiles, profile, managed_ids)
        foreign_ids = set().union(*foreign.values()) if foreign else set()
        if foreign:
            details = "; ".join(f"{name}={len(ids)}" for name, ids in foreign.items())
            print(f"  Preserving {len(foreign_ids)} node(s) referenced by other profiles: {details}")

        managed, reclaim = select_managed_by_name(
            known_managed, set(live_refs), expected_managed_names(), protected_ids=foreign_ids
        )
        # 目标 URL 只在看清现有节点之后才推导：地址换掉，凭据/参数沿用节点自己的。
        desired_urls = self.prepare(managed)
        if pending_phase == "create":
            unresolved = [name for name in desired_urls if name not in managed]
            if unresolved:
                names = ", ".join(unresolved)
                raise RuntimeError(
                    "pending create has no fresh per-name recovery evidence; "
                    f"refusing duplicate POST for: {names}"
                )
        # Unmanaged refs are the user's own nodes (JP etc) and must be carried
        # forward. A ref that did not resolve is a stale pointer left by an earlier
        # failure and is dropped, because binding it back would be rejected.
        preserved_ids = [
            ref for ref in live_refs if ref in resolved and ref not in managed_ids
        ]
        dropped = len([ref for ref in live_refs if ref not in resolved])
        if dropped:
            print(f"  Dropping {dropped} stale profile node reference(s)")
        if preserved_ids:
            print(f"  Preserving {len(preserved_ids)} unmanaged profile node(s)")

        # Every delete happens here, before any profile write. Deleting a node makes
        # upstream write back a possibly stale profiles snapshot, so a delete can only
        # revert references that predate this run; the fresh read further down
        # observes that and the bind repairs it. Deleting after a bind is what caused
        # the 12:07 outage.
        if reclaim:
            print(f"  Reclaiming {len(reclaim)} unreferenced duplicate node(s)")
            mark_pending("reclaim")
            self.delete_nodes(reclaim, "reclaim")

        print("\n[2/5] Creating any missing managed node...")
        created: list[ManagedNode] = []
        if any(name not in managed for name in desired_urls):
            mark_pending("create")
        for name, url in desired_urls.items():
            if name in managed:
                continue
            node = self.create_managed_node(name, url)
            managed[name] = node
            created.append(node)
            print(f"  Created: {name}")
        if not created:
            print("  Nothing to create; the managed set is complete")

        print("\n[3/5] Confirming new nodes resolve by id...")
        self.wait_for_node_visibility(created)

        print("\n[4/5] Updating managed node URLs in place...")
        changed = 0
        if any(managed[name].url != url for name, url in desired_urls.items()):
            mark_pending("update")
        for name, url in desired_urls.items():
            node = managed[name]
            if node.url == url:
                continue
            managed[name] = self.update_managed_node_url(node, url)
            changed += 1
            print(f"  Updated: {name}")
        print(f"  {changed} url(s) changed, {len(desired_urls) - changed} already current")
        validate_replacement(list(managed.values()))

        print("\n[5/5] Reconciling profile references...")
        expected_profile_ids = preserved_ids + [managed[name].id for name in desired_urls]
        current_refs = self.get_profile_refs(profile_id)
        if current_refs == expected_profile_ids:
            print(f"  Profile {PROFILE_NAME} already references the correct {len(current_refs)} nodes")
        else:
            missing = [ref for ref in expected_profile_ids if ref not in current_refs]
            extra = [ref for ref in current_refs if ref not in expected_profile_ids]
            print(f"  Repairing profile references: {len(missing)} missing, {len(extra)} extra")
            mark_pending("bind")
            self.bind_profile_refs(profile_id, expected_profile_ids)
            print(f"  Profile {PROFILE_NAME} bound to {len(expected_profile_ids)} nodes")

        self.verify_final_state(profile_id, expected_profile_ids, managed, desired_urls)
        clear_pending_reconcile(path=self.pending_path)
        print(f"  Verified {len(desired_urls)} managed node(s) and {len(expected_profile_ids)} profile refs")
        print(f"\nDone. {changed} url(s) updated, {len(created)} created, {len(reclaim)} reclaimed.")


def execute_push(
    *,
    prepare: Callable[[], dict[str, str]],
    request: PushRequest,
    pending_path: Path,
    sleep: Callable[[float], None],
) -> None:
    """Reconcile using explicit runtime dependencies, preserving partial effects.

    prepare reads the desired inputs and runs every preflight; it is called only
    after pending validation. request follows the existing transport contract.
    pending_path must be private to this execution environment. sleep controls
    bounded visibility and bind retries; neither dependency changes the policy.
    """
    if not isinstance(pending_path, Path):
        raise TypeError("pending reconcile path is invalid")
    _PushExecution(prepare, request, pending_path, sleep).run()


def main() -> None:
    host = os.environ.get("CFST_NODE_HOST", "").strip()
    prepare = (lambda managed: expected_published_urls(host)) if host else _prepare_desired_urls
    if host:
        print(f"Publishing through the stable address {host} (no IP substitution)")
    execute_push(
        prepare=prepare,
        request=api_request,
        pending_path=PENDING_RECONCILE_FILE,
        sleep=time.sleep,
    )


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)
