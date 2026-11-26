"""Publication guard for this public mirror.

The repository is a sanitized copy of a private production system. These tests
fail loudly if a future sync reintroduces something that must never be public:

  * credential files or literal tokens;
  * live relay endpoints (template SNI/HOST must stay placeholders);
  * runtime state (pool, history, published set, cooldowns, tier files);
  * measured candidate addresses in the bulky replay fixture.
"""

from __future__ import annotations

import ast
import ipaddress
import re
from pathlib import Path

ROOT = Path(__file__).parents[1]

REQUIRED_FILES = [
    "README.md",
    "config.sh",
    "cycle.sh",
    "cycle_result.py",
    "audit_evidence.py",
    "quality_evidence.py",
    "publication_snapshot.py",
    "dns_publish.py",
    "vless_template.py",
    "rank.py",
    "admission.py",
    "cooldown.py",
    "atomic_io.py",
    "ip_validation.py",
    "replay.py",
    "apply.sh",
    "push_to_misub.py",
    "verify_vless.sh",
    "scan_latency.sh",
    "status.py",
]

RUNTIME_STATE_NAMES = {
    "secrets",
    "backups",
    ".env",
    ".publish_desired.json",
    ".dns_preference.json",
    ".quality_evidence_enabled",
    ".misub-reconcile-pending.json",
    ".apply_state.pending",
    "contenders.tsv.lifecycle.json",
    "vless_history.tsv.requests.jsonl",
    ".hermes",
    "results",
    ".tiers",
    ".shadow",
    "contenders.tsv",
    "vless_history.tsv",
    "discovered_ips.tsv",
    "best_ips.txt",
    ".apply_state",
    ".capacity_cooldown.tsv",
    ".screen_blacklist.tsv",
    "ip_ranges.txt",
}

DOC_RANGES = ("127.0.0.", "192.0.2.", "198.51.100.", "203.0.113.")


def text_files() -> list[Path]:
    return [
        path
        for path in ROOT.rglob("*")
        if path.is_file()
        and ".git" not in path.parts
        and path.name != "test_distribution_contract.py"
    ]


def read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return ""


def test_publication_keeps_the_operational_surface():
    for name in REQUIRED_FILES:
        assert (ROOT / name).is_file(), name
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "secrets/" in readme
    assert "example.com" in readme


def test_publication_contains_no_credential_or_runtime_state_surfaces():
    for path in text_files():
        assert not any(part in RUNTIME_STATE_NAMES for part in path.parts), path


def test_publication_contains_no_literal_credentials():
    patterns = [
        re.compile(r"(?i)(token|secret|password|api_key)\s*[=:]\s*[\"']?[0-9a-f]{24,}"),
        re.compile(r"(?i)bearer\s+[A-Za-z0-9._-]{20,}"),
        re.compile(r"://[^/\s:@]+:[^/\s@]+@"),
    ]
    for path in text_files():
        content = read(path)
        for pattern in patterns:
            assert pattern.search(content) is None, path


def test_relay_endpoints_are_placeholders():
    config = (ROOT / "config.sh").read_text(encoding="utf-8")
    assert re.search(r'^COLO_HOST="trace\.example\.com"(?:\s|$)', config, re.M)
    for key in ("HK", "HT", "SG"):
        for field in ("SNI", "HOST"):
            match = re.search(rf'^CFST_TEMPLATE_{key}_{field}="([^"]+)"', config, re.M)
            assert match, f"{key}_{field}"
            assert match.group(1).endswith("example.com"), f"{key}_{field}"


def test_publication_adapter_defaults_are_placeholders():
    for filename, expected in (
        ("dns_publish.py", {"RECORD_NAME": "preferred.example.com", "ZONE_ID": "0" * 32}),
        ("push_to_misub.py", {"MISUB_BASE": "https://subscription.example.com/api/ext/v1"}),
    ):
        source = ast.parse((ROOT / filename).read_text(encoding="utf-8"))
        defaults = {
            node.targets[0].id: ast.literal_eval(node.value)
            for node in source.body
            if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name)
            and node.targets[0].id in expected
        }
        assert defaults == expected


def test_replay_fixture_holds_only_documentation_or_private_addresses():
    fixture = ROOT / "tests" / "fixtures" / "history_7d.tsv"
    assert fixture.is_file(), "replay fixture is required by the rank CLI tests"
    addresses = set()
    for line in fixture.read_text(encoding="utf-8").splitlines():
        columns = line.split("\t")
        if len(columns) > 1:
            addresses.add(columns[1])
    assert addresses
    for address in addresses:
        parsed = ipaddress.ip_address(address)
        assert parsed.is_private or address.startswith(DOC_RANGES), address
