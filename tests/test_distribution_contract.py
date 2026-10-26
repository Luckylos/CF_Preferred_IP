from pathlib import Path
import ipaddress
import re

ROOT = Path(__file__).parents[1]


def text_files():
    for path in ROOT.rglob("*"):
        if path.is_file() and ".git" not in path.parts and path.name != "test_distribution_contract.py":
            try:
                yield path, path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                continue


def test_distribution_has_core_and_usage_contract():
    required = [
        "README.md",
        "config.example.sh",
        "pyproject.toml",
        "LICENSE",
        "rank.py",
        "admission.py",
        "cooldown.py",
        "atomic_io.py",
        "ip_validation.py",
        "replay.py",
        "docs/design.md",
        "docs/data-contract.md",
        "examples/history.tsv",
    ]
    for name in required:
        assert (ROOT / name).is_file(), name
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "config.example.sh" in readme
    assert "not a drop-in production deployment" in readme
    assert "offline" in readme.lower()


def test_public_distribution_contains_no_runtime_state_or_secret_surfaces():
    forbidden_names = {
        "secrets", ".hermes", "results", ".tiers", "contenders.tsv",
        "vless_history.tsv", "discovered_ips.tsv", "best_ips.txt",
        "apply_state", ".capacity_cooldown.tsv", ".screen_blacklist.tsv",
    }
    for path, _ in text_files():
        if path.parent.name == "examples":
            continue
        assert not any(part in forbidden_names for part in path.parts), path


def test_public_distribution_contains_no_live_endpoints_or_credentials():
    forbidden = [
        "/" + "opt/cfst",
        "/" + "dev/shm/cfst",
        "/" + "run/lock/cfst",
        "CFST_" + "TEMPLATE_",
        "VLESS_" + "UUID",
        "PRIVATE" + " KEY",
        "Authorization" + ":",
        "wss" + "://",
        "vless" + "://",
    ]
    ipv4 = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
    allowed_prefixes = ("127.0.0.", "192.0.2.", "198.51.100.", "203.0.113.")
    for path, content in text_files():
        for marker in forbidden:
            assert marker not in content, f"{marker} in {path}"
        for address in ipv4.findall(content):
            try:
                ipaddress.ip_address(address)
            except ValueError:
                continue
            if ipaddress.ip_address(address).is_private:
                continue
            assert address.startswith(allowed_prefixes), f"non-documentation address {address} in {path}"


def test_example_config_is_safe_by_default():
    config = (ROOT / "config.example.sh").read_text(encoding="utf-8")
    assert "CHANGE_ME" in config
    assert "set -euo pipefail" in config
    assert "CFST_DIR=" in config
    assert "SECRETS_DIR=" in config
