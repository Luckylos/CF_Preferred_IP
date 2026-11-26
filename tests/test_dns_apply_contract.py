"""发布落地已从 MiSub 推送改为 DNS 记录集合：接口与门禁的契约。"""
from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def _module(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / filename)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class NodeAddressContract(unittest.TestCase):
    def setUp(self) -> None:
        self.push = _module("dns_apply_push", "push_to_misub.py")
        self.enterContext(patch.object(
            self.push, "get_vless_uuid", return_value="00000000-0000-4000-8000-000000000001"
        ))

    def test_node_address_accepts_ipv4_and_hostname_but_not_junk(self) -> None:
        self.assertEqual(self.push.node_address("203.0.113.7"), "203.0.113.7")
        self.assertEqual(self.push.node_address("preferred.example.com"), "preferred.example.com")
        for bad in ["", "not-an-ip", "http://x", "../evil.example.com", "-x.example.com"]:
            with self.assertRaises(RuntimeError):
                self.push.node_address(bad)

    def test_published_urls_share_one_stable_address(self) -> None:
        host = "preferred.example.com"
        urls = self.push.expected_published_urls(host)
        self.assertEqual(len(urls), len(self.push.REGIONS) * len(self.push.SUFFIXES))
        for region in self.push.REGIONS:
            for suffix in self.push.SUFFIXES:
                url = urls[f"{region['prefix']} {suffix}"]
                self.assertTrue(url.startswith("vless://"))
                self.assertIn(f"@{host}:443", url)
                self.assertIn(f"sni={region['sni']}", url)
                self.assertNotIn("@203.", url)

    def test_ip_urls_still_match_the_legacy_form(self) -> None:
        region = self.push.REGIONS[0]
        url = self.push.build_vless_url(region, "203.0.113.7", "CM")
        self.assertIn("@203.0.113.7:443", url)
        self.assertIn(f"{region['sni']}", url)


class ApplyShellContract(unittest.TestCase):
    """发布落地走 apply.sh：misub / dns / both 三种通道，任一启用通道失败就不写状态。"""

    def setUp(self) -> None:
        self.apply = (ROOT / "apply.sh").read_text()
        self.cycle = (ROOT / "cycle.sh").read_text()
        self.config = (ROOT / "config.sh").read_text()

    def test_cycle_keeps_apply_as_the_single_publish_entry(self) -> None:
        self.assertIn('"$CFST_DIR/apply.sh"', self.cycle)
        self.assertNotIn("apply_dns.sh", self.cycle)

    def test_apply_keeps_lock_state_and_maintenance_gates(self) -> None:
        self.assertIn("exec 7>", self.apply)
        self.assertIn("flock -n 7", self.apply)
        self.assertIn(".push_disabled", self.apply)
        self.assertIn("compute_apply_state", self.apply)
        self.assertIn("APPLY_STATE", self.apply)

    def test_publish_mode_defaults_to_both_and_rejects_unknown_channels(self) -> None:
        self.assertIn('CFST_PUBLISH="${CFST_PUBLISH:-both}"', self.config)
        self.assertIn('PUBLISH_MODE="${CFST_PUBLISH:-both}"', self.apply)
        self.assertIn("expected misub|dns|both", self.apply)
        self.assertIn('"$PUBLISH_MODE" = "dns" ] || [ "$PUBLISH_MODE" = "both"', self.apply)
        self.assertIn('"$PUBLISH_MODE" = "misub" ] || [ "$PUBLISH_MODE" = "both"', self.apply)

    def test_dns_publishes_only_the_best_n_addresses(self) -> None:
        self.assertIn('CFST_DNS_TOP_N="${CFST_DNS_TOP_N:-1}"', self.config)
        self.assertIn('head -n "${CFST_DNS_TOP_N:-1}"', self.apply)
        self.assertIn('apply "${DNS_IPS[@]}"', self.apply)
        self.assertNotIn('apply "${TOP_IPS[@]}"', self.apply)
        self.assertIn("DNS publish needs at least one address", self.apply)

    def test_state_is_written_only_after_every_enabled_channel_succeeds(self) -> None:
        dns_fail = self.apply.index('apply: DNS publish failed')
        push_fail = self.apply.index('apply: push_to_misub failed')
        success = self.apply.index('mv -fT -- "$PENDING_FILE" "$CURRENT_FILE"')
        self.assertLess(dns_fail, success)
        self.assertLess(push_fail, success)
        self.assertIn("PUBLISH_OK=0", self.apply)
        self.assertIn('if (( PUBLISH_OK ))', self.apply)
        self.assertIn("publish incomplete, will retry next round", self.apply)

    def test_state_tracks_the_dns_subset_size(self) -> None:
        self.assertIn("dns_top=%s", self.config)
        self.assertGreaterEqual(self.config.count("CFST_PUBLISH:-both"), 2)


class DnsTopNSlice(unittest.TestCase):
    """publish_set | head -n N 就是 DNS 实际写入的地址集合。"""

    def test_slice_takes_the_ranked_leader(self) -> None:
        import subprocess
        import tempfile
        best = Path(tempfile.mkdtemp()) / "best_ips.txt"
        best.write_text("# --- BEST_IPS (machine-readable, one IP per line) ---\n"
                        "203.0.113.11\n203.0.113.12\n203.0.113.13\n", encoding="utf-8")
        script = (
            f'cd "{ROOT}" && source ./config.sh >/dev/null 2>&1; '
            f'BEST="{best}"; CFST_DNS_TOP_N=1; publish_set | head -n "$CFST_DNS_TOP_N"'
        )
        out = subprocess.run(["bash", "-c", script], capture_output=True, text=True)
        self.assertEqual(out.stdout.split(), ["203.0.113.11"])


if __name__ == "__main__":
    unittest.main()
