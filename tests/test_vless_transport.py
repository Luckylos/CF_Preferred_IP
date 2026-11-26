"""探测必须按模板 QUERY 的传输类型建链，而不是写死 ws。"""
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import unittest
import urllib.parse
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

spec = importlib.util.spec_from_file_location("vless_transport_contract", ROOT / "vless_template.py")
assert spec and spec.loader
transport = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = transport
spec.loader.exec_module(transport)

WS = "encryption=none&security=tls&sni=sg-relay.example.com&fp=chrome&type=ws&host=sg-relay.example.com&path=%2Fargo%3Fed%3D2560"
XHTTP = ("encryption=none&security=tls&sni=hk-relay.example.com&fp=chrome&type=xhttp"
         "&host=hk-relay.example.com&path=%2Fargo&mode=auto"
         "&extra=%7B%22xPaddingObfsMode%22%3Atrue%2C%22xPaddingHeader%22%3A%22X-Cache%22%7D")


class StreamSettingsContract(unittest.TestCase):
    def test_ws_query_produces_ws_settings(self) -> None:
        stream = transport.stream_settings(WS)
        self.assertEqual(stream["network"], "ws")
        self.assertEqual(stream["wsSettings"]["path"], "/argo?ed=2560")
        self.assertEqual(stream["wsSettings"]["headers"]["Host"], "sg-relay.example.com")
        self.assertEqual(stream["tlsSettings"]["serverName"], "sg-relay.example.com")

    def test_xhttp_query_keeps_mode_and_padding(self) -> None:
        stream = transport.stream_settings(XHTTP)
        self.assertEqual(stream["network"], "xhttp")
        settings = stream["xhttpSettings"]
        self.assertEqual((settings["path"], settings["host"], settings["mode"]), ("/argo", "hk-relay.example.com", "auto"))
        self.assertEqual(settings["extra"], {"xPaddingObfsMode": True, "xPaddingHeader": "X-Cache"})

    def test_unsupported_or_incomplete_transport_is_refused(self) -> None:
        for query in ["type=grpc&sni=x.example.com", "type=ws&path=%2Fargo", "", "type=xhttp&sni=x.example.com&extra=%7Bbad"]:
            with self.assertRaises(ValueError):
                transport.stream_settings(query)

    def test_cli_fails_closed_on_bad_query(self) -> None:
        bad = subprocess.run([sys.executable, str(ROOT / "vless_template.py"), "--query", "type=grpc"],
                             capture_output=True, text=True)
        self.assertEqual(bad.returncode, 2)
        good = subprocess.run([sys.executable, str(ROOT / "vless_template.py"), "--query", XHTTP],
                              capture_output=True, text=True)
        self.assertEqual(good.returncode, 0)
        self.assertEqual(json.loads(good.stdout)["network"], "xhttp")


class VerifyShellContract(unittest.TestCase):
    def setUp(self) -> None:
        self.text = (ROOT / "verify_vless.sh").read_text()

    def test_transport_is_not_hardcoded(self) -> None:
        self.assertNotIn('"network": "ws"', self.text)
        self.assertIn("vless_template.py", self.text)
        self.assertIn("--query", self.text)

    def test_documented_fallback_queries_still_parse(self) -> None:
        """config.sh 注释里留的备用 QUERY 必须真的能用，避免切换入口时贴错。"""
        for marker in ("# argo xhttp 备用: ", "# ws 备用: "):
            line = next((l for l in (ROOT / "config.sh").read_text().splitlines()
                         if l.startswith(marker)), None)
            if line is None:
                continue
            stream = transport.stream_settings(line[len(marker):].strip())
            expected = "xhttp" if "xhttp" in marker else "ws"
            self.assertEqual(stream["network"], expected, marker)

    def test_caller_can_supply_node_credentials(self) -> None:
        """推送 preflight 用节点自己的 uuid/参数，不再依赖 config 里的模板默认值。"""
        self.assertIn("VLESS_TEMPLATE_UUID", self.text)
        self.assertIn("VLESS_TEMPLATE_QUERY", self.text)

    def test_audit_can_select_any_template(self) -> None:
        for key in ("HK", "SG", "HT"):
            self.assertIn(f"{key}) VLESS_NODE=", self.text)


if __name__ == "__main__":
    unittest.main()
