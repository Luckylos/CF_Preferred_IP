#!/usr/bin/env python3
"""把订阅链接的 QUERY 解析成 xray 的 streamSettings：探测必须和用户实际用的传输一致。

只接受 vless 分享链接里出现的传输类型；缺字段就报错，不做猜测性的默认值。
"""
from __future__ import annotations

import json
import sys
import urllib.parse
from typing import Any

SUPPORTED = {"ws", "xhttp"}


def parse(query: str) -> dict[str, Any]:
    if not query or any(char.isspace() for char in query):
        raise ValueError("invalid transport query")
    fields = dict(urllib.parse.parse_qsl(query, keep_blank_values=True))
    kind = fields.get("type", "ws")
    if kind not in SUPPORTED:
        raise ValueError(f"unsupported transport type: {kind!r}")
    sni, host = fields.get("sni") or fields.get("host"), fields.get("host")
    if not sni:
        raise ValueError("transport query has no sni")
    path = fields.get("path") or "/"
    if "{kind}" == "ws" and not host:
        raise ValueError("ws transport needs a host header")
    return {"type": kind, "sni": sni, "host": host, "path": path,
            "fp": fields.get("fp") or "chrome", "mode": fields.get("mode"),
            "alpn": fields.get("alpn"), "extra": fields.get("extra")}


def stream_settings(query: str) -> dict[str, Any]:
    fields = parse(query)
    tls: dict[str, Any] = {"serverName": fields["sni"], "fingerprint": fields["fp"]}
    if fields["alpn"]:
        tls["alpn"] = [a for a in fields["alpn"].split(",") if a]
    stream: dict[str, Any] = {"network": fields["type"], "security": "tls", "tlsSettings": tls}
    if fields["type"] == "ws":
        stream["wsSettings"] = {"path": fields["path"], "headers": {"Host": fields["host"]}}
    else:
        settings: dict[str, Any] = {"path": fields["path"], "host": fields["host"]}
        if fields["mode"]:
            settings["mode"] = fields["mode"]
        if fields["extra"]:
            try:
                settings["extra"] = json.loads(fields["extra"])
            except json.JSONDecodeError as exc:
                raise ValueError(f"transport extra is not valid JSON: {exc}") from exc
        stream["xhttpSettings"] = settings
    return stream


def legacy_ws(host: str, path: str, fingerprint: str = "chrome") -> dict[str, Any]:
    """兼容只有 host/path 字段的旧模板配置（等价于 ws）。"""
    if not host:
        raise ValueError("legacy ws needs a host")
    return {"network": "ws", "security": "tls",
            "tlsSettings": {"serverName": host, "fingerprint": fingerprint or "chrome"},
            "wsSettings": {"path": path or "/", "headers": {"Host": host}}}


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)

    def option(name: str) -> str:
        return args[args.index(name) + 1] if name in args else ""

    try:
        if "--query" in args:
            payload = stream_settings(option("--query"))
        elif "--ws-host" in args:
            payload = legacy_ws(option("--ws-host"), option("--ws-path"), option("--ws-fp"))
        else:
            print("usage: vless_template.py --query <query> | --ws-host H [--ws-path P] [--ws-fp F]",
                  file=sys.stderr)
            return 2
    except ValueError as exc:
        print(f"vless_template: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(payload, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
