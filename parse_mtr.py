#!/usr/bin/env python3
"""从 stdin 读取 MTR 输出，打印路由结构摘要（不含地理推断）。"""
import re
import sys

# 已知 ISP 前缀 → 标签
_RANGES = {
    "移动": [
        "112.", "120.199.", "117.148.", "223.92.", "221.183.",
        "120.196.", "120.198.", "111.24.",
    ],
    "CMI": ["223.120.", "223.119.", "223.121."],
    "CF": [
        "104.16.", "104.17.", "104.18.", "104.19.",
        "172.64.", "172.67.", "172.68.", "108.162.",
        "141.101.", "103.21.", "103.22.", "103.31.",
    ],
}


def _classify_hop(ip: str) -> str:
    if ip.startswith(("192.168.", "10.", "100.64.", "127.")):
        return "LAN"
    for label, prefixes in _RANGES.items():
        for pfx in prefixes:
            if ip.startswith(pfx):
                return label
    return "transit"


def parse_and_summarize(text: str) -> str:
    """解析 MTR 输出，返回路由段摘要。

    输出格式: 移动[4跳] → CMI[3跳] → CF[1跳]
    只标注 ISP 归属和跳数，不做地理推断。
    """
    pat = re.compile(
        r'\s*(\d+)\.\|--\s+'
        r'(\S+)\s+'
        r'([\d.]+)%\s+'
        r'\d+\s+'        # Snt
        r'[\d.]+\s+'     # Last
        r'([\d.]+)\s+'   # Avg
    )
    hops = []
    for line in text.splitlines():
        m = pat.match(line)
        if m:
            ip = m.group(2)
            if ip != "???":
                hops.append(ip)

    if not hops:
        return "—"

    # 合并相邻同 ISP 的跳为一段
    segments = []  # [(label, hop_count), ...]
    prev_label = None
    count = 0
    for ip in hops:
        label = _classify_hop(ip)
        if label == "LAN":
            continue
        if label == "transit":
            # transit 跳归入前一段（中间不可见路由器）
            if prev_label:
                count += 1
            continue
        if label == prev_label:
            count += 1
        else:
            if prev_label is not None:
                segments.append((prev_label, count))
            prev_label = label
            count = 1
    if prev_label is not None:
        segments.append((prev_label, count))

    if not segments:
        return "—"

    parts = []
    for label, n in segments:
        parts.append(f"{label}[{n}跳]")
    return " → ".join(parts)


if __name__ == "__main__":
    text = sys.stdin.read()
    print(parse_and_summarize(text))
