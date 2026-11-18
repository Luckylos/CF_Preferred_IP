#!/usr/bin/env python3
"""只读运行状态汇总：回答「CFST 跑得怎么样」。不改任何状态文件。

用法：./status.py            # 人类可读
      ./status.py --json     # 机器可读

Contender pool（2026-10-15 重构）新增解析的日志行契约：
  rank 摘要行（rank.py 输出，出现在 results/fast.log 与 results/<ts>.log）：
    [ts] rank: pool=N core=N challengers=N evicted=N published=ip1,ip2,ip3 changed=0|1 \
         guard=none|coverage|systemic|no_evidence
  cycle 行（cycle.sh 输出）：
    [ts] cycle: mode=slow|fast guard=... rank=...
  影子对照行（results/shadow.log，切换前由 run.sh 末尾写入；本文件定义格式）：
    [ts] shadow: legacy=ip1,ip2,ip3 new=ip1,ip2,ip3 same=0|1
    legacy = 旧链路（score.py）实际发布的 Top3，new = rank.py --dry-run 算出的 Top3，
    均为有序逗号列表（可少于 3 个；空则为 "-"）；same=1 表示两者逐位相等。
  影子硬门（设计 §6）：48h 内 new Top3 变化（有序比较，换序也算）≤ 2 次，且每次变化后的
  Top3 ⊆ 合格集；合格集 = 7 天 vless_history.tsv 中原始 TTFB p90 ≤ 65ms 且 FAIL=0 的 IP。
"""
from __future__ import annotations

import argparse
import sys
if __name__ == '__main__':
    sys.dont_write_bytecode = True  # 只读CLI也不产生本地依赖的.pyc
from cycle_result import (parse_round, _ts_of, parse_rank_line, parse_cycle_line,
                          _last_tagged, collect_contender, last_match, read_status)
import json
import re
from datetime import datetime, timedelta
from pathlib import Path

CFST = Path(__file__).resolve().parent
TS_FMT = "%Y-%m-%d %H:%M:%S"
IP_RE = r"(?:\d{1,3}\.){3}\d{1,3}"
SHADOW_QUAL_P90_MS = 65   # 影子硬门合格集：7d 原始 TTFB p90 上限（设计 §6）
SHADOW_WINDOW_H = 48
QUAL_HISTORY_DAYS = 7


def config_int(key: str, default: int) -> int:
    for raw in (CFST / "config.sh").read_text(encoding="utf-8").splitlines():
        m = re.match(rf"^{key}=(\d+)", raw.strip())
        if m:
            return int(m.group(1))
    return default


def qualified_set(history_text: str, now: datetime, days: int = QUAL_HISTORY_DAYS,
                  p90_max: int = SHADOW_QUAL_P90_MS) -> set[str]:
    """影子硬门合格集：窗口内原始 TTFB（PASS 行第 4 列）p90 ≤ p90_max 且无 FAIL 行的 IP。"""
    cutoff = now - timedelta(days=days)
    ttfb: dict[str, list[int]] = {}
    failed: set[str] = set()
    for raw in history_text.splitlines():
        f = raw.split("\t")
        if len(f) < 4 or not re.fullmatch(IP_RE, f[1]):
            continue
        try:
            ts = datetime.strptime(f[0], TS_FMT)
        except ValueError:
            continue
        if ts < cutoff:
            continue
        if f[2] == "PASS" and f[3].isdigit():
            ttfb.setdefault(f[1], []).append(int(f[3]))
        elif f[2] in ("FAIL", "PARTIAL"):
            failed.add(f[1])
    out = set()
    for ip, vals in ttfb.items():
        if ip in failed:
            continue
        s = sorted(vals)
        if s[min(len(s) - 1, int(len(s) * 0.9))] <= p90_max:
            out.add(ip)
    return out


def parse_shadow_line(line: str) -> dict | None:
    m = re.search(r"shadow: legacy=(\S+) new=(\S+) same=([01])", line)
    if not m:
        return None
    return {"legacy": re.findall(IP_RE, m.group(1)), "new": re.findall(IP_RE, m.group(2)),
            "same": m.group(3) == "1"}


def collect_shadow(shadow_log: Path, history: Path, now: datetime,
                   extra_logs: tuple[Path, ...] = ()) -> dict | None:
    """48h 窗口内影子 Top3 变化次数与每次变化是否 ⊆ 合格集；无 shadow 行返回 None。
    shadow 行来自 slow 影子（shadow.log）与 fast 影子（fast.log），按时间合并。"""
    rows = []
    for log in (shadow_log, *extra_logs):
        if not log.exists():
            continue
        for raw in log.read_text(encoding="utf-8", errors="replace").splitlines():
            d = parse_shadow_line(raw)
            ts = _ts_of(raw)
            if d is not None and ts is not None:
                rows.append((ts, d))
    if not rows:
        return None
    rows.sort(key=lambda r: r[0])
    qual = qualified_set(history.read_text(encoding="utf-8", errors="replace"), now) if history.exists() else set()
    cutoff = now - timedelta(hours=SHADOW_WINDOW_H)
    window = [(ts, d) for ts, d in rows if ts >= cutoff]
    # 变化基准：窗口前最后一行（若有），避免窗口首行被误计为变化
    before = [d for ts, d in rows if ts < cutoff]
    prev = before[-1]["new"] if before else (window[0][1]["new"] if window else None)
    changes = []
    for ts, d in window:
        if d["new"] != prev:
            bad = [ip for ip in d["new"] if ip not in qual]
            changes.append({"at": ts.strftime(TS_FMT), "top3": d["new"], "qualified": not bad, "unqualified": bad})
        prev = d["new"]
    latest_ts, latest = rows[-1]
    return {"rounds_48h": len(window), "changes_48h": len(changes), "changes": changes,
            "latest": {"at": latest_ts.strftime(TS_FMT), **latest},
            "qualified_count": len(qual), "gate_ok": len(changes) <= 2 and all(c["qualified"] for c in changes)}


def read_top(best: Path, n: int = 3) -> list[str]:
    ips = []
    for raw in best.read_text(encoding="utf-8").splitlines():
        m = re.match(rf"\s*({IP_RE})\s", raw)
        if m:
            ips.append(m.group(1))
    return ips[:n]


def collect(now: datetime | None = None) -> dict:
    now = now or datetime.now()
    results = CFST / "results"
    rounds = sorted(results.glob("20*.log"))
    pool_max = config_int("POOL_MAX", 0)
    paths = sorted(
        set(results.glob("*.log")) | set(results.glob("cron.log*")) | set(results.glob("fast.log*"))
    )
    report = read_status(results / "cycle-results", now=now, legacy_paths=paths)
    rep = {
        "now": now.strftime(TS_FMT),
        "warnings": [],
        "cycle_result": {k: v for k, v in report.items() if k != "records"},
    }
    latest = rounds[-1] if rounds else None
    r = parse_round(latest.read_text(encoding="utf-8", errors="replace")) if latest else {"audit_ttfb": {}}
    rep["latest_round"] = (
        {
            "file": latest.name,
            "age_min": int((now - datetime.strptime(latest.stem, "%Y%m%d_%H%M%S")).total_seconds() // 60),
            **r,
        }
        if latest
        else None
    )
    if latest is None and report["latest_attempt"] is None:
        rep["warnings"].append("results/ 下没有任何轮次日志或周期结果")
    top = read_top(CFST / "best_ips.txt") if (CFST / "best_ips.txt").exists() else []
    rep["top3"] = [{"ip": ip, "ttfb_ms": r["audit_ttfb"].get(ip)} for ip in top]
    c = collect_contender(results, latest, now)
    modern = next(
        (d for d in report["records"] if d["state"] != "invalid" and d.get("rank") is not None), None
    )
    if modern:
        fast = next((d for d in report["records"] if d["state"] != "invalid" and d["mode"] == "fast"), None)
        rank = modern["rank"]
        c = {k: v for k, v in rank.items() if k not in {"schema_version", "kind", "dry_run"}}
        c.update(
            at=rank["at"],
            source=Path(modern["_path"]).name,
            fast_age_min=int((now - datetime.fromisoformat(fast["started_at"])).total_seconds() // 60)
            if fast
            else None,
            last_cycle={"mode": modern["mode"], "guard": rank["guard"], "rank": modern["rank_status"]},
        )
    rep["contender"] = c
    flow = report["flow_7d"]
    rep["flow_7d"] = {k: flow[k] for k in ("rounds", "screened", "admitted", "evicted")}
    rep["flow_7d"].update(pool_now=c["pool"] if modern else r.get("pool"), pool_max=pool_max)
    push = report["last_push"]
    rep["last_publish"] = {
        "at": push["at"] if push else None,
        "age_h": round((now - datetime.strptime(push["at"], TS_FMT)).total_seconds() / 3600, 1)
        if push
        else None,
        "ips": push["ips"] if push else [],
        "source": push["source"] if push else None,
    }
    ts, _ = last_match([results / "cron.log", results / "cron.log.1"], r"latency scan:")
    rep["last_scan_age_min"] = int((now - ts).total_seconds() // 60) if ts else None
    rep["shadow"] = (
        collect_shadow(
            results / "shadow.log", CFST / "vless_history.tsv", now, extra_logs=(results / "fast.log",)
        )
        if (CFST / ".shadow").is_dir()
        else None
    )
    if latest is not None and rep["latest_round"]["age_min"] > 150:
        rep["warnings"].append(f"最近慢轮日志已过去 {rep['latest_round']['age_min']} 分钟（预期 ≤120）")
    if rep["last_scan_age_min"] is None or rep["last_scan_age_min"] > 15:
        rep["warnings"].append(f"轻扫停摆：上次 latency scan 在 {rep['last_scan_age_min']} 分钟前")
    if r.get("systemic"):
        rep["warnings"].append("最近一轮被判为系统性劣化轮（未累计 IP 级证据）")
    if r.get("unreachable"):
        rep["warnings"].append(f"池审计 {r['unreachable']} 个 IP 本轮不可达")
    if rep["last_publish"]["age_h"] is not None and rep["last_publish"]["age_h"] > 48:
        rep["warnings"].append(f"已 {rep['last_publish']['age_h']}h 未发布（Top3 长期未变或发布链路异常）")
    attempt = report["latest_attempt"]
    if attempt is not None:
        if attempt["state"] == "failed":
            rep["warnings"].append("最近尝试失败；旧完整结果不代表本轮成功")
        elif attempt["state"] == "invalid":
            rep["warnings"].append("最近尝试记录无法解释")
        elif attempt["state"] == "open":
            rep["warnings"].append("最近尝试未收束，不能确定仍在运行或已经中断")
        if attempt.get("warnings"):
            rep["warnings"].append("最近尝试警告：" + ",".join(attempt["warnings"]))
    rep["warnings"].extend(report["errors"])
    return rep


def render(rep: dict) -> str:
    lines = [f"CFST 状态 @ {rep['now']}"]
    lr = rep.get("latest_round")
    if lr:
        lines.append(f"最近慢轮日志: {lr['file']}  {lr['age_min']} 分钟前"
                     + ("  [池满，暂停快筛]" if lr.get("pool_full") else ""))
        if "returned" in lr:
            lines.append(f"池审计: {lr['returned']}/{lr['requested']} 返回, 不可达 {lr['unreachable']}, "
                         f"audit_ok={int(lr['audit_ok'])}, guard {lr['guard']}")
        if "ttfb_p50" in lr:
            lines.append(f"池 TTFB: p50 {lr['ttfb_p50']:.0f}ms  p90 {lr['ttfb_p90']}ms  max {lr['ttfb_max']}ms")
        lines.append("发布 Top3（建议集）: " + "  ".join(
            f"{t['ip']}({t['ttfb_ms']}ms)" if t["ttfb_ms"] is not None else f"{t['ip']}(本轮无样本)"
            for t in rep.get("top3", [])) or "发布 Top3: (无)")
        f = rep["flow_7d"]
        lines.append(f"池流动 7d: 快筛 {f['screened']} → 入池 {f['admitted']}, 淘汰 {f['evicted']}; "
                     f"排名时 {f['pool_now']}/{f['pool_max']}")
        lp = rep["last_publish"]
        lines.append(f"上次发布: {lp['at'] or '无记录'}" + (f"  {lp['age_h']}h 前  {' '.join(lp['ips'])}" if lp["at"] else ""))
        lines.append(f"上次轻扫: {rep['last_scan_age_min']} 分钟前")
        c = rep.get("contender")
        if c:
            age = f"{c['fast_age_min']} 分钟前" if c["fast_age_min"] is not None else "无记录"
            lines.append(f"Contender 池: pool {c['pool']} / core {c['core']} / challengers {c['challengers']}"
                         f"，最近 fast 周期 {age}，最近 guard {c['guard']}"
                         f"，发布 {','.join(c['published']) or '-'}" + ("  [排名建议已变更]" if c["changed"] else ""))
            if "evaluated" in c:
                lines.append(f"验证覆盖: 已完成 {c['evaluated']} / 待验证 {c['waiting']}；"
                             f"本轮质量退出 {c['quality_evicted']} / 容量退出 {c['capacity_evicted']}")
        else:
            lines.append("Contender 池: 未启用")
        s = rep.get("shadow")
        if s:
            lines.append(f"影子对照 48h: {s['rounds_48h']} 轮, Top3 变化 {s['changes_48h']} 次"
                         f"，最近 new={','.join(s['latest']['new']) or '-'}"
                         f" legacy={','.join(s['latest']['legacy']) or '-'}"
                         + ("  硬门通过" if s["gate_ok"] else "  硬门未通过"))
            for ch in s["changes"]:
                mark = "⊆合格集" if ch["qualified"] else "⊄合格集 (" + ",".join(ch["unqualified"]) + ")"
                lines.append(f"  [{ch['at']}] {','.join(ch['top3'])} {mark}")
        else:
            lines.append("影子对照: 未启用")
    cycle = rep.get('cycle_result', {})
    attempt = cycle.get('latest_attempt')
    complete = cycle.get('latest_complete')
    if attempt is not None:
        lines.append(f"最近尝试: {attempt['state']}  {attempt.get('started_at', '时间未知')}")
        lines.append(f"最近完整结果: {complete['started_at']} ({complete['mode']})" if complete else "最近完整结果: 未知或尚无")
        if not lr and rep.get('contender'):
            c=rep['contender']
            lines.append(f"Contender 池: pool {c['pool']} / core {c['core']} / challengers {c['challengers']} (排名时刻)")
    if cycle.get('flow_7d',{}).get('incomplete'):
        lines.append('七日流动统计不完整，未知项未伪造为已确认数量')
    for w in rep["warnings"]:
        lines.append(f"⚠ {w}")
    if not rep["warnings"]:
        lines.append("无告警")
    return "\n".join(lines)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--now", help="测试用：覆盖当前时间 'YYYY-MM-DD HH:MM:SS'")
    a = ap.parse_args()
    rep = collect(datetime.strptime(a.now, TS_FMT) if a.now else None)
    print(json.dumps(rep, ensure_ascii=False, indent=1) if a.json else render(rep))


if __name__ == "__main__":
    main()
