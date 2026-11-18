#!/usr/bin/env python3
"""网段级历史校准 —— 用真实 VLESS TTFB 历史给 /24 与 /16 定性。

存在理由（本轮实测根因）：发现门 `QUAL_LAT=70` 量的是 cfst TCP 平均延迟，
准入门 `VLESS_ADMIT_TTFB=100` 量的是真实 VLESS TTFB。两者不是同一个量，
104.19 段相差约 4 倍，于是形成闭环空转：

    平峰期 TTFB 短暂跌破 100ms 被 screen 录取
      → 拥塞期 probation 复测测到 ~200ms
      → PROBATION_MAX_SLOW=0 计费，撞 fail_limit 拉黑
      → 24h 冷却过期
      → scan_latency 按 TCP 50-61ms < 70 重新发现
      → 回队列

实测代价：104.19 占发现队列 247/300，累计 1271 个 distinct IP、172 个曾
单次达标、当前 master 里 0 个；最近 16 轮 320 个候选只录取 20 个（6.25%），
13/16 轮录取 0 个。优质段反被挤出队列（172.66 仅 15/300、104.18 仅 6/300）。

本模块把 `vless_history.tsv` 里已有的真实测量聚合成网段判定，让发现阶段
不再把算力投在结构性不达标的网段上。

## 粒度：/24 优先，/16 兜底

两个方向都有实测反例，所以必须双层：

  - 104.19 的 32 个 /24 子段无一达标（med<=100 的子段数 = 0），/16 判劣
    不会误杀段内优质子段；未测过的新 /24 也应被整段判劣拦下。
  - 172.64 整体 med=50ms 判优，段内却藏着 4 个劣化 /24（.157/.158/.229/…），
    纯 /16 会放行它们。

## 安全姿态：fail-open

判定只在有足够证据时才拦截。样本不足、history 缺失、行无法解析 —— 全部
放行。这个模块只做「减少浪费」，绝不能成为新的静默阻塞点：错误地拦住一个
好 IP 比多筛几个坏 IP 代价高得多。

判据是 median 毫秒值，不是 PASS/FAIL 状态。`104.19.57.172 PASS 201` 在
history 里是 PASS，但 201ms 是实打实的劣化证据。median<=0（timeout，
没测到值）不参与中位数。

## 判定持久化：打破证据自擦除

上面的设计有一个负反馈缺陷：判定的判据来自被判定对象产生的观测。拦住一个
段之后，该段不再被 screen 测量，不再产生新的 history 行；`SEGMENT_WINDOW_DAYS`
又恰好等于 `verify_vless.sh` 的 `VLESS_HISTORY_DAYS`，于是证据被 prune 时
判定一起消亡：

    A 拦住 104.19 → 该段零测量来源 → 7d 后最后一批证据被 prune
      → 段回落 UNKNOWN → 放行 → 空转闭环以 ~8 天为周期重启

实测确认：拦截后 104.19 在 master/probation/best/discovered 全为 0，最后
测量日 2026-09-15，证据将于 2026-09-22 被删。

修复是把 verdict 落盘并给它独立、更长的 TTL，让判定寿命与证据寿命解耦：

  - live 证据永远覆盖 store —— 段真的改善时新证据立刻生效，不被旧 BAD 压住；
    live 明确判 UNKNOWN（介于 good/bad 之间）同样是真实证据，也要覆盖。
  - store 只在证据被 prune 之后接管，维持判定。
  - store 到期（`SEGMENT_VERDICT_TTL_DAYS`）后释放该段，给它重新证明自己的
    机会 —— 这是有意的再评估窗口，避免永久封段且无重新纳入路径。
"""
from __future__ import annotations

import argparse
import os
import sys
from datetime import datetime, timedelta
from pathlib import Path

from ip_validation import is_valid_ipv4
# median 契约必须与 probation 门控逐字一致：同一份历史、同一种取中位数
# 方式。自造一份会让两处对同一段数据得出不同结论。
from probation import TS_FMT, _median_ms

BAD = "BAD"
GOOD = "GOOD"
UNKNOWN = "UNKNOWN"


def _octets(ip: str) -> list[str] | None:
    if not is_valid_ipv4(ip):
        return None
    return ip.split(".")


def seg24(ip: str) -> str | None:
    o = _octets(ip)
    return ".".join(o[:3]) if o else None


def seg16(ip: str) -> str | None:
    o = _octets(ip)
    return ".".join(o[:2]) if o else None


def load_measurements(path: Path, cutoff: datetime | None) -> dict[str, list[int]]:
    """从 vless_history.tsv 读出每个 IP 的真实 TTFB 测量值。

    行格式: 时间戳<TAB>IP<TAB>PASS|FAIL|PARTIAL<TAB>median_ms<TAB>reason

    只收 median > 0 的行：timeout 行的 median 是 0，代表「没测到」而不是
    「测到 0ms」，计入会把劣化段的中位数拉低。
    """
    out: dict[str, list[int]] = {}
    if not path.exists():
        return out
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        f = raw.split("\t")
        if len(f) < 4:
            continue
        if cutoff is not None:
            try:
                if datetime.strptime(f[0], TS_FMT) < cutoff:
                    continue
            except ValueError:
                continue
        ip = f[1]
        if not is_valid_ipv4(ip):
            continue
        try:
            median = int(f[3])
        except ValueError:
            continue
        if median <= 0:
            continue
        out.setdefault(ip, []).append(median)
    return out


def aggregate(rows: list[tuple[str, str, str, int]]) -> dict[str, list[int]]:
    """测试夹具用：把 (ts, ip, status, median) 元组聚成 per-IP 测量表。"""
    out: dict[str, list[int]] = {}
    for _ts, ip, _st, median in rows:
        if is_valid_ipv4(ip) and median > 0:
            out.setdefault(ip, []).append(median)
    return out


def classify(measurements: dict[str, list[int]], *, min_samples: int, min_ips: int,
             bad_ttfb: int, good_ttfb: int,
             min_samples_24: int | None = None,
             min_ips_24: int | None = None) -> dict[str, str]:
    """把 per-IP 测量聚合成 per-segment 判定（/24 与 /16 各一套）。

    一个网段要被定性，必须同时有足够样本数与足够 distinct IP 数 —— 单个
    IP 刷满样本不能代表整段。两者任一不足即 UNKNOWN（放行）。

    med > bad_ttfb        → BAD
    med <= good_ttfb      → GOOD
    两者之间               → UNKNOWN（不判优也不判劣，保持放行）

    ## /24 用独立门槛

    一个 /16 最多 65536 个 IP，一个 /24 最多 254 个。用同一个样本门槛等于
    要求 /24 攒到 /16 级别的证据才准定性，实测后果是 32 个中位数已超标的
    /24 定不了性，被父 /16 的 GOOD 放行 —— 其中 172.64.229 有 26 个
    distinct IP 全在 201ms，证据早已充分。

    `min_samples_24` / `min_ips_24` 为 None 时回落到共用门槛，保持旧调用
    逐字等价。
    """
    lim = {
        2: (min_samples, min_ips),
        3: (min_samples if min_samples_24 is None else min_samples_24,
            min_ips if min_ips_24 is None else min_ips_24),
    }

    buckets: dict[str, tuple[list[int], set[str]]] = {}
    for ip, values in measurements.items():
        for key in (seg24(ip), seg16(ip)):
            if key is None:
                continue
            vals, ips = buckets.setdefault(key, ([], set()))
            vals.extend(values)
            ips.add(ip)

    verdicts: dict[str, str] = {}
    for key, (vals, ips) in buckets.items():
        need_n, need_ips = lim[key.count(".") + 1]
        if len(vals) < need_n or len(ips) < need_ips:
            continue  # 证据不足：不写判定 = UNKNOWN = 放行
        med = _median_ms(vals)
        if med > bad_ttfb:
            verdicts[key] = BAD
        elif med <= good_ttfb:
            verdicts[key] = GOOD
        else:
            verdicts[key] = UNKNOWN
    return verdicts


def verdict_for_ip(ip: str, verdicts: dict[str, str]) -> tuple[str, str | None]:
    """返回 (判定, 命中的前缀)。/24 优先于 /16。

    /24 是更精确的证据，一旦有定性结论就用它 —— 这既让 BAD /16 内的达标
    /24 得以放行，也让 GOOD /16 内的劣化 /24 被拦下。/24 为 UNKNOWN 或
    无记录时才回退到 /16。
    """
    k24, k16 = seg24(ip), seg16(ip)
    if k24 is not None:
        v = verdicts.get(k24)
        if v in (BAD, GOOD):
            return v, k24
    if k16 is not None:
        v = verdicts.get(k16)
        if v in (BAD, GOOD):
            return v, k16
    return UNKNOWN, None


def allowed(ip: str, verdicts: dict[str, str]) -> bool:
    """只有明确 BAD 才拦；UNKNOWN 与 GOOD 一律放行（fail-open）。"""
    return verdict_for_ip(ip, verdicts)[0] != BAD


# ── 判定持久化：verdict 寿命与证据寿命解耦 ──────────────────────────────

def load_verdict_store(path: Path | None, *, now: datetime,
                       ttl_days: int) -> dict[str, tuple[str, datetime]]:
    """读取落盘判定，丢弃过期项。

    行格式: 网段前缀<TAB>BAD|GOOD<TAB>last_confirmed

    缺失、不可读、损坏行一律当作「无判定」—— 这个 store 只能加强拦截，
    绝不能因自身故障造成断供，所以任何异常都退化为 fail-open。
    只接受 BAD/GOOD：UNKNOWN 等于默认放行，落盘毫无信息量。
    """
    out: dict[str, tuple[str, datetime]] = {}
    if path is None or not path.exists():
        return out
    cutoff = now - timedelta(days=ttl_days) if ttl_days > 0 else None
    try:
        body = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return out
    for raw in body.splitlines():
        f = raw.split("\t")
        if len(f) < 3:
            continue
        key, verdict, stamp = f[0].strip(), f[1].strip(), f[2].strip()
        if not key or verdict not in (BAD, GOOD):
            continue
        try:
            last = datetime.strptime(stamp, TS_FMT)
        except ValueError:
            continue
        if cutoff is not None and last < cutoff:
            continue  # 到期释放：给该段重新证明自己的机会
        out[key] = (verdict, last)
    return out


def save_verdict_store(path: Path, entries: dict[str, tuple[str, datetime]]) -> None:
    """原子写入判定 store；只落 BAD/GOOD。

    同目录临时文件 + os.replace：中途失败不会留下半截文件，读侧永远看到
    完整的旧版或完整的新版。
    """
    lines = [f"{k}\t{v}\t{ts.strftime(TS_FMT)}"
             for k, (v, ts) in sorted(entries.items())
             if v in (BAD, GOOD)]
    payload = "".join(f"{ln}\n" for ln in lines)
    tmp = path.with_name(f".{path.name}.tmp.{os.getpid()}")
    try:
        tmp.write_text(payload, encoding="utf-8")
        os.replace(tmp, path)
    finally:
        if tmp.exists():
            tmp.unlink()


def merge_verdicts(live: dict[str, str],
                   stored: dict[str, tuple[str, datetime]]) -> dict[str, str]:
    """合并 live 与落盘判定；live 永远优先。

    live 里出现的键一律用 live 值 —— 包括 live 明确判出的 UNKNOWN。那是
    「测到了，介于 good/bad 之间」的真实证据，不是「没测到」，必须能推翻
    过期的 stored BAD，否则段真的改善后永远出不来。

    stored 只填补 live 没有的键，即证据已被 prune 的那些段。
    """
    merged = {k: v for k, (v, _ts) in stored.items()}
    merged.update(live)
    return merged


def refresh_verdict_store(path: Path, live: dict[str, str], *, now: datetime,
                          ttl_days: int) -> dict[str, tuple[str, datetime]]:
    """用 live 证据刷新 store：确认、降级、到期清理。

      - live 判 BAD/GOOD  → 写入并把 last_confirmed 推到 now
      - live 判 UNKNOWN   → 删除该键（最新证据推翻了旧判定）
      - live 无该键        → 保留（证据被 prune 了，判定继续生效直到到期）
      - 已过期            → 从盘上清掉
    """
    entries = load_verdict_store(path, now=now, ttl_days=ttl_days)
    for key, verdict in live.items():
        if verdict in (BAD, GOOD):
            entries[key] = (verdict, now)
        else:
            entries.pop(key, None)
    save_verdict_store(path, entries)
    return entries


def _now_of(args: argparse.Namespace) -> datetime:
    return datetime.strptime(args.now, TS_FMT) if args.now else datetime.now()


def _live_verdicts(args: argparse.Namespace) -> dict[str, str]:
    """只按 history 现存证据判定，不掺 store。"""
    cutoff = None
    if args.window_days > 0:
        cutoff = _now_of(args) - timedelta(days=args.window_days)
    meas = load_measurements(args.history, cutoff)
    return classify(meas, min_samples=args.min_samples, min_ips=args.min_ips,
                    min_samples_24=args.min_samples_24, min_ips_24=args.min_ips_24,
                    bad_ttfb=args.bad_ttfb, good_ttfb=args.good_ttfb)


def _build_verdicts(args: argparse.Namespace) -> dict[str, str]:
    """判定的生效值：live 证据 + 落盘判定兜底。"""
    live = _live_verdicts(args)
    stored = load_verdict_store(args.verdict_store, now=_now_of(args),
                                ttl_days=args.verdict_ttl_days)
    return merge_verdicts(live, stored)


def _cmd_filter(args: argparse.Namespace) -> int:
    """stdin → stdout，剔除落在 BAD 网段的行，其余逐字保留。

    无法解析的行原样透传：这个过滤器不承担格式校验职责（那是
    ip_validation.py 的事），静默吞掉未知格式会造成难查的数据丢失。
    """
    verdicts = _build_verdicts(args)
    idx = args.field - 1
    for line in sys.stdin:
        row = line.rstrip("\n")
        fields = row.split("\t")
        if idx >= len(fields):
            sys.stdout.write(line)
            continue
        ip = fields[idx].strip()
        if not is_valid_ipv4(ip) or allowed(ip, verdicts):
            sys.stdout.write(line)
    return 0


def _cmd_classify(args: argparse.Namespace) -> int:
    """stdin → `IP<TAB>判定<TAB>命中前缀`，供审计与调试。"""
    verdicts = _build_verdicts(args)
    idx = args.field - 1
    for line in sys.stdin:
        fields = line.rstrip("\n").split("\t")
        if idx >= len(fields):
            continue
        ip = fields[idx].strip()
        if not is_valid_ipv4(ip):
            continue
        v, prefix = verdict_for_ip(ip, verdicts)
        print(f"{ip}\t{v}\t{prefix or '-'}")
    return 0


def _cmd_refresh(args: argparse.Namespace) -> int:
    """按 live 证据刷新判定 store，输出确认/保留/清理计数。

    必须每轮跑：不刷新的 store 会停在第一次写入的判定上，段改善后永不解封，
    等于把 fail-open 设计变成永久封段。
    """
    if args.verdict_store is None:
        print("refresh 需要 --verdict-store", file=sys.stderr)
        return 2
    now = _now_of(args)
    live = _live_verdicts(args)
    before = load_verdict_store(args.verdict_store, now=now,
                                ttl_days=args.verdict_ttl_days)
    after = refresh_verdict_store(args.verdict_store, live, now=now,
                                  ttl_days=args.verdict_ttl_days)
    confirmed = sum(1 for k, v in live.items() if v in (BAD, GOOD))
    carried = sum(1 for k in after if k not in live)
    demoted = sum(1 for k in before if live.get(k) == UNKNOWN)
    print(f"verdict store: confirmed={confirmed} carried={carried} "
          f"demoted={demoted} total={len(after)}")
    return 0


def _cmd_report(args: argparse.Namespace) -> int:
    """按网段列出判定、样本数、distinct IP 数与中位数。"""
    cutoff = None
    if args.window_days > 0:
        cutoff = _now_of(args) - timedelta(days=args.window_days)
    meas = load_measurements(args.history, cutoff)
    verdicts = _build_verdicts(args)

    stats: dict[str, tuple[list[int], set[str]]] = {}
    for ip, values in meas.items():
        for key in (seg24(ip), seg16(ip)):
            if key is None:
                continue
            vals, ips = stats.setdefault(key, ([], set()))
            vals.extend(values)
            ips.add(ip)

    print(f"{'segment':<16} {'verdict':<8} {'n':>6} {'IPs':>5} {'med':>6}")
    rows = []
    for key, (vals, ips) in stats.items():
        depth = key.count(".") + 1
        rows.append((depth, key, verdicts.get(key, UNKNOWN), len(vals), len(ips),
                     _median_ms(vals)))
    for depth, key, v, n, nip, med in sorted(rows, key=lambda r: (r[0], -r[3])):
        if args.only_defined and v == UNKNOWN:
            continue
        print(f"{key:<16} {v:<8} {n:>6} {nip:>5} {med:>6}")
    return 0


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="按真实 VLESS TTFB 历史给网段定性（/24 优先，/16 兜底）")
    p.add_argument("mode", choices=("filter", "classify", "report", "refresh"))
    p.add_argument("--history", type=Path, required=True, help="vless_history.tsv")
    p.add_argument("--field", type=int, default=1, help="stdin 中 IP 所在列（1-based）")
    p.add_argument("--min-samples", type=int, default=50,
                   help="定性所需最少测量样本数，不足即放行")
    p.add_argument("--min-ips", type=int, default=8,
                   help="定性所需最少 distinct IP 数，防单 IP 代表整段")
    # /24 最多 254 个 IP，/16 最多 65536 个：同一门槛会让 /24 永远攒不够证据。
    # 不传则回落到共用门槛。
    p.add_argument("--min-samples-24", type=int, default=None,
                   help="/24 专用最少样本数（默认沿用 --min-samples）")
    p.add_argument("--min-ips-24", type=int, default=None,
                   help="/24 专用最少 distinct IP 数（默认沿用 --min-ips）")
    p.add_argument("--bad-ttfb", type=int, default=150,
                   help="段中位数超过该值判劣（对应 VLESS_RETIRE_TTFB）")
    p.add_argument("--good-ttfb", type=int, default=100,
                   help="段中位数不超过该值判优（对应 VLESS_ADMIT_TTFB）")
    p.add_argument("--window-days", type=int, default=7,
                   help="证据窗口天数，0 表示不限")
    # 判定 store：证据被 prune 后维持判定，避免「拦截切断证据 → 判定消亡 →
    # 重新放行」的自擦除闭环。不传则完全退化为旧行为（纯 live 判定）。
    p.add_argument("--verdict-store", type=Path, default=None,
                   help="判定持久化文件（不传则只用 live 证据）")
    p.add_argument("--verdict-ttl-days", type=int, default=30,
                   help="落盘判定寿命，须严格长于 history 保留期；到期释放该段")
    p.add_argument("--now", default=None, help="窗口基准时间（默认当前）")
    p.add_argument("--only-defined", action="store_true",
                   help="report 模式只列有明确判定的网段")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    return {"filter": _cmd_filter,
            "classify": _cmd_classify,
            "report": _cmd_report,
            "refresh": _cmd_refresh}[args.mode](args)


if __name__ == "__main__":
    sys.exit(main())
