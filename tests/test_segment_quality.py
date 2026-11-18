#!/usr/bin/env python3
"""网段级历史校准（A）回归测试。

根因（本轮实测）：发现门 `QUAL_LAT=70` 量的是 cfst TCP 平均延迟，准入门
`VLESS_ADMIT_TTFB=100` 量的是真实 VLESS TTFB。104.19 段两者相差约 4 倍，
于是形成闭环空转：平峰期 TTFB 短暂跌破 100ms 被 screen 录取 → 拥塞期复测
测到 ~200ms → PROBATION_MAX_SLOW=0 计费 → 撞 fail_limit 拉黑 → 24h 冷却
过期 → scan_latency 按 TCP 50-61ms < 70 重新发现 → 回队列。

实测证据：104.19 累计 1271 个 distinct IP、172 个曾单次达标、当前 master
里 0 个；该段 32 个 /24 子段无一达标（med<=100 的子段数 = 0）。同时 172.64
段整体 med=50ms 判优，段内却藏着 4 个劣化 /24 —— 所以粒度必须 /24 优先、
/16 兜底，不能只做 /16。

本模块的硬约束（每条都有对应测试）：
  1. /24 判定优先于 /16；BAD /16 内的达标 /24 必须放行
  2. GOOD /16 内的劣化 /24 必须拦下
  3. 样本不足 = UNKNOWN = 放行（fail-open，绝不因无知拦截）
  4. history 缺失/不可读 = 全部放行
  5. 判据是 median 毫秒值，不是 PASS/FAIL 状态（PASS 201ms 是劣化证据）
  6. median<=0 的 timeout 行不参与中位数计算
  7. median 契约与 probation.py 逐字一致（同一函数对象）
"""
from __future__ import annotations

import re
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime
from pathlib import Path

CFST = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(CFST))

import segment_quality as sq  # noqa: E402


def sq_ts_fmt() -> str:
    """判定 store 的时间戳格式必须与 history/probation 逐字一致。"""
    return sq.TS_FMT


def hist(rows: list[tuple[str, str, str, int]]) -> str:
    """构造 vless_history.tsv 文本：ts, ip, status, median, reason"""
    return "".join(f"{ts}\t{ip}\t{st}\t{md}\t\n" for ts, ip, st, md in rows)


def seg_rows(prefix: str, n_ips: int, samples_per_ip: int, median: int,
             ts: str = "2026-09-15 12:00:00") -> list[tuple[str, str, str, int]]:
    """为一个 /24 前缀批量生成同质样本。"""
    out = []
    for i in range(1, n_ips + 1):
        for _ in range(samples_per_ip):
            status = "PASS" if median <= 100 else "FAIL"
            out.append((ts, f"{prefix}.{i}", status, median))
    return out


class SegmentKeyTests(unittest.TestCase):
    def test_prefix_extraction(self) -> None:
        self.assertEqual(sq.seg24("104.19.59.128"), "104.19.59")
        self.assertEqual(sq.seg16("104.19.59.128"), "104.19")

    def test_invalid_ip_yields_no_prefix(self) -> None:
        self.assertIsNone(sq.seg24("not-an-ip"))
        self.assertIsNone(sq.seg16("999.1.1.1"))


class MedianContractTests(unittest.TestCase):
    def test_median_helper_is_the_probation_one(self) -> None:
        """禁止自造 median：必须复用 probation.py 的同一函数对象。"""
        import probation
        self.assertIs(sq._median_ms, probation._median_ms)

    def test_even_sample_contract(self) -> None:
        self.assertEqual(sq._median_ms([40, 50]), 45)
        self.assertEqual(sq._median_ms([40, 51]), 46)


class LoadMeasurementTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())

    def w(self, rows) -> Path:
        p = self.tmp / "h.tsv"
        p.write_text(hist(rows), encoding="utf-8")
        return p

    def test_pass_over_threshold_counts_as_a_real_measurement(self) -> None:
        """104.19.57.172 PASS 201 是实测劣化证据，不能因 PASS 就忽略。"""
        p = self.w([("2026-09-15 12:00:00", "104.19.57.172", "PASS", 201)])
        m = sq.load_measurements(p, cutoff=None)
        self.assertEqual(m["104.19.57.172"], [201])

    def test_zero_median_timeout_is_excluded(self) -> None:
        p = self.w([
            ("2026-09-15 12:00:00", "1.1.1.1", "FAIL", 0),
            ("2026-09-15 12:00:00", "1.1.1.1", "PASS", 45),
        ])
        m = sq.load_measurements(p, cutoff=None)
        self.assertEqual(m["1.1.1.1"], [45], "median<=0 不是测量值")

    def test_missing_file_returns_empty(self) -> None:
        self.assertEqual(sq.load_measurements(self.tmp / "nope.tsv", None), {})

    def test_cutoff_filters_old_rows(self) -> None:
        from datetime import datetime
        p = self.w([
            ("2026-09-01 12:00:00", "1.1.1.1", "PASS", 40),
            ("2026-09-15 12:00:00", "1.1.1.1", "PASS", 50),
        ])
        m = sq.load_measurements(p, cutoff=datetime(2026, 9, 10))
        self.assertEqual(m["1.1.1.1"], [50])


class ClassificationTests(unittest.TestCase):
    LIM = dict(min_samples=30, min_ips=5, bad_ttfb=150, good_ttfb=100)

    def test_bad_segment_is_flagged(self) -> None:
        meas = sq.aggregate(seg_rows("104.19.59", n_ips=10, samples_per_ip=5, median=199))
        v = sq.classify(meas, **self.LIM)
        self.assertEqual(v["104.19.59"], sq.BAD)
        self.assertEqual(v["104.19"], sq.BAD)

    def test_good_segment_is_flagged(self) -> None:
        meas = sq.aggregate(seg_rows("172.66.1", n_ips=10, samples_per_ip=5, median=48))
        v = sq.classify(meas, **self.LIM)
        self.assertEqual(v["172.66.1"], sq.GOOD)

    def test_insufficient_samples_is_unknown(self) -> None:
        meas = sq.aggregate(seg_rows("104.19.59", n_ips=2, samples_per_ip=2, median=199))
        v = sq.classify(meas, **self.LIM)
        self.assertEqual(v.get("104.19.59", sq.UNKNOWN), sq.UNKNOWN)

    def test_few_distinct_ips_is_unknown_even_with_many_samples(self) -> None:
        """单个 IP 刷满样本不得代表整段。"""
        meas = sq.aggregate(seg_rows("104.19.59", n_ips=1, samples_per_ip=100, median=199))
        v = sq.classify(meas, **self.LIM)
        self.assertEqual(v.get("104.19.59", sq.UNKNOWN), sq.UNKNOWN)

    def test_borderline_between_good_and_bad_is_unknown(self) -> None:
        """100 < med <= 150 既不判优也不判劣，保持放行。"""
        meas = sq.aggregate(seg_rows("104.20.1", n_ips=10, samples_per_ip=5, median=130))
        v = sq.classify(meas, **self.LIM)
        self.assertEqual(v["104.20.1"], sq.UNKNOWN)


class PerDepthThresholdTests(unittest.TestCase):
    """/24 必须能用比 /16 更低的定性门槛。

    一个 /16 最多 65536 个 IP，一个 /24 最多 254 个 —— 对两者用同一个样本
    门槛，等于要求 /24 攒到 /16 级别的证据才准定性。实测后果：生产窗口里
    有 32 个 /24 中位数已超 150ms 却因样本不足定不了性，其中 172.64.229
    有 26 个 distinct IP 全在 201ms，证据充分，仍被 172.64 的 GOOD 放行。

    门槛选 n>=10 IPs>=5 的依据（生产 7d 窗口实测）：
      - 新捕获 BAD /24 从 18 涨到 35，堵住 3 个 GOOD /16 内的泄漏段
      - 危险方向（BAD /16 内被 GOOD /24 误放行）在该门槛下为 0 个
      - 再放宽到 n>=6 IPs>=3 时，BAD 覆盖 GOOD /16 的数量跳到 12，过拟合
    """

    def test_low_sample_bad_24_inside_good_16_is_caught(self) -> None:
        """实测泄漏场景 172.64.229：26 个 IP 全 201ms，样本仅 30。"""
        rows = (seg_rows("172.64.153", 17, 4, 51)      # 撑起 /16 的 GOOD 判定
                + seg_rows("172.64.229", 26, 1, 201))  # 泄漏段：IP 多、样本少
        meas = sq.aggregate(rows)

        # 同一门槛：/24 定不了性，被 /16 的 GOOD 放行 —— 这是缺陷
        same = sq.classify(meas, min_samples=50, min_ips=8,
                           bad_ttfb=150, good_ttfb=100)
        self.assertEqual(same["172.64"], sq.GOOD)
        self.assertNotIn("172.64.229", same, "样本不足，同门槛下定不了性")
        self.assertTrue(sq.allowed("172.64.229.5", same), "缺陷复现：被放行")

        # 独立 /24 门槛：证据充分，必须判劣并拦下
        split = sq.classify(meas, min_samples=50, min_ips=8,
                            min_samples_24=10, min_ips_24=5,
                            bad_ttfb=150, good_ttfb=100)
        self.assertEqual(split["172.64"], sq.GOOD, "/16 判定不受影响")
        self.assertEqual(split["172.64.229"], sq.BAD)
        self.assertFalse(sq.allowed("172.64.229.5", split),
                         "GOOD /16 内的劣化 /24 必须被拦")

    def test_24_threshold_does_not_leak_into_16(self) -> None:
        """/24 的低门槛不得让 /16 也用低门槛定性。"""
        rows = seg_rows("104.20.1", 6, 2, 199)   # 12 样本 6 IP
        v = sq.classify(sq.aggregate(rows), min_samples=50, min_ips=8,
                        min_samples_24=10, min_ips_24=5,
                        bad_ttfb=150, good_ttfb=100)
        self.assertEqual(v["104.20.1"], sq.BAD, "/24 达到自己的门槛")
        self.assertNotIn("104.20", v, "/16 样本不足，不得借用 /24 门槛")

    def test_tiny_24_still_cannot_be_classified(self) -> None:
        """低门槛不是没门槛：n=3 的 /24 仍必须放行。"""
        rows = seg_rows("104.20.9", 3, 1, 201)
        v = sq.classify(sq.aggregate(rows), min_samples=50, min_ips=8,
                        min_samples_24=10, min_ips_24=5,
                        bad_ttfb=150, good_ttfb=100)
        self.assertNotIn("104.20.9", v)
        self.assertTrue(sq.allowed("104.20.9.1", v))

    def test_defaults_fall_back_to_the_shared_threshold(self) -> None:
        """不传 /24 专用门槛时，行为与旧签名逐字一致（向后兼容）。"""
        rows = seg_rows("104.19.59", 10, 5, 199)
        meas = sq.aggregate(rows)
        old = sq.classify(meas, min_samples=30, min_ips=5,
                          bad_ttfb=150, good_ttfb=100)
        new = sq.classify(meas, min_samples=30, min_ips=5,
                          min_samples_24=None, min_ips_24=None,
                          bad_ttfb=150, good_ttfb=100)
        self.assertEqual(old, new)

    def test_cli_exposes_the_per_depth_threshold(self) -> None:
        """CLI 必须能传 /24 门槛，否则 scan_latency.sh 用不上。"""
        tmp = Path(tempfile.mkdtemp())
        h = tmp / "h.tsv"
        h.write_text(hist(seg_rows("172.64.153", 17, 4, 51)
                          + seg_rows("172.64.229", 26, 1, 201)),
                     encoding="utf-8")
        r = subprocess.run(
            [sys.executable, str(CFST / "segment_quality.py"), "filter",
             "--history", str(h), "--field", "1",
             "--min-samples", "50", "--min-ips", "8",
             "--min-samples-24", "10", "--min-ips-24", "5",
             "--window-days", "0"],
            input="172.64.229.5\t50.0\n172.64.153.9\t51.0\n",
            capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertNotIn("172.64.229.5", r.stdout, "泄漏 /24 必须被 CLI 拦下")
        self.assertIn("172.64.153.9", r.stdout)


class VerdictResolutionTests(unittest.TestCase):
    """粒度规则：/24 优先，/16 兜底，都不知则放行。"""
    LIM = dict(min_samples=30, min_ips=5, bad_ttfb=150, good_ttfb=100)

    def test_good_24_inside_bad_16_is_allowed(self) -> None:
        rows = (seg_rows("104.19.59", 10, 5, 199)
                + seg_rows("104.19.60", 10, 5, 199)
                + seg_rows("104.19.7", 10, 5, 45))
        v = sq.classify(sq.aggregate(rows), **self.LIM)
        self.assertEqual(v["104.19"], sq.BAD, "整段应判劣")
        verdict, prefix = sq.verdict_for_ip("104.19.7.9", v)
        self.assertEqual(verdict, sq.GOOD)
        self.assertEqual(prefix, "104.19.7", "/24 必须优先于 /16")
        self.assertTrue(sq.allowed("104.19.7.9", v))

    def test_bad_24_inside_good_16_is_blocked(self) -> None:
        """172.64 实测场景：整段 med=50ms，段内仍有劣化 /24。"""
        rows = (seg_rows("172.64.146", 10, 5, 48)
                + seg_rows("172.64.153", 10, 5, 47)
                + seg_rows("172.64.157", 10, 5, 210))
        v = sq.classify(sq.aggregate(rows), **self.LIM)
        self.assertEqual(v["172.64"], sq.GOOD)
        self.assertFalse(sq.allowed("172.64.157.7", v), "GOOD /16 不得放行劣化 /24")
        self.assertTrue(sq.allowed("172.64.146.81", v))

    def test_bad_16_blocks_unmeasured_24(self) -> None:
        """104.19 内未测过的新 /24 应被整段判劣拦下。"""
        rows = seg_rows("104.19.59", 10, 5, 199) + seg_rows("104.19.60", 10, 5, 201)
        v = sq.classify(sq.aggregate(rows), **self.LIM)
        verdict, prefix = sq.verdict_for_ip("104.19.200.5", v)
        self.assertEqual(verdict, sq.BAD)
        self.assertEqual(prefix, "104.19")
        self.assertFalse(sq.allowed("104.19.200.5", v))

    def test_completely_unknown_ip_is_allowed(self) -> None:
        v = sq.classify(sq.aggregate(seg_rows("104.19.59", 10, 5, 199)), **self.LIM)
        self.assertTrue(sq.allowed("8.8.8.8", v), "无证据必须放行")
        self.assertEqual(sq.verdict_for_ip("8.8.8.8", v)[0], sq.UNKNOWN)

    def test_empty_verdicts_allow_everything(self) -> None:
        """fail-open：history 不可用时不得拦任何 IP。"""
        for ip in ("104.19.59.1", "172.64.157.7", "1.2.3.4"):
            self.assertTrue(sq.allowed(ip, {}))


class CliFilterTests(unittest.TestCase):
    """CLI 必须能就地插进 scan_latency.sh 的两条管道。"""

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())
        rows = (seg_rows("104.19.59", 10, 5, 199)
                + seg_rows("172.64.157", 10, 5, 210)
                + seg_rows("172.64.146", 10, 5, 48))
        self.h = self.tmp / "h.tsv"
        self.h.write_text(hist(rows), encoding="utf-8")

    def run_cli(self, args: list[str], stdin: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, str(CFST / "segment_quality.py"), *args,
             "--now", "2026-09-22 12:00:00"],
            input=stdin, capture_output=True, text=True)

    def test_filter_field1_drops_bad_keeps_good_and_unknown(self) -> None:
        stdin = "104.19.59.20\t61.4\n172.64.146.81\t45.0\n172.64.157.7\t50.0\n8.8.8.8\t40.0\n"
        r = self.run_cli(["filter", "--history", str(self.h), "--field", "1",
                          "--min-samples", "30", "--min-ips", "5"], stdin)
        self.assertEqual(r.returncode, 0, r.stderr)
        out = r.stdout
        self.assertNotIn("104.19.59.20", out, "BAD /16 必须剔除")
        self.assertNotIn("172.64.157.7", out, "BAD /24 必须剔除")
        self.assertIn("172.64.146.81", out)
        self.assertIn("8.8.8.8", out, "UNKNOWN 必须放行")
        self.assertIn("172.64.146.81\t45.0", out, "非目标列必须逐字保留")

    def test_filter_field2_handles_queue_rows(self) -> None:
        stdin = ("2026-09-15 09:00:00\t104.19.59.20\t0\t61.4\n"
                 "2026-09-15 09:00:00\t172.64.146.81\t2\t45.0\n")
        r = self.run_cli(["filter", "--history", str(self.h), "--field", "2",
                          "--min-samples", "30", "--min-ips", "5"], stdin)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertNotIn("104.19.59.20", r.stdout)
        self.assertIn("2026-09-15 09:00:00\t172.64.146.81\t2\t45.0", r.stdout,
                      "4 字段契约必须逐字穿过")

    def test_filter_fails_open_when_history_missing(self) -> None:
        stdin = "104.19.59.20\t61.4\n"
        r = self.run_cli(["filter", "--history", str(self.tmp / "nope.tsv"),
                          "--field", "1"], stdin)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("104.19.59.20", r.stdout, "history 缺失必须 fail-open")

    def test_malformed_line_is_passed_through(self) -> None:
        r = self.run_cli(["filter", "--history", str(self.h), "--field", "2",
                          "--min-samples", "30", "--min-ips", "5"], "garbage\n")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("garbage", r.stdout, "无法解析的行不得静默丢弃")

    def test_report_mode_lists_segments(self) -> None:
        r = self.run_cli(["report", "--history", str(self.h),
                          "--min-samples", "30", "--min-ips", "5"], "")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("104.19", r.stdout)
        self.assertIn("BAD", r.stdout)

    def test_classify_mode_emits_verdict_and_prefix(self) -> None:
        r = self.run_cli(["classify", "--history", str(self.h), "--field", "1",
                          "--min-samples", "30", "--min-ips", "5"],
                         "104.19.59.20\n172.64.146.81\n8.8.8.8\n")
        self.assertEqual(r.returncode, 0, r.stderr)
        got = dict(l.split("\t")[0:2] for l in r.stdout.strip().split("\n"))
        self.assertEqual(got["104.19.59.20"], sq.BAD)
        self.assertEqual(got["172.64.146.81"], sq.GOOD)
        self.assertEqual(got["8.8.8.8"], sq.UNKNOWN)


class VerdictStoreTests(unittest.TestCase):
    """判定持久化：verdict 寿命与证据寿命解耦。

    根因（本轮实测）：段判定完全由 vless_history.tsv 现存内容每轮重算，
    而 SEGMENT_WINDOW_DAYS=7 恰好等于 VLESS_HISTORY_DAYS=7 —— 判定寿命
    == 证据寿命。于是拦截规则的判据来自被拦截对象产生的观测：

        A 拦住 104.19 → 该段不再被 screen 测量 → 不再产生新 history 行
          → 7d 后 prune_vless_history 删掉最后一批证据
          → 段回落 UNKNOWN → 放行 → 空转闭环以 ~8 天为周期重启

    实测确认：拦截后 104.19 在 master/probation/best/discovered 全部为 0，
    唯一测量来源已切断；最后测量日 2026-09-15，证据将于 2026-09-22 被删。

    修复：把 verdict 落盘并给它独立、更长的 TTL。live 证据永远覆盖 store
    （段真的改善时立刻生效），store 只在证据被 prune 后接管，到期后释放该
    段重新证明自己的机会。成本 0 screen 预算。
    """

    NOW = datetime(2026, 9, 22, 12, 0, 0)
    LIM = dict(min_samples=30, min_ips=5, bad_ttfb=150, good_ttfb=100)

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())
        self.store = self.tmp / "segment_verdicts.tsv"

    def ts(self, days_ago: float) -> str:
        from datetime import timedelta
        return (self.NOW - timedelta(days=days_ago)).strftime(sq_ts_fmt())

    # ── store I/O ──

    def test_missing_store_is_empty_not_an_error(self) -> None:
        self.assertEqual(
            sq.load_verdict_store(self.store, now=self.NOW, ttl_days=30), {})

    def test_store_round_trip(self) -> None:
        sq.save_verdict_store(self.store, {
            "104.19": (sq.BAD, self.NOW),
            "172.66": (sq.GOOD, self.NOW),
        })
        got = sq.load_verdict_store(self.store, now=self.NOW, ttl_days=30)
        self.assertEqual(got["104.19"][0], sq.BAD)
        self.assertEqual(got["172.66"][0], sq.GOOD)

    def test_store_write_is_atomic_and_leaves_no_temp(self) -> None:
        sq.save_verdict_store(self.store, {"104.19": (sq.BAD, self.NOW)})
        leftovers = [p.name for p in self.tmp.iterdir() if p != self.store]
        self.assertEqual(leftovers, [], f"临时文件残留: {leftovers}")

    def test_corrupt_lines_are_skipped_not_fatal(self) -> None:
        self.store.write_text(
            "garbage\n"
            f"104.19\t{sq.BAD}\t{self.ts(1)}\n"
            "172.66\tNOTAVERDICT\t" + self.ts(1) + "\n"
            f"104.18\t{sq.GOOD}\tnot-a-timestamp\n",
            encoding="utf-8")
        got = sq.load_verdict_store(self.store, now=self.NOW, ttl_days=30)
        self.assertEqual(set(got), {"104.19"}, "只有合法行被采纳")

    def test_unknown_is_not_persisted(self) -> None:
        """UNKNOWN == 放行 == 默认，落盘只会让文件膨胀。"""
        sq.save_verdict_store(self.store, {
            "104.19": (sq.BAD, self.NOW),
            "104.20": (sq.UNKNOWN, self.NOW),
        })
        got = sq.load_verdict_store(self.store, now=self.NOW, ttl_days=30)
        self.assertEqual(set(got), {"104.19"})

    # ── TTL ──

    def test_entry_within_ttl_survives(self) -> None:
        sq.save_verdict_store(self.store, {"104.19": (sq.BAD, self.NOW)})
        self.store.write_text(f"104.19\t{sq.BAD}\t{self.ts(29)}\n",
                              encoding="utf-8")
        got = sq.load_verdict_store(self.store, now=self.NOW, ttl_days=30)
        self.assertIn("104.19", got, "29d < 30d TTL，判定仍有效")

    def test_entry_beyond_ttl_is_dropped(self) -> None:
        """到期释放：给该段重新证明自己的机会（这是有意的再评估窗口）。"""
        self.store.write_text(f"104.19\t{sq.BAD}\t{self.ts(31)}\n",
                              encoding="utf-8")
        got = sq.load_verdict_store(self.store, now=self.NOW, ttl_days=30)
        self.assertNotIn("104.19", got, "31d > 30d TTL，判定必须失效")

    # ── 合并语义：live 永远覆盖 store ──

    def test_live_evidence_overrides_stale_stored_bad(self) -> None:
        """段真的改善时，新证据必须立刻生效，不能被旧 BAD 压住。"""
        live = sq.classify(sq.aggregate(seg_rows("104.19.59", 8, 5, 48)),
                           **self.LIM)
        stored = {"104.19": (sq.BAD, self.NOW), "104.19.59": (sq.BAD, self.NOW)}
        merged = sq.merge_verdicts(live, stored)
        self.assertEqual(merged["104.19.59"], sq.GOOD)
        self.assertTrue(sq.allowed("104.19.59.7", merged),
                        "live GOOD 必须覆盖 stored BAD")

    def test_live_defined_unknown_also_overrides_store(self) -> None:
        """介于 good/bad 之间的 UNKNOWN 是真实证据，不是「无证据」。"""
        live = sq.classify(sq.aggregate(seg_rows("104.19.59", 8, 5, 130)),
                           **self.LIM)
        self.assertEqual(live["104.19.59"], sq.UNKNOWN, "前提：live 判 UNKNOWN")
        merged = sq.merge_verdicts(live, {"104.19.59": (sq.BAD, self.NOW)})
        self.assertTrue(sq.allowed("104.19.59.7", merged),
                        "live 明确 UNKNOWN 必须覆盖 stored BAD")

    def test_store_fills_the_gap_when_evidence_was_pruned(self) -> None:
        """核心回归：证据被 prune 后判定仍生效（自擦除修复）。"""
        live = sq.classify(sq.aggregate([]), **self.LIM)
        self.assertEqual(live, {}, "前提：history 已无该段证据")
        merged = sq.merge_verdicts(live, {"104.19": (sq.BAD, self.NOW)})
        self.assertFalse(sq.allowed("104.19.59.7", merged),
                         "证据消失不得让判定消失，否则空转闭环重启")

    def test_expired_store_releases_the_segment(self) -> None:
        """完整自擦除→再评估链路：TTL 到期后该段重新可被发现。"""
        self.store.write_text(f"104.19\t{sq.BAD}\t{self.ts(31)}\n",
                              encoding="utf-8")
        stored = sq.load_verdict_store(self.store, now=self.NOW, ttl_days=30)
        merged = sq.merge_verdicts(sq.classify(sq.aggregate([]), **self.LIM),
                                   stored)
        self.assertTrue(sq.allowed("104.19.59.7", merged),
                        "到期后必须放行，否则永久封段且无重新纳入路径")

    # ── refresh ──

    def test_refresh_updates_last_confirmed_for_live_verdicts(self) -> None:
        self.store.write_text(f"104.19.59\t{sq.BAD}\t{self.ts(5)}\n",
                              encoding="utf-8")
        live = sq.classify(sq.aggregate(seg_rows("104.19.59", 8, 5, 199)),
                           **self.LIM)
        sq.refresh_verdict_store(self.store, live, now=self.NOW, ttl_days=30)
        got = sq.load_verdict_store(self.store, now=self.NOW, ttl_days=30)
        self.assertEqual(got["104.19.59"][1], self.NOW,
                         "live 再确认必须刷新 last_confirmed")

    def test_refresh_keeps_unconfirmed_but_unexpired_entries(self) -> None:
        self.store.write_text(f"104.19\t{sq.BAD}\t{self.ts(10)}\n",
                              encoding="utf-8")
        sq.refresh_verdict_store(self.store, {}, now=self.NOW, ttl_days=30)
        got = sq.load_verdict_store(self.store, now=self.NOW, ttl_days=30)
        self.assertIn("104.19", got, "证据没了但未到期，判定必须保留")

    def test_refresh_prunes_expired_entries(self) -> None:
        self.store.write_text(
            f"104.19\t{sq.BAD}\t{self.ts(31)}\n"
            f"172.64.229\t{sq.BAD}\t{self.ts(2)}\n",
            encoding="utf-8")
        sq.refresh_verdict_store(self.store, {}, now=self.NOW, ttl_days=30)
        body = self.store.read_text(encoding="utf-8")
        self.assertNotIn("104.19\t", body, "到期项必须从盘上清掉")
        self.assertIn("172.64.229\t", body)

    def test_refresh_does_not_persist_live_unknown(self) -> None:
        live = sq.classify(sq.aggregate(seg_rows("104.19.59", 8, 5, 130)),
                           **self.LIM)
        sq.refresh_verdict_store(self.store, live, now=self.NOW, ttl_days=30)
        self.assertNotIn("104.19.59",
                         self.store.read_text(encoding="utf-8")
                         if self.store.exists() else "")

    def test_refresh_demotes_a_segment_that_recovered(self) -> None:
        """stored BAD + live GOOD → 盘上必须变成 GOOD，不能残留 BAD。"""
        self.store.write_text(f"104.19.59\t{sq.BAD}\t{self.ts(3)}\n",
                              encoding="utf-8")
        live = sq.classify(sq.aggregate(seg_rows("104.19.59", 8, 5, 48)),
                           **self.LIM)
        sq.refresh_verdict_store(self.store, live, now=self.NOW, ttl_days=30)
        got = sq.load_verdict_store(self.store, now=self.NOW, ttl_days=30)
        self.assertEqual(got["104.19.59"][0], sq.GOOD)


class VerdictStoreCliTests(unittest.TestCase):
    """CLI 必须暴露 store，否则 scan_latency.sh 用不上。"""

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())
        self.hist = self.tmp / "h.tsv"
        self.store = self.tmp / "segment_verdicts.tsv"

    def run_cli(self, args: list[str], stdin: str = "") -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, str(CFST / "segment_quality.py"), *args],
            input=stdin, capture_output=True, text=True)

    def test_filter_blocks_using_store_when_history_is_empty(self) -> None:
        """端到端自擦除修复：history 空 + store 有 BAD → 仍拦。"""
        self.hist.write_text("", encoding="utf-8")
        self.store.write_text(
            f"104.19\t{sq.BAD}\t2026-09-22 00:00:00\n", encoding="utf-8")
        r = self.run_cli(
            ["filter", "--history", str(self.hist),
             "--verdict-store", str(self.store),
             "--verdict-ttl-days", "30", "--now", "2026-09-22 12:00:00",
             "--field", "1", "--window-days", "0"],
            "104.19.59.7\t50.0\n172.66.1.1\t51.0\n")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertNotIn("104.19.59.7", r.stdout, "store 判定必须生效")
        self.assertIn("172.66.1.1", r.stdout)

    def test_refresh_mode_writes_the_store(self) -> None:
        self.hist.write_text(hist(seg_rows("172.64.229", 26, 1, 201)),
                             encoding="utf-8")
        r = self.run_cli(
            ["refresh", "--history", str(self.hist),
             "--verdict-store", str(self.store),
             "--verdict-ttl-days", "30", "--now", "2026-09-22 12:00:00",
             "--window-days", "0",
             "--min-samples", "50", "--min-ips", "8",
             "--min-samples-24", "10", "--min-ips-24", "5"])
        self.assertEqual(r.returncode, 0, r.stderr)
        body = self.store.read_text(encoding="utf-8")
        self.assertIn("172.64.229", body)
        self.assertIn(sq.BAD, body)

    def test_filter_fails_open_when_store_is_unreadable(self) -> None:
        self.hist.write_text("", encoding="utf-8")
        r = self.run_cli(
            ["filter", "--history", str(self.hist),
             "--verdict-store", str(self.tmp / "nope.tsv"),
             "--verdict-ttl-days", "30", "--field", "1", "--window-days", "0"],
            "104.19.59.7\t50.0\n")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("104.19.59.7", r.stdout, "store 缺失必须 fail-open")

    def test_store_is_optional_for_backward_compatibility(self) -> None:
        """不传 --verdict-store 时行为与旧版逐字一致。"""
        self.hist.write_text(hist(seg_rows("104.19.59", 10, 5, 199)),
                             encoding="utf-8")
        r = self.run_cli(
            ["filter", "--history", str(self.hist), "--field", "1",
             "--window-days", "0", "--min-samples", "30", "--min-ips", "5"],
            "104.19.59.7\t50.0\n172.66.1.1\t51.0\n")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertNotIn("104.19.59.7", r.stdout)
        self.assertIn("172.66.1.1", r.stdout)


class VerdictLifetimeInvariantTests(unittest.TestCase):
    """判定寿命必须严格长于证据寿命，否则 store 毫无意义。"""

    @staticmethod
    def cfg() -> dict[str, str]:
        return TurnoverInvariantTests.cfg()

    def test_verdict_ttl_outlives_the_evidence_window(self) -> None:
        c = self.cfg()
        verdict_ttl = int(c["SEGMENT_VERDICT_TTL_DAYS"])
        window = int(c["SEGMENT_WINDOW_DAYS"])
        self.assertGreater(
            verdict_ttl, window,
            f"判定 TTL {verdict_ttl}d 未超过证据窗口 {window}d："
            "判定会随证据一起消亡，自擦除闭环仍然成立")

    def test_verdict_ttl_outlives_history_retention(self) -> None:
        """真正的自擦除源头是 history 保留期，不是判定窗口。"""
        c = self.cfg()
        verdict_ttl = int(c["SEGMENT_VERDICT_TTL_DAYS"])
        m = re.search(r"VLESS_HISTORY_DAYS=\$\{VLESS_HISTORY_DAYS:-(\d+)\}",
                      (CFST / "verify_vless.sh").read_text(encoding="utf-8"))
        self.assertIsNotNone(m, "未能解析 VLESS_HISTORY_DAYS 默认值")
        retention = int(m.group(1))
        self.assertGreater(
            verdict_ttl, retention,
            f"判定 TTL {verdict_ttl}d 未超过 history 保留期 {retention}d")

    def test_scan_latency_passes_the_store_to_the_filter(self) -> None:
        """配置定义了不等于调用点接上了。"""
        body = (CFST / "scan_latency.sh").read_text(encoding="utf-8")
        self.assertIn("--verdict-store", body, "filter 未接 store")
        self.assertIn("--verdict-ttl-days", body, "filter 未接 TTL")
        self.assertIn("SEGMENT_VERDICT_STORE", body)

    def test_scan_latency_refreshes_the_store(self) -> None:
        """store 必须每轮按 live 证据刷新，否则判定永不更新。

        用正则而非子串：真实调用是 `python3 "$CFST_DIR/segment_quality.py"
        refresh`，脚本变量必须带引号，字面子串匹配会被引号打断而误判未接入。
        """
        body = (CFST / "scan_latency.sh").read_text(encoding="utf-8")
        self.assertRegex(body, r"segment_quality\.py\"?\s+refresh",
                         "store 必须每轮按 live 证据刷新，否则判定永不更新")


class TurnoverInvariantTests(unittest.TestCase):
    """C：队列周转必须快于 TTL，否则候选过期比被筛到更快。"""

    @staticmethod
    def cfg() -> dict[str, str]:
        out: dict[str, str] = {}
        for raw in (CFST / "config.sh").read_text(encoding="utf-8").splitlines():
            raw = raw.strip()
            if raw.startswith("#") or "=" not in raw:
                continue
            k, _, v = raw.partition("=")
            if k.isidentifier():
                out[k] = v.split("#")[0].strip().strip('"')
        return out

    def test_queue_turnover_is_faster_than_discovery_ttl(self) -> None:
        c = self.cfg()
        limit = int(c["DISCOVERY_LIMIT"])
        per_round = int(c["VLESS_SCREEN_MAX"])
        ttl = int(c["DISCOVERY_TTL_HOURS"])
        interval_h = 2  # crontab: 0 */2 * * * run.sh
        turnover_h = (limit / per_round) * interval_h
        self.assertLess(
            turnover_h, ttl,
            f"周转 {turnover_h:.1f}h 不快于 TTL {ttl}h："
            f"候选会先过期再被筛到（limit={limit} per_round={per_round}）")

    def test_screen_batch_fits_the_round_budget(self) -> None:
        """实测 ~2.5s/IP（20 个 26-83s）；一轮预算 7200s。"""
        c = self.cfg()
        per_round = int(c["VLESS_SCREEN_MAX"])
        self.assertLess(per_round * 2.5, 600,
                        "screen 批量不得挤占整轮预算")


if __name__ == "__main__":
    unittest.main(verbosity=2)
