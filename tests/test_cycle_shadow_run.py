"""cycle.sh --shadow 实跑级沙箱测试（slow → fast）。

config.sh 的 CFST_DIR 硬编码为脚本所在目录，所以把 cycle.sh / rank.py / ip_validation.py /
atomic_io.py 复制到 tmp_path/cfst，再写一份精简 config.sh；verify_vless.sh / systemic.py /
apply.sh / probe.sh 全部为桩（桩的留痕写到 tmp_path/stub，不污染沙箱状态目录）。

校验点（原 xfail 的三个 cycle.sh 缺陷已于 2026-10-15 修复）：
1. rc=0，stdout 含 rank 行、cycle 结束行、shadow 对比行（legacy 取自沙箱 best_ips.txt）。
   摘要行必须是 `rank: pool=...` 且 shadow 行 new= 等于其 published（曾是 cycle.sh grep -m1 取错行的缺陷）。
2. 影子只写 .shadow/ 与 .tiers/（以及共享的 vless_history.tsv）；旧链路状态逐字节不变；
   apply / probe / screen 均未被调用。
3. 本轮 audit 样本被 rank 计入（RANK_NOW 在 audit 之后取样）：预置 6 个样本 n_eff≈5.62 <
   PUBLISH_MIN_NEFF=6，加上本轮 1 条才 ≥ 6.5 并进入 .shadow/best_ips.txt。
4. fast --shadow 的 audit 输入 = .tiers/core.txt ∪ challengers.txt；缺 challengers.txt 也能 audit core。
   （曾是 pipefail 清空输入的缺陷）
5. 外部持锁时 fast --shadow 应等待而非立刻 exit 75（曾是 shift 后判断 $2 的缺陷）。
6. results/ 无 .audit/.rank 等临时残留。
"""
from __future__ import annotations

import fcntl
import os
import re
import shutil
import subprocess
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
TS_FMT = "%Y-%m-%d %H:%M:%S"
POOL = ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"]
LEGACY_PUBLISHED = ["10.0.0.1", "10.0.0.2", "10.0.0.9"]
# 预置样本年龄（小时）：半衰期 24h 下权重和 ≈ 5.62 < 6；再加本轮 1 条 ≈ 6.62
PRESEED_AGES_H = [1.0, 1.5, 2.0, 2.5, 3.0, 3.5]

BEST_MARKER = "# --- BEST_IPS (machine-readable, one IP per line) ---"
LEGACY_BEST = "# legacy best_ips.txt\n" + BEST_MARKER + "\n" + "".join(f"{ip}\n" for ip in LEGACY_PUBLISHED)
DISCOVERED = "2026-10-15 10:00:00\t10.0.0.50\t0\t40\n2026-10-15 11:00:00\t10.0.0.51\t1\t45\n"
SCREEN_BLACKLIST = "10.0.0.60\t2026-10-15 09:00:00\n"
APPLY_STATE = "deadbeefdeadbeef\n"

# 影子轮允许变化/新增的沙箱内路径（vless_history.tsv 按设计由 audit 共享追加）
SHADOW_WRITES = {
    ".shadow/contenders.tsv", ".shadow/best_ips.txt", ".shadow/blacklist.tsv",
    ".tiers/core.txt", ".tiers/challengers.txt", "vless_history.tsv",
}

CONFIG_TEMPLATE = """\
CFST_DIR={sb}
RESULT_DIR="$CFST_DIR/results"
CFST_LOCK="$CFST_DIR/cfst.lock"
BEST="$CFST_DIR/best_ips.txt"
DISCOVERED="$CFST_DIR/discovered_ips.tsv"
APPLY_STATE="$CFST_DIR/.apply_state"
SCREEN_BLACKLIST="$CFST_DIR/.screen_blacklist.tsv"
CONTENDERS="$CFST_DIR/contenders.tsv"
TIERS_DIR="$CFST_DIR/.tiers"
SCREEN_BLACKLIST_HOURS=24
DISCOVERY_TTL_HOURS=24
DISCOVERY_LIMIT=180
MASTER_MIN_COVERAGE_PERCENT=80
MASTER_SYSTEMIC_P10_MS=150
MASTER_SYSTEMIC_MIN_SAMPLES=10
RANK_HALF_LIFE_HOURS=24
RANK_FLOOR_MS=50
RANK_Z=1.0
RANK_SIGMA0=0.15
RANK_PEAK_HOURS="0-23"
RANK_PEAK_WEIGHT=3
RANK_PEAK_MIN_SAMPLES=1
CORE_N=2
POOL_TARGET=60
POOL_MAX=90
PUBLISH_MIN_NEFF=6
PUBLISH_MARGIN=0.02
SCORE_TOP_N=5
PUBLISH_TOP_N=3
VLESS_HARD_MAX_FAIL=0.30
SCREEN_PEAK_HOURS="0-23"
VLESS_SCREEN_ENABLED=1
VLESS_SCREEN_MAX=20
VLESS_SCREEN_MAX_FAIL=3
publish_set() {{
  sed -n '/^# --- BEST_IPS/,$ {{ /^[0-9]/ p }}' "$BEST" | head -n "$PUBLISH_TOP_N"
}}
compute_apply_state() {{ publish_set | md5sum | cut -d' ' -f1; }}
vless_screen_admit_ttfb() {{ echo 100; }}
"""

# --audit：每个 IP 输出 PASS 并把样本追加到 history；IN 内容按次序留痕到 $STUB_OUT/audit_in.N
VERIFY_STUB = """\
#!/bin/bash
set -eu
D=$(cd "$(dirname "$0")" && pwd)
H="${VLESS_HISTORY:-$D/vless_history.tsv}"
case "${1:-}" in
  --audit)
    IN=$2
    n=$(ls "$STUB_OUT"/audit_in.* 2>/dev/null | wc -l)
    cp "$IN" "$STUB_OUT/audit_in.$n"
    ts=$(date '+%F %T')
    echo "verify stub: audit $(wc -l < "$IN") targets" >&2
    echo ""
    echo "=== AUDIT RESULTS ==="
    while IFS= read -r ip; do
      [ -n "$ip" ] || continue
      echo "  $ip  PASS"
      printf '%s\\t%s\\tPASS\\t50\\t\\n' "$ts" "$ip" >> "$H"
    done < "$IN"
    ;;
  --screen) touch "$STUB_OUT/screen_called"; exit 0 ;;
  *) echo "verify stub: unexpected args: $*" >&2; exit 64 ;;
esac
"""
SYSTEMIC_STUB = "import sys\nprint('0')\nprint('systemic stub: normal', file=sys.stderr)\n"
APPLY_STUB = "#!/bin/bash\ntouch \"$STUB_OUT/apply_called\"\nexit 0\n"
PROBE_STUB = "#!/bin/bash\ntouch \"$STUB_OUT/probe_called\"\nexit 0\n"


def _history(now: datetime) -> str:
    rows = []
    for ip in POOL:
        for age in PRESEED_AGES_H:
            rows.append(f"{(now - timedelta(hours=age)).strftime(TS_FMT)}\t{ip}\tPASS\t50\t\n")
    return "".join(rows)


def _exe(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8")
    path.chmod(0o755)


class Sandbox:
    def __init__(self, tmp_path: Path) -> None:
        self.sb = tmp_path / "cfst"
        self.stub = tmp_path / "stub"
        self.sb.mkdir()
        self.stub.mkdir()
        (self.sb / "results").mkdir()
        (self.sb / ".shadow").mkdir()
        for name in ("cycle.sh", "rank.py", "ip_validation.py", "cycle_result.py", "atomic_io.py", "cooldown.py", "admission.py"):
            shutil.copy(ROOT / name, self.sb / name)
        (self.sb / "cycle.sh").chmod(0o755)
        (self.sb / "config.sh").write_text(CONFIG_TEMPLATE.format(sb=self.sb), encoding="utf-8")
        _exe(self.sb / "verify_vless.sh", VERIFY_STUB)
        _exe(self.sb / "apply.sh", APPLY_STUB)
        _exe(self.sb / "probe.sh", PROBE_STUB)
        (self.sb / "systemic.py").write_text(SYSTEMIC_STUB, encoding="utf-8")
        # 旧链路状态（影子下必须逐字节不变）
        (self.sb / "best_ips.txt").write_text(LEGACY_BEST, encoding="utf-8")
        (self.sb / "discovered_ips.tsv").write_text(DISCOVERED, encoding="utf-8")
        (self.sb / ".screen_blacklist.tsv").write_text(SCREEN_BLACKLIST, encoding="utf-8")
        (self.sb / ".apply_state").write_text(APPLY_STATE, encoding="utf-8")
        (self.sb / "cfst.lock").write_bytes(b"")
        # 影子池 + 共享 history
        (self.sb / ".shadow" / "contenders.tsv").write_text(
            "# contenders.tsv — ip<TAB>first_seen<TAB>last_sampled<TAB>origin\n"
            + "".join(f"{ip}\t2026-10-01 00:00:00\t2026-10-01 00:00:00\tmaster\n" for ip in POOL),
            encoding="utf-8")
        (self.sb / "vless_history.tsv").write_text(_history(datetime.now()), encoding="utf-8")

    # ── 运行 ──
    def env(self) -> dict[str, str]:
        env = os.environ.copy()
        env["STUB_OUT"] = str(self.stub)
        env["VLESS_HISTORY"] = str(self.sb / "vless_history.tsv")
        env["PYTHONDONTWRITEBYTECODE"] = "1"  # 沙箱内 rank.py import 不得留下 __pycache__
        return env

    def run(self, *args: str, timeout: int = 60) -> subprocess.CompletedProcess[str]:
        return subprocess.run([str(self.sb / "cycle.sh"), *args], env=self.env(), cwd=self.sb,
                              capture_output=True, text=True, timeout=timeout, check=False)

    # ── 观测 ──
    def snapshot(self) -> dict[str, bytes]:
        return {str(p.relative_to(self.sb)): p.read_bytes()
                for p in sorted(self.sb.rglob("*")) if p.is_file()}

    def audit_inputs(self) -> list[list[str]]:
        files = sorted(self.stub.glob("audit_in.*"), key=lambda p: int(p.suffix[1:]))
        return [f.read_text(encoding="utf-8").splitlines() for f in files]

    def markers(self) -> set[str]:
        return {p.name for p in self.stub.iterdir() if not p.name.startswith("audit_in.")}

    def tiers(self, name: str) -> list[str]:
        return (self.sb / ".tiers" / name).read_text(encoding="utf-8").splitlines()

    def shadow_best_rows(self) -> dict[str, list[str]]:
        """发布行：`  IP lcb u ucb n_eff fail% med p90`（标记段之前）"""
        rows: dict[str, list[str]] = {}
        for line in (self.sb / ".shadow" / "best_ips.txt").read_text(encoding="utf-8").splitlines():
            if line.startswith(BEST_MARKER):
                break
            parts = line.split()
            if parts and re.fullmatch(r"\d+\.\d+\.\d+\.\d+", parts[0]):
                rows[parts[0]] = parts
        return rows


@pytest.fixture
def sandbox(tmp_path: Path) -> Sandbox:
    return Sandbox(tmp_path)


def _assert_shadow_only_writes(before: dict[str, bytes], after: dict[str, bytes]) -> None:
    changed = {k for k in before.keys() | after.keys() if before.get(k) != after.get(k)}
    allowed = SHADOW_WRITES | {k for k in changed if k.startswith('.shadow/cycle-results/cycle-') and k.endswith('.json')}
    assert changed <= allowed, f"影子轮越界写入: {sorted(changed - allowed)}"
    assert set(before) - set(after) == set(), "影子轮不得删除文件"
    for name in ("best_ips.txt", "discovered_ips.tsv", ".screen_blacklist.tsv", ".apply_state"):
        assert after[name] == before[name], f"{name} 必须逐字节不变"
    assert "contenders.tsv" not in after, "影子下不得生成生产 contenders.tsv"


def _assert_common_contract(sandbox: Sandbox, proc: subprocess.CompletedProcess[str], mode: str) -> None:
    assert proc.returncode == 0, f"rc={proc.returncode}\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
    out = proc.stdout
    ts = r"\[\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\] "
    assert re.search(ts + rf"{mode} audit \(VLESS\): targets=\d+$", out, re.M), out
    assert re.search(ts + r"audit evidence: returned=(\d+)/\1 .* audit_ok=1 systemic=0 guard=none$", out, re.M), out
    assert re.search(ts + r"rank: .*guard=none evaluated=\d+ waiting=\d+ quality_evicted=\d+ capacity_evicted=\d+$", out, re.M), out
    assert re.search(ts + rf"cycle: mode={mode} shadow=1 guard=none rank=ok$", out, re.M), out
    m_shadow = re.search(ts + r"shadow: legacy=(\S+) new=(\S+) same=([01])$", out, re.M)
    assert m_shadow, out
    legacy, new, same = m_shadow.groups()
    assert legacy == ",".join(LEGACY_PUBLISHED), "legacy 必须取自沙箱 best_ips.txt 的 BEST_IPS 段"
    assert same == str(int(legacy == new))
    assert "shadow: apply skipped" in out
    # 临时文件全部清理；影子日志走 stdout，不落 results/
    assert [p.name for p in (sandbox.sb / "results").iterdir()] == []
    assert sandbox.markers() == set(), f"影子下不得调用 apply/probe/screen: {sandbox.markers()}"
    import json
    record_dir=sandbox.sb/'.shadow/cycle-results'
    assert record_dir.is_dir()
    paths=list(record_dir.iterdir())
    assert paths and all(p.is_file() and p.name.startswith('cycle-') and p.suffix=='.json' for p in paths)
    for path in paths:
        data=json.loads(path.read_text())
        assert data['shadow'] is True and data['state']=='completed'
        assert data['application']=='shadow_skipped'

    assert set(p.name for p in (sandbox.sb / ".shadow").iterdir()) <= {"contenders.tsv", "best_ips.txt", "blacklist.tsv", "cycle-results"}


def test_slow_then_fast_shadow(sandbox: Sandbox) -> None:
    # ── slow --shadow ──
    before = sandbox.snapshot()
    slow = sandbox.run("slow", "--shadow")
    _assert_common_contract(sandbox, slow, "slow")
    _assert_shadow_only_writes(before, sandbox.snapshot())

    # audit 输入 = 全池；每个 IP 本轮追加 1 条样本
    assert sandbox.audit_inputs() == [POOL]
    hist = (sandbox.sb / "vless_history.tsv").read_text(encoding="utf-8").splitlines()
    assert len(hist) == len(POOL) * (len(PRESEED_AGES_H) + 1)

    # RANK_NOW 在 audit 之后取样：预置 6 条 ≈ 5.62 < 6 不可发布；计入本轮 1 条后 ≥ 6.5 才进 best
    rows = sandbox.shadow_best_rows()
    assert set(rows) == set(POOL), rows
    for ip, parts in rows.items():
        assert float(parts[4]) >= 6.5, f"{ip} n_eff={parts[4]}：本轮 audit 样本未被 rank 计入"
    best_text = (sandbox.sb / ".shadow" / "best_ips.txt").read_text(encoding="utf-8")
    machine = best_text.split(BEST_MARKER, 1)[1].strip().splitlines()
    assert sorted(machine) == POOL
    # 池未淘汰 → 不产生影子黑名单；contenders 的 last_sampled 已更新为本轮 audit 时间
    assert not (sandbox.sb / ".shadow" / "blacklist.tsv").exists()
    cont = [ln.split("\t") for ln in (sandbox.sb / ".shadow" / "contenders.tsv").read_text().splitlines()
            if ln and not ln.startswith("#")]
    assert [r[0] for r in cont] == POOL
    assert all(r[2] == hist[-1].split("\t")[0] for r in cont), cont

    core, chal = sandbox.tiers("core.txt"), sandbox.tiers("challengers.txt")
    assert len(core) == 2 and set(core) | set(chal) == set(POOL), (core, chal)

    # ── fast --shadow：audit 输入 = core ∪ challengers（去重，保持顺序）──
    before = sandbox.snapshot()
    fast = sandbox.run("fast", "--shadow")
    _assert_common_contract(sandbox, fast, "fast")
    _assert_shadow_only_writes(before, sandbox.snapshot())
    inputs = sandbox.audit_inputs()
    assert len(inputs) == 2
    assert inputs[1] == core + [ip for ip in chal if ip not in core]
    rows = sandbox.shadow_best_rows()
    assert all(float(parts[4]) >= 7.5 for parts in rows.values()), rows



def test_fast_shadow_audits_core_when_challengers_missing(sandbox: Sandbox) -> None:
    assert sandbox.run("slow", "--shadow").returncode == 0
    (sandbox.sb / ".tiers" / "challengers.txt").unlink()
    core = sandbox.tiers("core.txt")
    assert core
    before = sandbox.snapshot()
    fast = sandbox.run("fast", "--shadow")
    _assert_common_contract(sandbox, fast, "fast")
    _assert_shadow_only_writes(before, sandbox.snapshot())
    assert sandbox.audit_inputs()[1] == core
    assert (sandbox.sb / ".tiers" / "challengers.txt").exists(), "rank 应重新产出 challengers.txt"


def test_rank_summary_line_and_shadow_new_set(sandbox: Sandbox) -> None:
    slow = sandbox.run("slow", "--shadow")
    assert slow.returncode == 0, slow.stderr
    ts = r"\[\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\] "
    m_rank = re.search(ts + r"rank: pool=(\d+) core=\d+ challengers=\d+ evicted=\d+ "
                       r"published=(\S*) changed=[01] guard=none evaluated=\d+ waiting=\d+ quality_evicted=\d+ capacity_evicted=\d+$", slow.stdout, re.M)
    assert m_rank, slow.stdout
    assert int(m_rank.group(1)) == len(POOL)
    m_shadow = re.search(ts + r"shadow: legacy=(\S+) new=(\S+) same=([01])$", slow.stdout, re.M)
    assert m_shadow, slow.stdout
    legacy, new, same = m_shadow.groups()
    assert new == m_rank.group(2) != "-", "new 必须等于 rank 摘要的 published"
    assert same == str(int(legacy == new))
    machine = (sandbox.sb / ".shadow" / "best_ips.txt").read_text(encoding="utf-8").split(BEST_MARKER, 1)[1]
    assert machine.strip().splitlines()[:3] == new.split(",")


def test_fast_shadow_without_tiers_exits_zero(sandbox: Sandbox) -> None:
    proc = sandbox.run("fast", "--shadow")
    assert proc.returncode == 0, proc.stderr
    assert "no tiers" in proc.stdout
    assert re.search(r"cycle: mode=fast shadow=1 guard=none rank=skipped$", proc.stdout, re.M)
    assert sandbox.audit_inputs() == [] and sandbox.markers() == set()


def test_fast_shadow_waits_for_external_lock(sandbox: Sandbox) -> None:
    # 先让 slow 产出 .tiers，fast 才有 audit 对象
    assert sandbox.run("slow", "--shadow").returncode == 0
    lock_fd = os.open(sandbox.sb / "cfst.lock", os.O_RDWR | os.O_CREAT)
    fcntl.flock(lock_fd, fcntl.LOCK_EX)
    timer = threading.Timer(2.0, lambda: fcntl.flock(lock_fd, fcntl.LOCK_UN))
    try:
        t0 = time.monotonic()
        timer.start()
        proc = sandbox.run("fast", "--shadow", timeout=30)
        elapsed = time.monotonic() - t0
    finally:
        timer.cancel()
        os.close(lock_fd)
    assert proc.returncode == 0, f"rc={proc.returncode}（持锁期间应等待，不应立刻 exit 75）\n{proc.stdout}{proc.stderr}"
    assert elapsed >= 1.5, "fast --shadow 应等待外部锁释放"
    assert re.search(r"cycle: mode=fast shadow=1 guard=none rank=ok$", proc.stdout, re.M)


# ═══════════════════════════════════════════════════════════════════
# 生产（非影子）慢周期：apply 状态校验 fail-closed（原 run.sh 契约，
# 2026-10-15 切换后由 cycle.sh 承担；见 tests/test_batch3_reliability.py 旧版）
# ═══════════════════════════════════════════════════════════════════

# 生产 apply 桩：默认写入与 compute_apply_state 一致的状态；APPLY_STATE_OVERRIDE 可伪造错误状态。
LIVE_APPLY_STUB = """\
#!/bin/bash
set -eu
touch "$STUB_OUT/apply_called"
D=$(cd "$(dirname "$0")" && pwd)
source "$D/config.sh"
if [ -n "${APPLY_STATE_OVERRIDE:-}" ]; then
  printf '%s\\n' "$APPLY_STATE_OVERRIDE" > "$APPLY_STATE"
else
  compute_apply_state > "$APPLY_STATE"
fi
exit 0
"""


def _go_live(sandbox: Sandbox) -> None:
    shutil.copy(sandbox.sb / ".shadow" / "contenders.tsv", sandbox.sb / "contenders.tsv")
    shutil.rmtree(sandbox.sb / ".shadow")
    _exe(sandbox.sb / "apply.sh", LIVE_APPLY_STUB)


def _slow_log(sandbox: Sandbox) -> str:
    logs = sorted((sandbox.sb / "results").glob("*.log"))
    assert len(logs) == 1, [p.name for p in logs]
    return logs[0].read_text(encoding="utf-8")


def test_live_slow_verified_apply_runs_probe(sandbox: Sandbox) -> None:
    _go_live(sandbox)
    proc = sandbox.run("slow")
    assert proc.returncode == 0, f"rc={proc.returncode}\n{proc.stdout}{proc.stderr}"
    log = _slow_log(sandbox)
    assert re.search(r"cycle: mode=slow guard=none rank=ok$", log, re.M), log
    assert {"apply_called", "probe_called"} <= sandbox.markers(), sandbox.markers()
    best = (sandbox.sb / "best_ips.txt").read_text(encoding="utf-8")
    assert BEST_MARKER in best and "legacy best_ips" not in best, "生产轮必须重写 best_ips.txt"
    assert (sandbox.sb / "contenders.tsv").read_text(encoding="utf-8").count("\n") >= len(POOL)
    assert not (sandbox.sb / ".shadow").exists()


def test_live_slow_apply_state_mismatch_fails_closed_and_skips_probe(sandbox: Sandbox, monkeypatch) -> None:
    _go_live(sandbox)
    monkeypatch.setenv("APPLY_STATE_OVERRIDE", "WRONG-STATE")
    proc = sandbox.run("slow")
    assert proc.returncode != 0
    log = _slow_log(sandbox)
    assert "apply state mismatch" in log, log
    assert re.search(r"cycle: mode=slow guard=none rank=ok$", log, re.M), "finish_line 仍须落日志"
    assert "apply_called" in sandbox.markers()
    assert "probe_called" not in sandbox.markers(), "状态不一致时不得继续探测"
    assert (sandbox.sb / ".apply_state").read_text(encoding="utf-8").strip() == "WRONG-STATE"
