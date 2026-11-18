# 实施计划：Contender Pool 重构

设计：`docs/superpowers/specs/2026-10-15-contender-pool-design.md`（已批准）。
约束：TDD；每个任务结束必须 `python3 -m pytest -q -p no:cacheprovider` 全绿并 commit；
作者身份 `GIT_AUTHOR_NAME="Hermes Agent" GIT_AUTHOR_EMAIL=agent@localhost`（同 committer）；只本地 commit，不 push；
不读/不输出 `secrets/`、`.hermes/`；不改 cron、不删旧文件、不改写 `best_ips.txt`/`contenders.tsv` 生产数据——直到 Task 9（切换）由用户明确授权。
线上 cron 每 2h/5min 仍在跑旧链路；所有新代码在切换前只以 `--dry-run`/影子方式运行。

## 架构速览

```
vless_history.tsv ──► rank.py ──► contenders.tsv（更新）
                        │         best_ips.txt（Top5，带 BEST_IPS 标记段）
                        │         stdout: "rank: ..." 单行摘要 + core/challenger 列表文件
cycle.sh slow  (2h)  : audit 全池 → systemic → rank → apply → screen 补池 → probe
cycle.sh fast (15m)  : audit core∪challenger → systemic → rank → apply
watchdog.sh          : 连续失联 → cycle.sh fast --emergency
```

rank.py 模块结构（纯函数优先，便于测试）：
- `load_history(path, now, days=7) -> list[Sample]`　Sample = (ts, ip, status, median)
- `bucket_rounds(samples, minutes=10) -> dict[bucket, list[Sample]]`
- `round_baselines(rounds, floor, min_samples=10) -> dict[bucket, (baseline, systemic_fail: bool)]`
- `ip_stats(samples, baselines, now, half_life_h, peak_hours) -> dict[ip, Stats]`
  Stats = (n_eff, fail, med, tail, peak_ok, last_seen, consecutive_unreachable)
- `utility(stats, cfg) -> (u, lcb, ucb)`
- `derive_tiers(ranked, cfg) -> (core, challengers, reserve)`
- `evict(ranked, cfg, guards) -> (kept, evicted_with_reason)`
- `sticky_publish(ranked, previous_top, cfg) -> list[ip]`
- `write_best(path, rows, published)`（原样迁移 score.write_best 的标记段写法与原子写）
- CLI：`rank.py --now TS [--dry-run] [--audit-requested N --audit-returned M] [--systemic 0|1] [--audit-ok 0|1] [--previous-best FILE] [--tiers-out DIR]`

## Task 1：rank.py 统计核心（加权、去共因、置信区间）
文件：`rank.py`（新）、`tests/test_rank_stats.py`（新）
测试（先写、先红）：
- 半衰期权重：24h 前样本权重 0.5，48h 前 0.25；n_eff 为权重和。
- 轮桶：同一 10 分钟内样本同桶；桶 PASS 样本 ≥10 才有基线，否则基线 = FLOOR。
- 去共因：基线 300 时 q = ttfb − 250；基线 ≤ FLOOR 时 q = ttfb。
- 轮失败率 ≥50% → `systemic_fail=True`，该轮 FAIL 不计入 ip fail。
- 加权 p90 / 中位数：手工构造 5 个权重样本验证。
- peak_ok：近 24h 拥塞时段 PASS ≥2（复用 `probation.parse_peak_hours` 的解析逻辑——复制该函数进 rank.py，probation.py 将删除）。
- consecutive_unreachable：最近连续 FAIL(reason 含 timeout/all timeouts) 计数。
- utility：tail=50 → u_tail=0.906（沿用分段曲线）；fail=0 → u_fail=1；lcb/ucb = u ∓ K/sqrt(n_eff)。
实现：仅标准库；`from atomic_io import atomic_write`。
Commit：`feat(rank): weighted stats, round baselines, confidence bounds`

## Task 2：层派生、淘汰、粘性发布
文件：`rank.py`、`tests/test_rank_policy.py`（新）
测试：
- core = lcb 前 CORE_N 且 n_eff ≥3；challenger = ucb > core 末位 lcb，最多 10；其余 reserve。
- 淘汰规则 1–4 各一个用例；守卫：覆盖率 <80% 或 audit_ok=0 或 systemic=1 时不淘汰（但 POOL_MAX 裁剪仍执行？——**否**，守卫轮一律不淘汰）。
- 淘汰写黑名单格式 `ip<TAB>ts`。
- 粘性发布：在任 [A,B,C]，新 lcb 排序 [B,A,D,C]：B 领先 A 不足 0.02 → 顺序保持 A,B；D 领先 C 超 0.02 → C 换出；输出 [A,B,D]。
- 在任失去资格（fail>30% / 被淘汰 / peak_ok=False）→ 立即换出不受滞回。
- 合格数 <3 → 返回 None（调用方不改写 best）。3≤n<5 → 输出 n 个。
- best_ips.txt 含 `# --- BEST_IPS (machine-readable, one IP per line) ---` 且其后每行一个 IP，`config.sh publish_set` 能解析（用 bash 调用验证）。
- 幂等：同输入两次运行输出字节一致。
Commit：`feat(rank): tiers, eviction with guards, sticky publication`

## Task 3：rank.py CLI、contenders.tsv、7 天回放工具
文件：`rank.py`、`tests/test_rank_cli.py`、`tests/fixtures/history_7d.tsv`（脱敏：IP 保留、无其他字段；history 本身不含凭据）
- contenders.tsv 格式：`# contenders.tsv — ip<TAB>first_seen<TAB>last_sampled<TAB>origin`；读写原子。
- `--dry-run`：不写任何文件，stdout 打印摘要 + Top5 + 淘汰候选；`--tiers-out DIR` 写 `core.txt`/`challengers.txt`。
- 摘要行契约（status.py 依赖）：`rank: pool=N core=N challengers=N evicted=N published=ip1,ip2,ip3 changed=0|1 guard=none|coverage|systemic|no_evidence`
- `replay.py`（新，只读）：对 fixture 按日滚动输出 Top3 与变化次数；作为参考输出写入 `docs/decisions/`。
测试：CLI dry-run 不改 mtime；fixture 回放确定性；contenders 读写往返。
Commit：`feat(rank): CLI, contenders.tsv, replay tool`

## Task 4：cycle.sh 编排（slow / fast / --emergency）
文件：`cycle.sh`（新）、`tests/test_cycle_contract.py`（新）
从 run.sh 迁移：锁与 flock 9、黑名单清理、发现队列整理、audit 调用、systemic 调用、覆盖率守卫、screen 补池（池 < POOL_MAX 时；systemic 轮跳过）、apply、apply_state 校验、probe（仅 slow）、日志清理。
删除：probation recheck/prune、pool.py 调用、score.py 调用。
fast：audit 输入 = tiers-out 的 core ∪ challengers（上轮产出；文件不存在则退出 0）；verify 锁忙（rc 75）→ 退出 75；`--emergency` 仅影响日志标记与跳过冷却判断（冷却仍在 watchdog）。
日志：slow 写 `results/<ts>.log`，fast 写 `results/fast.log`（logrotate 由 find -mtime 清理同今日）。
测试（结构契约，同 test_systemic_guard 的 if/fi 配对手法）：systemic 跳过 screen 存在；fast 不调用 screen/probe；两模式都在 rank 之后 apply；apply 失败 exit 非零；`bash -n` 通过。
Commit：`feat(cycle): slow/fast orchestration replacing run.sh core`

## Task 5：周边适配（scan_latency、watchdog、status、config）
文件：`scan_latency.sh`、`watchdog.sh`、`status.py`、`config.sh`、对应测试
- scan_latency 排除集 = contenders.tsv（存在时）∪ master_ips.txt（存在时，过渡期）。
- watchdog 紧急调用 `cycle.sh fast --emergency`，rc 75 保留 miss 计数。
- config.sh 新增 §7 阈值；旧阈值先保留（切换后 Task 10 清理）；`probation_screen_backpressure` 保留到 Task 10。
- status.py 解析 `rank:` 摘要行与 fast.log；新增"影子对照"输出（Task 6 产生）。
测试：scan_latency 排除逻辑（bash 片段）；watchdog 结构契约；status 新行解析。
Commit：`feat: adapt discovery, watchdog, status to contender pool`

## Task 6：影子模式接入（不改发布）
文件：`run.sh`（末尾追加 3 行）、`cycle.sh`、`tests/test_shadow.py`
- run.sh 末尾：`python3 rank.py --dry-run --now "$NOW" --previous-best "$BEST" >> results/shadow.log`，并把新旧 Top3 对照一行写入同文件。
- 新增 cron 行 **由用户手动添加**（计划只给出行文本）：`7-59/15 * * * * cd /opt/cfst && /usr/bin/bash cycle.sh fast --shadow >> results/fast.log 2>&1`；`--shadow` = audit + rank --dry-run，不 apply。
- `status.py` 显示影子 Top3、48h 内变化次数、每次是否 ⊆ 合格集（原始 7d p90 ≤65 且 fail=0）。
测试：run.sh 含 dry-run 调用且在 apply 之后；`--shadow` 路径不调用 apply。
Commit：`feat: shadow mode for contender ranking`
**里程碑：用户添加 fast 影子 cron；观察 ≥48h；status.py 判定硬门通过后才进入 Task 7。**

## Task 7：migrate.sh / rollback.sh
文件：`migrate.sh`、`rollback.sh`、`tests/test_migrate.py`
- migrate：master_ips → origin=master，probation_pool → origin=probation，生成 contenders.tsv；旧三文件改名 `.legacy`；run.sh 改为 `exec cycle.sh slow "$@"`；打印需要用户添加的 cron 行（fast 去掉 --shadow）。
- rollback：恢复 .legacy、恢复 run.sh（git checkout 指定 commit 的 run.sh）、提示删除 fast cron 行。
- 二者幂等、拒绝在锁被持有时运行（flock -n 9）。
测试：临时目录内 migrate→rollback 往返集合一致。
Commit：`feat: migration and rollback scripts`

## Task 8：切换前复核（Verifier）
独立 verifier：对照设计 §5/§6 逐条核对契约与守卫；运行全量测试；审 cycle.sh 与 apply/push 的 fail-closed 链；审 secrets 不被读取/打印。输出 PASS/FAIL。

## Task 9：切换（需用户当场授权）
1. 确认影子硬门通过（status.py）。2. `./migrate.sh`。3. 用户改 cron（fast 去 --shadow）。4. 观察一轮 slow + 两轮 fast 的日志与 `./status.py`。5. 回滚预案 `./rollback.sh`。

## Task 10：清理
删除 score.py、pool.py、probation.py、probation_pool.py、旧专属测试、config.sh 失效阈值、`probation_screen_backpressure`、README 全面更新、decision record（回放结果与切换结果）。
Commit：`chore: remove legacy pool/probation/score pipeline`

## 旧测试处置清单（Task 10 执行，Task 4–6 期间保持通过）
删除：test_pool.py、test_probation_pool.py、test_probation_fail_charge.py、test_probation_backpressure.py、test_batch5_score_contract.py、test_batch5_score_config_contract.py、test_path_stability.py、test_b3_offpeak_contract.py 中 score 相关用例。
改写：test_batch1_boundaries / test_batch2_contract / test_batch3_reliability / test_systemic_guard 中引用 run.sh 结构的用例指向 cycle.sh；保留其 verify/segment/systemic 解析用例。
保留：test_publish_*、test_push_to_misub、test_batch4_misub_contract、test_misub_stale_cache、test_segment_quality、test_discovery_latency、test_scan_latency_flags、test_network_guard、test_verify_tmpfs、test_atomic_io、test_status。
