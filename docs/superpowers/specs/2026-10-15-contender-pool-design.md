# 设计：单池连续采样 + 不确定性驱动排名（Contender Pool）

日期：2026-10-15（模型定稿 2026-10-16）　状态：已上线　范围：/opt/cfst 运行链路核心重构

## 1. 意图与为什么

目标：**让真正优秀的 IP 尽快浮出水面，让退化的 IP 尽快退出，且不随机丢弃任何候选。**
稳态质量的上限是物理的（移动→HKG 真实链路 TTFB 下限 ≈47–50ms），当前
Top3 已经是最优 IP；决定性空间在**动态**：

| 指标 | 现状（实测 2026-10-08..15） | 目标 |
|---|---|---|
| 新 IP 发现→进入发布 Top3 | ≈5 天（队列 18h + 试用 ≥24h + 成熟度 4 天） | 下一个完整晚高峰验证后按证据上位 |
| 已发布 IP 退化→掉出 Top3 | ≈48h（7 天平窗均值） | <2h |
| 候选因超时/配额被丢弃（与质量无关） | 93%（试用池 TTL） | 0 |
| 互相制约的阈值 | 25 个 | ≤10 个 |
| 轮次共因噪声记在 IP 头上 | 是（每轮慢样本占比 0–85%） | 否 |

现行架构是四层固定规则（发现队列 → 试用池 → 主池 → 评分），每层都用 TTL、
计数器和边际阈值近似"不确定性"。本设计用一个显式的不确定性模型替代它们。

## 2. 目标 / 非目标 / 反目标

**目标**
- 单一候选池（contenders），单一排名模型，采样预算按不确定性分配。
- 发布按置信下界，淘汰按置信上界——不再有 TTL、fail_limit、challenge margin、
  retire 轮数、maturity floor。
- 保留全部外部契约（§5）和已验证的守卫（§6）。

**非目标**
- 不改 verify_vless.sh 的测量方法、VLESS 模板、凭据处理。
- 不改 MiSub 发布器、发布预检、publish_watchdog、segment_quality 网段门、systemic.py。watchdog 只改紧急调用目标（§3.9）。
- 不改发现（scan_latency.sh）的探测方法。

**反目标（技术上能跑也算失败）**
- 发布集在 5 天滚动回放中抖动 >1 次/5 天。
- 因为采样密度提高导致 xray 并发超出今天的峰值（一轮 ≤120 IP）。
- 凭据缺失/系统性故障轮次导致批量淘汰。
- 切换时发布集非预期变化（必须先影子运行比对）。

## 3. 核心模型

### 3.1 样本与去共因
样本来源仍是 `vless_history.tsv`（ts, ip, status, median, reason），7 天保留不变。
**轮次**：时间戳落在同一 10 分钟桶内的样本视为同一轮。
**轮基线** `B_r` = 该轮所有 PASS 样本 median 的中位数（样本数 ≥10 时生效，否则 `B_r = FLOOR`）。
**去共因 TTFB**：`q = ttfb − max(0, B_r − FLOOR)`，`FLOOR = 50ms`。
只扣除轮次的系统性超额，正常轮次 q 就是绝对值。
**系统性故障轮**（两种形态任一）：(a) 现有 `systemic.py` 判定（PASS p10 > 150ms，全体抬升）；(b) 轮次失败率 ≥50%。
系统性轮：FAIL/PARTIAL 不计入任何 IP 的失败证据，不淘汰，**不快筛**（保留今日"入口 C"防线及其测试）；
PASS 样本仍计入但经 B_r 去共因。systemic.py 保留，由 cycle.sh 在每次 audit 后调用。

### 3.2 逐样本效用与加权统计
每个样本一个分数 `s ∈ [0,1]`：PASS → `f(q)`（分段线性：≤80ms 0.85–1.0，80–150 0.45–0.85，150–300 0.10–0.45，>300 趋零；阈值来自 tail-aware 体感回放），非 PASS → 0。系统性轮的失败不计。
权重 `w = d(age) × r(hour)`：时效 `d = 0.5^(age/24h)`；时段相关性 `r = RANK_PEAK_WEIGHT(3)`（晚高峰 `RANK_PEAK_HOURS=20-23,0`），否则 1。
对每个 IP：
- `mu = Σws/Σw`，`σ̂² = Σw(s−mu)²/Σw`
- `n_eff = min(Σd, (Σw)²/Σw²)`：证据量只按时效计；时段权重改变"哪些样本更能代表体验"，不虚增证据；Kish 项保证权重极不均时不高估
- `fail / med / tail`：只按时效加权的原始失败率、中位数、p90——供硬失败规则与展示，**不参与排名**
- `peak_samples`：近 24h 晚高峰（非系统性轮）样本数；`peak_ok = peak_samples ≥ RANK_PEAK_MIN_SAMPLES(3)`

**为什么是逐样本均值**：p90 在 n≈5 时就是最大值，失败率是点估计，各自都需要置信修正；逐样本分数把尾部（300ms→0.10）和失败（0）放进同一个有界随机变量，均值的置信区间有 CLT 支撑，一个估计量解决全部。
**为什么晚高峰加权**：7 天数据里晚高峰的共同基线只从 49 涨到 56ms（去共因能抹掉），但同轮 IP 间 IQR 从 4ms 涨到 80–110ms、失败率从 1–2% 涨到 6–10%——晚高峰不是"噪声大要宽容"，而是**唯一有区分度的时段**；全天等权时一个"晚高峰 20% 概率 300ms"的 IP 在全天 p90 里不可见（实测 17/151 个池内 IP 如此）。

### 3.3 置信区间
`half = z·√(σ̂² + σ0²)/√n_eff`，`z = RANK_Z = 1`，`σ0 = RANK_SIGMA0 = 0.15`（逐样本效用的先验标准差，区间宽度下限）；`lcb = mu − half`，`ucb = mu + half`。
稳定在 50ms 的 IP σ̂≈0.03，区间≈σ0/√n；白天 50ms、晚高峰偶发 300ms 的 IP σ̂≈0.3，区间宽一倍以上。
惩罚（丢 core/发布位、淘汰）看保守侧，探索看 ucb——两侧同一个估计量，区间宽度由样本自己的离散度决定：
5×50ms + 1×300ms 的候选 mu≈0.77、σ̂≈0.30、ucb≈0.91，会丢 core 位但不会被判"确定不如第 60 名"。
MTR 路径/colo 不进入排名；probe.sh 只做诊断。

### 3.4 池与层
单文件 `contenders.tsv`：`ip  first_seen  last_sampled  origin  evaluated_at`。
层是**派生**的，每次排名重新计算：
- **core**：按 lcb 排前 `CORE_N = 10` 且 `n_eff ≥ 3`。
- **challenger**：非 core 且 `ucb > core 第 CORE_N 名的 lcb`，最多 10 个，分两槽：探索槽（n_eff<3，默认 5）+ 晋升槽（n_eff≥3），各按 ucb 降序，一侧不足另一侧补齐。
  不分槽时新 IP 的宽区间 ucb 天然最高，每轮 20 个新 IP 会把攒到 4–5 个样本的候选挤回 reserve。
- 其余为 **reserve**。

### 3.5 验证 / 进入 / 退出
**验证生命周期**：evaluated_at 缺省为 -，兼容旧四列。入池后同一晚 20–21、22–23、00 三个时段均有有效观察且 n_eff≥8 时记录完成时间；00 归属前一晚。重复快周期不能替代跨时段覆盖，系统性失败轮不计覆盖，有效 PASS/FAIL/PARTIAL 都算观察。完成状态持久化，不随 24h 窗口撤销；它只解除相对退出保护，不替代近期评分或发布资格。

**进入**：快筛预算 = min(VLESS_SCREEN_MAX, max(0, POOL_MAX−池大小))。只接纳本轮请求集合中合法、去重的 PASS，准入时再次严格限制空位；所有候选元数据原子保留。容量不足的通过者保持等待，不记失败；快筛执行非零退出时不接纳、不累计候选失败。

**退出**（守卫轮不退出）：
1. 已完成验证、n_eff≥8，且 ucb < 第 POOL_TARGET(60) 名已证明（n_eff≥3）IP 的 lcb → unworthy；已证明者不足 60 则不触发。
2. n_eff≥3 且失败率 Wilson 下界 >30% → hard_fail；不要求完成晚高峰验证。
3. 连续三轮完全不可达 → unreachable；不要求完成晚高峰验证。
4. 池 > POOL_MAX−VLESS_SCREEN_MAX 时，只在已完成验证、n_eff≥8 且不在 lcb 前 POOL_TARGET 名的候选中，按 ucb 升序退出，每轮至多 VLESS_SCREEN_MAX 个 → overflow。

未完成验证者不参与规则 1、4。池由优质和待验证候选组成、没有合法退出者时，暂停接纳是预期背压，不为维持吞吐而提前裁人。候选池没有 TTL；发现队列仍有原有有效期和容量限制。

质量退出（规则 1–3）与连续快筛失败写入 .screen_blacklist.tsv，冷却 24h；容量退出写入独立 .capacity_cooldown.tsv，冷却 6h，不代表质量判差。发现与快筛使用相同的有效期判断，所有新状态写入复用 atomic_io。

### 3.6 采样调度
- **慢周期（2h，cron 现有行）**：audit 全池（≤ POOL_MAX IP，150 个约 4–11 分钟）→ 排名 → 发布 → 快筛补池。
- **快周期（15min）**：audit core ∪ challenger（≤20 IP，<1 分钟）→ 排名 → 发布。
  verify_vless 持有独占锁，两周期天然互斥；快周期遇锁直接退出。
- 快周期让 core 每天得到 ~96 样本，新 challenger 6 样本只需 1.5h。

### 3.7 发布
`best_ips.txt` 的 Top N（SCORE_TOP_N=5）按 lcb 排序，仅取合格 IP：`n_eff ≥ 6` 且 `peak_ok` 且原始失败率 ≤ 30%。
**晚高峰门槛**：peak_ok = 近 24h 晚高峰样本 ≥3，用于发布新鲜度；它与生命周期的同晚三时段验证不同，不能相互替代。有效失败计入样本数，失败惩罚已体现在 mu。
**边界**：合格 IP < PUBLISH_TOP_N(3) 时**不改写** best_ips.txt，只记告警（fail-closed，不推送残缺集）；3 ≤ 合格数 < 5 时输出合格的全部。
**滞回（含顺序）**：以上一份 best_ips 的前 3 位为在任者，按"粘性排序"生成新序：在任者保持原相对顺序，仅当某 IP 的 `lcb` 高出其前一位 `lcb + PUBLISH_MARGIN(0.02)` 时才上移/换入；顺序参与 `compute_apply_state` 哈希，所以换序也受滞回约束。
在任者失去资格（硬门、淘汰、peak_ok 失效）时立即换出，不受滞回约束。
**段多样性**：发布集内同一 /16 最多 `MAX_PER_SEGMENT=2`；超额网段中 lcb 最低者被候补里第一个"所属网段未满且 lcb ≥ 其 lcb − PUBLISH_MARGIN"的 IP 换入，找不到则保持——不拿质量换多样性。
优先级：合格性 > 质量（滞回内视为同等）> 多样性 > 粘性顺序。
发布集变化检测、预检、推送全部沿用 apply.sh / push_to_misub.py。

### 3.8 样本来源
history 中**所有**行都是样本：慢/快周期 audit、快筛 `--screen`（新 IP 的第 1 个样本，使其立即以高 ucb 进入 challenger——这是意图）。
push_to_misub 预检使用独立临时 history，不污染；手动 `./verify_vless.sh` 的样本同样计入（本来就是真实测量）。

### 3.9 紧急路径（watchdog）
watchdog 连续 3 次 TCP 失联后改为调用 `cycle.sh fast --emergency`（而非 score.py）：
先 audit core ∪ challenger（真实 VLESS 证据进入 history），再排名发布。
遇 verify 锁则退出 75 并保留 miss 计数（下一次 5 分钟再试）；冷却逻辑沿用。

## 4. 文件与脚本变化

| 新 | 替代 | 说明 |
|---|---|---|
| `rank.py` | score.py + pool.py + probation_pool.py + probation.py | 读 history 与 contenders，输出 contenders（更新）、best_ips.txt、本轮 core/challenger 列表；`--dry-run` 只打印 |
| `cycle.sh slow|fast` | run.sh 主体 | 编排；run.sh 保留为 `exec cycle.sh slow` 以免改 cron |
| `contenders.tsv` | master_ips.txt + master_state.tsv + probation_pool.tsv | 原子写（atomic_io） |

修改：`scan_latency.sh` 排除集改读 contenders.tsv；`status.py` 改读新日志行；
`config.sh` 删除失效阈值、新增 §7 的阈值；README 全面更新。
删除：score.py、pool.py、probation.py、probation_pool.py 及其专属测试（迁移后）。
`u_tail/u_fail` 分段曲线与 best_ips.txt 写法从 score.py 原样迁入 rank.py。

## 5. 必须保留的外部契约
- `verify_vless.sh --audit FILE` / `--screen IN OUT` 的调用方式、`=== AUDIT RESULTS ===` 输出块、history 追加格式、exit 2（凭据）/75（并发）。
- `best_ips.txt` 的 `# --- BEST_IPS (machine-readable, one IP per line) ---` 标记与其后"每行一个 IP"的区段（push_to_misub / watchdog / probe / config.sh 都依赖）。
- `apply.sh`、`compute_apply_state()`、`PUBLISH_TOP_N=3`、`.push_disabled`、锁文件、secrets 权限检查。
- cron 的 2h / 5min 两行保持；只新增一行 15min。
- `.screen_blacklist.tsv`、`discovered_ips.tsv` 格式。

## 6. 必须移植的守卫
1. 覆盖率守卫：本轮 audit 返回行数 < 80% 请求数 → 本轮不淘汰（仍更新统计）。
2. 系统性故障轮：§3.1；全池同轮全失败 → 拒绝淘汰（pool.py 现有 SystemExit 语义）。
3. verify 非零退出 / 超时 / 凭据缺失 → 本轮视为无证据，不淘汰不发布变更。
4. 崩溃安全：contenders.tsv 与 best_ips.txt 原子写；rank.py 幂等（重跑同一 history 得同一结果）。
5. 发布 fail-closed：预检失败不改远端（沿用）。

## 7. 阈值（config.sh）
`RANK_HALF_LIFE_HOURS=24`、`RANK_FLOOR_MS=50`、`RANK_Z=1.0`、`RANK_SIGMA0=0.15`、`RANK_PEAK_HOURS="20-23,0"`、`RANK_PEAK_WEIGHT=3`、`RANK_PEAK_MIN_SAMPLES=3`、
`CORE_N=10`、`POOL_TARGET=60`、`POOL_MAX=150`、`PUBLISH_MIN_NEFF=6`、`PUBLISH_MARGIN=0.02`；
rank.py 内置默认：`explore_slots=5`、`max_per_segment=2`、`evict_min_neff=8`；`trim_headroom` 取 `VLESS_SCREEN_MAX`。
沿用：`VLESS_HARD_MAX_FAIL=0.30`、`SCREEN_PEAK_HOURS`（仅快筛平峰判断）、`PUBLISH_TOP_N`、`SCORE_TOP_N`、快筛门槛组。

容量冷却：CAPACITY_COOLDOWN_HOURS=6，质量冷却 SCREEN_BLACKLIST_HOURS=24。

## 8. 迁移与上线
1. **影子期（≥24h）**：cycle.sh slow 在旧链路末尾额外运行 `rank.py --dry-run`，把新旧 Top3 差异写入日志；不发布。
2. 回放（参考，不是硬门）：用 7 天 history 回放输出新旧 Top3 对照；现有 history 是 2h 稀疏采样，不代表快周期密度，不为通过回放而调 K/H。
   **硬门是影子期**：连续 48h 内影子 Top3 变化 ≤2 次，且每次影子 Top3 ⊆ {7d **原始** TTFB p90 ≤65ms 且 fail=0 的 IP}。
   影子期内 cycle.sh fast 已按新密度采样（只写 history，不发布），所以影子期数据就是未来的真实分布。
3. 切换：`migrate.sh` 由 master_ips（全部）+ probation_pool（仅近 24h 有 PASS 样本者）生成 contenders.tsv（origin 标注来源）；cron 新增快周期；旧文件改名 `.legacy` 保留 7 天。
4. 回滚：git revert + 删除快周期 cron 行 + 恢复 `.legacy` 文件；一条命令完成（`rollback.sh`）。

## 9. 测试策略
- rank.py 纯函数：衰减权重、轮基线与去共因、加权分位数、lcb/ucb、层派生、进出规则、发布滞回、守卫（覆盖率/系统性/无证据）、幂等。
- 回放测试：固定一份脱敏 history 快照（tests/fixtures），断言 Top3 与抖动。
- cycle.sh 结构契约测试（同今日 run.sh 的做法）。
- 迁移测试：从现有三文件生成 contenders 并保证集合一致。
- 现有 294 项中与 score/pool/probation 专属逻辑绑定的约 120 项随旧模块删除；契约类（publish、misub、verify、segment、systemic 解析、status）保留并通过。

## 10. 交给 builder 决定
- rank.py 内部数据结构与加权分位数的实现方式。
- cycle.sh 的日志行格式（status.py 随之调整）。
- fixtures 的脱敏方式。
- 快周期 cron 的具体分钟偏移（避开 2h 整点）。
