# Cloudflare 优选 IP 长期评分系统

移动 HKG 方向 Cloudflare CDN IP 自动优选。每 5 分钟做 TCP 延迟候选发现；每 2 小时对整个 contender 池做完整 VLESS+WS+TLS TTFB 审计，每 15 分钟对 core/challenger 复采样；rank.py 以半衰期加权统计 + 不确定性区间排名，淘汰只凭证据，发布带滞回。目标：真正优秀的 IP 尽快浮出水面，旧的中庸 IP 不长期占位，候选不因随机丢弃而消失。Cloudflare 下载测速不参与准入、淘汰或评分。

## 公开版本说明（脱敏）

本仓库是私有生产系统的公开镜像，已做以下处理，因此**不是可直接部署的副本**：

- 中继域名（模板 SNI/HOST 与 MiSub 地址）替换为 `example.com` 占位符，需自行填写；
- 凭据不随仓库分发：`secrets/misub.env`、`secrets/vless.env` 需本机自建并保持 `0600`；
- 运行状态（候选池、历史、发布集、冷却、分层、`ip_ranges.txt`）不包含在内；
- 回放夹具中的实测地址已改写为私有网段，仅保留时间与状态结构。

`tests/test_distribution_contract.py` 会阻止上述内容被重新引入。

设计与决策记录：
- docs/superpowers/specs/2026-10-15-contender-pool-design.md（算法与契约）
- docs/decisions/2026-10-15-contender-pool-shadow.md（影子期与切换）

## 目录结构
```
/opt/cfst/
├── bin/xray              # xray 25.6.8（verify_vless 使用）
├── cfst                  # CloudflareST v2.3.5 二进制
├── config.sh             # 共享配置：路径、门槛、节点模板、锁、超时
├── run.sh                # 薄壳：exec cycle.sh slow（保留 cron 兼容）
├── cycle.sh              # 慢/快周期编排：audit → systemic 守卫 → rank → apply → screen → probe
├── cycle_result.py       # 周期证据、机器结果、收束与历史状态解释
├── rank.py               # 池统计、分层、淘汰、粘性发布 → contenders.tsv / best_ips.txt / .tiers/
├── admission.py          # 发现队列维护、快筛选择与限额准入，保留候选验证状态
├── cooldown.py           # 质量/容量冷却有效期与原子写入
├── replay.py             # 用历史 vless_history 回放 rank 策略（离线评估）
├── scan_latency.sh       # 高频 TCP 延迟发现 → discovered_ips.tsv
├── probation.py          # 仅保留 _median_ms 契约（segment_quality.py 复用）
├── segment_quality.py    # /24、/16 网段级历史定性，拦截明确劣段
├── systemic.py           # 共因劣化轮判定（p10 判据）
├── verify_vless.sh       # VLESS 真实链路 TTFB 门控（并行批次验证）
├── watchdog.sh           # Top1 连通性监测 → cycle.sh fast --emergency
├── publish_watchdog.sh   # 发布链路停摆告警（Hermes no-agent 定时调用）
├── apply.sh              # best_ips 变化检测 → push_to_misub
├── probe.sh              # MTR 路径诊断 → routes.tsv
├── status.py             # 只读运行状态汇总（./status.py 或 --json）
├── migrate.sh / rollback.sh  # 旧链路 ⇄ contender 池 切换与回滚
├── push_to_misub.py      # 推送到 MiSub（apply.sh 调用，不含 Token）
├── secrets/misub.env     # MiSub Token（0600，仅本机）
├── parse_mtr.py          # MTR 输出摘要解析
├── ip_ranges.txt         # HKG 候选网段（11 个 CIDR；允许 # 注释行）
├── contenders.tsv        # 单一候选池：ip, first_seen, last_sampled, origin, evaluated_at
├── .screen_blacklist.tsv # 质量退出/连续快筛失败，24h 冷却
├── .capacity_cooldown.tsv # 容量退出，6h 冷却（不代表质量判差）
├── .tiers/               # core.txt / challengers.txt（fast 周期 audit 输入）
├── discovered_ips.tsv    # 高频发现待快筛 24h 队列
├── vless_history.tsv     # VLESS 审计历史（rank 的单一证据源，7 天）
├── best_ips.txt          # 最终输出：排名表 + Top 纯 IP 列表
├── routes.tsv            # MTR 路由摘要（7 天窗口）
├── *.legacy              # 切换前的 master/probation 文件（rollback.sh 使用）
└── results/              # 每轮 log、fast.log、cron.log
```

## 候选验证与容量

- contenders.tsv 第五列 evaluated_at 记录生命周期验证完成时间；旧四列按待验证读取。
- 入池后同一晚的 20–21 / 22–23 / 00 三个时段均有有效观察，且 n_eff≥8，才完成验证。重复快周期不能替代时间覆盖；系统性失败轮不算覆盖，有效 PASS/FAIL/PARTIAL 均算观察。
- 完成状态不随 24h 滚动撤销；近期晚高峰样本、评分和发布资格仍实时衰减，历史验证完成不等于现在优秀。
- unworthy 与 overflow 只退出已验证且证据充分的候选；硬失败、持续不可达规则及系统性/覆盖率守卫不变。
- 池上限 150，每轮只筛剩余空位。池满且无合适退出者时暂停接纳，不裁未验证候选换吞吐；发现队列仍遵守原有 TTL 与容量。
- 质量冷却 24h，容量冷却 6h；两者都在发现及准入前排除。快筛执行失败不计候选失败，不接纳部分输出。
- status.py 展示已完成/待验证数量，以及质量/容量退出分项。

## 发现与准入 module

发现队列规则集中在 admission.py；scan_latency.sh 与 cycle.sh 保留锁、调度和外部探测，不再各自维护 TSV 解析与排序。

- maintain：整理、合并及输出队列目标，兼容旧 2/3 列，保留首次发现时间、失败数与延迟；超限保留较新记录，再按时间升序落盘。
- select：排除池内与有效冷却集合，按失败数/日期及既有同键次序选择，统一预算 min(screen_max, 剩余空位)；选择本身不改队列。
- process_screen：仅接纳实际请求与通过结果的交集；原 Python 调用与无子命令 CLI 保持兼容。
- interface 是业务动作，不暴露独立的解析/排序/序列化 interface；领域术语见 GLOSSARY.md。
- 写入使用 atomic_io.atomic_write；顺序为池 → 质量冷却 → 队列 → 接纳输出。文件读写错误非零退出；单文件原子不等于跨文件事务，中断后重新读取持久状态选择，不盲目重放旧请求。

## 周期结果 module

cycle_result.py集中审计守卫、机器receipt、周期收束和历史adapter；cycle.sh仍执行网络命令，rank.py仍负责统计，status.py只读呈现。设计见docs/superpowers/specs/2026-10-28-cycle-result-design.md。

- 每周期一份带版本JSON，位于results/cycle-results；shadow单独使用.shadow/cycle-results。开始记录open，收尾只替换自己的文件，旧slow晚结束不会盖过新fast。
- rank.py可选--result-out输出受控receipt；旧CLI与可读摘要保持。周期不再从人类摘要猜测排名成功。覆盖率规则共用现有配置，独立CLI默认80%。
- 最近尝试与最近完整结果分别显示时间和来源；池计数标明排名时刻，不冒充此刻的池大小。合法守卫/非致命警告可完整；完整结果不等于候选完整验证，也不等于本轮新推送。
- 排名变更、应用确认、推送证据分开；记录的本轮push_evidence在没有可归属证据时为unknown。最近确切推送由同一adapter读取slow/fast/cron既有明确成功标记，数量不齐的截断标记不当成功。
- begin记录写失败不启动后续业务；收尾写失败非零退出，已采样/已应用不回滚、不自动重放。SIGKILL显示未收束，不断言仍在运行。坏新记录明确报问题，不静默回退为旧成功。
- 保留7天及最近尝试/最近完整所需记录；原子临时记录与receipt超过180分钟后随下一次维护回收，仅自己的命名空间。单文件原子，不是跨文件事务。
- status.py在没有旧慢轮日志时也能显示新记录；--json不输出全部历史记录，且CLI不产生本地.pyc。新旧统计按cycle-record ID去重，未知数量明确标成统计不完整。

## 执行链路

```
cron 每 2h → run.sh → cycle.sh slow
  ├─ 全池 VLESS audit（返回率 < 80% → coverage 守卫轮，不淘汰）
  ├─ systemic.py 共因劣化判定（PASS median p10 > 150ms → systemic 守卫轮）
  ├─ rank.py：7d 半衰期加权统计 → core/challenger/reserve 分层 → 淘汰 → 粘性发布
  ├─ apply.sh → push_to_misub（发布集或模板变化才推）
  ├─ discovered FIFO VLESS 快筛（预算 min(20, 剩余空位)，PASS 原子准入；等待不计失败）
  └─ probe.sh MTR 路径诊断

cron 每 15min → cycle.sh fast
  └─ 只 audit core ∪ challengers → rank → apply（快速让挑战者积累证据）

cron 每 5min → scan_latency.sh
  ├─ CloudflareST 仅做 TCP 延迟候选发现 → discovered_ips.tsv（排除池内 IP）
  └─ watchdog.sh（Top1 连通性监测 → cycle.sh fast --emergency）
```

## 关键参数

### 发现与快筛
- `QUAL_LAT=70ms`：TCP 发现门槛，只负责把候选送入 `discovered_ips.tsv`
- `VLESS_SCREEN_MAX=20`：每轮最多快筛 20 个新候选；`VLESS_SCREEN_MAX_FAIL=3` 连续失败拉黑 24h
- `VLESS_ADMIT_TTFB=100ms` / `VLESS_OFFPEAK_SCREEN_TTFB=60ms`：快筛准入线（04:00–09:00 平峰收紧）
- `POOL_MAX=150`：池达到上限时本轮跳过快筛（日志 `discovery screen skipped: pool full`）；池 > POOL_MAX−20 时 rank.py 规则 4 每轮裁 ≤20 个已完成晚高峰验证且证据充分的最差者

### rank.py（contender 池）
- 证据窗口 7d，半衰期 `RANK_HALF_LIFE_HOURS=24`；每个样本一个效用分 s=f(去共因 TTFB)（失败=0），按时效 × 时段加权（晚高峰 `RANK_PEAK_HOURS=20-23,0` 权重 `RANK_PEAK_WEIGHT=3`）求 mu、σ̂；n_eff 只按时效计
- 10 分钟轮桶基线去共因：`q = ttfb − max(0, B_r − RANK_FLOOR_MS)`
- `lcb/ucb = mu ∓ RANK_Z·√(σ̂²+RANK_SIGMA0²)/√n_eff`（z=1, σ0=0.15）：稳定 IP 区间窄，双峰 IP 区间宽——丢 core 位但不被误剔
- 分层：core = lcb 前 `CORE_N=10`（n_eff ≥ 3）；challenger = ucb 高于 core 末位 lcb（≤10）；其余 reserve
- 淘汰（守卫轮不淘汰）：① 已完成晚高峰验证、n_eff ≥ 8 且 ucb < 第 `POOL_TARGET=60` 名已证明 IP 的 lcb（需 ≥ 60 个已证明 IP）；② n_eff ≥ 3 且失败率 Wilson 下界 > `VLESS_HARD_MAX_FAIL=0.30`；③ 连续 3 次不可达；④ 池 > POOL_MAX−20 时在"已完成验证、n_eff≥8 且不在前 60 名"里按 ucb 裁最差者，每轮 ≤20（防池同质化冻结）
- 发布：粘性、含顺序，挑战者 lcb 需高出在任者 `PUBLISH_MARGIN=0.02`；资格 = n_eff ≥ `PUBLISH_MIN_NEFF=6` 且近 24h 晚高峰样本 ≥ `RANK_PEAK_MIN_SAMPLES=3`（必须扛过一个晚高峰）且失败率 ≤ 30%；同 /16 最多 2 个（仅滞回内有跨段合格者时替换）；合格者不足 3 个时不改写发布集（fail-closed）
- 日志契约：`rank: pool=N core=N challengers=N evicted=N published=a,b,c changed=0|1 guard=none|coverage|systemic|no_evidence`

### verify_vless.sh
- 并行批次（硬上限 2），每 IP 启动临时 xray → 3 次 TTFB 取中位数
- 普通验证阈值 500ms；超过只形成失败证据，淘汰由 rank.py 的统计决定
- 使用 `BYPASS_GID` 绕过 TUN 直连 CF edge
- `VLESS_TEMPLATE=HK|SG` 选择对应地区的 SNI/Host/path/UUID 模板；默认 `HK`
- `--audit FILE`：审计模式，只报告不改写
- `--screen IN OUT`：入池快筛模式，cycle.sh 按时段传入实际 `VLESS_ADMIT_TTFB`，只输出达标 IP 到 OUT

### watchdog.sh
- Top1 连续 3 次 TCP 443 不可达 → `cycle.sh fast --emergency`（audit core∪challenger → rank → apply）
- verify 锁忙（rc=75）或维护闸门 `.push_disabled` 时保留 miss 计数、不进冷却；冷却 1h
- ShellCrash 每小时从 misub 拉取订阅并重启，节点切换由 Mihomo url-test 组自动 failover

## 网络配置

本机 ShellCrash 全局 TUN，`table inet shellcrash` 对 gid 7890 旁路直连。cfst/xray 用 `setpriv --regid 7890` 拿到物理直连。

## cron

```cron
0 */2 * * * cd /opt/cfst && /usr/bin/bash run.sh >> results/cron.log 2>&1
7-59/15 * * * * cd /opt/cfst && /usr/bin/bash cycle.sh fast >> results/fast.log 2>&1
1-59/5 * * * * cd /opt/cfst && /usr/bin/bash scan_latency.sh >> results/cron.log 2>&1
```

- **run.sh → cycle.sh slow** — 每 2h 全链路（全池 audit + rank + apply + screen + probe），日志 `results/<ts>.log`
- **cycle.sh fast** — 每 15min core/challenger 复采样 + rank + apply；与 slow 共用 `CFST_LOCK`，锁忙则等待
- **scan_latency.sh** — 每 5min 轻量发现 + `watchdog.sh`
- **publish_watchdog.sh** — 独立 Hermes no-agent job 每 30min 调用 profile-local 薄 wrapper，wrapper 转发到 `/opt/cfst/publish_watchdog.sh`；正常静默，检测到发布停摆才输出告警。它不属于 root crontab。

## 手动操作

```bash
cd /opt/cfst
./status.py                        # 运行状态汇总：最近轮次/池 TTFB/Top3/池流动/发布与轻扫时效/告警
bash run.sh                        # 手动慢周期（= cycle.sh slow）
./cycle.sh fast                    # 手动快周期
python3 rank.py --dry-run          # 只算不写（best/contenders 不变；需 config.sh 阈值，见 cycle.sh 调用）
python3 replay.py --help           # 用历史回放策略
./verify_vless.sh                  # 验证当前 Top N
./verify_vless.sh --audit <(cut -f1 contenders.tsv | grep -v '^#')  # 审计全池
./probe.sh --top 5                 # MTR Top 5
cat best_ips.txt                   # 当前排名与发布集
./rollback.sh                      # 回滚到切换前的 master/probation 链路（需 git 历史中的旧脚本）
```

## 消费方式

`best_ips.txt` 末尾 `# --- BEST_IPS` 段为纯 IP 列表，供 apply.sh 推送到 misub。

ShellCrash 每小时从 misub 拉取订阅并重启 Mihomo，无需本地 provider YAML 热加载。

节点模板定义在 `config.sh` 的 `NODE_HK/NODE_SG` 关联数组中，所有 CFST 脚本共用，单点维护；JP 节点由手动订阅维护，不属于 CFST 自动推送范围。

MiSub 外部 API Token 存放在 `/opt/cfst/secrets/misub.env` 的 `MISUB_TOKEN=...` 中，文件权限必须为 `0600`；`push_to_misub.py` 不再保存 Token 原文。可通过环境变量 `MISUB_TOKEN_FILE` 指定隔离测试文件，`apply.sh` 会把 Token 文件摘要纳入变化键，Token 轮换后会触发一次重新推送。

节点 VLESS UUID 存放在 `/opt/cfst/secrets/vless.env` 的 `VLESS_UUID=...` 中，文件权限必须为 `0600`；`config.sh` 与 `push_to_misub.py` 均按需读取，源码不再内联凭据。可通过环境变量 `VLESS_SECRET_FILE` 指定隔离测试文件。凭据缺失或权限过宽时，`verify_vless.sh` 直接 exit 2、`push_to_misub.py` 抛 RuntimeError，以避免用空凭据探测导致节点被误判退役。

`rank.py` 输出 `SCORE_TOP_N=5`（发布集 + 候补集）；MiSub 只发布前 `PUBLISH_TOP_N=3` 位。推送前对这 3 个候选分别用 HK、SG 模板做真实链路验证，任一失败即中止远端改动。发布器按节点名复用既有 CFST 节点，URL 变化时原地更新；只在节点缺失时创建，只回收未被引用的重复节点，并且回收发生在 profile 写入前。profile 引用集合正确时不写 profile；最终通过按 ID 新鲜读取核验节点 URL 与引用集合。稳态通常不创建/更新/删除节点，也不写 profile；JP 等非 CFST 节点保留。

## 注意事项

- **移动 QoS**：达标 IP 天然稀有；rank.py 用连续统计与置信区间替代单次尖峰进出，发布带滞回
- **`ip_ranges.txt` 可以写 `#` 注释行**：`scan_latency.sh` 在交给 `cfst -f` 之前已用 `grep -vE '^[[:space:]]*(#|$)'` 过滤注释与空行（旧文档称会报错，实测不成立）
- **latency scan 用 `-dd` 而非 `-dn 0` 禁用下载测速**：`-dn` 是「下载测速数量」，传 `0` 会落回默认队列 10 个 IP，每个最长 `-dt 10` 秒，约 100s 恒定开销直接撞满 `SCAN_TIMEOUT=90`。实测同目标集 `-dn 0` 为 113.4s、`-dd` 为 13.5s
- **Hermes terminal 有 `_lc` 报错**：cron 用绝对路径 `/usr/bin/bash` 绕过
