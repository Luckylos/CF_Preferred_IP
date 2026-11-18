# 发现与准入 module

状态：已批准。范围：发现与准入；周期结果另行设计。

## 已确定的取舍

- 以 admission.py 为基础 deepening，不增设独立队列框架或新依赖。
- 保留 TSV、atomic_io.atomic_write，以及池/质量冷却先写、队列后写的顺序。
- 允许跨文件中断后出现暂留记录；不承诺跨文件事务、回滚或 exactly-once。
- 全部筛选、验证、评分和发布策略不变。

## module 与 seam

发现与准入 module 拥有发现队列的格式兼容、整理、选择与筛选结果写回 implementation。
interface 是三个业务动作，不把行解析、排序、序列化等辅助函数变成调用方必须掌握的 interface。
seam 位于 scanner/slow cycle 与队列状态操作之间；现有进程锁仍由 shell 持有。
模块不调用真实网络；测量工具/本地桩作为既有 adapter 留在外部执行。
这样 depth 来自隐藏队列不变量，locality 来自规则集中，leverage 来自 scanner 与 slow cycle 共用 implementation。

## interface：三个业务动作

### 1. maintain（整理与合并）

- 读取队列，按现有调用场景整理；可合并 scanner 给出的“IP + 发现延迟”候选。
- 时间与现有 TTL/limit 显式传入，不在模块内读取真实时钟或 source config.sh。
- 对 slow cycle 需要的质量/容量冷却排除，沿用 cooldown.py 的有效集合判断。
- 生产现有场景保持：scanner 的普通整理与 slow cycle 的冷却清理不被偷偷合并为更强清理。
- 既有记录优先，重复发现不刷新首次发现时间、不清零失败次数或覆盖既有延迟。
- 超限时保留较新记录，再按首次发现时间升序选取；同时间的排序也做特征测试。
- 原子写回，返回必要队列计数，shell 不再自行理解持久 TSV 列。

### 2. select（生成请求集合）

- 读取整理后的队列、当前池和有效冷却状态。
- 按现有排除规则生成实际请求，预算为 min(screen_max, max(0, pool_max - pool_size))。
- 模块负责预算和队列顺序；shell 不再重复计算并维护另一套规则。
- 请求输出仍为每行一个 IPv4，适配未修改的 verify_vless.sh。
- 满池输出空请求；无网络调用，不更新个体失败计数。
- 时间、路径和原有数值配置由调用方显式提供，不新增自动发现配置或通用策略对象。

### 3. process_screen（接纳与结果写回）

- 保留现有 Python 调用兼容及“requested 与 passed 交集”约束。
- 按最新持久池再核容量，保留旧候选元数据，新候选仍是待验证。
- 等待、未请求、成功但未接纳者不增加失败；整次筛选执行失败由调用方跳过此动作。
- 写入顺序保持：池 → 质量冷却 → 队列 → 实际接纳输出。
- shared 行处理 implementation 内部复用，但保留当前不同动作的序列化语义：整理会规范旧格式；结果写回仍保留未变更旧行。
- 保留现有无 subcommand 的命令调用作为兼容入口，避免破坏直接调用方；新动作通过同一 admission.py 命令入口调用。

maintain/select 使用显式命令动作；process_screen 保持原无子命令调用。不引入额外公共的 read/parse/sort/write interface。

## 调用方改动

- scan_latency.sh：保留锁、测量、既有候选资格/网段校准与 watchdog；把队列整理/合并交给 maintain。
- cycle.sh：保留调度、audit/rank/apply、系统性守卫、快筛进程和资源回收；改为 maintain → select → 外部 screen → process_screen。
- shell 仍可解析测量输出与请求文件，但不解析、排序或改写持久发现队列 TSV。
- 原有路径、状态文件、调度与对外日志含义不变；候选2的周期结果改造不混入。
- 受保护 verify_vless.sh/apply.sh/segment_quality.py 等保持不变。

## 中断与错误

- 输入/配置错误应在任何写入前拒绝；状态文件与请求/结果输出不得互相覆盖，写入路径别名须验证。
- 文件读写失败非零退出、传播异常，禁止以空集合代替读取失败后继续覆盖状态。
- 验证池写失败、冷却写失败、队列写失败及结果输出写失败时的可见状态和未执行的后续写入。
- 队列写失败时已成功持久化的池/冷却不回滚；下轮重新读取当前状态选择，不盲目重放旧请求。
- 单文件原子替换不声称具备整轮全有或全无语义。

## 测试迁移与验收

1. 先增加特征测试：TTL 临界、超限保留新记录/FIFO、同时间排序、重复发现、旧2/3/4列、延迟与失败计数保留；对合成输入与旧 shell 行为比对，不使用生产历史或凭据。
2. 对 maintain/select/process_screen 的 interface 验证可观察文件和返回值，不在测试里复制队列算法。
3. 保留现有容量、请求集合、执行失败、等待不惩罚、冷却隔离和元数据行为测试。
4. 增加逐个写入点的故障注入与后续重新选择测试；不同单文件写入使用现有 atomic_io，不新增存储 adapter。
5. scanner 与 slow cycle 的本地桩集成测试跨越真实 shell/Python seam；保留已有网络封锁。
6. 同等行为覆盖建立后，移除复制实现/依赖 shell 字面文本的脆弱断言；不能因 implementation 改形而削弱有效断言。
7. bash -n、git diff --check、相关诊断和完整 pytest 回归（基线395，最终数量按新增/迁移据实报告）。

若发现旧行为存在安全/数据保护缺陷，先单独说明并补回归，不以行为等价为由保留缺陷，也不在纯重构中静默改策略。

## 实施与交付约束

在不含凭据和生产状态的隔离工作区 TDD 实施；不进行生产热改。
生产部署、本地提交等操作按既有审批规则执行，部署持 /run/lock/cfst.lock；不 push。
候选1验证并交付后，才进入候选2的设计与实施。

领域术语见仓库根目录 GLOSSARY.md。
