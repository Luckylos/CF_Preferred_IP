# 发现与准入 deepening 实施计划

批准依据：docs/superpowers/specs/2026-10-28-discovery-admission-design.md；只实施发现与准入。

目标：在 admission.py 集中发现队列维护、请求选择与结果写回；shell 保留锁、网络与编排。隔离实现完成后，生产锁内部署、验收与仅本地提交已另获用户明确授权；不覆盖运行状态。

## 步骤与验证

1. 隔离基线：从5477028建立 /tmp/cfst-queue-deepening detached worktree，不带生产凭据、状态或ip_ranges.txt未提交改动。完整回归基线395 passed。
2. maintain：先写tests/test_discovery_admission.py覆盖TTL边界、旧格式、first-wins、最新保留、同时间次序、scanner/cycle排除差异与输入错误；观察RED，再扩展admission.py通过GREEN。
3. select与写回：先验证failcount/date/旧排序tie-break、空池/满池/单空位、冷却、请求输出；增加路径别名和逐写入故障测试，保留process_screen兼容与实际写序。
4. shell迁移：本地scanner桩集成、slow-cycle行为覆盖先RED；替换两个shell中的队列规则，保留既有外部过滤、守卫、快筛rc和影子限制。
5. 迁移test_discovery_latency.py：使用真实module interface，不再复制awk/排序implementation；等价覆盖后删除脆弱断言。
6. 文档/领域：记录GLOSSARY.md及当前设计，最小README说明。运行相关测试、完整回归、bash -n、diff --check、LSP诊断及最终diff审阅。

## 不变项

TTL24h/limit180、最新保留、请求按failcount/date次序、满池暂停、等待不惩罚、质量24h/容量6h、验证保护与发布策略；不改受保护脚本。

## 存储契约

使用atomic_io.atomic_write；池→冷却→队列→接纳输出。单文件原子，不宣称跨文件事务。失败原样传播；测试读取故障、路径重合、各写入点与重新选择。

## 交付

候选1通过后报告实际diff/验证与未决事项，等待部署和本地commit授权。不push。交付后再进入候选2设计。
