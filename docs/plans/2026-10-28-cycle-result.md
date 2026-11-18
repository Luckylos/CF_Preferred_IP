# 周期结果 module 实施计划

批准依据：docs/superpowers/specs/2026-10-28-cycle-result-design.md；用户已批准整体设计和从487bbf3隔离TDD实施，不包含部署/commit/push。主代理直接执行，不委派。

基线：/tmp/cfst-cycle-result detached487bbf3，不含生产凭据/运行状态/外部ip_ranges修改；干净完整回归437 passed（退出0）。

## 执行与检查点

1. 核心证据：先tests/test_cycle_result.py锁定守卫优先级、阈值/零值/缺省、审计格式读取和失败，观察RED，再实现assess_audit。原resolve_guard仅在requested>0时检查覆盖；保留原适用条件和ceil临界，不将缺省当0，也不引入新惩罚。
2. 周期生命周期：先测试open→finish、失败/跳过/非致命、严格版本、读取错误、路径/别名、迟收尾交错、shadow与按开始排序；实现begin_cycle/finish_cycle/read_status及自身命名空间保留/回收。写入使用atomic_io。
3. RankReceipt与rank：先覆盖receipt验证、--result-out、旧CLI、dry-run、路径别名及失败；添加可选机器输出/可配置覆盖率，并复用非统计守卫。所有领域写入和统计次序不变。
4. cycle：先新增本地桩集成测试证明begin失败在探测前停止、可捕获失败收束、未rank跳过、apply证据、slow/fast/shadow；再迁移证据/摘要读取到module，加入EXIT收束及临时receipt清理。守卫、锁释放、应用核验与非致命策略保持。
5. status/历史adapter：先把fast-only推送漏报变成RED，再覆盖纯新/纯旧/混合/坏新版本/七日去重；集中旧解析，仅保留status薄兼容入口和呈现。最新失败不能被旧成功盖掉。
6. 最终检查：对已有测试仅在同等或更强业务覆盖后迁移文本implementation断言；完整pytest（PYTHONDONTWRITEBYTECODE=1、-p no:cacheprovider，≥150s）、bash -n、diff --check、LSP、最终diff/保护文件/生产未改检查。分别报告通过、失败、跳过和不确定项。

## 不变项与交付

stdlib、set -euo pipefail、best marker、评分/发布/保护/准入/冷却策略不变。不得修改verify_vless.sh、push_to_misub.py、apply.sh、segment_quality.py、systemic.py、publish_watchdog.sh。测试禁真实外连，不在生产加探测/杀进程/强制填池。

新记录仅受控事实，不复制原始日志/状态指纹/节点URL。单文件原子，写失败非零，不回滚已发生动作、不自动重放。不使用旧/tmp/cfst-queue-deepening。隔离完成报告实际证据并另请交付授权。


## 隔离验收记录

- 代码与调用方已实施，未部署、未commit、未push；部署/本地提交仍须单独授权。
- 基线437项；最终完整pytest见本次执行结果，新增89项，包含机器interface、真实shell/模块集成、状态读取和故障路径。
- 删除原caller重复的审计/摘要/历史解释后，保留人类日志、旧rank CLI和status解析函数的薄兼容入口。
- 额外回归覆盖：大整数覆盖率精度、不可读记录目录的统计不完整、初始记录的时区/范围拒绝。均先观察RED再修复；shadow退出码/无tier跳过/无receipt拒绝应用为额外兼容验证。
- 排名统计及领域函数与Config共40项AST不变；256组默认守卫输入与原实现等价。未更改评分、发布、准入、冷却政策。
- bash -n、git diff --check通过；新文件空白检查通过。tests/test_status.py保留HEAD已有的输入fixture尾空格，不为检查改写测试数据。
- LSP非零：新module有1项未捕获JSON解析模板诊断和20项数值转换模板提示。严格解析刻意把错误交由CLI非零/读取错误报告，转换已有类型/正则校验；未关闭规则、未抑制诊断。rank/status另有原有模板提示，不能称诊断全绿。
- 生产仍为487bbf3，仅原有ip_ranges.txt改动且摘要与部署前记录相同；保护脚本和策略配置未变。未进行生产额外探测、部署或效果验证。
