# Data contract

公开样例只使用文档保留地址。生产数据应放在仓库外的私有运行目录。

## History rows

格式：timestamp<TAB>ip<TAB>PASS|FAIL|PARTIAL<TAB>median_ms<TAB>reason

时间使用 YYYY-MM-DD HH:MM:SS。reason 是不参与凭据传输的短标签；不要写入 token、订阅 URL 或命令行。

## Contender rows

格式：ip<TAB>first_seen<TAB>last_sampled<TAB>origin<TAB>evaluated_at

旧的四列格式可以由核心兼容读取；新写出的状态使用第五列。未知完成时间使用 -。

## Published set

发布文件是部署层输入。样例只展示格式，不代表真实节点：

    # --- PUBLISHED (machine-readable, one address per line) ---
    192.0.2.10

## Cooldown rows

格式：ip<TAB>timestamp

质量和容量冷却使用不同文件，不要合并含义。过期、未来或格式非法的记录应被忽略；写入应使用原子替换。

## Privacy rules

- 不提交真实 IP 清单、历史样本、日志、UUID、订阅地址或节点模板。
- 不在 reason、origin 或 issue 中嵌入凭据。
- 公开复盘只报告聚合统计，不报告可回溯到真实节点的原始样本。
