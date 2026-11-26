# CF Preferred IP

[![测试](https://github.com/Luckylos/CF_Preferred_IP/actions/workflows/test.yml/badge.svg)](https://github.com/Luckylos/CF_Preferred_IP/actions/workflows/test.yml)

面向自有 Cloudflare 中继的 IPv4 优选与自动发布工具。它先用 TCP 延迟发现候选，再通过实际 VLESS 链路采样 TTFB 和请求失败率，根据近期证据给候选分层，并将选出的地址发布到 Cloudflare DNS、MiSub 或两者。

- **持续验证。** 慢周期审计评分池、快筛新候选，快周期复测核心层和挑战层。首次请求与连接复用后的请求分开记录。
- **带守卫的排名。** 审计覆盖不足、共因异常或证据无法核验时，暂停淘汰和新发布。
- **一致的发布。** 排名原子更新 `.publish_desired.json`。DNS 和 MiSub 在同一次应用中使用同一版快照，所有启用通道读回成功后才写入已应用指纹。

[部署与运维教程](docs/deployment.md) · [领域术语](GLOSSARY.md) · [许可证](LICENSE)

## 先在本地试用

需要 Git 和 Python 3.11 或以上版本。以下命令在普通检出目录运行，使用公开测试夹具，无需 Cloudflare、MiSub 或 VLESS 凭据。安装 `pytest` 需要访问 Python 包索引。

```bash
git clone https://github.com/Luckylos/CF_Preferred_IP.git
cd CF_Preferred_IP
python3 -m venv "$HOME/.venvs/cf-preferred-ip"
. "$HOME/.venvs/cf-preferred-ip/bin/activate"
python -m pip install pytest
python -m pytest tests/test_rank_cli.py tests/test_audit_evidence.py tests/test_publication_snapshot.py
```

这组测试覆盖排名、审计证据和发布快照，远端调用使用本地桩。运行 `python -m pytest` 可检查全部可移植用例。干净检出时，测试配置跳过依赖部署目录或真实二进制的套件。

## 部署到自己的 Linux 主机

运行目录为 `/opt/cfst`。部署需要 Bash、Python 3.11+、Xray、CloudflareST 和系统网络工具，以及你自己的中继、候选网段和所选发布通道的凭据。部署教程从依赖、节点配置和候选验证讲起，提供首次发布、cron、状态确认、升级和回滚步骤。 [部署与运维教程](docs/deployment.md)

公开仓库的节点、MiSub、DNS 和路由诊断地址均使用 `example.com` 示例。真实节点、运行状态和生产网段由部署者在本机配置。VLESS 和 MiSub 凭据存放在本地 `secrets/`。回放夹具使用脱敏地址。 [安全说明](SECURITY.md)

## 运行机制

| 环节 | 入口 | 结果 |
| --- | --- | --- |
| TCP 发现 | `scan_latency.sh` | 将低延迟候选加入 `discovered_ips.tsv` |
| 实际链路审计 | `verify_vless.sh` | 写入区分首次请求和复用请求的结构化证据 |
| 周期与排名 | `cycle.sh slow` / `cycle.sh fast` | 更新候选池、分层、榜单和期望发布快照 |
| 发布 | `apply.sh` | 按同一快照独立协调 DNS 和 MiSub，记录已应用或待发布指纹 |
| 观察与回放 | `status.py` / `replay.py` | 查看当前状态，或按指定参考和截止时间回放已有证据 |

当前发布集包含三个有序成员。DNS 默认选择一个 A 记录目标，MiSub 将三个成员映射到各地区的稳定节点槽位。`best_ips.txt` 保留人读榜单和机器可读的 IP 段。

- [首次请求、复用请求与批证据](docs/adr/0001-request-observations-and-batch-evidence.md)
- [证据质量与选择规则](docs/superpowers/specs/2026-11-25-evidence-quality-selection-design.md)
- [期望发布快照与跨轮重试](docs/superpowers/specs/2026-11-26-publication-snapshot-design.md)

提交问题时，请注明版本、发布模式、复现步骤和脱敏的周期结果。 [报告问题](https://github.com/Luckylos/CF_Preferred_IP/issues)

本项目采用 [MIT 许可证](LICENSE)。
