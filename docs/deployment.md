# CF Preferred IP 部署与运维

本教程以 Linux、`/opt/cfst` 和 root 的 crontab 为例。首次部署从自己已验证的候选建立发布快照。已有部署请走本页的[升级与回滚](#升级与回滚)。

## 1. 准备主机与依赖

以下命令由部署账户执行。本教程使用 root，因为默认的锁、凭据路径和 `setpriv` 均按这个布局配置。主机时间和时区应与期望的采样时段一致。

```bash
git clone https://github.com/Luckylos/CF_Preferred_IP.git /opt/cfst
cd /opt/cfst
chmod 0700 /opt/cfst
umask 077
install -d -m 0700 bin results secrets
touch .push_disabled
```

- 安装 Bash 4.3+、Python 3.11+、`curl` 7.75+（须支持 `%{exitcode}`）、`iproute2`（`ss`）、`util-linux`（`flock`、`setpriv`、`setsid`）、GNU coreutils 和 `mtr`。使用 cron 调度时，主机需要运行 cron 服务。
- 按主机架构获取 CloudflareST 和 Xray，并按上游说明验证下载。将可执行文件分别放到 `/opt/cfst/cfst` 和 `/opt/cfst/bin/xray`，权限设为 `0755`。 [CloudflareST 发布](https://github.com/XIU2/CloudflareSpeedTest/releases) · [Xray 发布](https://github.com/XTLS/Xray-core/releases)
- 在 `config.sh` 中把 `BYPASS_GID` 改成适合本机的数字 GID。没有 TUN 策略路由且按本教程用 root 运行时可用 `0`。有 TUN 时，选用已配置为直连的 GID，并确认该组能出站。
- 按[第 3 节](#3-准备扫描目标筛选候选并初始化快照)准备 `ip_ranges.txt` 和首批候选。

```bash
python3 --version
command -v bash curl ss flock setpriv setsid timeout mtr
./cfst -h
./bin/xray version
for script in config.sh cycle.sh verify_vless.sh apply.sh scan_latency.sh; do
  bash -n "$script" || exit 1
done
```

## 2. 填写本地配置与凭据

| 位置 | 部署者填写的内容 |
| --- | --- |
| `config.sh` | 各地区 `CFST_TEMPLATE_{HK,HT,SG}_*` 字段。使 `QUERY` 中的 `sni`、`host`、`path` 和传输类型与实际 VLESS 中继一致，同时更新对应的 `SNI`、`HOST`、`PATH` 等字段。`COLO_HOST` 填支持 `/cdn-cgi/trace` 的自有 Cloudflare 域名。 |
| `secrets/vless.env` | 一行 `VLESS_UUID=<探测中继的 UUID>`。首次创建 MiSub 节点时也使用这个 UUID；应能用于准备创建节点的各地区。对于 UUID 不同的地区，应先在相应槽位准备有效的现有节点，发布器会保留其凭据。 |
| `secrets/misub.env` | MiSub 通道启用时写入 `MISUB_TOKEN=<外部 API Token>`。当前 `apply.sh` 在任何模式都会检查此文件是否存在。仅使用 DNS 时可创建权限为 `0600` 的空文件。 |
| `push_to_misub.py` | MiSub 通道启用时配置 `MISUB_BASE`（包含 API 路径）和 `PROFILE_NAME`。目标 profile 必须已存在且同名项只有一个。节点前缀与已有受管节点命名一致。 |
| `dns_publish.py` | DNS 通道启用时配置 `ZONE_ID`、`RECORD_NAME` 和需要时的 `TOKEN_FILE`。选用归 CFST 管理的专用 FQDN，发布会协调该名称下的整个 A 记录集。 |
| `/root/.config/credentials/cloudflare.env` | DNS 通道启用时写入 `CLOUDFLARE_API_TOKEN=<Token>`，至少有对目标区域读取和编辑 DNS 记录的权限。路径与 `dns_publish.py` 的 `TOKEN_FILE` 保持一致。 |

用权限为 `0600` 的本地文件保存凭据。配置时使用本地编辑器，避免将实际值写入命令历史。仅首次部署可用下列命令创建空白凭据文件，随后按上表填写。

```bash
install -m 0600 /dev/null secrets/vless.env
install -m 0600 /dev/null secrets/misub.env
# DNS 通道启用时，创建默认路径下的 Token 文件。
install -d -m 0700 /root/.config/credentials
install -m 0600 /dev/null /root/.config/credentials/cloudflare.env
```

在 `config.sh` 中将 `CFST_PUBLISH` 的默认值设为你要使用的 `dns`、`misub` 或 `both`，让手动与 cron 走同一配置。默认是 `both`。默认 `CFST_DNS_TOP_N=1`，DNS 适配器创建 DNS-only A 记录，TTL 为 60 秒。在首轮测试前决定是否执行 `touch .quality_evidence_enabled`。该文件启用单地址 DNS 首选选择。

## 3. 准备扫描目标、筛选候选并初始化快照

### 扫描目标从哪里来

仓库随附空的 `/opt/cfst/ip_ranges.txt`。每行填写一个待测 IPv4 地址或 CIDR，填写后的扫描范围只保存在部署主机。初次部署的 TCP 扫描从这份文件取目标。可以从 Cloudflare 公布的 IPv4 网段选取一部分，也可以填入你已有的合法测试地址。官方名单是网段来源，实际位置和延迟以部署主机的探测结果为准。项目不会自动下载网段，公开包只提供空模板。扫描没有任何有效目标时会记录 `no valid scan targets` 并跳过测速。 [Cloudflare IPv4 网段](https://www.cloudflare.com/ips-v4)

文件支持整行注释和空行，格式如下。这里的地址只用于展示格式，部署时换成实际待测地址。

```text
# 每行一个 IPv4 地址或 CIDR
192.0.2.0/24
198.51.100.42
```

每轮扫描合并 `ip_ranges.txt`、`discovered_ips.tsv` 中仍有效的候选、`contenders.tsv` 的已有成员，以及存在时的旧版 `master_ips.txt`。去重后用 CloudflareST 测 TCP 443 平均延迟。新地址低于 `QUAL_LAT`（默认 70 ms）且通过冷却、网段过滤等条件后，写入 `discovered_ips.tsv`。这份发现队列默认保留 24 小时，最多 180 条。

有了评分池后，正常慢周期每轮按剩余容量从发现队列最多选 20 个候选，用 VLESS 测试真实链路。快筛通过的地址写入 `contenders.tsv`，随后参与排名和分层。

### 从发现队列筛出首批成员

首次启动需要先从已通过 VLESS 快筛的地址中选定三个发布成员。保持 `.push_disabled` 并暂不开启 cron。执行一次 TCP 扫描，按平均延迟升序从发现队列选最多 20 个，再做 VLESS 快筛。

```bash
(
  set -euo pipefail
  cd /opt/cfst
  umask 077
  test -f .push_disabled
  bash scan_latency.sh
  test -s discovered_ips.tsv
  awk -F '\t' '$1 !~ /^#/ && $2 != "" && $4 + 0 > 0 { print $4, $2 }' discovered_ips.tsv \
    | sort -k1,1n -k2,2 \
    | awk 'NR <= 20 { print $2 }' > secrets/seed-candidates.txt
  test -s secrets/seed-candidates.txt
)
```

`discovered_ips.tsv` 的第 2 列是 IPv4，第 4 列是 TCP 平均延迟（ms）。若已有待验证的 IPv4，也可直接按每行一个写入 `secrets/seed-candidates.txt`。若 TCP 扫描没有生成候选，可先检查 `ip_ranges.txt`、直连路径和探测日志，再按本机 RTT 核对 `QUAL_LAT`。

每次运行快筛都清空上一轮名单。空结果时先查看快筛日志。

```bash
(
  set -euo pipefail
  cd /opt/cfst
  umask 077
  : > secrets/seed-passed.txt
  test -x bin/xray
  test -s secrets/seed-candidates.txt
  VLESS_TEMPLATE=HK bash verify_vless.sh --screen secrets/seed-candidates.txt secrets/seed-passed.txt
  test -s secrets/seed-passed.txt
)
```

`--screen` 可能以成功状态退出但没有通过项。检查输出，只挑三位通过快筛的不同 IPv4，按期望槽位顺序写入 `secrets/seed-selected.txt`。MiSub 发布还会按启用的地区做实际链路预检。先在手动维护窗口运行以下首次初始化命令，保持 cron 未启用。

```bash
python3 - <<'PY'
from datetime import datetime
from pathlib import Path

from ip_validation import is_valid_ipv4
from publication_snapshot import FILENAME, MARKER, migrate
from rank import Contender, write_contenders

selected = Path('secrets/seed-selected.txt').read_text().split()
passed = set(Path('secrets/seed-passed.txt').read_text().split())
if len(selected) != 3 or len(set(selected)) != 3 or any(
    not is_valid_ipv4(ip) or ip not in passed for ip in selected
):
    raise SystemExit('请选择三个已通过快筛的不同 IPv4')
best = Path('best_ips.txt')
pool = Path('contenders.tsv')
if any(path.exists() or path.is_symlink() for path in (best, pool, Path(FILENAME))):
    raise SystemExit('已有榜单、评分池或期望快照，请走升级流程')
now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
best.write_text('\n'.join([MARKER, *selected, '']))
write_contenders(pool, [Contender(ip, now, '-', 'screen') for ip in selected])
migrate(best, 3)
PY
python3 publication_snapshot.py targets .publish_desired.json --count 3
```

快照命令输出的第一行是可选的 DNS 首选，首次初始化通常为空，后三行是按顺序保存的成员。检查文件和目标仅需本机访问。

## 4. 首次发布与确认

检查域名、订阅 profile、目标地址和所选通道后，打开维护闸门并显式允许首次发布。第二条命令会请求远端并可能更改 DNS 或订阅。仅 DNS 模式可先通过 `python3 dns_publish.py status` 读取现有记录，以确认配置指向正确域名。

```bash
rm .push_disabled
APPLY_RETRY_ONLY=0 bash apply.sh
(
  set -euo pipefail
  source ./config.sh
  expected=$(compute_apply_state)
  test ! -e .apply_state.pending
  test "$(<.apply_state)" = "$expected"
)
```

两个通道都启用时，只有两边都成功且读回目标后才确认 `.apply_state`。任一路失败会留下 `.apply_state.pending`。修复失败原因后，可运行 `bash apply.sh` 重试同一指纹。部署者手动修改快照或配置后，旧待发布记录不会通过默认重试检查。

核对首次发布后，手动完成一轮慢周期并查看状态。慢周期可生成快周期所需的分层，首次采样后仍需积累证据才能进入稳定分层和得到新的发布选择。

```bash
bash cycle.sh slow
python3 status.py
python3 status.py --json
```

## 5. 定时执行与日常检查

将下面三行放进部署账户的 `crontab -e`。现场手动执行和 cron 应使用同一套凭据、时区和发布配置。

```cron
0 */2 * * * umask 077; cd /opt/cfst && /usr/bin/bash run.sh >> results/cron.log 2>&1
7-59/15 * * * * umask 077; cd /opt/cfst && /usr/bin/bash cycle.sh fast >> results/fast.log 2>&1
1-59/5 * * * * umask 077; cd /opt/cfst && /usr/bin/bash scan_latency.sh >> results/cron.log 2>&1
```

- **慢周期每两小时。** 审计全池、排名、应用并快筛新候选。慢轮详情保存在 `results/`。
- **快周期每十五分钟。** 复测核心层和挑战层。慢、快周期共用写锁，锁忙返回 `75`，下一调度窗口再运行。
- **TCP 发现每五分钟。** 更新发现队列并运行目标健康检查。可另行调度 `publish_watchdog.sh` 检查持续发布分歧。

| 现象 | 检查 |
| --- | --- |
| `snapshot requires distinct IPv4 members` 或成员数量错误 | 查看 `.publish_desired.json` 是否由三个不同 IPv4 构成。首次部署重查快筛和初始化记录，已有部署排查状态来源。 |
| 快周期无分层，或 `coverage`、`no_evidence` | 查看慢周期、Xray、`ss`、出站路由和候选的实际请求结果。确认中继 `/cdn-cgi/trace` 可达及传输配置有效。 |
| `systemic` | 查看同一时间窗的共因故障与参考链路。该守卫会暂停淘汰和新的发布尝试。 |
| 拒绝空凭据、权限出错 | 检查 `secrets/vless.env`、`secrets/misub.env` 与 DNS Token 文件的路径及 `0600` 权限。日志和工单使用脱敏信息。 |
| 已应用与期望不一致，或 `.apply_state.pending` 长时间存在 | 查 `results/` 中 DNS 或 MiSub 的失败原因，核对 Token 权限、记录解析和 MiSub profile。恢复后让下一轮或相同指纹的手动重试对账。 |

维护时可创建 `.push_disabled` 暂停 `apply.sh` 发布。直接调用适配器与手动远端编辑不受这个闸门控制。周期机器结果位于 `results/cycle-results/`。审计、发布结果和日志可能包含部署地址，保留在本机。

## 升级与回滚

升级前暂停定时任务，创建 `.push_disabled`，并等待在途的周期、应用和验证结束。备份代码、节点配置、凭据和运行态到权限受限位置。切换时持有 `/run/lock/cfst.lock`、`/opt/cfst/.apply.lock` 和 `/opt/cfst/.verify_vless.lock` 三把锁再替换源码或迁移状态。以下是确认三把锁和执行迁移的命令，应在同一个维护 Shell 内完成所有切换检查。

```bash
cd /opt/cfst
set -euo pipefail
umask 077
exec 9>>/run/lock/cfst.lock 7>>.apply.lock 8>>.verify_vless.lock
flock -n 9
flock -n 7
flock -n 8
```

1. 替换源码前，用旧版读取方式记录当前有序成员、有效 DNS 目标及 `compute_apply_state` 指纹。保留 `.apply_state`、`.apply_state.pending` 和既有榜单，两路目标核对不需要主动推送。
2. 将新源码放入 `/opt/cfst`，保留自有配置。首次从旧榜单切到快照时运行 `python3 publication_snapshot.py migrate best_ips.txt 3`，从机器可读榜单与已有的 `.dns_preference.json` 初始化。已经有 `.publish_desired.json` 的部署直接验证现有快照。
3. 使用 `read_publish_targets` 和 `compute_apply_state` 比对升级前后的目标和指纹。只迁移状态格式时，两者应一致。若此次升级也改变模板、发布器或指纹算法，先确认差异与预期一致并决定何时发布。确认本地状态正常后，退出维护 Shell 释放锁，撤下本次维护设置的 `.push_disabled`，再恢复调度。
4. 需要回到读取旧榜单及 DNS 状态的版本时，持同一组三把锁，在恢复旧源码前运行 `python3 publication_snapshot.py project-legacy best_ips.txt 3`。它把**当前**快照投影回榜单和 DNS 防抖文件。恢复备份代码后，确认旧读取方式与当前目标相同，保留当时的已应用和待发布记录，再恢复调度。

`migrate.sh` 与 `rollback.sh` 对应更早的候选池切换。这里的快照升级和回滚使用 `publication_snapshot.py` 的两个子命令。 [快照设计与兼容契约](superpowers/specs/2026-11-26-publication-snapshot-design.md)
