#!/bin/bash
# 共享配置 — 所有脚本 source 此文件
CFST_DIR=/opt/cfst
RESULT_DIR="$CFST_DIR/results"
BYPASS_GID=7890           # ShellCrash TUN 旁路直连 GID
QUAL_LAT=70               # TCP 延迟达标上限 ms（scan_latency 发现门槛）

# VLESS 入池快筛：低延迟发现候选须真实 VLESS TTFB 达标才进 master。
# 权威信号：VLESS TTFB 走完整 VLESS+WS+TLS 链路，反映实际 IP 延迟与体感。
# CFST 下载测速已废弃（弱相关 + 撞 speed.cloudflare.com 字节配额 429）。
VLESS_SCREEN_ENABLED=1    # 1=启用入池快筛；0=停用（发现候选不入池）
VLESS_ADMIT_TTFB=100      # 快筛准入 TTFB 上限（毫秒，入池门控）
VLESS_OFFPEAK_SCREEN_TTFB=60  # 04:00-09:00 发现快筛门；只收紧 screen，不改 probation recheck
VLESS_SCREEN_MAX=20       # 每轮从发现队列快筛的最大新候选数（控 xray 编排开销）
VLESS_SCREEN_MAX_FAIL=3   # 发现候选连续快筛失败上限，达到即永久剔除
SCREEN_BLACKLIST_HOURS=24 # 剔除后冷却小时数，冷却期内 scan_latency 不重新入队
CAPACITY_COOLDOWN="$CFST_DIR/.capacity_cooldown.tsv"  # 容量退出独立记录，不代表质量判差
CAPACITY_COOLDOWN_HOURS=6  # 容量冷却短于质量冷却，防止立即重入造成空转
SCREEN_BLACKLIST="$CFST_DIR/.screen_blacklist.tsv"  # IP<TAB>剔除时间戳

# 发现快筛的"平峰"判断：此时段之外（04-09，人人 49ms）候选必须做到 VLESS_OFFPEAK_SCREEN_TTFB 才入池。
# 与排名的晚高峰（RANK_PEAK_HOURS）是两个概念：一个是"没区分度的时段"，一个是"最有区分度的时段"。
SCREEN_PEAK_HOURS="10-23,0-3"

# 发现队列 screen 的时段门控：平峰只接受更严格的真实 TTFB；
# 池 audit 不设门槛（rank.py 用连续统计而非单次阈值）。
vless_screen_admit_ttfb() {
  local hour="${1:-$(date +%H)}"
  local range start end
  local -a peak_ranges

  if [[ ! "$hour" =~ ^[0-9]{1,2}$ ]] || (( 10#$hour < 0 || 10#$hour > 23 )); then
    echo "config: invalid hour for vless_screen_admit_ttfb: $hour" >&2
    return 2
  fi

  IFS=',' read -r -a peak_ranges <<< "${SCREEN_PEAK_HOURS:?SCREEN_PEAK_HOURS is required}"
  for range in "${peak_ranges[@]}"; do
    if [[ "$range" == *-* ]]; then
      IFS='-' read -r start end <<< "$range"
      if [[ "$start" =~ ^[0-9]{1,2}$ && "$end" =~ ^[0-9]{1,2}$ ]] \
        && (( 10#$hour >= 10#$start && 10#$hour <= 10#$end )); then
        printf '%s\n' "$VLESS_ADMIT_TTFB"
        return 0
      fi
    elif [[ "$range" =~ ^[0-9]{1,2}$ ]] && (( 10#$hour == 10#$range )); then
      printf '%s\n' "$VLESS_ADMIT_TTFB"
      return 0
    fi
  done

  printf '%s\n' "$VLESS_OFFPEAK_SCREEN_TTFB"
}
# 旧链路文件路径：仅供 migrate.sh / rollback.sh 迁移与回滚使用（切换后不存在）。
PROBATION_POOL="$CFST_DIR/probation_pool.tsv"

# ── Contender pool（2026-10-15 重构）──
# 设计：docs/superpowers/specs/2026-10-15-contender-pool-design.md §3。
# 单池连续采样 + 不确定性驱动排名：逐样本效用 → 时效×时段加权均值/方差 → 方差感知置信区间。
RANK_HALF_LIFE_HOURS=24   # 样本权重半衰期（小时）：24h 前样本权重 0.5，48h 前 0.25（§3.1）
RANK_FLOOR_MS=50          # 轮基线地板 ms：移动→HKG 物理 TTFB 下限 ≈47–50ms，去共因不低于此（§3.2）
RANK_Z=1.0                # 置信半宽 z：lcb/ucb = mu ∓ z·√(σ̂²+σ0²)/√n_eff
RANK_SIGMA0=0.15          # 逐样本效用先验标准差：区间宽度下限；稳定 IP 区间≈σ0/√n，离散 IP 自动更宽
RANK_PEAK_HOURS="20-23,0" # 晚高峰：唯一有区分度的时段（同轮 IP 间 IQR 80–110ms vs 其余 4–19ms，失败率 6–10% vs 1–2%）
RANK_PEAK_WEIGHT=3        # 晚高峰样本在 mu/σ̂ 估计中的权重（不计入 n_eff）：约占估计权重 40%
RANK_PEAK_MIN_SAMPLES=3   # 发布新鲜度门槛：近 24h 晚高峰样本数；生命周期验证另要求同晚 20/22/00 覆盖
CORE_N=10                 # core 层容量：按 lcb 排前 N 且 n_eff ≥ 3；fast 周期只 audit core ∪ challenger（§3.4）
POOL_TARGET=60            # 池目标规模：n_eff ≥ 8 且 ucb < 第 POOL_TARGET 名已证明 IP 的 lcb → 淘汰（§3.5 规则 1）
POOL_MAX=150              # 池上限：≥ 此值停止快筛补池；> POOL_MAX−VLESS_SCREEN_MAX 时规则 4 每轮裁 ≤ VLESS_SCREEN_MAX 个已表征最差者（§3.5）。150 IP audit ≈ 4–11 分钟/2h
PUBLISH_MIN_NEFF=6        # 发布门槛：n_eff ≥ 6 且晚高峰样本 ≥ RANK_PEAK_MIN_SAMPLES 的 IP 才可进 best_ips.txt（§3.7）
PUBLISH_MARGIN=0.02       # 发布滞回：挑战者 lcb 需高出在任者 lcb + 0.02 才换入/上移，含顺序（§3.7）
VLESS_HARD_MAX_FAIL=0.30  # 硬门失败率：n_eff ≥ 3 且失败率 Wilson 下界 > 30% 即淘汰；原始失败率 > 30% 失去发布资格（§3.5 规则 2）
CONTENDERS="$CFST_DIR/contenders.tsv"  # 单池文件：ip<TAB>first_seen<TAB>last_sampled<TAB>origin（§3.4，原子写）
TIERS_DIR="$CFST_DIR/.tiers"           # rank.py --tiers-out 产出 core.txt/challengers.txt，供 cycle.sh fast 取 audit 输入

# 旧链路文件路径：切换后以 *.legacy 存放，仅 migrate.sh / rollback.sh（及 scan_latency 兼容读取）使用。
MASTER="$CFST_DIR/master_ips.txt"
MASTER_STATE="$CFST_DIR/master_state.tsv"
# xray 临时配置含 VLESS UUID：放 tmpfs，避免落盘、进备份或快照。
# SIGKILL 会跳过 EXIT trap，tmpfs 下重启即自动清理。
VERIFY_TMPDIR_BASE="${VERIFY_TMPDIR_BASE:-/dev/shm/cfst}"

DISCOVERED="$CFST_DIR/discovered_ips.tsv"  # 发现队列：时间戳<TAB>IP<TAB>快筛失败次数
SCAN="$CFST_DIR/ip_ranges.txt"
BEST="$CFST_DIR/best_ips.txt"
ROUTES="$CFST_DIR/routes.tsv"
COLO_HOST="trace.example.com"  # cdn-cgi/trace 用的 CF 域名（probe.sh MTR colo 检测）

# 运行控制
CFST_LOCK=/run/lock/cfst.lock
SCAN_TIMEOUT=90           # 轻量扫描 cfst 最长运行秒数
SCAN_TIMEOUT_GRACE=10     # TERM 后强制 KILL 前的宽限秒数
DISCOVERY_TTL_HOURS=24    # 未经 VLESS 快筛验证的发现候选保留时长
# 队列周转必须快于 TTL，否则候选先过期再被筛到，算力白花。
# 周转 = (DISCOVERY_LIMIT / VLESS_SCREEN_MAX) * 2h（cycle.sh slow cron 轮距）。
# 旧值 300/20 → 30h > TTL 24h：实测 61 个录取里 22 个已因过期消失。
# 现 180/20 → 18h < 24h，留 6h 余量。由 test_segment_quality.py 的
# test_queue_turnover_is_faster_than_discovery_ttl 守住该不变式。
DISCOVERY_LIMIT=180       # 待快筛发现队列 FIFO 硬上限

MASTER_MIN_COVERAGE_PERCENT=80  # 池 audit 返回率低于该值时判 coverage 守卫轮（不淘汰）

# ── 网段级历史校准（A）：让发现门与准入门量同一个东西 ──
# 发现门 QUAL_LAT=70 量 cfst TCP 平均延迟；准入门 VLESS_ADMIT_TTFB=100 量
# 真实 VLESS TTFB。104.19 段两者差约 4 倍，于是平峰录取→拥塞拉黑→冷却过期
# →按 TCP 重新发现，闭环空转。实测该段 1271 个 IP、172 个曾单次达标、
# master 里 0 个，却占满队列 247/300。
# segment_quality.py 用 vless_history.tsv 的真实测量给 /24（优先）与 /16
# （兜底）定性，只拦明确 BAD 的段；样本不足或 history 缺失一律放行。
SEGMENT_CALIBRATION_ENABLED=1   # 1=启用发现阶段网段校准；0=完全旁路
SEGMENT_MIN_SAMPLES=50          # /16 定性所需最少测量样本，不足即放行
SEGMENT_MIN_IPS=8               # /16 定性所需最少 distinct IP，防单 IP 代表整段
# /24 用更低门槛：一个 /16 最多 65536 个 IP，一个 /24 只有 254 个，同一门槛
# 等于要求 /24 攒到 /16 级别证据才准定性。实测（7d 窗口）该缺陷让 32 个中位数
# 已超 150ms 的 /24 定不了性，被父 /16 的 GOOD 放行；其中 172.64.229 有 26 个
# distinct IP 全在 201ms。选 10/5 的依据：新捕获 BAD /24 由 18 增至 35，堵住
# 3 个 GOOD /16 内的泄漏段，而危险方向（BAD /16 内被 GOOD /24 误放行）为 0；
# 再放宽到 6/3 时该危险指标跳到 12，开始过拟合。
SEGMENT_MIN_SAMPLES_24=10       # /24 定性所需最少测量样本
SEGMENT_MIN_IPS_24=5            # /24 定性所需最少 distinct IP
SEGMENT_BAD_TTFB=150            # 段中位数超过该值判劣（对齐 VLESS_RETIRE_TTFB）
SEGMENT_GOOD_TTFB=100           # 段中位数不超过该值判优（对齐 VLESS_ADMIT_TTFB）
SEGMENT_WINDOW_DAYS=7           # 证据窗口天数（对齐 rank.py 7d 窗口）
# ── 判定持久化：打破证据自擦除 ──
# 上面的校准有一个负反馈缺陷：判定的判据来自被判定对象产生的观测。拦住一个段
# 后，该段不再被 screen 测量，不再产生新 history 行；而 SEGMENT_WINDOW_DAYS=7
# 恰好等于 verify_vless.sh 的 VLESS_HISTORY_DAYS=7，于是证据被 prune 时判定
# 一起消亡 → 段回落 UNKNOWN → 放行 → 空转闭环以 ~8 天为周期重启。
# 实测确认：拦截后 104.19 在 master/probation/best/discovered 全为 0，唯一测量
# 来源已切断；最后测量日 2026-09-15，证据将于 2026-09-22 被 prune。
# 修复：verdict 落盘 + 独立 TTL。live 证据永远覆盖 store（段真的改善时立刻
# 生效），store 只在证据被 prune 后接管；到期后释放该段重新证明自己的机会。
# TTL 取 30d 的依据：须严格长于 history 保留期 7d 才有意义（否则与证据同时
# 消亡）；30d ≈ 4 倍保留期，既能跨过整个 prune 周期，又保证被拦段每月有一次
# 重新评估窗口，避免永久封段且无重新纳入路径。成本 0 screen 预算。
SEGMENT_VERDICT_STORE="$CFST_DIR/segment_verdicts.tsv"
SEGMENT_VERDICT_TTL_DAYS=30      # 落盘判定寿命，须严格 > VLESS_HISTORY_DAYS

# ── 系统性劣化守卫（共因故障轮不转化为 IP 级处罚）──────────────────────
# 2026-08-26 04:00 实测：本地出口/上游整体劣化一轮，42 个 master 中 39 个 PASS
# 但 median 集中到 346-414ms，仅 3 个仍在 ~45ms。当轮把 40 条 ttfb_slow 记到
# 单个 IP 头上，并污染 37 个 non-master 候选的 24h 证据窗口；配合
# （历史）probation 阈值会在持续故障下批量拉黑；现由 rank.py 守卫轮不淘汰承担。
#
# 判据 = 本轮 master audit 的 PASS median p10（抗离群）。标定数据 8319 行 / 84 轮：
#   正常区间 min=43.0 p50=45.0 p90=47.0，次高轮 48.5；事件轮 380.0（分离度 7.8x）
#   80/100/120/150/200/250/300ms 全部只命中同一轮 → 判据极不敏感，150 取安全中点
# floor(最小值)不可用：事件轮 floor 仍是 45ms（3 个 IP 未受影响）。
# median 不可用：要半数劣化才动，太晚。p10 表达「连最快的一批都慢了」。
MASTER_SYSTEMIC_P10_MS=150       # 超过即判本轮为共因劣化（严格大于）
MASTER_SYSTEMIC_MIN_SAMPLES=10   # PASS 样本不足则 fail-open，照常处罚

# verify_vless.sh 默认输入位数（best_ips.txt 前 N 位 = 发布集 + 候补集）；不等于发布位数。
SCORE_TOP_N=5

# Watchdog（紧急切换）
WATCHDOG_MISS_THRESHOLD=3 # Top1 连续 N 次不可达触发 mini 验证
WATCHDOG_COOLDOWN=3600    # mini 验证冷却秒数（1h）
WATCHDOG_STATE="$CFST_DIR/.watchdog_state"

# Apply（发布落地）
# dns: 把发布集写成 dns_publish.py 里那个域名的 A 记录，节点地址不再变；
# misub: 旧路径，按 IP 改写 MiSub 节点 URL。
# 落地方式：misub（推 IP 到订阅，客户端零 DNS）| dns（写单个域名的 A 记录）| both（两条都落地）
# both 是 2026-11-24 起的选择：订阅拿 IP 走 MiSub，备用域名 cmcf 只写最好的那 1 个。
CFST_PUBLISH="${CFST_PUBLISH:-both}"
if [ -f "$CFST_DIR/.quality_evidence_enabled" ]; then
  CFST_QUALITY_EVIDENCE="${CFST_QUALITY_EVIDENCE:-1}"
fi
CFST_DNS_TOP_N="${CFST_DNS_TOP_N:-1}"   # DNS 只发布最好的前 N 个（默认 1，多一个就多一次客户端解析）
APPLY_COOLDOWN=3600       # 发布冷却秒数（1h）
APPLY_STATE="$CFST_DIR/.apply_state"

# ── 发布契约（P3.1 方案 C）────────────────────────────────────────────
# 评分给出 SCORE_TOP_N=5（发布集 + 候补集），但 MiSub 只发布前 PUBLISH_TOP_N 位。
# 变化检测必须只看**实际发布的位次**：rank4/rank5 抖动不代表用户可见节点变了，
# 按 SCORE_TOP_N 跟踪会导致候补集换位就重推一次（改 6 个节点 + 下游全量重订阅）。
# 必须与 push_to_misub.py 的 TOP_N 保持一致；tests/test_publish_contract.py 固化该等式。
PUBLISH_TOP_N=3           # 实际发布到 MiSub 的位数（= push_to_misub.py TOP_N）

# 发布集的单一真相源：apply.sh 写 .apply_state 与 run.sh 评分后比对都调用它。
# 历史上这段公式在 apply.sh 与 run.sh 各存一份拷贝，任一处漏改都会让两侧哈希
# 永久不等，run.sh 每轮 fail-closed exit 1（2026-08-24 实测过该故障）。
publish_set() {
  sed -n '/^# --- BEST_IPS/,$ { /^[0-9]/ p }' "$BEST" | head -n "$PUBLISH_TOP_N"
}

dns_preference() {
  if [ "${CFST_QUALITY_EVIDENCE:-0}" = "1" ] && [ "${CFST_DNS_TOP_N:-1}" = "1" ]; then
    local choice_file="${BEST%/*}/.dns_preference.json"
    if [ -f "$choice_file" ]; then
      python3 "$CFST_DIR/dns_selection.py" "$choice_file"
    fi
  fi
}

# 首行是可选 DNS 发布首选，其余行是同一份快照的有序发布集。
read_publish_targets() {
  local flags=()
  if [ "${CFST_QUALITY_EVIDENCE:-0}" != "1" ] || [ "${CFST_DNS_TOP_N:-1}" != "1" ] || [ "${CFST_PUBLISH:-both}" = "misub" ]; then
    flags+=(--ignore-preference)
  fi
  python3 "$CFST_DIR/publication_snapshot.py" targets "${BEST%/*}/.publish_desired.json" \
    --count "$PUBLISH_TOP_N" "${flags[@]}"
}

# 状态键 = 推送模板哈希 + 凭据哈希 + 有序发布集。
# 顺序参与哈希：push_to_misub 把 rank1/2/3 映射到 CM/CM2/CM3，换序就是换内容，不排序。
# 缺凭据时用 secret=missing 参与哈希，公式本身不 fail；fail-closed 由调用方决定。
# 节点 URL 的真正内容由地区模板决定：模板改动（换入口/换 padding）必须触发重新推送，
# 否则 apply 会以"状态未变"提前退出，订阅永远停在旧入口。
template_fingerprint() {
  local key var name
  for key in HK SG HT; do
    for var in KEY NAME_PREFIX QUERY SNI HOST PATH FP ALPN LEGACY_INSECURE_FLAGS AUDIT_KEY; do
      name="CFST_TEMPLATE_${key}_${var}"
      printf '%s=%s\n' "$name" "${!name}"
    done
  done
}

compute_apply_state() {
  local template_hash secret_file secret_hash preferred members
  if (( $# == 2 )); then
    preferred="$1"
    members="$2"
  else
    local targets
    targets=$(read_publish_targets) || return
    preferred=${targets%%$'\n'*}
    members=${targets#*$'\n'}
  fi
  template_hash=$(sha256sum "$CFST_DIR/push_to_misub.py" | awk '{print $1}')
  secret_file="${MISUB_TOKEN_FILE:-$CFST_DIR/secrets/misub.env}"
  if [ -f "$secret_file" ]; then
    secret_hash=$(sha256sum "$secret_file" | awk '{print $1}')
  else
    secret_hash=missing
  fi
  {
    # 落地方式参与状态：同内容换通道也算变更，否则切回时会被判"无变化"而跳过首次推送。
    printf 'publish=%s\n' "${CFST_PUBLISH:-both}"
    printf 'dns_top=%s\n' "${CFST_DNS_TOP_N:-1}"
    if [[ "${CFST_PUBLISH:-both}" != misub && -n "$preferred" && "$preferred" != "${members%%$'\n'*}" ]]; then
      printf 'dns_preference=%s\n' "$preferred"
    fi
    printf 'template=%s\n' "$template_hash"
    template_fingerprint
    printf 'secret=%s\n' "$secret_hash"
    if [ -n "$members" ]; then
      printf '%s\n' "$members"
    fi
  } | md5sum | cut -d' ' -f1
}

# ── 节点凭据：UUID 不入版本库，改由 0600 私密文件提供 ──────────────────
# 与 push_to_misub.py 的 get_misub_token() 同约定：限权文件 + *_FILE 路径覆盖。
VLESS_SECRET_FILE="${VLESS_SECRET_FILE:-$CFST_DIR/secrets/vless.env}"
VLESS_UUID=""
if [[ -f "$VLESS_SECRET_FILE" ]]; then
  _vless_mode=$(stat -c %a "$VLESS_SECRET_FILE" 2>/dev/null)
  if [[ -n "$_vless_mode" && $((8#$_vless_mode & 8#077)) -ne 0 ]]; then
    echo "cfst config: VLESS secret file must be 0600 or stricter: $VLESS_SECRET_FILE" >&2
  else
    VLESS_UUID=$(sed -n 's/^VLESS_UUID=//p' "$VLESS_SECRET_FILE" | tail -n1 | tr -d "\"'" )
  fi
  unset _vless_mode
else
  echo "cfst config: VLESS secret file missing: $VLESS_SECRET_FILE" >&2
fi

# 节点模板参数：config.sh 是唯一声明源；Shell 关联数组和 Python Region 均从这些无 secret 标量投影。
# 连接地址由待测 IP 注入。HK/SG/HT 是 CFST 当前自动管理的地区；JP 节点由手动订阅维护，不在 CFST 推送范围。
# QUERY 是该地区订阅节点的固定参数串（传输方式、padding 全在里面），推送时只替换 IP。
# AUDIT_KEY 指定用哪套 NODE 参数做可用性探测：探测只需同一批 IP 的链路质量，
# 目前只有 ws 端点可探测（SG），HK/HT 的 xhttp 参数只用于生成订阅节点。
CFST_TEMPLATE_HK_KEY=HK
CFST_TEMPLATE_HK_NAME_PREFIX="🇭🇰 HK Example"
# HK 入口：ws /argo?ed=2560 @ hksenior（2026-11-24 15:0x 换回；xhttp 入口已不通）
# argo xhttp 备用: encryption=none&security=tls&sni=hk-relay.example.com&fp=chrome&type=xhttp&host=hk-relay.example.com&path=%2Fargo&mode=auto&extra=%7B%22xPaddingObfsMode%22%3Atrue%2C%22xPaddingMethod%22%3A%22tokenish%22%2C%22xPaddingPlacement%22%3A%22queryInHeader%22%2C%22xPaddingHeader%22%3A%22X-Cache%22%2C%22xPaddingKey%22%3A%22_Luckylos%22%7D
CFST_TEMPLATE_HK_QUERY='encryption=none&security=tls&sni=hk-relay.example.com&fp=chrome&type=ws&host=hk-relay.example.com&path=%2Fargo%3Fed%3D2560'
CFST_TEMPLATE_HK_AUDIT_KEY=HK
CFST_TEMPLATE_HK_SNI="hk-relay.example.com"
CFST_TEMPLATE_HK_HOST="hk-relay.example.com"
CFST_TEMPLATE_HK_PATH="/argo?ed=2560"
CFST_TEMPLATE_HK_FP="chrome"
CFST_TEMPLATE_HK_ALPN=""
CFST_TEMPLATE_HK_LEGACY_INSECURE_FLAGS=0
CFST_TEMPLATE_SG_KEY=SG
CFST_TEMPLATE_SG_NAME_PREFIX="🇸🇬 SG Example"
CFST_TEMPLATE_SG_QUERY='encryption=none&security=tls&sni=sg-relay.example.com&fp=chrome&type=ws&host=sg-relay.example.com&path=%2Fargo%3Fed%3D2560&insecure=0&allowInsecure=0'
CFST_TEMPLATE_SG_AUDIT_KEY=SG
CFST_TEMPLATE_SG_SNI="sg-relay.example.com"
CFST_TEMPLATE_SG_HOST="sg-relay.example.com"
CFST_TEMPLATE_SG_PATH="/argo?ed=2560"
CFST_TEMPLATE_SG_FP="chrome"
CFST_TEMPLATE_SG_ALPN=""
CFST_TEMPLATE_SG_LEGACY_INSECURE_FLAGS=1
CFST_TEMPLATE_HT_KEY=HT
CFST_TEMPLATE_HT_NAME_PREFIX="🇭🇰 HT Example"
CFST_TEMPLATE_HT_QUERY='encryption=none&security=tls&sni=ht-relay.example.com&fp=chrome&insecure=0&allowInsecure=0&type=xhttp&host=ht-relay.example.com&path=%2Fargo&mode=auto&extra=%7B%22xPaddingObfsMode%22%3Atrue%2C%22xPaddingMethod%22%3A%22tokenish%22%2C%22xPaddingPlacement%22%3A%22queryInHeader%22%2C%22xPaddingHeader%22%3A%22X-Cache%22%2C%22xPaddingKey%22%3A%22_Luckylos%22%7D'
CFST_TEMPLATE_HT_AUDIT_KEY=SG
CFST_TEMPLATE_HT_SNI="ht-relay.example.com"
CFST_TEMPLATE_HT_HOST="ht-relay.example.com"
CFST_TEMPLATE_HT_PATH="/argo"
CFST_TEMPLATE_HT_FP="chrome"
CFST_TEMPLATE_HT_ALPN=""
CFST_TEMPLATE_HT_LEGACY_INSECURE_FLAGS=1

declare -A NODE_HK=(
  [key]="$CFST_TEMPLATE_HK_KEY"
  [sni]="$CFST_TEMPLATE_HK_SNI"
  [host]="$CFST_TEMPLATE_HK_HOST"
  [path]="$CFST_TEMPLATE_HK_PATH"
  [uuid]="$VLESS_UUID"
  [fp]="$CFST_TEMPLATE_HK_FP"
  [alpn]="$CFST_TEMPLATE_HK_ALPN"
  [prefix]="$CFST_TEMPLATE_HK_NAME_PREFIX"
  [legacy_insecure_flags]="$CFST_TEMPLATE_HK_LEGACY_INSECURE_FLAGS"
  [query]="$CFST_TEMPLATE_HK_QUERY"
)
declare -A NODE_SG=(
  [key]="$CFST_TEMPLATE_SG_KEY"
  [sni]="$CFST_TEMPLATE_SG_SNI"
  [host]="$CFST_TEMPLATE_SG_HOST"
  [path]="$CFST_TEMPLATE_SG_PATH"
  [uuid]="$VLESS_UUID"
  [fp]="$CFST_TEMPLATE_SG_FP"
  [alpn]="$CFST_TEMPLATE_SG_ALPN"
  [prefix]="$CFST_TEMPLATE_SG_NAME_PREFIX"
  [legacy_insecure_flags]="$CFST_TEMPLATE_SG_LEGACY_INSECURE_FLAGS"
  [query]="$CFST_TEMPLATE_SG_QUERY"
)
declare -A NODE_HT=(
  [key]="$CFST_TEMPLATE_HT_KEY"
  [sni]="$CFST_TEMPLATE_HT_SNI"
  [host]="$CFST_TEMPLATE_HT_HOST"
  [path]="$CFST_TEMPLATE_HT_PATH"
  [uuid]="$VLESS_UUID"
  [fp]="$CFST_TEMPLATE_HT_FP"
  [alpn]="$CFST_TEMPLATE_HT_ALPN"
  [prefix]="$CFST_TEMPLATE_HT_NAME_PREFIX"
  [legacy_insecure_flags]="$CFST_TEMPLATE_HT_LEGACY_INSECURE_FLAGS"
  [query]="$CFST_TEMPLATE_HT_QUERY"
)
