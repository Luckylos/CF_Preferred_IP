#!/bin/bash
# 高频 TCP 延迟发现：每次仅做握手探测；发现的陌生低延迟 IP 入 24h 队列。
# 发现与准入module维护队列；快筛通过且池有空位才进入候选池。
#
# discovered_ips.tsv 字段契约（P2.0 起为 4 列）：
#   1 首次发现时间  2 IP  3 快筛连续失败次数  4 发现时 TCP 平均延迟(ms)
# 第 4 列来自 cfst CSV 第 5 列「平均延迟」，供阈值标定使用；队列超限保留较新记录。
# 历史 2/3 列行仍可读，延迟留空表示未采集。
set -euo pipefail
source "$(dirname "$0")/config.sh"

cd "$CFST_DIR"
# 沙箱/旧 config.sh 可能未定义 CONTENDERS；默认路径与 config.sh 一致。
CONTENDERS="${CONTENDERS:-$CFST_DIR/contenders.tsv}"
exec 9>"$CFST_LOCK"
flock -n 9 || exit 0

TARGET=$(mktemp "$RESULT_DIR/.lat_target.XXXXXX")
OUT=$(mktemp "$RESULT_DIR/.lat_scan.XXXXXX.csv")
QUEUE_TMP=$(mktemp "$RESULT_DIR/.discovered.XXXXXX")
MASTER_SET=$(mktemp "$RESULT_DIR/.lat_master.XXXXXX")
BLACKLIST_SET=$(mktemp "$RESULT_DIR/.lat_blacklist.XXXXXX")
SEG_RAW=$(mktemp "$RESULT_DIR/.lat_segraw.XXXXXX")
SEG_KEPT=$(mktemp "$RESULT_DIR/.lat_segkept.XXXXXX")
trap 'rm -f "$TARGET" "$OUT" "$QUEUE_TMP" "$MASTER_SET" "$BLACKLIST_SET" "$SEG_RAW" "$SEG_KEPT"' EXIT

# 队列规则由发现与准入module统一维护；保留本次整理时钟，避免测速后移动TTL边界。
QUEUE_NOW=$(date '+%F %T')
QUEUE_COUNTS=$(python3 "$CFST_DIR/admission.py" maintain --queue "$DISCOVERED" \
  --now "$QUEUE_NOW" --ttl-hours "$DISCOVERY_TTL_HOURS" --limit "$DISCOVERY_LIMIT" \
  --targets "$QUEUE_TMP")

# 目标集：contenders（单池，在用）+ master（过渡期）+ 发现队列（待筛）+ ip_ranges.txt 全部网段，每轮全量。
# 不分片：实测下载测速才是耗时来源（见下方 -dd），延迟测速阶段全量仅约 13.5s，
# 是 SCAN_TIMEOUT=90 的 1/6.6。分片反而会把全量覆盖周期拖到 4 轮 20 分钟，
# 拖慢 discovered_ips.tsv 第 4 列延迟数据的积累。
{
  if [ -f "$CONTENDERS" ]; then
    awk -F'\t' '$1 !~ /^[[:space:]]*#/ && $1 != "" {print $1}' "$CONTENDERS" \
      | python3 "$CFST_DIR/ip_validation.py" --filter || true
  fi
  grep -vE '^[[:space:]]*(#|$)' "$MASTER" 2>/dev/null | awk '{print $1}' \
    | python3 "$CFST_DIR/ip_validation.py" --filter || true
  cat "$QUEUE_TMP"
  grep -vE '^[[:space:]]*(#|$)' "$SCAN" 2>/dev/null \
    | python3 "$CFST_DIR/ip_validation.py" --filter-network || true
} | awk '!seen[$0]++' > "$TARGET"
TARGET_COUNT=$(awk 'END {print NR + 0}' "$TARGET")

# -dd 而非 -dn 0：-dn 是「下载测速数量」，-dd 才是「禁用下载测速」。传 -dn 0 会落回
# 默认队列 10 个 IP，每个最长 -dt 10 秒 —— 实测全量 113.4s、单网段 83~100s，直接撞满
# SCAN_TIMEOUT=90（同目标集改 -dd 后 13.5s）。本脚本只用 CSV 第 5 列平均延迟，
# 下载测速的产出从未被消费。注意 -dd 下结果按延迟排序，第 6 列速度值为空。
set +e
timeout --signal=TERM --kill-after="${SCAN_TIMEOUT_GRACE}s" "${SCAN_TIMEOUT}s" \
  setpriv --regid "$BYPASS_GID" --clear-groups ./cfst \
    -f "$TARGET" \
    -n 500 \
    -t 4 \
    -tp 443 \
    -tl "$QUAL_LAT" \
    -dd \
    -o "$OUT" \
    > /dev/null 2>&1
RC=$?
set -e

if [ "$RC" -eq 124 ]; then
  # 区分 partial 与 dead：超时但已有输出的轮次，其结果仍然有效，
  # 旧实现一律 exit 0 丢弃，等于把已完成的探测白扔。
  if [ -s "$OUT" ]; then
    PARTIAL_ROWS=$(awk 'END {print NR > 0 ? NR - 1 : 0}' "$OUT")
    echo "[$(date '+%F %T')] latency scan: timeout after ${SCAN_TIMEOUT}s (partial: targets=${TARGET_COUNT} rows=${PARTIAL_ROWS}) — keeping results"
  else
    echo "[$(date '+%F %T')] latency scan: timeout after ${SCAN_TIMEOUT}s (dead: targets=${TARGET_COUNT} rows=0)"
    exit 0
  fi
fi
if [ "$RC" -ne 0 ] && [ "$RC" -ne 124 ]; then
  echo "[$(date '+%F %T')] latency scan: cfst failed (exit=$RC)" >&2
  exit "$RC"
fi
if [ ! -s "$OUT" ]; then
  echo "[$(date '+%F %T')] latency scan: cfst 无输出"
  exit 0
fi

# 已知 IP 集（排除集）：contenders.tsv 第 1 列（2026-10-15 单池重构）∪ master_ips.txt
# （过渡期：切换后 master 改名 .legacy 即自然消失）。两者均经 ip_validation.py --filter，
# 缺文件/空文件不报错。结果写入 $1（每行一个 IPv4，可重复，调用方按集合读）。
known_ip_set() {
  local out="${1:?known set path required}"
  : > "$out"
  if [ -f "$CONTENDERS" ]; then
    awk -F'\t' '$1 !~ /^[[:space:]]*#/ && $1 != "" {print $1}' "$CONTENDERS" \
      | python3 "$CFST_DIR/ip_validation.py" --filter >> "$out" || true
  fi
  if [ -f "$MASTER" ]; then
    grep -vE '^[[:space:]]*(#|$)' "$MASTER" 2>/dev/null | awk '{print $1}' \
      | python3 "$CFST_DIR/ip_validation.py" --filter >> "$out" || true
  fi
}

# 仅把 contenders/master 中尚不存在的低延迟 IP 作为“待快筛验证”发现项。
NOW=$(date '+%F %T')
known_ip_set "$MASTER_SET"
python3 "$CFST_DIR/cooldown.py" --quality "$SCREEN_BLACKLIST" \
  --capacity "${CAPACITY_COOLDOWN:-$CFST_DIR/.capacity_cooldown.tsv}" \
  --quality-hours "${SCREEN_BLACKLIST_HOURS:-24}" --capacity-hours "${CAPACITY_COOLDOWN_HOURS:-6}" \
  --now "$NOW" > "$BLACKLIST_SET"
# cfst CSV 列：1 IP,2 已发送,3 已接收,4 丢包率,5 平均延迟,6 下载速度,7 地区码
# 保留第 5 列平均延迟，供 P2 的阈值标定与质量排序使用。
NEW=$(awk -F, -v L="$QUAL_LAT" -v OFS='\t' \
        'NR > 1 && $5 + 0 > 0 && $5 + 0 < L {print $1, $5}' "$OUT" \
  | python3 "$CFST_DIR/ip_validation.py" --filter --field 1 \
  | awk -F'\t' -v OFS='\t' -v master="$MASTER_SET" -v blacklist="$BLACKLIST_SET" '
      BEGIN {
        while ((getline line < master) > 0) {
          if (line != "") known[line]=1
        }
        close(master)
        while ((getline line < blacklist) > 0) {
          if (line != "") black[line]=1
        }
        close(blacklist)
      }
      !known[$1] && !black[$1] && !seen[$1]++ {print $1, $2}
    ')

# ── 网段校准（A）：按真实 VLESS TTFB 历史剔除结构性不达标的段 ──
# 发现门 QUAL_LAT 量的是 cfst TCP 平均延迟，准入门 VLESS_ADMIT_TTFB 量的是
# 真实 VLESS TTFB。104.19 段两者差约 4 倍，导致「平峰录取→拥塞拉黑→冷却
# 过期→按 TCP 重新发现」的闭环空转，占满队列 247/300 却零沉淀。
#
# 只作用于本轮「新发现」：已在队列的候选不追溯剔除，避免判定变动清空队列。
# 落盘到临时文件再过滤，不用管道 —— 管道里 `|| cat` 是假回退：过滤器中途
# 失败时 stdin 已被消费，cat 只能拿到残余，等于静默丢数据。两步式保证回退
# 拿到的是完整原始集合。
# 先刷新判定 store，再过滤。刷新不依赖「本轮是否有新发现」：空发现轮同样要
# 确认 live 判定、清理到期项，否则 store 会停在旧判定上，段改善后永不解封。
# 判定 store 打破证据自擦除 —— 拦住一个段会切断它的测量来源，7d 后证据被
# prune、判定随之消亡、该段重新入队，闭环以 ~8 天为周期重启。store 让判定
# 寿命（30d）长于证据寿命（7d），到期才释放该段重新证明自己。
if [ "${SEGMENT_CALIBRATION_ENABLED:-0}" = "1" ] \
     && [ -f "$CFST_DIR/segment_quality.py" ] \
     && [ -n "${SEGMENT_VERDICT_STORE:-}" ]; then
  if SEG_REFRESH=$(python3 "$CFST_DIR/segment_quality.py" refresh \
       --history "${VLESS_HISTORY:-$CFST_DIR/vless_history.tsv}" \
       --verdict-store "$SEGMENT_VERDICT_STORE" \
       --verdict-ttl-days "${SEGMENT_VERDICT_TTL_DAYS:-30}" \
       --min-samples "${SEGMENT_MIN_SAMPLES:-50}" \
       --min-ips "${SEGMENT_MIN_IPS:-8}" \
       --min-samples-24 "${SEGMENT_MIN_SAMPLES_24:-10}" \
       --min-ips-24 "${SEGMENT_MIN_IPS_24:-5}" \
       --bad-ttfb "${SEGMENT_BAD_TTFB:-150}" \
       --good-ttfb "${SEGMENT_GOOD_TTFB:-100}" \
       --window-days "${SEGMENT_WINDOW_DAYS:-7}" 2>/dev/null)
  then
    echo "[$(date '+%F %T')] $SEG_REFRESH"
  else
    # store 刷新失败不影响过滤：filter 仍按 live 证据工作（fail-open）。
    echo "[$(date '+%F %T')] verdict store refresh failed (非致命)" >&2
  fi
fi

if [ -n "$NEW" ] && [ "${SEGMENT_CALIBRATION_ENABLED:-0}" = "1" ] \
     && [ -f "$CFST_DIR/segment_quality.py" ]; then
  printf '%s\n' "$NEW" > "$SEG_RAW"
  if python3 "$CFST_DIR/segment_quality.py" filter \
       --history "${VLESS_HISTORY:-$CFST_DIR/vless_history.tsv}" \
       --field 1 \
       --verdict-store "${SEGMENT_VERDICT_STORE:-/nonexistent}" \
       --verdict-ttl-days "${SEGMENT_VERDICT_TTL_DAYS:-30}" \
       --min-samples "${SEGMENT_MIN_SAMPLES:-50}" \
       --min-ips "${SEGMENT_MIN_IPS:-8}" \
       --min-samples-24 "${SEGMENT_MIN_SAMPLES_24:-10}" \
       --min-ips-24 "${SEGMENT_MIN_IPS_24:-5}" \
       --bad-ttfb "${SEGMENT_BAD_TTFB:-150}" \
       --good-ttfb "${SEGMENT_GOOD_TTFB:-100}" \
       --window-days "${SEGMENT_WINDOW_DAYS:-7}" \
       < "$SEG_RAW" > "$SEG_KEPT" 2>/dev/null
  then
    RAW_N=$(sed '/^$/d' "$SEG_RAW" | wc -l)
    KEPT_N=$(sed '/^$/d' "$SEG_KEPT" | wc -l)
    NEW=$(cat "$SEG_KEPT")
    if (( RAW_N > KEPT_N )); then
      echo "[$(date '+%F %T')] segment calibration: discovered=$RAW_N kept=$KEPT_N dropped=$((RAW_N - KEPT_N)) (bad-segment候选未入队)"
    fi
  else
    # 校准器故障：保留未过滤的完整 NEW，绝不因校准断供。
    echo "[$(date '+%F %T')] segment calibration failed (非致命，本轮不过滤)" >&2
  fi
fi

if [ -n "$NEW" ]; then
  printf '%s\n' "$NEW" > "$SEG_RAW"
  QUEUE_COUNTS=$(python3 "$CFST_DIR/admission.py" maintain --queue "$DISCOVERED" \
    --now "$QUEUE_NOW" --ttl-hours "$DISCOVERY_TTL_HOURS" --limit "$DISCOVERY_LIMIT" \
    --incoming "$SEG_RAW" --discovered-at "$NOW")
fi

read -r DISCOVERED_COUNT LAT_COVERED <<< "$QUEUE_COUNTS"
NEW_COUNT=$(printf '%s\n' "$NEW" | sed '/^$/d' | wc -l)
echo "[$NOW] latency scan: targets=${TARGET_COUNT} discovered=$NEW_COUNT queued=$DISCOVERED_COUNT lat_covered=$LAT_COVERED"

# ── Watchdog: 检测当前 Top1 是否可达 ──
flock -u 9  # 释放锁再跑 watchdog，避免阻塞下一轮
if [ -x "$CFST_DIR/watchdog.sh" ]; then
  "$CFST_DIR/watchdog.sh" || true
fi


