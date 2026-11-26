#!/bin/bash
# verify_vless.sh — VLESS 真实链路验证门控（并行版）
# 对指定 IP 列表启动临时 xray 进程，通过完整 VLESS+WS+TLS 链路
# 测量 TTFB，淘汰不达标 IP。使用 BYPASS_GID 绕过 TUN 直连 CF edge。
#
# 用法：
#   ./verify_vless.sh              # 默认验证 best_ips.txt 的 BEST_IPS 段
#   ./verify_vless.sh --audit FILE # 全量审计指定文件中所有 IP，只报告不改写
set -euo pipefail
source "$(dirname "$0")/config.sh"

cd "$CFST_DIR"
exec 8>"$CFST_DIR/.verify_vless.lock"
flock -n 8 || {
  echo "[$(date '+%F %T')] verify_vless: another verification is already running" >&2
  exit 75
}

# ── 参数解析 ──
AUDIT_MODE=false
SCREEN_MODE=false
INPUT_FILE=""
SCREEN_OUT=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --audit) AUDIT_MODE=true; INPUT_FILE="$2"; shift 2 ;;
    --screen) SCREEN_MODE=true; INPUT_FILE="$2"; SCREEN_OUT="$3"; shift 3 ;;
    *) INPUT_FILE="$1"; shift ;;
  esac
done

# ── 配置 ──
XRAY_BIN="$CFST_DIR/bin/xray"
VLESS_HISTORY="${VLESS_HISTORY:-$CFST_DIR/vless_history.tsv}"
VLESS_HISTORY_DAYS=${VLESS_HISTORY_DAYS:-7}
VLESS_VERIFY_TIMEOUT=${VLESS_VERIFY_TIMEOUT:-5}    # 单次 curl 超时（秒）
VLESS_MAX_TTFB=${VLESS_MAX_TTFB:-500}             # 门控阈值（毫秒，fail-safe 而非质量目标）
VLESS_ADMIT_TTFB=${VLESS_ADMIT_TTFB:-100}         # 快筛准入 TTFB 上限（毫秒，入 master 前的体感门控）
if [[ "$SCREEN_MODE" == true ]]; then
  # config.sh 提供常规基线；run.sh 通过独立环境变量覆盖 screen，避免 source 顺序吞掉时段门槛。
  VLESS_ADMIT_TTFB="${VLESS_SCREEN_ADMIT_TTFB:-$VLESS_ADMIT_TTFB}"
fi
VLESS_TRIES=${VLESS_TRIES:-3}                      # 每个 IP 测试次数
VLESS_TEMPLATE=${VLESS_TEMPLATE:-HK}
case "$VLESS_TEMPLATE" in
  HK) VLESS_NODE="NODE_HK" ;;
  SG) VLESS_NODE="NODE_SG" ;;
  HT) VLESS_NODE="NODE_HT" ;;
  *)
    echo "verify_vless: unsupported VLESS_TEMPLATE=$VLESS_TEMPLATE (expected HK, SG or HT)" >&2
    exit 2
    ;;
esac
declare -n VLESS_REF="$VLESS_NODE"
VLESS_HOST="${VLESS_REF[host]}"
VLESS_PATH="${VLESS_REF[path]}"
VLESS_UUID="${VLESS_REF[uuid]}"
VLESS_FP="${VLESS_REF[fp]}"
VLESS_QUERY="${VLESS_REF[query]:-}"
unset -n VLESS_REF
# 推送 preflight 会带上节点自己那份凭据与参数（HT 与 HK/SG 的 uuid 不同）。
VLESS_UUID="${VLESS_TEMPLATE_UUID:-$VLESS_UUID}"
VLESS_QUERY="${VLESS_TEMPLATE_QUERY:-$VLESS_QUERY}"
# 探测必须与用户实际使用的传输一致：ws / xhttp 由模板 QUERY 决定，不在此处写死。
if [[ -n "$VLESS_QUERY" ]]; then
  STREAM_SETTINGS=$(python3 "$CFST_DIR/vless_template.py" --query "$VLESS_QUERY") || {
    echo "verify_vless: 无法从 QUERY 解析传输配置（$VLESS_TEMPLATE）" >&2
    exit 2
  }
else
  # 旧配置只有 host/path/fp 时按 ws 建链，保持向后兼容。
  STREAM_SETTINGS=$(python3 "$CFST_DIR/vless_template.py" --ws-host "$VLESS_HOST" --ws-path "$VLESS_PATH" --ws-fp "$VLESS_FP") || exit 2
fi
if [[ -z "$VLESS_UUID" ]]; then
  echo "verify_vless: VLESS_UUID 不可用（检查 $VLESS_SECRET_FILE）；拒绝以空凭据探测，避免误判退役" >&2
  exit 2
fi
VLESS_VERIFY_URL="https://${VLESS_HOST}/cdn-cgi/trace"
BASE_PORT=41000
REQUESTED_BATCH_SIZE=${VLESS_BATCH_SIZE:-2}
if ! [[ "$REQUESTED_BATCH_SIZE" =~ ^[1-9][0-9]*$ ]]; then
  echo "verify_vless: invalid VLESS_BATCH_SIZE=$REQUESTED_BATCH_SIZE" >&2
  exit 2
fi
# Hard ceiling: an operator/env typo must not restore the old 10-way burst.
if (( REQUESTED_BATCH_SIZE > 2 )); then
  echo "verify_vless: VLESS_BATCH_SIZE=$REQUESTED_BATCH_SIZE exceeds hard cap 2; clamped" >&2
  BATCH_SIZE=2
else
  BATCH_SIZE=$REQUESTED_BATCH_SIZE
fi
TERM_GRACE_SECONDS=${VLESS_TERM_GRACE_SECONDS:-2}
KILL_GRACE_SECONDS=${VLESS_KILL_GRACE_SECONDS:-2}

if [ ! -x "$XRAY_BIN" ]; then
  echo "[$(date '+%F %T')] verify_vless: xray binary not found at $XRAY_BIN" >&2
  exit 0
fi

# ── 读取 IP 列表 ──
if $AUDIT_MODE && [ -n "$INPUT_FILE" ]; then
  # 审计模式：读取文件中所有非注释非空行
  mapfile -t ALL_IPS < <(
    grep -E '^[0-9]' "$INPUT_FILE" | python3 "$CFST_DIR/ip_validation.py" --filter | awk '!seen[$0]++'
  )
elif [ -n "$INPUT_FILE" ]; then
  mapfile -t ALL_IPS < <(
    grep -E '^[0-9]' "$INPUT_FILE" | python3 "$CFST_DIR/ip_validation.py" --filter
  )
else
  # 默认：best_ips.txt BEST_IPS 段
  mapfile -t ALL_IPS < <(
    sed -n '/^# --- BEST_IPS/,$ { /^[0-9]/ p }' "$BEST" \
      | python3 "$CFST_DIR/ip_validation.py" --filter \
      | head -n "$SCORE_TOP_N"
  )
fi

if (( ${#ALL_IPS[@]} == 0 )); then
  echo "[$(date '+%F %T')] verify_vless: no IPs to verify" >&2
  exit 0
fi

# xray 配置含 VLESS UUID，放 tmpfs 且仅 owner 可读（历史上是 0644 的落盘文件）。
mkdir -p "$VERIFY_TMPDIR_BASE"
chmod 700 "$VERIFY_TMPDIR_BASE"
# 兜底回收：SIGKILL/OOM/断电不会触发 trap，含 UUID 的 verify 目录会滞留 tmpfs 直到重启。
# 只清理本脚本自己的命名空间，且只删超过 3 小时的（一次运行最长约 11 分钟）。
find "$VERIFY_TMPDIR_BASE" -maxdepth 1 -mindepth 1 -type d -name 'verify.*' -mmin +180 -exec rm -rf {} + 2>/dev/null || true
TMPDIR_VERIFY=$(mktemp -d "$VERIFY_TMPDIR_BASE/verify.XXXXXX")
chmod 700 "$TMPDIR_VERIFY"
OBS_INPUT="$TMPDIR_VERIFY/observations"
REFERENCE_KEY=""
if $AUDIT_MODE && [ -n "${VLESS_REFERENCE_OUT:-}" ] && [ -z "${VLESS_NO_RECORD:-}" ]; then
  REFERENCE_KEY=$(printf '%s\0' "$VLESS_TEMPLATE" "$STREAM_SETTINGS" "$VLESS_VERIFY_URL" \
    "$BYPASS_GID" "$VLESS_VERIFY_TIMEOUT" "$VLESS_TRIES" | python3 "$CFST_DIR/quality_evidence.py" reference)
  if [ -n "${VLESS_AUDIT_RUN:-}" ]; then
    python3 "$CFST_DIR/audit_evidence.py" bind "$VLESS_REFERENCE_OUT" \
      "$VLESS_AUDIT_RUN" "$REFERENCE_KEY" "${ALL_IPS[@]}"
  fi
fi
PIDS=()
PGIDS=()

proc_group_alive() {
  local pgid="$1"
  ps -eo pgid=,stat= 2>/dev/null | awk -v g="$pgid" '$1 == g && $2 !~ /^Z/ { found=1 } END { exit(found ? 0 : 1) }'
}

find_xray_group() {
  local config="$1"
  ps -eo pid=,pgid=,args= 2>/dev/null \
    | awk -v cfg="$config" 'index($0, cfg) && $0 ~ /\/xray([[:space:]]|$)/ {print $1 " " $2; exit}'
}

cleanup_batch_processes() {
  local pgid pid deadline
  [ "${#PGIDS[@]}" -gt 0 ] || return 0

  # Signal process groups, not just the xray leaders: xray may have descendants,
  # and the parent shell can disappear before this EXIT trap runs.
  for pgid in "${PGIDS[@]}"; do
    [ -n "$pgid" ] || continue
    kill -TERM -- "-$pgid" 2>/dev/null || true
  done
  deadline=$((SECONDS + TERM_GRACE_SECONDS))
  while (( SECONDS < deadline )); do
    local any_alive=false
    for pgid in "${PGIDS[@]}"; do
      if [ -n "$pgid" ] && proc_group_alive "$pgid"; then any_alive=true; break; fi
    done
    $any_alive || break
    sleep 0.1
  done
  for pgid in "${PGIDS[@]}"; do
    [ -n "$pgid" ] && proc_group_alive "$pgid" && kill -KILL -- "-$pgid" 2>/dev/null || true
  done
  deadline=$((SECONDS + KILL_GRACE_SECONDS))
  while (( SECONDS < deadline )); do
    local any_alive=false
    for pgid in "${PGIDS[@]}"; do
      if [ -n "$pgid" ] && proc_group_alive "$pgid"; then any_alive=true; break; fi
    done
    $any_alive || break
    sleep 0.1
  done
  for pid in "${PIDS[@]}"; do
    wait "$pid" 2>/dev/null || true
  done
  PIDS=()
  PGIDS=()
}

cleanup_all() {
  cleanup_batch_processes
  # A launcher can be interrupted before its xray row is registered in PGIDS;
  # remove only operation-owned xray processes whose config lives in our temp dir.
  if [ -d "${TMPDIR_VERIFY:-}" ]; then
    local -a orphan_pgids=()
    while read -r pid pgid; do
      [ -n "${pid:-}" ] || continue
      orphan_pgids+=("$pgid")
    done < <(ps -eo pid=,pgid=,args= 2>/dev/null | awk -v d="$TMPDIR_VERIFY/" 'index($0,d) && $0 ~ /\/xray([[:space:]]|$)/ {print $1 " " $2}')
    for pgid in "${orphan_pgids[@]}"; do
      kill -TERM -- "-$pgid" 2>/dev/null || true
    done
    sleep 0.2
    for pgid in "${orphan_pgids[@]}"; do
      proc_group_alive "$pgid" && kill -KILL -- "-$pgid" 2>/dev/null || true
    done
  fi
  rm -rf "$TMPDIR_VERIFY"
}

on_signal() {
  local exit_code="$1"
  cleanup_all
  exit "$exit_code"
}

trap cleanup_all EXIT
trap 'on_signal 129' HUP
trap 'on_signal 130' INT
trap 'on_signal 143' TERM

# Temporary files are removed only after every owned process group is reaped.


# ── 结果收集 ──
declare -A RESULTS  # ip -> "PASS|FAIL|PARTIAL median_ms [reason]"

declare -a HISTORY_BUFFER=()

append_vless_history() {
  local ip="$1"
  local status="$2"   # PASS|FAIL|PARTIAL
  local median="$3"   # ms
  local reason="${4:-}"
  local ts
  ts=$(date '+%F %T')
  HISTORY_BUFFER+=("$(printf '%s\t%s\t%s\t%s\t%s' "$ts" "$ip" "$status" "$median" "$reason")")
}

# 写盘前统一裁决：一次运行里 IP 全部死在传输层（timeout/xray 起不来），
# 那是入口不可用，不是这些 IP 的证据；记进去会冤枉一池子好 IP。
flush_vless_history() {
  local total=${#HISTORY_BUFFER[@]}
  [ "$total" -gt 0 ] || return 0
  if [ -n "${VLESS_NO_RECORD:-}" ]; then
    echo "verify_vless: VLESS_NO_RECORD set; $total record(s) discarded" >&2
    HISTORY_BUFFER=()
    return 0
  fi
  if [ "$total" -ge 5 ]; then
    local transport=0 row reason
    for row in "${HISTORY_BUFFER[@]}"; do
      reason="${row##*$'\t'}"
      case "$reason" in
        timeout|xray_start_failed) (( transport++ )) || true ;;
      esac
    done
    if [ "$transport" -eq "$total" ]; then
      echo "verify_vless: all $total IPs failed at the transport layer; entry looks unavailable — discarding this run instead of blaming the IPs" >&2
      HISTORY_BUFFER=()
      return 0
    fi
  fi
  printf '%s\n' "${HISTORY_BUFFER[@]}" >> "$VLESS_HISTORY"
  HISTORY_BUFFER=()
}

prune_vless_history() {
  [ -s "$VLESS_HISTORY" ] || return 0
  local cutoff
  cutoff=$(date -d "${VLESS_HISTORY_DAYS} days ago" '+%F %T' 2>/dev/null || true)
  [ -n "$cutoff" ] || return 0
  awk -F'\t' -v cutoff="$cutoff" 'NF>=3 && $1 >= cutoff' "$VLESS_HISTORY" > "$VLESS_HISTORY.tmp" \
    && mv "$VLESS_HISTORY.tmp" "$VLESS_HISTORY"
}

verify_batch() {
  local -n batch_ips=$1
  local batch_offset=$2
  local -a ports=()

  # 启动本批次所有 xray 实例；每个实例独立 session/process group。
  for (( j=0; j<${#batch_ips[@]}; j++ )); do
    local ip="${batch_ips[$j]}"
    local slot=$(( batch_offset + j ))
    local port=$(( BASE_PORT + slot ))
    local config="$TMPDIR_VERIFY/xray_${slot}.json"
    ports+=("$port")

    # 该文件含 VLESS UUID。先建成 0600 再写入，避免默认 umask 留下 0644 窗口。
    : > "$config"
    chmod 600 "$config"
    cat > "$config" <<EOF
{
  "log": {"loglevel": "none"},
  "inbounds": [{"listen": "127.0.0.1", "port": ${port}, "protocol": "http", "settings": {}}],
  "outbounds": [{"protocol": "vless", "settings": {"vnext": [{"address": "${ip}", "port": 443, "users": [{"id": "${VLESS_UUID}", "encryption": "none"}]}]}, "streamSettings": $STREAM_SETTINGS}]
}
EOF

    setsid --wait -- \
      setpriv --pdeathsig TERM --regid "$BYPASS_GID" --clear-groups \
        "$XRAY_BIN" run -c "$config" >/dev/null 2>&1 &
    local pid=$!
    local pgid=""
    # setsid --wait may exec the target, so the background PID can become the
    # xray PID; resolve the final xray PGID instead of trusting the transient
    # setsid/launcher process.
    for (( pg_try=0; pg_try<40; pg_try++ )); do
      local group_row
      group_row=$(find_xray_group "$config" || true)
      if [ -n "$group_row" ]; then
        pid=${group_row%% *}
        pgid=${group_row#* }
        break
      fi
      sleep 0.05
    done
    if [ -z "$pgid" ]; then
      echo "verify_vless: failed to determine xray process group for config=$config" >&2
      pgid=$(ps -o pgid= -p "$pid" 2>/dev/null | tr -d ' ' || true)
      [ -n "$pgid" ] || pgid="$pid"
    fi
    PIDS+=("$pid")
    PGIDS+=("$pgid")
  done

  # 等待所有端口就绪（最多 3s）
  local ready=0
  for (( w=0; w<30; w++ )); do
    ready=0
    for port in "${ports[@]}"; do
      if ss -tlnp 2>/dev/null | grep -q ":${port} "; then
        (( ready++ )) || true
      fi
    done
    if (( ready == ${#ports[@]} )); then
      break
    fi
    sleep 0.1
  done

  # 对每个 IP 做延迟测量
  for (( j=0; j<${#batch_ips[@]}; j++ )); do
    local ip="${batch_ips[$j]}"
    local port="${ports[$j]}"
    local proxy="http://127.0.0.1:${port}"

    # 检查该端口是否就绪
    if ! ss -tlnp 2>/dev/null | grep -q ":${port} "; then
      RESULTS["$ip"]="FAIL 0 (xray_start_failed)"
      append_vless_history "$ip" "FAIL" "0" "xray_start_failed"
      if [ -n "$REFERENCE_KEY" ]; then
        printf '%s\t%s\txray_start_failed\n' "$(date '+%FT%T')" "$ip" >> "$OBS_INPUT"
      fi
      continue
    fi

    # 单 curl 进程多 URL：第 1 个预热，后续取 TTFB
    local urls_args=("$VLESS_VERIFY_URL" -o /dev/null)
    for (( t=0; t<VLESS_TRIES; t++ )); do
      urls_args+=("$VLESS_VERIFY_URL" -o /dev/null)
    done

    local raw_output curl_rc observed_at
    observed_at=$(date '+%FT%T')
    if raw_output=$(curl -s \
      --proxy "$proxy" \
      --connect-timeout "$VLESS_VERIFY_TIMEOUT" \
      --max-time $(( VLESS_VERIFY_TIMEOUT * (VLESS_TRIES + 1) )) \
      "${urls_args[@]}" \
      -w '%{urlnum}\t%{http_code}\t%{time_starttransfer}\t%{exitcode}\n' 2>/dev/null
    ); then
      curl_rc=0
    else
      curl_rc=$?
    fi

    if [ -n "$REFERENCE_KEY" ]; then
      printf '%s\t%s\t%s\n' "$observed_at" "$ip" "${raw_output//$'\n'/|}" >> "$OBS_INPUT"
    fi
    local structured=false first_line="${raw_output%%$'\n'*}"
    if [[ "$first_line" == *$'\t'*$'\t'*$'\t'* ]]; then
      structured=true
    fi
    # 只有 2xx 才算成功样本；非 2xx 的正 TTFB 仍可证明链路可测，
    # 因而归入 slow/fail 而不是 unreachable。
    local ttfbs=()
    local timeouts=0
    local successful_samples=0
    local http_failures=()
    local attempts_seen=0
    local line_num=0
    while IFS= read -r line; do
      [ -z "$line" ] && continue
      (( line_num++ )) || true
      if $structured; then
        local transfer_index="${line%%$'\t'*}" transfer_rc="${line##*$'\t'}"
        [[ "$transfer_index" =~ ^[0-9]+$ ]] || continue
        (( transfer_index == 0 || transfer_index > VLESS_TRIES )) && continue
        line="${line#*$'\t'}"
        line="${line%$'\t'*}"
        if [[ "$transfer_rc" != 0 ]]; then
          (( attempts_seen++, timeouts++ )) || true
          continue
        fi
      elif (( line_num == 1 )); then
        continue
      fi
      (( attempts_seen++ )) || true
      local http_code timing ms
      if [[ "$line" == *$'\t'* ]]; then
        http_code="${line%%$'\t'*}"
        timing="${line#*$'\t'}"
      else
        # 兼容旧的本地 fake/历史探针输出：没有状态码时只能按 200 解析。
        http_code=200
        timing="$line"
      fi
      if ! [[ "$http_code" =~ ^[0-9]{3}$ ]]; then
        (( timeouts++ )) || true
        continue
      fi
      ms=$(awk "BEGIN {printf \"%.0f\", $timing * 1000}" 2>/dev/null) || { (( timeouts++ )) || true; continue; }
      if (( ms == 0 )); then
        (( timeouts++ )) || true
      else
        ttfbs+=("$ms")
        if (( http_code >= 200 && http_code < 300 )); then
          (( successful_samples++ )) || true
        else
          http_failures+=("$http_code")
        fi
      fi
    done <<< "$raw_output"
    if (( attempts_seen < VLESS_TRIES )); then
      (( timeouts += VLESS_TRIES - attempts_seen )) || true
    fi

    if (( ${#ttfbs[@]} == 0 )); then
      RESULTS["$ip"]="FAIL 0 (timeout)"
      append_vless_history "$ip" "FAIL" "0" "timeout"
      echo "[$(date '+%F %T')] verify_vless: $ip FAIL (all timeouts)" >&2
      continue
    fi

    # 中位数
    local sorted
    sorted=$(printf '%s\n' "${ttfbs[@]}" | sort -n)
    local count=${#ttfbs[@]}
    local median
    if (( count % 2 == 1 )); then
      median=$(printf '%s\n' "$sorted" | awk -v n="$count" 'NR == (n+1)/2 {print; exit}')
    else
      local lower upper
      lower=$(printf '%s\n' "$sorted" | awk -v n="$count" 'NR == n/2 {print; exit}')
      upper=$(printf '%s\n' "$sorted" | awk -v n="$count" 'NR == n/2+1 {print; exit}')
      median=$(( (lower + upper + 1) / 2 ))
    fi

    if (( successful_samples > 0 && (curl_rc != 0 || ${#http_failures[@]} > 0) )); then
      partial_reason="partial_success=${successful_samples}/${VLESS_TRIES} failed=$(( VLESS_TRIES - successful_samples )) timeouts=${timeouts}"
      if (( ${#http_failures[@]} > 0 )); then
        partial_reason+=" http_status=${http_failures[0]}"
      fi
      if (( curl_rc != 0 )); then
        partial_reason+=" curl_rc=${curl_rc}"
      fi
      RESULTS["$ip"]="PARTIAL $median ($partial_reason)"
      append_vless_history "$ip" "PARTIAL" "$median" "$partial_reason"
      echo "[$(date '+%F %T')] verify_vless: $ip PARTIAL (median=${median}ms, $partial_reason)" >&2
    elif (( ${#http_failures[@]} > 0 )); then
      http_reason="http_status=${http_failures[0]}"
      RESULTS["$ip"]="FAIL $median ($http_reason)"
      append_vless_history "$ip" "FAIL" "$median" "$http_reason"
      echo "[$(date '+%F %T')] verify_vless: $ip FAIL (median=${median}ms, $http_reason)" >&2
    elif (( curl_rc != 0 )); then
      curl_reason="curl_rc=${curl_rc}"
      RESULTS["$ip"]="FAIL $median ($curl_reason)"
      append_vless_history "$ip" "FAIL" "$median" "$curl_reason"
      echo "[$(date '+%F %T')] verify_vless: $ip FAIL (median=${median}ms, $curl_reason)" >&2
    elif (( successful_samples < VLESS_TRIES )); then
      partial_reason="partial_success=${successful_samples}/${VLESS_TRIES} failed=$(( VLESS_TRIES - successful_samples )) timeouts=${timeouts}"
      RESULTS["$ip"]="PARTIAL $median ($partial_reason)"
      append_vless_history "$ip" "PARTIAL" "$median" "$partial_reason"
      echo "[$(date '+%F %T')] verify_vless: $ip PARTIAL (median=${median}ms, $partial_reason)" >&2
    elif (( median > VLESS_MAX_TTFB )); then
      RESULTS["$ip"]="FAIL $median (slow_ttfb)"
      append_vless_history "$ip" "FAIL" "$median" "slow_ttfb"
      echo "[$(date '+%F %T')] verify_vless: $ip FAIL (median=${median}ms > ${VLESS_MAX_TTFB}ms)" >&2
    else
      RESULTS["$ip"]="PASS $median"
      append_vless_history "$ip" "PASS" "$median" ""
      echo "[$(date '+%F %T')] verify_vless: $ip PASS (median=${median}ms)" >&2
    fi
  done

  # 发送 TERM/KILL 后按组等待；函数支持重复调用但不会误清下一批。
  cleanup_batch_processes
}

# ── 分批并行执行 ──
total=${#ALL_IPS[@]}
echo "[$(date '+%F %T')] verify_vless: testing $total IPs in batches of $BATCH_SIZE" >&2

for (( start=0; start<total; start+=BATCH_SIZE )); do
  batch=("${ALL_IPS[@]:$start:$BATCH_SIZE}")
  verify_batch batch "$start"
done

# ── 汇总 ──
pass_count=0
fail_count=0
PASSED_IPS=()
for ip in "${ALL_IPS[@]}"; do
  result="${RESULTS[$ip]:-FAIL 0 (no_result)}"
  if [[ "$result" == PASS* ]]; then
    (( pass_count++ )) || true
    PASSED_IPS+=("$ip")
  else
    (( fail_count++ )) || true
    # no_result should also enter history once (e.g. batch crash)
    if [[ "$result" == "FAIL 0 (no_result)" ]]; then
      append_vless_history "$ip" "FAIL" "0" "no_result"
    fi
  fi
done

if [ -n "$REFERENCE_KEY" ] && [ -s "$OBS_INPUT" ]; then
  if [ -n "${VLESS_AUDIT_RUN:-}" ]; then
    python3 "$CFST_DIR/audit_evidence.py" record "${VLESS_HISTORY}.requests.jsonl" \
      "$VLESS_REFERENCE_OUT" "$VLESS_AUDIT_RUN" "$REFERENCE_KEY" "$VLESS_TRIES" \
      "${ALL_IPS[@]}" < "$OBS_INPUT"
  else
    OBS_BATCH="$(date +%s%N)-$$"
    python3 "$CFST_DIR/quality_evidence.py" record "${VLESS_HISTORY}.requests.jsonl" \
      "$REFERENCE_KEY" "$OBS_BATCH" "$VLESS_TRIES" < "$OBS_INPUT"
    printf '%s\n%s\n' "$REFERENCE_KEY" "$OBS_BATCH" > "$VLESS_REFERENCE_OUT"
  fi
fi
flush_vless_history || true
prune_vless_history || true
echo "[$(date '+%F %T')] verify_vless: ${pass_count}/${total} IPs passed, ${fail_count} failed" >&2

# ── 审计模式：只报告，不改写 ──
if $AUDIT_MODE; then
  echo ""
  echo "=== AUDIT RESULTS ==="
  for ip in "${ALL_IPS[@]}"; do
    result="${RESULTS[$ip]:-UNKNOWN}"
    echo "  $ip  $result"
  done
  exit 0
fi

# ── 快筛准入模式：输出 median TTFB ≤ VLESS_ADMIT_TTFB 的 IP，不改写 best ──
# 目的：候选入 master 前先过真实 VLESS 体感门控，避免“假高速”污染候选池。
if $SCREEN_MODE; then
  admitted=0
  : > "$SCREEN_OUT"
  for ip in "${ALL_IPS[@]}"; do
    result="${RESULTS[$ip]:-FAIL 0 (no_result)}"
    # result 形如 "PASS 46" / "FAIL 0 (timeout)" / "FAIL 173"
    status="${result%% *}"
    rest="${result#* }"
    median="${rest%% *}"
    if [[ "$status" == "PASS" ]] && [[ "$median" =~ ^[0-9]+$ ]] && (( median <= VLESS_ADMIT_TTFB )); then
      echo "$ip" >> "$SCREEN_OUT"
      (( admitted++ )) || true
    fi
  done
  echo "[$(date '+%F %T')] verify_vless(screen): admitted=${admitted}/${total} (TTFB<=${VLESS_ADMIT_TTFB}ms)" >&2
  exit 0
fi

# ── 正常模式：写回 best_ips.txt ──
if (( ${#PASSED_IPS[@]} == 0 )); then
  echo "[$(date '+%F %T')] verify_vless: all IPs failed verification, keeping original list" >&2
  exit 0
fi

# 重写 best_ips.txt，保留 header
{
  sed -n '1,/^# --- BEST_IPS/p' "$BEST"
  printf '%s\n' "${PASSED_IPS[@]}"
} > "$BEST.tmp"
mv "$BEST.tmp" "$BEST"

echo "[$(date '+%F %T')] verify_vless: ${#PASSED_IPS[@]}/${total} IPs passed" >&2
