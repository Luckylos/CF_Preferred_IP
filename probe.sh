#!/bin/bash
# MTR 路径诊断 + CF colo 检测，摘要写入 routes.tsv
#
# 用法：
#   probe.sh <IP>           # 单 IP
#   probe.sh --all          # best_ips.txt 所有达标 IP
#   probe.sh --top [N]      # best_ips.txt 综合榜 Top N
set -euo pipefail
source "$(dirname "$0")/config.sh"

# probe 不持有 run/scan 的共享锁；它们在候选池阶段结束后可并行调度。
# 独立锁同时保护 routes.tsv 追加、清理和临时文件，避免双 probe 互相覆盖。
PROBE_LOCK_PATH="${PROBE_LOCK:-$CFST_DIR/.probe.lock}"
exec 7>"$PROBE_LOCK_PATH"
flock 7

MTR_COUNT=10
MTR_WAIT=1

probe_one() {
  local ip="$1"
  local ts
  ts=$(date '+%F %T')

  # 1) cdn-cgi/trace 获取真实 colo（HTTPS + --resolve 绕过 TUN）
  local colo="?"
  local trace
  trace=$(setpriv --regid "$BYPASS_GID" --clear-groups \
    curl -sk --max-time 5 \
    --resolve "$COLO_HOST:443:$ip" \
    "https://$COLO_HOST/cdn-cgi/trace" 2>/dev/null) && {
    colo=$(echo "$trace" | sed -n 's/^colo=//p')
  }

  # 2) MTR 路径结构
  local mtr_out
  mtr_out=$(setpriv --regid "$BYPASS_GID" --clear-groups \
    mtr -n -r -w -c "$MTR_COUNT" -i "$MTR_WAIT" "$ip" 2>/dev/null) || {
    echo "[probe] $ip 探测失败" >&2
    return 1
  }
  local path
  path=$(echo "$mtr_out" | python3 "$CFST_DIR/parse_mtr.py")

  # 3) 组合：路径 + 落地节点
  local route
  if [ "$path" = "—" ]; then
    route="@${colo:-?}"
  else
    route=$(echo "$path" | sed "s/CF\[/CF@${colo:-?}[/")
  fi

  printf '%s\t%s\t%s\n' "$ts" "$ip" "$route" >> "$ROUTES"
  echo "[probe] $ip -> $route"
}

extract_ips() {
  local limit="${1:-9999}"
  sed -n '/^# --- BEST_IPS/,$ { /^[0-9]/ p }' "$BEST" \
    | python3 "$CFST_DIR/ip_validation.py" --filter \
    | head -n "$limit"
}

validate_single_ip() {
  local candidate="$1"
  local validated
  if ! validated=$(printf '%s\n' "$candidate" | python3 "$CFST_DIR/ip_validation.py" --strict); then
    echo "probe: invalid IPv4: $candidate" >&2
    exit 2
  fi
  printf '%s' "$validated"
}

case "${1:-}" in
  --all)
    [ -s "$BEST" ] || { echo "best_ips.txt 不存在或为空" >&2; exit 1; }
    IPS=$(extract_ips)
    [ -n "$IPS" ] || { echo "未从 best_ips.txt 提取到 IP" >&2; exit 1; }
    for ip in $IPS; do probe_one "$ip" || true; done
    ;;
  --top)
    N="${2:-3}"
    [ -s "$BEST" ] || { echo "best_ips.txt 不存在或为空" >&2; exit 1; }
    IPS=$(extract_ips "$N")
    [ -n "$IPS" ] || { echo "未从 best_ips.txt 提取到 IP" >&2; exit 1; }
    for ip in $IPS; do probe_one "$ip" || true; done
    ;;
  '')
    echo "用法: $0 <IP>  |  $0 --all  |  $0 --top [N]" >&2; exit 2
    ;;
  *)
    validated_ip=$(validate_single_ip "$1")
    probe_one "$validated_ip"
    ;;
esac

# 清理 routes.tsv 超 7 天条目
if [ -s "$ROUTES" ]; then
  CUTOFF=$(date -d '7 days ago' '+%F %T' 2>/dev/null || date '+%F %T')
  ROUTES_TMP=$(mktemp "$ROUTES.XXXXXX")
  if awk -F'\t' -v cutoff="$CUTOFF" '$1 >= cutoff' "$ROUTES" > "$ROUTES_TMP"; then
    mv "$ROUTES_TMP" "$ROUTES"
  else
    rm -f "$ROUTES_TMP"
    exit 1
  fi
fi
