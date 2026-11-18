#!/bin/bash
# watchdog.sh — Top1 健康监测 + 紧急 rescore & push。
# 由 scan_latency.sh 尾部调用（每 5 分钟一次节奏）。
# 职责：检测当前 Top1 IP 是否可达，连续失效时触发 cycle.sh fast --emergency
# （audit core∪challenger → rank → apply），遇 verify 锁忙 rc=75 保留 miss 计数。
set -euo pipefail
source "$(dirname "$0")/config.sh"

cd "$CFST_DIR"

# ── 读取当前 Top1 ──
TOP1=$(sed -n '/^# --- BEST_IPS/,$ { /^[0-9]/ {p;q} }' "$BEST" 2>/dev/null || true)
if [ -z "$TOP1" ]; then
  exit 0
fi
if ! TOP1=$(printf '%s\n' "$TOP1" | python3 "$CFST_DIR/ip_validation.py" --strict); then
  echo "[$(date '+%F %T')] watchdog: invalid Top1 IPv4; skipping health check" >&2
  exit 0
fi

# ── TCP 连通性检测（443 端口，3 秒超时）──
check_tcp() {
  local ip="$1"
  timeout 3 bash -c 'echo >/dev/tcp/$1/443' -- "$ip" 2>/dev/null
}

# ── 状态管理 ──
MISS_COUNT=0
if [ -f "$WATCHDOG_STATE" ]; then
  read -r STORED_IP STORED_MISSES < "$WATCHDOG_STATE" 2>/dev/null || true
  if [ "$STORED_IP" = "$TOP1" ]; then
    MISS_COUNT=${STORED_MISSES:-0}
  fi
fi

# ── 检测 Top1 ──
if check_tcp "$TOP1"; then
  echo "$TOP1 0" > "$WATCHDOG_STATE"
  exit 0
fi

# 不可达 — 累计
(( MISS_COUNT += 1 ))
echo "$TOP1 $MISS_COUNT" > "$WATCHDOG_STATE"

if (( MISS_COUNT < WATCHDOG_MISS_THRESHOLD )); then
  exit 0
fi

# ── 达到阈值：触发紧急 rescore + push ──
echo "[$(date '+%F %T')] watchdog: Top1=$TOP1 unreachable ${MISS_COUNT}x, triggering emergency rescore" >&2

# 冷却检查
COOLDOWN_FILE="$CFST_DIR/.watchdog_cooldown"
if [ -f "$COOLDOWN_FILE" ]; then
  LAST=$(cat "$COOLDOWN_FILE")
  NOW_EPOCH=$(date +%s)
  if (( NOW_EPOCH - LAST < WATCHDOG_COOLDOWN )); then
    echo "[$(date '+%F %T')] watchdog: in cooldown, skipping" >&2
    exit 0
  fi
fi

# ── cycle.sh fast --emergency（audit core∪challenger → rank → apply；设计 §3.9）──
# 维护闸门在前：推送被禁用时不触发 cycle，保留 miss 计数且不进冷却。
if [ -f "$CFST_DIR/.push_disabled" ]; then
  echo "[$(date '+%F %T')] watchdog: push disabled; retaining miss state without cooldown" >&2
  exit 75
fi
# 清除旧 apply 冷却，只在本轮真正完成并验证新的 apply 后重新写入。
rm -f "$CFST_DIR/.apply_cooldown"
if "$CFST_DIR/cycle.sh" fast --emergency; then
  :
else
  cycle_rc=$?
  if [ "$cycle_rc" -eq 75 ]; then
    echo "[$(date '+%F %T')] watchdog: emergency cycle skipped, lock busy (rc=75); retaining miss state" >&2
    exit 75
  fi
  echo "[$(date '+%F %T')] watchdog: emergency cycle failed (rc=$cycle_rc); retaining miss state" >&2
  exit "$cycle_rc"
fi

APPLY_STATE_PATH="${APPLY_STATE:-$CFST_DIR/.apply_state}"
if [ ! -f "$APPLY_STATE_PATH" ]; then
  echo "[$(date '+%F %T')] watchdog: apply returned success without verified state at $APPLY_STATE_PATH; retaining miss state" >&2
  exit 1
fi

date +%s > "$COOLDOWN_FILE"
rm -f "$WATCHDOG_STATE"
echo "[$(date '+%F %T')] watchdog: emergency push done" >&2
