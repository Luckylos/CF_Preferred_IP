#!/bin/bash
# apply.sh — 检测 best_ips 变化后推送到外部订阅服务（misub + substore）。
# ShellCrash 每小时从 misub 拉取订阅并重启，不需要本地 provider 操作。
set -euo pipefail
source "$(dirname "$0")/config.sh"

cd "$CFST_DIR"

# apply 由 run.sh 嵌入调用，也允许被 cron/人工单独调用；不能复用
# CFST_LOCK，否则 run 持有共享锁时会把自己拒绝。发布级锁只保护外部 reconcile。
APPLY_LOCK_PATH="${APPLY_LOCK:-$CFST_DIR/.apply.lock}"
exec 7>"$APPLY_LOCK_PATH"
if ! flock -n 7; then
  echo "[$(date '+%F %T')] apply: another publish is running; skipping (rc=75)" >&2
  exit 75
fi

# ── 维护闸门：存在 .push_disabled 时不推送 ──
# P0 修复期间使用。MiSub 的 DELETE /manual-nodes/<id> 会以陈旧 profile 快照全量写回
# manualNodeIds，从而覆盖 bind 阶段写入的新节点引用（2026-08-24 12:07 事故根因）。
# 在 delete 阶段按真实语义修好之前，禁止自动推送。
# 提前 exit 0 保证不写 .apply_state / .apply_cooldown，修复后首轮会自动重新推送。
# 注意：仅拦截自动化路径；直接调用 push_to_misub.py 不受影响，以便修复期间做受控验收。
if [ -f "$CFST_DIR/.push_disabled" ]; then
  echo "[$(date '+%F %T')] apply: push disabled by $CFST_DIR/.push_disabled; skipping (see file for rationale)"
  exit 0
fi

# ── 读取实际发布集（PUBLISH_TOP_N；候补集 rank4/rank5 不参与推送触发） ──
mapfile -t TOP_IPS < <(publish_set)
if (( ${#TOP_IPS[@]} == 0 )); then
  echo "[$(date '+%F %T')] apply: no IPs in best_ips.txt" >&2
  exit 0
fi

# 凭据缺失是推送路径的 fail-closed 条件：不要用空 Token 去改生产订阅。
# （状态公式本身允许 secret=missing，以便 run.sh 侧只做比对而不崩溃。）
PUSH_SECRET_FILE="${MISUB_TOKEN_FILE:-$CFST_DIR/secrets/misub.env}"
if [ ! -f "$PUSH_SECRET_FILE" ]; then
  echo "[$(date '+%F %T')] apply: MiSub token file missing: $PUSH_SECRET_FILE" >&2
  exit 1
fi

# ── 变化检测（状态公式来自 config.sh，run.sh 复用同一函数）──
CURRENT_FILE="$APPLY_STATE"
CURRENT=""
[ -f "$CURRENT_FILE" ] && CURRENT=$(cat "$CURRENT_FILE" 2>/dev/null || true)
NEW_STATE=$(compute_apply_state)
if [ "$NEW_STATE" = "$CURRENT" ]; then
  exit 0
fi

# ── 冷却检查 ──
COOLDOWN_FILE="$CFST_DIR/.apply_cooldown"
if [ -f "$COOLDOWN_FILE" ]; then
  LAST=$(cat "$COOLDOWN_FILE")
  NOW_EPOCH=$(date +%s)
  if (( NOW_EPOCH - LAST < APPLY_COOLDOWN )); then
    # 即使处于冷却期，调用方也可以用 APPLY_FORCE=1 完成显式同步。
    if [ "${APPLY_FORCE:-0}" != "1" ]; then
      exit 0
    fi
  fi
fi

# ── 推送到外部订阅服务 ──
PUSH_OK=0

if [ -f "$CFST_DIR/push_to_misub.py" ]; then
  if MISUB_TOKEN_FILE="$PUSH_SECRET_FILE" python3 "$CFST_DIR/push_to_misub.py" 2>&1 | sed 's/^/[misub] /'; then
    (( PUSH_OK++ )) || true
  else
    echo "[$(date '+%F %T')] apply: push_to_misub failed" >&2
  fi
fi

if (( PUSH_OK > 0 )); then
  echo "$NEW_STATE" > "$CURRENT_FILE"
  date +%s > "$COOLDOWN_FILE"
  echo "[$(date '+%F %T')] apply: pushed ${#TOP_IPS[@]} IPs -> $(printf '%s ' "${TOP_IPS[@]}")"
else
  echo "[$(date '+%F %T')] apply: all pushes failed, will retry next round" >&2
  exit 1
fi
