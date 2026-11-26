#!/bin/bash
# apply.sh — 从期望发布快照协调 DNS 和 MiSub。
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

PUBLISH_TARGETS=$(read_publish_targets)
mapfile -t TARGETS <<< "$PUBLISH_TARGETS"
DNS_PREFERRED="${TARGETS[0]}"
TOP_IPS=("${TARGETS[@]:1}")

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
PUBLISH_MEMBERS=$(printf '%s\n' "${TOP_IPS[@]}")
NEW_STATE=$(compute_apply_state "$DNS_PREFERRED" "$PUBLISH_MEMBERS")
PENDING_FILE="$CURRENT_FILE.pending"
RETRY_ONLY=1
if [ "${APPLY_RETRY_ONLY:-1}" = "0" ]; then
  RETRY_ONLY=0
fi
if [ "$RETRY_ONLY" = "1" ]; then
  if [ ! -f "$PENDING_FILE" ] || [ "$(cat "$PENDING_FILE")" != "$NEW_STATE" ]; then
    echo "[$(date '+%F %T')] apply: guarded round has no matching pending target"
    exit 0
  fi
fi
if [ "$NEW_STATE" = "$CURRENT" ] && [ ! -e "$PENDING_FILE" ]; then
  exit 0
fi

# ── 冷却检查 ──
COOLDOWN_FILE="$CFST_DIR/.apply_cooldown"
if [ -f "$COOLDOWN_FILE" ] && [ ! -e "$PENDING_FILE" ]; then
  LAST=$(cat "$COOLDOWN_FILE")
  NOW_EPOCH=$(date +%s)
  if (( NOW_EPOCH - LAST < APPLY_COOLDOWN )); then
    # 即使处于冷却期，调用方也可以用 APPLY_FORCE=1 完成显式同步。
    if [ "${APPLY_FORCE:-0}" != "1" ]; then
      exit 0
    fi
  fi
fi

# ── 发布落地 ───────────────────────────────────────────────────────────
# misub：把 IP 写进订阅节点（客户端零额外解析）
# dns  ：把最好的 CFST_DNS_TOP_N 个（默认 1）写成备用域名的 A 记录
# both ：两条都落地；两条都成功才写状态，任一失败下一轮重试
PUBLISH_MODE="${CFST_PUBLISH:-both}"
case "$PUBLISH_MODE" in
  misub|dns|both) ;;
  *)
    echo "[$(date '+%F %T')] apply: unknown CFST_PUBLISH=$PUBLISH_MODE (expected misub|dns|both)" >&2
    exit 2
    ;;
esac

if [ "$RETRY_ONLY" = "0" ]; then
  pending_tmp=$(mktemp "$PENDING_FILE.XXXXXX")
  if ! printf '%s\n' "$NEW_STATE" > "$pending_tmp" || ! mv -fT -- "$pending_tmp" "$PENDING_FILE"; then
    rm -f -- "$pending_tmp"
    exit 1
  fi
fi
PUBLISH_OK=1
CHANNELS=""

if [ "$PUBLISH_MODE" = "dns" ] || [ "$PUBLISH_MODE" = "both" ]; then
  # 只取最好的前 N 个：DNS 每多一条都让客户端多一次解析，收益抵不上抖动。
  if [ -n "$DNS_PREFERRED" ]; then
    DNS_IPS=("$DNS_PREFERRED")
  else
    mapfile -t DNS_IPS < <(printf '%s\n' "${TOP_IPS[@]}" | head -n "${CFST_DNS_TOP_N:-1}")
  fi
  if (( ${#DNS_IPS[@]} == 0 )); then
    echo "[$(date '+%F %T')] apply: DNS publish needs at least one address" >&2
    exit 1
  fi
  set +e
  dns_output=$(python3 "$CFST_DIR/dns_publish.py" apply "${DNS_IPS[@]}" 2>&1)
  dns_rc=$?
  set -e
  printf '%s\n' "$dns_output" | sed 's/^/[dns] /'
  if (( dns_rc != 0 )); then
    echo "[$(date '+%F %T')] apply: DNS publish failed (rc=$dns_rc)" >&2
    PUBLISH_OK=0
  else
    CHANNELS="dns(${#DNS_IPS[@]})"
  fi
fi

if [ "$PUBLISH_MODE" = "misub" ] || [ "$PUBLISH_MODE" = "both" ]; then
  if [ -f "$CFST_DIR/push_to_misub.py" ] \
    && MISUB_TOKEN_FILE="$PUSH_SECRET_FILE" python3 "$CFST_DIR/publication_snapshot.py" misub "${TOP_IPS[@]}" 2>&1 | sed 's/^/[misub] /'; then
    CHANNELS="${CHANNELS:+$CHANNELS+}misub(${#TOP_IPS[@]})"
  else
    echo "[$(date '+%F %T')] apply: push_to_misub failed" >&2
    PUBLISH_OK=0
  fi
fi

if (( PUBLISH_OK )); then
  date +%s > "$COOLDOWN_FILE"
  mv -fT -- "$PENDING_FILE" "$CURRENT_FILE"
  echo "[$(date '+%F %T')] apply: published via $CHANNELS -> $(printf '%s ' "${TOP_IPS[@]}")"
else
  echo "[$(date '+%F %T')] apply: publish incomplete, will retry next round" >&2
  exit 1
fi
