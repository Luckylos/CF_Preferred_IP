#!/bin/bash
# publish_watchdog.sh — 发布链路「静默停摆」检测器。正常时零输出。
#
# 背景（2026-09-12）：push_to_misub.py 的模板校验把 CR/LF 转义写成了两层，
# 模块级 REGIONS 初始化即抛 RuntimeError，apply 连续 59 轮失败，订阅节点冻结
# 约 4 天 20 小时无人发现。run.sh 把 apply 失败当致命（exit 1），但整条链路
# 没有任何告警出口 —— 这个缺口比转义 bug 本身更值得补。
#
# ── 为什么不看 .apply_state 的 mtime ──
# apply.sh L49-51 在 cur == new 时提前 exit 0，**不触碰** .apply_state。
# Top3 稳定时该文件 mtime 天然就是旧的，按 mtime 告警会每天误报。
#
# ── 权威信号：状态分歧的持续时长 ──
# cur(.apply_state) != compute_apply_state() 表示「存在待发布的变更」。
# 发布健康时它会在下一轮 run.sh（cron 每 2h，且以 APPLY_FORCE=1 调用，
# 不受 APPLY_COOLDOWN 阻挡）内收敛；持续超过 PUBLISH_STALE_HOURS 即为停摆。
# 该单一信号同时覆盖：push 失败、MiSub 凭据缺失（apply fail-closed）、
# .push_disabled 忘记摘除、apply.sh 未被调度、apply 锁长期被占。
#
# ── 第二个独立信号：pipeline 新鲜度 ──
# 若发现/评分链路整体死亡，best_ips.txt 不再变化，两侧状态会一直相等而
# 不产生分歧，信号 1 看不见。score.py 每轮以 os.replace 原子重写
# best_ips.txt，所以其 mtime 是 pipeline 存活的直接证据。
#
# ── 输出契约 ──
# 无异常 → 完全不输出（配合 no_agent 定时任务即「静默 watchdog」）。
# 有异常 → 每项一行，纯文本。始终 exit 0：告警走 stdout，不靠退出码。
#
# ── 边界 ──
# 只读生产（除自身状态文件外不写任何文件），不发起网络请求，不回显任何凭据。

set -uo pipefail

# 阈值（可用环境变量覆盖；同时作为自测接缝）
PUBLISH_STALE_HOURS="${PUBLISH_STALE_HOURS:-3}"   # 分歧容忍时长：一整轮 2h + 余量
PIPELINE_STALE_HOURS="${PIPELINE_STALE_HOURS:-5}" # best_ips 停更容忍：2 轮 + 余量
ALERT_REPEAT_HOURS="${ALERT_REPEAT_HOURS:-6}"     # 同一次停摆的重复告警间隔

CFST_CONFIG="${CFST_CONFIG:-/opt/cfst/config.sh}"

# config.sh 在 secrets 缺失/权限不对时会往 stderr 写警告（不影响 rc）；
# 那些情况由信号 1 的分歧持续时长兜住，这里只关心 source 是否成功。
if ! source "$CFST_CONFIG" 2>/dev/null; then
  echo "[cfst-watchdog] CRITICAL: 无法 source $CFST_CONFIG；看门狗自身失效，发布健康度未知"
  exit 0
fi

# 发布落地方式决定告警文案与失败线索（2026-11-22 起默认 dns）。
PUBLISH_MODE="${CFST_PUBLISH:-misub}"
STATE_FILE="${PUBLISH_WATCHDOG_STATE:-$CFST_DIR/.publish_watchdog_state}"
APPLY_STATE_FILE="${WATCHDOG_APPLY_STATE:-${APPLY_STATE:-$CFST_DIR/.apply_state}}"
BEST_FILE="${WATCHDOG_BEST_FILE:-${BEST:-$CFST_DIR/best_ips.txt}}"

now=$(date +%s)
alerts=()

# ── 信号 2：pipeline 新鲜度 ──────────────────────────────────────────
if [ -f "$BEST_FILE" ]; then
  best_mtime=$(stat -c %Y "$BEST_FILE" 2>/dev/null || echo 0)
  best_age=$(( now - best_mtime ))
  if (( best_age > PIPELINE_STALE_HOURS * 3600 )); then
    alerts+=("[cfst-watchdog] pipeline 停摆：best_ips.txt 已 $(( best_age / 3600 ))h 未更新（阈值 ${PIPELINE_STALE_HOURS}h；run.sh 每 2h 应原子重写）")
  fi
else
  alerts+=("[cfst-watchdog] pipeline 异常：best_ips.txt 不存在（$BEST_FILE）")
fi

# ── 信号 1：发布状态分歧持续时长 ────────────────────────────────────
new_state=""
members=""
if targets=$(read_publish_targets 2>/dev/null); then
  preferred=${targets%%$'\n'*}
  members=${targets#*$'\n'}
  new_state=$(compute_apply_state "$preferred" "$members" 2>/dev/null || true)
fi
cur_state=""
if [ -f "$APPLY_STATE_FILE" ] && [ ! -e "$APPLY_STATE_FILE.pending" ]; then
  cur_state=$(cat "$APPLY_STATE_FILE" 2>/dev/null || true)
fi

if [ -z "$new_state" ]; then
  alerts+=("[cfst-watchdog] compute_apply_state 失败;发布健康度未知(检查发布快照与模板配置)")
elif [ "$new_state" = "$cur_state" ]; then
  # 已收敛：清除分歧计时，下次分歧重新起算
  rm -f "$STATE_FILE"
else
  first_seen=""
  last_alert=""
  if [ -f "$STATE_FILE" ]; then
    read -r first_seen last_alert _ < "$STATE_FILE" 2>/dev/null || true
  fi
  # 计时只按「何时首次观察到分歧」起算，不按 new_state 的值起算：
  # 否则 Top3 每轮抖动会不停重置计时，把持续的发布失败永久藏住。
  case "${first_seen:-}" in ''|*[!0-9]*) first_seen="$now"; last_alert="" ;; esac
  case "${last_alert:-}" in ''|*[!0-9]*) last_alert=0 ;; esac

  age=$(( now - first_seen ))
  if (( age > PUBLISH_STALE_HOURS * 3600 )) && (( now - last_alert >= ALERT_REPEAT_HOURS * 3600 )); then
    case "$PUBLISH_MODE" in
      dns) target="DNS 记录集" ;;
      both) target="DNS 记录集 + MiSub" ;;
      *) target="MiSub" ;;
    esac
    alerts+=("[cfst-watchdog] 发布停摆：待发布变更已 $(( age / 3600 ))h 未落地 $target（阈值 ${PUBLISH_STALE_HOURS}h）")
    desired=${members//$'\n'/ }
    [ -n "${desired// /}" ] && alerts+=("  应发布 Top${PUBLISH_TOP_N}: ${desired% }")
    if [ -f "$CFST_DIR/.push_disabled" ]; then
      alerts+=("  原因线索: 存在 .push_disabled（维护闸门未摘除）")
    fi
    case "$PUBLISH_MODE" in
      dns) fail_pattern='apply: DNS publish failed|did not resolve to the published set' ;;
      both) fail_pattern='apply: DNS publish failed|did not resolve to the published set|apply: (push_to_misub failed|publish incomplete|all pushes failed)' ;;
      *) fail_pattern='apply: (all pushes failed|push_to_misub failed|publish incomplete)' ;;
    esac
    last_fail=$(grep -aE "$fail_pattern" "$RESULT_DIR/cron.log" 2>/dev/null | tail -n1 || true)
    [ -n "$last_fail" ] && alerts+=("  最近失败行: $last_fail")
    last_alert="$now"
  fi
  printf '%s %s %s\n' "$first_seen" "$last_alert" "$new_state" > "$STATE_FILE"
fi

if (( ${#alerts[@]} > 0 )); then
  printf '%s\n' "${alerts[@]}"
fi
exit 0
