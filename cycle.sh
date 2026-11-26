#!/bin/bash
# cycle.sh — Contender Pool 编排（取代 run.sh 主体）。
#   slow（2h）：黑名单清理 → 发现队列整理 → audit 全池 → systemic → rank → apply
#               → 快筛补池（池 < POOL_MAX 且非 systemic 轮）→ probe → 日志清理
#   fast（15m）：audit core ∪ challengers → systemic → rank → apply
# 用法：cycle.sh slow | cycle.sh fast [--emergency] [--shadow]
#   --emergency  仅在日志行加标记（冷却逻辑仍在 watchdog）
#   --shadow     状态重定向到 .shadow/（池/best/黑名单），不 apply、不 screen、不 probe、不整理队列
# 与 scan_latency.sh 共用非阻塞锁（flock 9），保护候选池读写。
set -euo pipefail
source "$(dirname "$0")/config.sh"

usage() { echo "usage: cycle.sh slow | cycle.sh fast [--emergency] [--shadow]" >&2; exit 64; }
MODE="${1:-}"
case "$MODE" in slow|fast) ;; *) usage ;; esac
shift
EMERGENCY=0
SHADOW=0
for arg in "$@"; do
  case "$arg" in
    --emergency) EMERGENCY=1 ;;
    --shadow) SHADOW=1 ;;
    *) usage ;;
  esac
done

cd "$CFST_DIR"
exec 9>"$CFST_LOCK"
if [ "$SHADOW" = "1" ]; then
  flock -w 120 9 || exit 75  # 影子：等待扫描/探测释放锁（scan 持锁约 15s），超时放弃
else
  flock -n 9 || exit 75  # 75: 已有全量任务在跑；让 cron 不执行后续步骤
fi

TS=$(date +%Y%m%d_%H%M%S)
NOW=$(date '+%F %T')
CONTENDERS="${CONTENDERS:-$CFST_DIR/contenders.tsv}"
TIERS_DIR="${TIERS_DIR:-$CFST_DIR/.tiers}"
CAPACITY_COOLDOWN="${CAPACITY_COOLDOWN:-$CFST_DIR/.capacity_cooldown.tsv}"
CAPACITY_COOLDOWN_HOURS="${CAPACITY_COOLDOWN_HOURS:-6}"
# ── 影子模式（切换前并行验证，设计 §6 Task 6）──
# 新链路全部状态重定向到 .shadow/（池、best、黑名单），rank 正常写入以保留粘性在任者与淘汰历史；
# 不 apply、不 screen、不 probe、不整理发现队列；只有 audit 样本进入共享的 vless_history.tsv。
# 结束时输出 "shadow: legacy=... new=... same=0|1" 供 status.py 统计 48h 硬门。
LEGACY_BEST="$BEST"
if [ "$SHADOW" = "1" ]; then
  SHADOW_DIR="$CFST_DIR/.shadow"
  mkdir -p "$SHADOW_DIR"
  CONTENDERS="$SHADOW_DIR/contenders.tsv"
  BEST="$SHADOW_DIR/best_ips.txt"
  SCREEN_BLACKLIST="$SHADOW_DIR/blacklist.tsv"
  CAPACITY_COOLDOWN="$SHADOW_DIR/capacity_cooldown.tsv"
  LEGACY_BEST="$CFST_DIR/best_ips.txt"
fi
if [ "$MODE" = "slow" ] && [ "$SHADOW" = "0" ]; then
  LOG="$RESULT_DIR/$TS.log"
  : > "$LOG"
else
  LOG=/dev/stdout  # fast / shadow：由 cron 或 run.sh 重定向到 results/fast.log / shadow.log
fi
log() { echo "[$(date '+%F %T')] $*" >> "$LOG"; }

CYCLE_RECORD=""
RANK_STATUS=skipped
GUARD=none
APPLICATION=unknown
AUDIT_READY=0
AUDIT_REQUESTED=0
AUDIT_RETURNED=0
AUDIT_OK=0
SYSTEMIC_ROUND=0
SCREEN_COUNT=0
ADMITTED=0
SCREEN_FAILED=0
PROBE_FAILED=0
CYCLE_INTERRUPTED=0
AUDIT_IN=""; AUDIT_OUT=""; AUDIT_REF=""; RANK_OUT=""; RANK_JSON=""
SCREEN_IN=""; SCREEN_OUT=""; POOL_SET=""; NEW_ROWS=""
cycle_exit() {
  local result=$?
  trap - EXIT
  if [ -n "$CYCLE_RECORD" ]; then
    local facts=(finish --record "$CYCLE_RECORD" --rank-status "$RANK_STATUS"
      --rank-receipt "$RANK_JSON" --application "$APPLICATION" --exit-code "$result"
      --screened "$SCREEN_COUNT" --admitted "$ADMITTED")
    if [ "$AUDIT_READY" = "1" ]; then
      facts+=(--requested "$AUDIT_REQUESTED" --returned "$AUDIT_RETURNED"
        --audit-ok "$AUDIT_OK" --systemic "$SYSTEMIC_ROUND" --percent "$MASTER_MIN_COVERAGE_PERCENT")
    fi
    if [ "$SCREEN_FAILED" = "1" ]; then facts+=(--warning screen_failed); fi
    if [ "$PROBE_FAILED" = "1" ]; then facts+=(--warning probe_failed); fi
    if [ "$CYCLE_INTERRUPTED" = "1" ]; then facts+=(--warning interrupted); fi
    if [ "$ADMITTED" = "-1" ]; then facts+=(--warning admission_unconfirmed); fi
    if python3 "$CFST_DIR/cycle_result.py" "${facts[@]}"; then :; else
      log "cycle-result-error: stage=finish; persisted actions are not rolled back"
      if [ "$result" = "0" ]; then result=1; fi
    fi
  fi
  local file
  for file in "$AUDIT_IN" "$AUDIT_OUT" "$AUDIT_REF" "$RANK_OUT" "$RANK_JSON" "$SCREEN_IN" "$SCREEN_OUT" "$POOL_SET" "$NEW_ROWS"; do
    if [ -n "$file" ]; then
      if rm -f "$file"; then :; else if [ "$result" = "0" ]; then result=1; fi; fi
    fi
  done
  exit "$result"
}
trap cycle_exit EXIT
trap 'CYCLE_INTERRUPTED=1; exit 143' TERM
trap 'CYCLE_INTERRUPTED=1; exit 130' INT
CYCLE_STORE="$RESULT_DIR/cycle-results"
BEGIN_FLAGS=()
if [ "$SHADOW" = "1" ]; then CYCLE_STORE="$SHADOW_DIR/cycle-results"; BEGIN_FLAGS+=(--shadow); fi
BEGIN_RESULT=$(python3 "$CFST_DIR/cycle_result.py" begin --store "$CYCLE_STORE" --mode "$MODE" "${BEGIN_FLAGS[@]}")
IFS= read -r CYCLE_RECORD <<< "$BEGIN_RESULT"
CYCLE_ID=$(tail -n1 <<< "$BEGIN_RESULT")
log "cycle-record: id=$CYCLE_ID"
AUDIT_IN=$(mktemp "$RESULT_DIR/.audit-in.XXXXXX")
AUDIT_OUT=$(mktemp "$RESULT_DIR/.audit.XXXXXX")
AUDIT_REF=$(mktemp "$RESULT_DIR/.audit.ref.XXXXXX")
RANK_OUT=$(mktemp "$RESULT_DIR/.rank.XXXXXX")
RANK_JSON=$(mktemp "$RESULT_DIR/.rank-result.XXXXXX")
SCREEN_IN=$(mktemp "$RESULT_DIR/.screen-in.XXXXXX")
SCREEN_OUT=$(mktemp "$RESULT_DIR/.screen-out.XXXXXX")
POOL_SET=$(mktemp "$RESULT_DIR/.pool-set.XXXXXX")
NEW_ROWS=$(mktemp "$RESULT_DIR/.newrows.XXXXXX")

# 结束行契约（status.py 解析）：[ts] cycle: mode=slow|fast [emergency=1] [shadow=1] guard=G rank=S
finish_line() {
  local flags=""
  if [ "$EMERGENCY" = "1" ]; then flags=" emergency=1"; fi
  if [ "$SHADOW" = "1" ]; then flags="$flags shadow=1"; fi
  log "cycle: mode=$MODE$flags guard=$GUARD rank=$RANK_STATUS"
  if [ "$SHADOW" = "1" ] && [ "$RANK_STATUS" = "ok" ]; then
    local legacy new same
    legacy=$(BEST="$LEGACY_BEST" publish_set | paste -sd, -)
    new=$(python3 "$CFST_DIR/cycle_result.py" receipt --path "$RANK_JSON" --published | tr ' ' ',')
    [ -n "$legacy" ] || legacy=-
    [ -n "$new" ] || new=-
    same=0; [ "$legacy" = "$new" ] && same=1
    log "shadow: legacy=$legacy new=$new same=$same"
  fi
}

# 池内有效 IP（排除注释/空行，经 ip_validation 过滤）
pool_ips() {
  grep -vE '^[[:space:]]*(#|$)' "$CONTENDERS" 2>/dev/null | cut -f1 \
    | python3 "$CFST_DIR/ip_validation.py" --filter || true
}

if [ "$MODE" = "slow" ]; then
  # 两类冷却共用有效期判断；只在慢轮原子整理，扫描侧只读。
  python3 "$CFST_DIR/cooldown.py" --quality "$SCREEN_BLACKLIST" --capacity "$CAPACITY_COOLDOWN" \
    --quality-hours "$SCREEN_BLACKLIST_HOURS" --capacity-hours "$CAPACITY_COOLDOWN_HOURS" \
    --now "$NOW" --prune > "$NEW_ROWS"

  # 发现队列由同一module整理；影子模式不触碰共享队列。
  if [ "$SHADOW" = "0" ]; then
    python3 "$CFST_DIR/admission.py" maintain --queue "$DISCOVERED" \
      --now "$NOW" --ttl-hours "$DISCOVERY_TTL_HOURS" --limit "$DISCOVERY_LIMIT" \
      --excluded "$NEW_ROWS" > /dev/null
  fi

  # ── audit 输入 = 全池 ──
  pool_ips > "$AUDIT_IN"
else
  audit_limit=20
  emergency_audit=0
  if [ "$EMERGENCY" = "1" ] && [ "$SHADOW" = "0" ]; then
    emergency_audit=1
  fi
  # 紧急轮先复测发布目标，有无 tiers 都不影响这一步。
  if [ "$emergency_audit" = "0" ] && [ ! -f "$TIERS_DIR/core.txt" ] && [ ! -f "$TIERS_DIR/challengers.txt" ]; then
    log "fast: no tiers at $TIERS_DIR (core.txt/challengers.txt); nothing to audit"
    finish_line
    exit 0
  fi
  (if [ "$emergency_audit" = "1" ]; then
     read_publish_targets || exit 1
   fi
   for f in "$TIERS_DIR/core.txt" "$TIERS_DIR/challengers.txt"; do [ -f "$f" ] && cat "$f"; done; true) \
    | grep -E '^[0-9]' | python3 "$CFST_DIR/ip_validation.py" --filter \
    | awk -v limit="$audit_limit" 'NF && !seen[$0]++ && (!limit || count++ < limit)' > "$AUDIT_IN" || : > "$AUDIT_IN"
  if [ "$emergency_audit" = "1" ] && [ ! -s "$AUDIT_IN" ]; then
    log "fast emergency: no valid addresses to audit"
    finish_line
    exit 1
  fi
fi
awk 'NF && !seen[$0]++' "$AUDIT_IN" > "$POOL_SET"
cat "$POOL_SET" > "$AUDIT_IN"
AUDIT_REQUESTED=$(awk 'END{print NR+0}' "$AUDIT_IN")
OBSERVATIONS="${VLESS_HISTORY:-$CFST_DIR/vless_history.tsv}.requests.jsonl"
AUDIT_REQUESTED=$((10#$AUDIT_REQUESTED))

# ── audit（verify_vless --audit：只报告，不改写；样本追加到 VLESS_HISTORY）──
AUDIT_OK=1
AUDIT_RC=0
AUDIT_START_NS=0
if (( AUDIT_REQUESTED > 0 )) && [ -x "$CFST_DIR/verify_vless.sh" ]; then
  log "$MODE audit (VLESS): targets=$AUDIT_REQUESTED"
  AUDIT_START_NS=$(date +%s%N)
  VLESS_REFERENCE_OUT="$AUDIT_REF" VLESS_AUDIT_RUN="$CYCLE_ID" \
    "$CFST_DIR/verify_vless.sh" --audit "$AUDIT_IN" > "$AUDIT_OUT" 2>> "$LOG" || AUDIT_RC=$?
else
  log "$MODE audit skipped: targets=$AUDIT_REQUESTED"
  AUDIT_OK=0
fi
case "$AUDIT_RC" in
  0) ;;
  2)
    log "audit credentials missing (rc=2); no evidence this round"
    AUDIT_OK=0
    ;;
  75)
    log "audit lock busy (rc=75); another verification is running"
    finish_line
    exit 75
    ;;
  *)
    log "audit command failed (rc=$AUDIT_RC); no evidence this round"
    AUDIT_OK=0
    ;;
esac

# 覆盖与共因守卫都来自经收据核对的结构化观测。
if [ "$AUDIT_OK" = "1" ]; then
  AUDIT_FACTS=$(python3 "$CFST_DIR/audit_evidence.py" facts "$OBSERVATIONS" "$AUDIT_REF" \
    "$CYCLE_ID" "$AUDIT_IN" "$AUDIT_START_NS" "$MASTER_MIN_COVERAGE_PERCENT" \
    "$MASTER_SYSTEMIC_P10_MS" "$MASTER_SYSTEMIC_MIN_SAMPLES")
  read -r GUARD AUDIT_REQUESTED AUDIT_RETURNED _ <<< "$AUDIT_FACTS"
else
  GUARD=no_evidence
  AUDIT_RETURNED=0
fi
[ "$GUARD" != "no_evidence" ] || AUDIT_OK=0
[ "$GUARD" != "systemic" ] || SYSTEMIC_ROUND=1
MIN_ROWS=$(( (AUDIT_REQUESTED * MASTER_MIN_COVERAGE_PERCENT + 99) / 100 ))
AUDIT_READY=1
RANK_NOW=$(date '+%F %T')
log "audit evidence: returned=$AUDIT_RETURNED/$AUDIT_REQUESTED (need >=$MIN_ROWS) audit_ok=$AUDIT_OK systemic=$SYSTEMIC_ROUND guard=$GUARD"

rank_options=()
if [ "$SHADOW" = "1" ]; then
  rank_options+=(--initialize-publication)
fi
set +e
python3 "$CFST_DIR/rank.py" "${rank_options[@]}" --observations "$OBSERVATIONS" \
  --reference-file "$AUDIT_REF" --audit-start-ns "$AUDIT_START_NS" \
  --audit-run "$CYCLE_ID" --audit-targets "$AUDIT_IN" \
  --audit-p10-ms "$MASTER_SYSTEMIC_P10_MS" --audit-min-samples "$MASTER_SYSTEMIC_MIN_SAMPLES" \
  --contenders "$CONTENDERS" \
  --best "$BEST" \
  --blacklist "$SCREEN_BLACKLIST" \
  --capacity-cooldown "$CAPACITY_COOLDOWN" \
  --capacity-cooldown-hours "$CAPACITY_COOLDOWN_HOURS" \
  --now "$RANK_NOW" \
  --audit-ok "$AUDIT_OK" \
  --result-out "$RANK_JSON" \
  --audit-min-coverage-percent "$MASTER_MIN_COVERAGE_PERCENT" \
  --tiers-out "$TIERS_DIR" \
  --half-life-hours "${RANK_HALF_LIFE_HOURS:?RANK_HALF_LIFE_HOURS is required}" \
  --floor-ms "${RANK_FLOOR_MS:?RANK_FLOOR_MS is required}" \
  --z "${RANK_Z:?RANK_Z is required}" \
  --sigma0 "${RANK_SIGMA0:?RANK_SIGMA0 is required}" \
  --peak-weight "${RANK_PEAK_WEIGHT:?RANK_PEAK_WEIGHT is required}" \
  --peak-min-samples "${RANK_PEAK_MIN_SAMPLES:?RANK_PEAK_MIN_SAMPLES is required}" \
  --trim-headroom "${VLESS_SCREEN_MAX:?VLESS_SCREEN_MAX is required}" \
  --core-n "${CORE_N:?CORE_N is required}" \
  --pool-target "${POOL_TARGET:?POOL_TARGET is required}" \
  --pool-max "${POOL_MAX:?POOL_MAX is required}" \
  --publish-min-neff "${PUBLISH_MIN_NEFF:?PUBLISH_MIN_NEFF is required}" \
  --publish-margin "${PUBLISH_MARGIN:?PUBLISH_MARGIN is required}" \
  --top-n "${SCORE_TOP_N:?SCORE_TOP_N is required}" \
  --publish-top-n "${PUBLISH_TOP_N:?PUBLISH_TOP_N is required}" \
  --hard-max-fail "${VLESS_HARD_MAX_FAIL:?VLESS_HARD_MAX_FAIL is required}" \
  --peak-hours "${RANK_PEAK_HOURS:?RANK_PEAK_HOURS is required}" \
  > "$RANK_OUT" 2>> "$LOG"
rank_rc=$?
set -e
# rank 摘要行（"rank: pool=... guard=..."）带时间戳原样入日志；其余 stdout 原样追加。
# 注意 rank.py 首行也以 "rank: now=" 开头，摘要行以 "rank: pool=" 开头，须精确匹配。
grep -v '^rank: pool=' "$RANK_OUT" >> "$LOG" || true
if (( rank_rc != 0 )); then
  RANK_STATUS=failed
  log "rank.py failed (rc=$rank_rc); refusing further apply; persisted state is not rolled back"
  finish_line
  exit "$rank_rc"
fi
if RANK_SUMMARY=$(python3 "$CFST_DIR/cycle_result.py" receipt --path "$RANK_JSON") &&
   RANK_GUARD=$(python3 "$CFST_DIR/cycle_result.py" receipt --path "$RANK_JSON" --guard) &&
   { [ "$GUARD" = "$RANK_GUARD" ] || { [ "$GUARD" = "none" ] && [ "$RANK_GUARD" = "no_evidence" ]; }; }; then
  GUARD=$RANK_GUARD
  log "$RANK_SUMMARY"
else
  RANK_STATUS=failed
  log "rank receipt missing, invalid or inconsistent with audit evidence; refusing further apply"
  finish_line
  exit 1
fi
RANK_STATUS=ok

# ── 应用优选结果到订阅服务（shadow 不发布）──
if [ "$SHADOW" = "0" ]; then
  # 发布落地由 apply.sh 负责：CFST_PUBLISH=dns 时写 DNS，misub 模式沿用旧推送。
  retry_only=0
  [ "$GUARD" = "none" ] || retry_only=1
  if [ -x "$CFST_DIR/apply.sh" ] && { [ "$retry_only" = "0" ] || [ -e "$APPLY_STATE.pending" ]; }; then
    if APPLY_FORCE=1 APPLY_RETRY_ONLY="$retry_only" "$CFST_DIR/apply.sh"; then
      :
    else
      apply_rc=$?
      APPLICATION=failed
      log "apply.sh failed (rc=$apply_rc); refusing further steps"
      finish_line
      exit "$apply_rc"
    fi
  fi
  APPLICATION=unconfirmed
  if [ ! -f "$APPLY_STATE" ]; then
    if [ -f "$CFST_DIR/.push_disabled" ]; then
      log "apply skipped by maintenance gate; no verified state, refusing further steps"
    else
      log "apply state missing at $APPLY_STATE; refusing further steps"
    fi
    finish_line
    exit 1
  fi
  if ! TOP_STATE=$(compute_apply_state); then
    log "desired publication state unavailable; refusing further steps"
    finish_line
    exit 1
  fi
  APPLIED_STATE=$(cat "$APPLY_STATE" 2>/dev/null || true)
  if [ -e "$APPLY_STATE.pending" ] || [ "$TOP_STATE" != "$APPLIED_STATE" ]; then
    log "apply state mismatch after ranking at $APPLY_STATE; refusing further steps"
    finish_line
    exit 1
  fi
  APPLICATION=confirmed
else
  APPLICATION=shadow_skipped
  log "shadow: apply skipped"
fi

if [ "$MODE" = "slow" ]; then
  # ── 发现队列滚动快筛（VLESS --screen）→ PASS 追加到 contenders.tsv ──
  # 优先级 = failcount ASC, timestamp ASC；排除已在池内的 IP。
  # 入口 C：systemic 轮跳过 —— 共因劣化轮不 screen，避免新候选被系统性误杀并推高黑名单；
  # 队列不更新是有意的：不 screen 就不该改 failcount。
  # 池满门控：池内有效行 ≥ POOL_MAX 时不再补池（取代旧试用池背压）。
  pool_ips > "$POOL_SET"
  CONTENDER_COUNT=$(awk 'END{print NR+0}' "$POOL_SET")
  CONTENDER_COUNT=$((10#$CONTENDER_COUNT))
  if [ "$GUARD" != "none" ]; then
    log "discovery screen skipped: $GUARD round"
  elif (( CONTENDER_COUNT >= POOL_MAX )); then
    log "discovery screen skipped: pool full (contenders=$CONTENDER_COUNT >= POOL_MAX=$POOL_MAX)"
  elif [ "$SHADOW" = "1" ]; then
    log "discovery screen skipped: shadow"
  elif [ -s "$DISCOVERED" ] && [ "${VLESS_SCREEN_ENABLED:-0}" = "1" ] && [ -x "$CFST_DIR/verify_vless.sh" ]; then
    SCREEN_ADMIT_TTFB=$(vless_screen_admit_ttfb "${NOW:11:2}")
    python3 "$CFST_DIR/cooldown.py" --quality "$SCREEN_BLACKLIST" --capacity "$CAPACITY_COOLDOWN" \
      --quality-hours "$SCREEN_BLACKLIST_HOURS" --capacity-hours "$CAPACITY_COOLDOWN_HOURS" \
      --now "$(date '+%F %T')" > "$NEW_ROWS"
    python3 "$CFST_DIR/admission.py" select --contenders "$CONTENDERS" \
      --queue "$DISCOVERED" --excluded "$NEW_ROWS" --requested "$SCREEN_IN" \
      --pool-max "$POOL_MAX" --screen-max "$VLESS_SCREEN_MAX"
    SCREEN_COUNT=$(awk 'END{print NR+0}' "$SCREEN_IN")
    if (( SCREEN_COUNT > 0 )); then
      log "discovery screen: candidates=$SCREEN_COUNT (admit TTFB<=${SCREEN_ADMIT_TTFB}ms, max_fail=${VLESS_SCREEN_MAX_FAIL})"
      SCREEN_STARTED=$(date '+%F %T')
      SCREEN_RC=0
      VLESS_SCREEN_ADMIT_TTFB="$SCREEN_ADMIT_TTFB" \
        "$CFST_DIR/verify_vless.sh" --screen "$SCREEN_IN" "$SCREEN_OUT" >> "$LOG" 2>&1 || SCREEN_RC=$?
      if (( SCREEN_RC == 0 )); then
        ADMITTED=-1
        python3 "$CFST_DIR/admission.py" --contenders "$CONTENDERS" \
          --requested "$SCREEN_IN" --passed "$SCREEN_OUT" --queue "$DISCOVERED" \
          --blacklist "$SCREEN_BLACKLIST" --now "$SCREEN_STARTED" \
          --pool-max "$POOL_MAX" --max-fail "$VLESS_SCREEN_MAX_FAIL" \
          --quality-hours "$SCREEN_BLACKLIST_HOURS"
        ADMITTED=$(awk 'END{print NR+0}' "$SCREEN_OUT")
      else
        SCREEN_FAILED=1
        : > "$SCREEN_OUT"
        log "discovery screen failed (非致命，本轮新候选不入池、不计失败)"
      fi
      log "discovery screen: screen_pass=$(awk 'END{print NR+0}' "$SCREEN_OUT") contenders=$(pool_ips | awk 'END{print NR+0}') queue=$(awk 'END{print NR+0}' "$DISCOVERED") blacklist=$(awk 'END{print NR+0}' "$SCREEN_BLACKLIST" 2>/dev/null || echo 0)"
    fi
  fi

  # 路由探测与候选池无共享写入；主动释放锁，避免 MTR 阶段阻塞下一次高频扫描。
  flock -u 9
  if [ "$SHADOW" = "0" ] && [ -s "$BEST" ] && [ -x "$CFST_DIR/probe.sh" ]; then
    "$CFST_DIR/probe.sh" --all || { PROBE_FAILED=1; log "MTR 探测失败（非致命）"; }
  fi

  # 保留最近 7 天日志（旧 CSV 自然过期清理）。
  find "$RESULT_DIR" -name '*.csv' -mtime +7 -delete
  find "$RESULT_DIR" -name '*.log' -mtime +7 -delete
  # 兜底回收被 SIGKILL 打断、EXIT trap 未能删除的点号临时文件（mktemp 名不以
  # .log/.csv 结尾，上面的 7 天保留规则命中不了）。一次运行最长约 11 分钟。
  find "$RESULT_DIR" -maxdepth 1 -type f -mmin +180 \
    \( -name '.discovered.*' -o -name '.audit-in.*' -o -name '.audit.*' -o -name '.rank.*' -o -name '.rank-result.*' -o -name '..rank-result.*' \
       -o -name '.screen-in.*' -o -name '.screen-out.*' -o -name '.pool-set.*' \
       -o -name '.contenders.*' -o -name '.newrows.*' -o -name '.lat_*' \) -delete
fi
finish_line
