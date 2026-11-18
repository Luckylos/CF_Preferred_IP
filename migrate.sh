#!/bin/bash
# migrate.sh — 切换到 Contender pool（设计 §6 步骤 3；计划 Task 7/Task 9）。
#   1. master_ips.txt（origin=master，全部）+ probation_pool.tsv 第 2 列（origin=probation，
#      仅最近 MIGRATE_PROBATION_HOURS=24 小时内在 ${VLESS_HISTORY:-$ROOT/vless_history.tsv}
#      中有 PASS 样本者；history 缺失则全部导入）→ contenders.tsv（ip<TAB>first_seen<TAB>last_sampled<TAB>origin），去重、master 优先、原子写。
#      first_seen：master 取 master_state.tsv 的 last_pass（第 2 列），probation 取第 1 列；缺失用当前时间。
#      last_sampled：master 取 master_state.tsv 的 last_checked（第 4 列），否则同 first_seen。
#   2. master_ips.txt / master_state.tsv / probation_pool.tsv 改名加 .legacy（保留 7 天后由用户清理）。
#   3. run.sh 备份为 run.sh.legacy，替换为 exec cycle.sh slow 的薄壳（现有 2h cron 行无需改动）。
#   4. 打印需用户手动添加的 fast cron 行（本脚本不改 crontab）。
#   影子池采用：若 .shadow/contenders.tsv 存在（影子期已连续采样/淘汰 48h），以它为准，只补入
#   尚不在影子池且不在影子黑名单的当前 master IP（影子期间新晋升者不丢）；影子黑名单并入
#   .screen_blacklist.tsv（沿用 24h 冷却）；.shadow 改名 .shadow.adopted 留档。
# 幂等：已迁移则提示并 exit 0；持锁（cycle/run/scan 正在跑）则 exit 75，不改任何文件。
# 测试覆盖：MIGRATE_ROOT 指定数据根目录（默认 $CFST_DIR），MIGRATE_LOCK 指定锁文件
# （默认：ROOT 为生产目录时用 $CFST_LOCK，否则 $ROOT/.cfst.lock）。
# 影子模式：migrate.sh --shadow-out FILE 只执行步骤 1 的"生成"并写到 FILE（不改名、不替换 run.sh、
# 不取锁——调用方 run.sh 正持锁，且本模式只读旧文件），供切换前的影子池同步使用。
set -euo pipefail
source "$(dirname "$0")/config.sh"

SHADOW_OUT=""
if [ "${1:-}" = "--shadow-out" ]; then
  SHADOW_OUT="${2:?--shadow-out 需要输出文件路径}"
fi

ROOT="${MIGRATE_ROOT:-$CFST_DIR}"
if [ "$ROOT" = "$CFST_DIR" ]; then
  LOCK="${MIGRATE_LOCK:-$CFST_LOCK}"
else
  LOCK="${MIGRATE_LOCK:-$ROOT/.cfst.lock}"
fi
if [ -z "$SHADOW_OUT" ]; then
  exec 9>"$LOCK"
  if ! flock -n 9; then
    echo "[$(date '+%F %T')] migrate: lock busy ($LOCK) — a cycle/run/scan is running; retry later" >&2
    exit 75
  fi
fi
cd "$ROOT"

MASTER_F="$ROOT/$(basename "$MASTER")"
STATE_F="$ROOT/$(basename "$MASTER_STATE")"
PROB_F="$ROOT/$(basename "$PROBATION_POOL")"
CONT_F="$ROOT/$(basename "$CONTENDERS")"
RUN_F="$ROOT/run.sh"
FAST_CRON='7-59/15 * * * * cd /opt/cfst && /usr/bin/bash cycle.sh fast >> results/fast.log 2>&1'

print_cron_hint() {
  echo "请手动添加快周期 cron 行（本脚本不改 crontab）："
  echo "$FAST_CRON"
}

# ── 幂等（影子生成模式不做状态检查）──
if [ -z "$SHADOW_OUT" ] && [ -f "$CONT_F" ] && [ -f "$MASTER_F.legacy" ] && [ ! -f "$MASTER_F" ]; then
  echo "[$(date '+%F %T')] migrate: 已迁移（$CONT_F 存在且旧文件已为 .legacy），无需重复执行"
  print_cron_hint
  exit 0
fi
if [ -z "$SHADOW_OUT" ] && [ -f "$CONT_F" ]; then
  echo "[$(date '+%F %T')] migrate: $CONT_F 已存在但旧文件未改名 .legacy，状态不一致，请人工检查" >&2
  exit 1
fi
if [ ! -f "$MASTER_F" ]; then
  echo "[$(date '+%F %T')] migrate: $MASTER_F 不存在，无可迁移数据" >&2
  exit 1
fi

NOW=$(date '+%F %T')
HISTORY_F="${VLESS_HISTORY:-$ROOT/vless_history.tsv}"
MIGRATE_PROBATION_HOURS="${MIGRATE_PROBATION_HOURS:-24}"
HIST_CUTOFF=$(date -d "-${MIGRATE_PROBATION_HOURS} hours" '+%F %T')
if [ ! -f "$HISTORY_F" ]; then
  echo "[$(date '+%F %T')] migrate: history $HISTORY_F 不存在，probation 候选全部导入" >&2
fi
TMP=$(mktemp "$ROOT/.contenders.XXXXXX")
trap 'rm -f "$TMP"' EXIT

# ── 生成 contenders.tsv ──
{
  printf '# contenders.tsv — ip\tfirst_seen\tlast_sampled\torigin\n'
  # master：经 ip_validation 过滤，再从 master_state 取 last_pass / last_checked
  grep -vE '^[[:space:]]*(#|$)' "$MASTER_F" | awk '{print $1}' \
    | python3 "$CFST_DIR/ip_validation.py" --filter \
    | awk -F'\t' -v OFS='\t' -v now="$NOW" -v state="$STATE_F" '
        BEGIN {
          # state 文件缺失时 getline 返回 -1，循环不执行
          while ((getline line < state) > 0) {
            n = split(line, f, "\t")
            if (line ~ /^[[:space:]]*#/ || n < 2 || f[1] == "") continue
            if (f[2] ~ /^[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9] [0-9][0-9]:[0-9][0-9]:[0-9][0-9]$/) fs[f[1]] = f[2]
            if (n >= 4 && f[4] ~ /^[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9] [0-9][0-9]:[0-9][0-9]:[0-9][0-9]$/) ls[f[1]] = f[4]
          }
          close(state)
        }
        { first = ($1 in fs) ? fs[$1] : now
          last  = ($1 in ls) ? ls[$1] : first
          print $1, first, last, "master" }' || true
  # probation：第 2 列 IP，第 1 列首次达标时间。
  # 只导入最近 MIGRATE_PROBATION_HOURS 内在 history 中有 PASS 样本的候选：全量导入 ~524 个
  # 会让首轮 slow audit 超过 20 分钟；24h 内有 PASS 的约 204 个，3 个 slow 周期后由
  # rank 规则 1 收敛。history 缺失时无法判断活跃度 → 全部导入（宁多勿漏）。
  if [ -f "$PROB_F" ]; then
    grep -vE '^[[:space:]]*(#|$)' "$PROB_F" \
      | python3 "$CFST_DIR/ip_validation.py" --filter --field 2 \
      | awk -F'\t' -v OFS='\t' -v now="$NOW" -v hist="$HISTORY_F" -v cutoff="$HIST_CUTOFF" '
          BEGIN {
            # history 缺失：getline 返回 -1，all=1 表示不过滤
            all = 1
            while ((getline line < hist) > 0) {
              all = 0
              n = split(line, f, "\t")
              if (n >= 3 && f[3] == "PASS" && f[1] >= cutoff) active[f[2]] = 1
            }
            close(hist)
          }
          NF >= 2 && (all || ($2 in active)) {
            first = ($1 ~ /^[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9] [0-9][0-9]:[0-9][0-9]:[0-9][0-9]$/) ? $1 : now
            print $2, first, first, "probation" }' || true
  fi
} | awk -F'\t' '/^#/ || !seen[$1]++' > "$TMP"

# ── 影子池采用（仅真正迁移时；--shadow-out 是为影子期生成候选，不在此列）──
SHADOW_F="$ROOT/.shadow/contenders.tsv"
SHADOW_BL="$ROOT/.shadow/blacklist.tsv"
ADOPTED=0
if [ -z "$SHADOW_OUT" ] && [ -s "$SHADOW_F" ]; then
  TMP2=$(mktemp "$ROOT/.contenders.XXXXXX")
  trap 'rm -f "$TMP" "$TMP2"' EXIT
  touch "$SHADOW_BL"
  {
    cat "$SHADOW_F"
    # 补入：当前 master（origin=master 的生成行）中不在影子池、不在影子黑名单的 IP
    awk -F'\t' '
      FILENAME==ARGV[1] { if ($0 !~ /^[[:space:]]*(#|$)/) seen[$1]=1; next }
      FILENAME==ARGV[2] { if ($1!="") bl[$1]=1; next }
      /^[[:space:]]*(#|$)/ { next }
      $4=="master" && !($1 in seen) && !($1 in bl) { print }
    ' "$SHADOW_F" "$SHADOW_BL" "$TMP"
  } | awk -F'\t' '/^#/ || !seen[$1]++' > "$TMP2"
  mv "$TMP2" "$TMP"
  ADOPTED=1
fi

ROWS=$(grep -cvE '^[[:space:]]*(#|$)' "$TMP" || true)
if [ "$ROWS" -eq 0 ]; then
  echo "[$(date '+%F %T')] migrate: 生成的 contenders 为空，拒绝迁移" >&2
  exit 1
fi

if [ -n "$SHADOW_OUT" ]; then
  chmod 644 "$TMP"
  mv "$TMP" "$SHADOW_OUT"
  trap - EXIT
  exit 0
fi

# ── 落盘：先原子写新文件，再改名旧文件（任一步失败都不会丢旧数据）──
chmod 644 "$TMP"
mv "$TMP" "$CONT_F"
trap - EXIT
if [ "$ADOPTED" = "1" ]; then
  BL_F="$ROOT/$(basename "$SCREEN_BLACKLIST")"
  if [ -s "$SHADOW_BL" ]; then
    cat "$SHADOW_BL" >> "$BL_F"
  fi
  rm -rf "$ROOT/.shadow.adopted"
  mv "$ROOT/.shadow" "$ROOT/.shadow.adopted"
  echo "[$(date '+%F %T')] migrate: 采用影子池 $SHADOW_F（并入当前 master 新成员；影子黑名单并入 $(basename "$BL_F")；.shadow → .shadow.adopted）"
fi
for f in "$MASTER_F" "$STATE_F" "$PROB_F"; do
  if [ -f "$f" ]; then
    mv "$f" "$f.legacy"
  fi
done

# ── run.sh → 薄壳 ──
if [ -f "$RUN_F" ] && [ ! -f "$RUN_F.legacy" ]; then
  cp -p "$RUN_F" "$RUN_F.legacy"
fi
RUN_TMP=$(mktemp "$ROOT/.run.sh.XXXXXX")
cat > "$RUN_TMP" <<'SHELL'
#!/bin/bash
# run.sh — 薄壳（由 migrate.sh 生成）：慢周期已迁移到 cycle.sh slow，保留此文件兼容现有 2h cron 行。
# 旧实现见 run.sh.legacy；回滚用 rollback.sh。
set -euo pipefail
CFST_DIR="$(cd "$(dirname "$0")" && pwd)"
exec "$CFST_DIR/cycle.sh" slow "$@"
SHELL
chmod 755 "$RUN_TMP"
mv "$RUN_TMP" "$RUN_F"

echo "[$(date '+%F %T')] migrate: contenders=$ROWS 行 → $CONT_F；旧文件已改名 .legacy；run.sh 已替换为薄壳（备份 run.sh.legacy）"
print_cron_hint
