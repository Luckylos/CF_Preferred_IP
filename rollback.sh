#!/bin/bash
# rollback.sh — 撤销 migrate.sh 的切换（设计 §6 步骤 4）。
#   1. master_ips.txt / master_state.tsv / probation_pool.tsv 从 .legacy 恢复；
#   2. run.sh 从 run.sh.legacy 恢复（薄壳被覆盖）；
#   3. contenders.tsv 改名 contenders.tsv.rolledback（保留证据，不删）；
#   4. 提示用户手动删除 fast cron 行（本脚本不改 crontab）。
# 若恢复目标已存在（非预期），先把它改名为 <name>.pre_rollback 再恢复，不覆盖任何数据。
# 幂等：无 .legacy 且无 contenders.tsv 时提示并 exit 0；持锁则 exit 75，不改任何文件。
# 测试覆盖：MIGRATE_ROOT / MIGRATE_LOCK 语义同 migrate.sh。
set -euo pipefail
source "$(dirname "$0")/config.sh"

ROOT="${MIGRATE_ROOT:-$CFST_DIR}"
if [ "$ROOT" = "$CFST_DIR" ]; then
  LOCK="${MIGRATE_LOCK:-$CFST_LOCK}"
else
  LOCK="${MIGRATE_LOCK:-$ROOT/.cfst.lock}"
fi
exec 9>"$LOCK"
if ! flock -n 9; then
  echo "[$(date '+%F %T')] rollback: lock busy ($LOCK) — a cycle/run/scan is running; retry later" >&2
  exit 75
fi
cd "$ROOT"

MASTER_F="$ROOT/$(basename "$MASTER")"
STATE_F="$ROOT/$(basename "$MASTER_STATE")"
PROB_F="$ROOT/$(basename "$PROBATION_POOL")"
CONT_F="$ROOT/$(basename "$CONTENDERS")"
RUN_F="$ROOT/run.sh"

print_cron_hint() {
  echo "请手动删除快周期 cron 行（本脚本不改 crontab）："
  echo "7-59/15 * * * * cd /opt/cfst && /usr/bin/bash cycle.sh fast >> results/fast.log 2>&1"
}

# ── 幂等 ──
HAS_LEGACY=0
for f in "$MASTER_F" "$STATE_F" "$PROB_F" "$RUN_F"; do
  [ -f "$f.legacy" ] && HAS_LEGACY=1
done
if [ "$HAS_LEGACY" -eq 0 ] && [ ! -f "$CONT_F" ]; then
  echo "[$(date '+%F %T')] rollback: 无 .legacy 文件且无 $CONT_F，已处于回滚后状态，无需重复执行"
  print_cron_hint
  exit 0
fi

# 恢复 src.legacy → src；src 已存在时先挪到 src.pre_rollback（不覆盖）
restore() {
  local f="$1"
  if [ -f "$f.legacy" ]; then
    if [ -e "$f" ] && [ "$f" != "$RUN_F" ]; then
      mv "$f" "$f.pre_rollback"
      echo "[$(date '+%F %T')] rollback: $f 已存在，保留为 $f.pre_rollback"
    fi
    mv "$f.legacy" "$f"
    echo "[$(date '+%F %T')] rollback: 已恢复 $f"
  fi
}

restore "$MASTER_F"
restore "$STATE_F"
restore "$PROB_F"
restore "$RUN_F"    # 薄壳直接被旧 run.sh 覆盖（薄壳可由 migrate.sh 再生成）

if [ -f "$CONT_F" ]; then
  mv "$CONT_F" "$CONT_F.rolledback"
  echo "[$(date '+%F %T')] rollback: $CONT_F → $CONT_F.rolledback"
fi

# Task 10（2026-10-15）删除了旧链路模块；旧 run.sh 依赖它们，缺失时从 git 历史恢复（最后含有它们的提交）。
LEGACY_MODULES_COMMIT="${LEGACY_MODULES_COMMIT:-b29b261}"
MISSING=()
for m in score.py pool.py probation_pool.py; do
  [ -f "$ROOT/$m" ] || MISSING+=("$m")
done
if [ "${#MISSING[@]}" -gt 0 ]; then
  if git -C "$ROOT" show "$LEGACY_MODULES_COMMIT:score.py" >/dev/null 2>&1; then
    for m in "${MISSING[@]}"; do
      git -C "$ROOT" show "$LEGACY_MODULES_COMMIT:$m" > "$ROOT/$m"
      chmod +x "$ROOT/$m"
      echo "[$(date '+%F %T')] rollback: 已从 git $LEGACY_MODULES_COMMIT 恢复 $m"
    done
  else
    echo "[$(date '+%F %T')] rollback: 警告：旧链路模块缺失（${MISSING[*]}）且无法从 git $LEGACY_MODULES_COMMIT 恢复；旧 run.sh 将无法运行" >&2
  fi
fi

echo "[$(date '+%F %T')] rollback: 完成"
print_cron_hint
