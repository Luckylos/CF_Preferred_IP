#!/bin/bash
# run.sh — 薄壳（由 migrate.sh 生成）：慢周期已迁移到 cycle.sh slow，保留此文件兼容现有 2h cron 行。
# 旧实现见 run.sh.legacy；回滚用 rollback.sh。
set -euo pipefail
CFST_DIR="$(cd "$(dirname "$0")" && pwd)"
exec "$CFST_DIR/cycle.sh" slow "$@"
