#!/usr/bin/env bash
set -euo pipefail

# Safe local template. Do not place credentials or real node endpoints here.
CFST_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
SECRETS_DIR="$HOME/.config/cf-preferred-ip"

# Copy to config.local.sh for local experiments. CHANGE_ME values are intentional.
export CFST_DIR
export SECRETS_DIR
export PROVIDER_NAME="CHANGE_ME"
export POOL_MAX="150"
export SCREEN_MAX="20"
export HISTORY_WINDOW_DAYS="7"
export PROVIDER_ADAPTER="CHANGE_ME"

# The public package contains no provider adapter and performs no network access.
