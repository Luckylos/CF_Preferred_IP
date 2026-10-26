#!/usr/bin/env bash
set -euo pipefail
ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
cp "$ROOT/examples/history.tsv" "$TMP/history.tsv"
cp "$ROOT/examples/contenders.tsv" "$TMP/contenders.tsv"
cp "$ROOT/examples/published.txt" "$TMP/published.txt"
cp "$ROOT/examples/quality_cooldown.tsv" "$TMP/quality.tsv"
cp "$ROOT/examples/capacity_cooldown.tsv" "$TMP/capacity.tsv"
python3 "$ROOT/rank.py" \
  --history "$TMP/history.tsv" \
  --contenders "$TMP/contenders.tsv" \
  --best "$TMP/published.txt" \
  --blacklist "$TMP/quality.tsv" \
  --capacity-cooldown "$TMP/capacity.tsv" \
  --now "2026-01-02 01:00:00"
