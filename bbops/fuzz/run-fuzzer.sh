#!/usr/bin/env bash
# bbops fuzz — thermal-throttled libFuzzer runner for a fanless Mac.
# Leaves cores free, runs niced, keeps the machine awake (not cooked).
#
# Usage:
#   ./run-fuzzer.sh <fuzzer-binary> [corpus-dir]
# Build a fuzzer first, e.g.:
#   clang -g -O1 -fsanitize=fuzzer,address examples/parser_fuzz.c -o /tmp/parser_fuzz
set -euo pipefail

BIN="${1:?usage: run-fuzzer.sh <fuzzer-binary> [corpus-dir]}"
CORPUS="${2:-./corpus}"
ARTIFACTS="${ARTIFACTS:-./crashes}"

# Thermal policy: by default use HALF the cores, minimum 1. Override with JOBS=.
CORES="$(sysctl -n hw.ncpu 2>/dev/null || nproc 2>/dev/null || echo 2)"
JOBS="${JOBS:-$(( CORES / 2 > 0 ? CORES / 2 : 1 ))}"
# Per-run time cap so it duty-cycles instead of pinning all-core forever.
MAX_TOTAL_TIME="${MAX_TOTAL_TIME:-3600}"   # seconds; 0 = unlimited (not advised on a Air)
RSS_LIMIT_MB="${RSS_LIMIT_MB:-2048}"

mkdir -p "$CORPUS" "$ARTIFACTS"
echo "[fuzz] binary=$BIN cores=$CORES jobs=$JOBS max_total_time=${MAX_TOTAL_TIME}s"
echo "[fuzz] corpus=$CORPUS artifacts=$ARTIFACTS"
echo "[fuzz] (fanless: keeping $((CORES - JOBS)) core(s) free, running niced)"

CAFFEINATE=""
command -v caffeinate >/dev/null 2>&1 && CAFFEINATE="caffeinate -i"

# shellcheck disable=SC2086
exec nice -n 10 $CAFFEINATE "$BIN" \
  "$CORPUS" \
  -jobs="$JOBS" -workers="$JOBS" \
  -max_total_time="$MAX_TOTAL_TIME" \
  -rss_limit_mb="$RSS_LIMIT_MB" \
  -artifact_prefix="$ARTIFACTS/"
