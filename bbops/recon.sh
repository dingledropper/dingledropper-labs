#!/usr/bin/env bash
# bbops recon — scope-gated subfinder -> httpx -> nuclei, diffed against last run.
# Refuses to run without an explicit in-scope allowlist. Thermal-aware.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BBOPS_HOME="${BBOPS_HOME:-$HOME/bbops}"
SCOPE_FILE="${SCOPE_FILE:-$SCRIPT_DIR/scope.txt}"
EXCLUDE_FILE="${EXCLUDE_FILE:-$SCRIPT_DIR/scope-exclude.txt}"

# Thermal knobs — keep these modest on a fanless Air.
NUCLEI_CONCURRENCY="${NUCLEI_CONCURRENCY:-20}"
NUCLEI_RATELIMIT="${NUCLEI_RATELIMIT:-100}"
HTTPX_THREADS="${HTTPX_THREADS:-30}"
SEVERITY="${SEVERITY:-low,medium,high,critical}"

# Load optional secrets (webhooks) without printing them.
[[ -f "$BBOPS_HOME/.env" ]] && set -a && . "$BBOPS_HOME/.env" && set +a

log()  { printf '\033[1;36m[recon]\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m[recon] ERROR:\033[0m %s\n' "$*" >&2; exit 1; }

# --- AUTHORIZATION GATE --------------------------------------------------
[[ -f "$SCOPE_FILE" ]] || die "No scope file at $SCOPE_FILE. Copy scope.txt.example and add YOUR authorized roots."
# strip comments/blank lines
mapfile -t ROOTS < <(grep -vE '^\s*(#|$)' "$SCOPE_FILE" | tr -d '\r' | awk 'NF')
[[ ${#ROOTS[@]} -gt 0 ]] || die "Scope file is empty. Add authorized root domains, one per line."
log "In-scope roots: ${#ROOTS[@]}"

RUN="$BBOPS_HOME/runs/$(date +%Y%m%d-%H%M%S)"
LATEST="$BBOPS_HOME/runs/latest"
mkdir -p "$RUN"
printf '%s\n' "${ROOTS[@]}" > "$RUN/roots.txt"

# Keep the machine awake only while we work (no-op off-macOS).
CAFFEINATE=""
command -v caffeinate >/dev/null 2>&1 && CAFFEINATE="caffeinate -i"

# --- 1. enumerate subdomains --------------------------------------------
log "subfinder..."
$CAFFEINATE subfinder -dL "$RUN/roots.txt" -silent 2>/dev/null | sort -u > "$RUN/subs.all.txt" || true

# --- 2. apply exclusions (out-of-scope discipline) ----------------------
if [[ -f "$EXCLUDE_FILE" ]]; then
  grep -vE '^\s*(#|$)' "$EXCLUDE_FILE" | tr -d '\r' | awk 'NF' > "$RUN/exclude.txt" || true
  grep -vF -f "$RUN/exclude.txt" "$RUN/subs.all.txt" > "$RUN/subs.txt" || cp "$RUN/subs.all.txt" "$RUN/subs.txt"
else
  cp "$RUN/subs.all.txt" "$RUN/subs.txt"
fi
log "$(wc -l < "$RUN/subs.txt" | tr -d ' ') in-scope hostnames after exclusions."

# --- 3. probe live hosts -------------------------------------------------
log "httpx (threads=$HTTPX_THREADS)..."
nice -n 10 $CAFFEINATE httpx -l "$RUN/subs.txt" -silent -threads "$HTTPX_THREADS" \
  -title -status-code -tech-detect -o "$RUN/live.txt" 2>/dev/null || true
awk '{print $1}' "$RUN/live.txt" 2>/dev/null | sort -u > "$RUN/live.hosts.txt" || true
log "$(wc -l < "$RUN/live.hosts.txt" 2>/dev/null | tr -d ' ') live hosts."

# --- 4. nuclei scan (low priority, capped concurrency) ------------------
log "nuclei (c=$NUCLEI_CONCURRENCY, rl=$NUCLEI_RATELIMIT, sev=$SEVERITY)..."
nice -n 10 $CAFFEINATE nuclei -l "$RUN/live.hosts.txt" \
  -severity "$SEVERITY" -c "$NUCLEI_CONCURRENCY" -rate-limit "$NUCLEI_RATELIMIT" \
  -silent -jsonl -o "$RUN/nuclei.jsonl" 2>/dev/null || true

# --- 5. diff against previous run ---------------------------------------
NEW_HOSTS=0; NEW_FINDINGS=0
if [[ -d "$LATEST" ]]; then
  comm -13 <(sort "$LATEST/live.hosts.txt" 2>/dev/null) <(sort "$RUN/live.hosts.txt" 2>/dev/null) > "$RUN/new.hosts.txt" || true
  if command -v jq >/dev/null 2>&1; then
    jq -r '."template-id" + " " + (.host // .matched_at // "")' "$RUN/nuclei.jsonl" 2>/dev/null | sort -u > "$RUN/findings.txt" || true
    jq -r '."template-id" + " " + (.host // .matched_at // "")' "$LATEST/nuclei.jsonl" 2>/dev/null | sort -u > "$RUN/findings.prev.txt" || true
    comm -13 "$RUN/findings.prev.txt" "$RUN/findings.txt" > "$RUN/new.findings.txt" 2>/dev/null || true
  fi
else
  cp "$RUN/live.hosts.txt" "$RUN/new.hosts.txt" 2>/dev/null || true
  [[ -f "$RUN/nuclei.jsonl" ]] && cp "$RUN/nuclei.jsonl" "$RUN/new.findings.txt"
fi
NEW_HOSTS=$(wc -l < "$RUN/new.hosts.txt" 2>/dev/null | tr -d ' ' || echo 0)
NEW_FINDINGS=$(wc -l < "$RUN/new.findings.txt" 2>/dev/null | tr -d ' ' || echo 0)

ln -sfn "$RUN" "$LATEST"
log "Run complete. NEW hosts: $NEW_HOSTS | NEW findings: $NEW_FINDINGS"
log "Results: $RUN"

# --- 6. notify only when something changed ------------------------------
if [[ "$NEW_HOSTS" -gt 0 || "$NEW_FINDINGS" -gt 0 ]]; then
  MSG="bbops recon: $NEW_HOSTS new host(s), $NEW_FINDINGS new finding(s). See $RUN"
  "$SCRIPT_DIR/notify.sh" "$MSG" || true
fi
