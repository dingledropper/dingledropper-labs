#!/usr/bin/env bash
# bbops notify — sends a one-line alert via Discord or Telegram, else logs it.
# Usage: ./notify.sh "your message"
set -euo pipefail

BBOPS_HOME="${BBOPS_HOME:-$HOME/bbops}"
[[ -f "$BBOPS_HOME/.env" ]] && set -a && . "$BBOPS_HOME/.env" && set +a

MSG="${1:-bbops: (no message)}"
mkdir -p "$BBOPS_HOME"
printf '%s  %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$MSG" >> "$BBOPS_HOME/alerts.log"

if [[ -n "${DISCORD_WEBHOOK_URL:-}" ]]; then
  curl -fsS -H 'Content-Type: application/json' \
    -d "$(jq -nc --arg c "$MSG" '{content:$c}')" \
    "$DISCORD_WEBHOOK_URL" >/dev/null && exit 0
fi

if [[ -n "${TELEGRAM_BOT_TOKEN:-}" && -n "${TELEGRAM_CHAT_ID:-}" ]]; then
  curl -fsS "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
    --data-urlencode "chat_id=${TELEGRAM_CHAT_ID}" \
    --data-urlencode "text=${MSG}" >/dev/null && exit 0
fi

# No channel configured — the line is already in alerts.log.
echo "[notify] no webhook configured; logged to $BBOPS_HOME/alerts.log"
