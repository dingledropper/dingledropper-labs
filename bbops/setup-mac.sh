#!/usr/bin/env bash
# bbops setup — prepares an Apple-Silicon macOS machine as a recon/fuzz rig.
# Safe to re-run. Does NOT touch anything network-facing without your scope file.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BBOPS_HOME="${BBOPS_HOME:-$HOME/bbops}"

log()  { printf '\033[1;36m[bbops]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[bbops] WARN:\033[0m %s\n' "$*"; }

install_schedule() {
  local plist="$HOME/Library/LaunchAgents/com.dingledropper.recon.plist"
  mkdir -p "$HOME/Library/LaunchAgents"
  sed -e "s|__RECON__|$SCRIPT_DIR/recon.sh|g" \
      -e "s|__LOGDIR__|$BBOPS_HOME|g" \
      "$SCRIPT_DIR/launchd/com.dingledropper.recon.plist" > "$plist"
  launchctl unload "$plist" 2>/dev/null || true
  launchctl load "$plist"
  log "Scheduled recon.sh every 6h via launchd ($plist)."
  log "Logs: $BBOPS_HOME/launchd.out / launchd.err"
}

if [[ "${1:-}" == "--install-schedule" ]]; then
  install_schedule
  exit 0
fi

# --- sanity --------------------------------------------------------------
[[ "$(uname -s)" == "Darwin" ]] || { warn "This is meant for macOS. Continuing anyway."; }
log "Working dir: $BBOPS_HOME"
mkdir -p "$BBOPS_HOME/runs"

# --- homebrew ------------------------------------------------------------
if ! command -v brew >/dev/null 2>&1; then
  log "Installing Homebrew..."
  /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
  eval "$(/opt/homebrew/bin/brew shellenv)" 2>/dev/null || true
fi

# --- toolchain -----------------------------------------------------------
log "Installing recon toolchain via Homebrew (idempotent)..."
brew install subfinder httpx nuclei dnsx naabu katana jq || warn "Some brew installs failed; check above."
brew install --cask tailscale || warn "Tailscale cask failed; install manually if you want remote access."

log "Updating nuclei templates..."
nuclei -update-templates >/dev/null 2>&1 || warn "nuclei template update failed (run 'nuclei -update-templates' manually)."

# --- keep-awake guidance (needs sudo / GUI; we don't force it) -----------
cat <<EOF

$(log "Toolchain ready. To make it a true always-on rig, run these yourself:")

  sudo systemsetup -setremotelogin on     # enable SSH
  sudo pmset -c sleep 0                    # never sleep while on power
  tailscale up                             # join your private net (then do the same on your phone)

Then add your scope and install the schedule:

  cp scope.txt.example scope.txt           # <-- put YOUR authorized root domains here
  cp scope-exclude.txt.example scope-exclude.txt
  ./setup-mac.sh --install-schedule

Run a one-off recon now with:

  ./recon.sh

EOF
