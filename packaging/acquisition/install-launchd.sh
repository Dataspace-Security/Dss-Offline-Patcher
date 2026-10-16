#!/bin/sh
# Installs a per-user launchd job that runs `pmctl auto` daily (macOS
# acquisition host). Usage: install-launchd.sh <pmctl> <acquire.json> [HH] [MM]
#   Uninstall: launchctl bootout gui/$(id -u)/com.offpatch.acquire && rm ~/Library/LaunchAgents/com.offpatch.acquire.plist
set -e
PMCTL=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
CFG=$(cd "$(dirname "$2")" && pwd)/$(basename "$2")
HOUR=${3:-7}; MIN=${4:-0}
LOG="$(dirname "$CFG")/auto/launchd.log"
mkdir -p "$(dirname "$LOG")" "$HOME/Library/LaunchAgents"
PLIST="$HOME/Library/LaunchAgents/com.offpatch.acquire.plist"
cat > "$PLIST" <<PL
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>com.offpatch.acquire</string>
  <key>ProgramArguments</key><array><string>$PMCTL</string><string>auto</string><string>-config</string><string>$CFG</string></array>
  <key>StartCalendarInterval</key><dict><key>Hour</key><integer>$HOUR</integer><key>Minute</key><integer>$MIN</integer></dict>
  <key>StandardOutPath</key><string>$LOG</string>
  <key>StandardErrorPath</key><string>$LOG</string>
  <key>ProcessType</key><string>Background</string>
</dict></plist>
PL
launchctl bootout "gui/$(id -u)/com.offpatch.acquire" 2>/dev/null || true
launchctl bootstrap "gui/$(id -u)" "$PLIST"
echo "scheduled daily at $(printf %02d:%02d "$HOUR" "$MIN"): $PMCTL auto -config $CFG (log: $LOG)"
echo "run now: launchctl kickstart gui/$(id -u)/com.offpatch.acquire"
