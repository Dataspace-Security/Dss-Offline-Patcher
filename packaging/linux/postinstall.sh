#!/bin/sh
# Enroll (if /etc/offpatch/enroll.env is present and the device is not yet
# enrolled) and install/start the systemd service.
set -e
STATE=/var/lib/offpatch
ENV=/etc/offpatch/enroll.env
if [ ! -f "$STATE/agent.json" ] && [ -f "$ENV" ]; then
  # shellcheck disable=SC1090
  . "$ENV"
  set -- enroll -server "$SERVER" -token "$TOKEN" -pubkey "$PUBKEY" -state-dir "$STATE" -platform linux
  [ -n "${CA:-}" ] && set -- "$@" -ca "$CA"
  [ -n "${ROOT:-}" ] && set -- "$@" -root-pubkey "$ROOT"
  if /usr/sbin/pmagent "$@"; then
    rm -f "$ENV"
  else
    echo "offpatch: enrollment failed; fix $ENV and run: pmagent enroll ... && pmagent service install" >&2
    exit 0
  fi
fi
if [ -f "$STATE/agent.json" ] && command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
  /usr/sbin/pmagent service install -state-dir "$STATE" || true
  systemctl try-restart offpatch-agent >/dev/null 2>&1 || true
fi
exit 0
