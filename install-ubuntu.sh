#!/usr/bin/env bash
# offpatch — one-command setup for Ubuntu (22.04 / 24.04, amd64 or arm64).
#
#   sudo ./install-ubuntu.sh                       # all-in-one lab: server + acquisition + local agent
#   sudo ./install-ubuntu.sh --role server         # isolated-zone management server only
#   sudo ./install-ubuntu.sh --role acquisition    # connected-zone downloader (pmctl auto) only
#   sudo ./install-ubuntu.sh --role agent --server https://pm.example:8443 --token enr_... \
#        --ca ca.pem --pubkey bundle.pub [--root-pubkey root.pub]
#   sudo ./install-ubuntu.sh --status              # show what is installed and running
#   sudo ./install-ubuntu.sh --uninstall           # stop and remove services (keeps data unless --purge)
#
# Options: --hosts "pm.corp.local,10.0.0.5"  extra names/IPs for the server TLS certificate
#          --port 8443                        server port
#          --insecure-lab                     plain HTTP (isolated lab only; NOT for production)
#          --no-agent                         all-in-one without the local agent
#          --go-version 1.27.2                Go toolchain to install if needed
#
# Safe to re-run: existing keys, certificates, tokens and data are kept.
# Run from the repository root (the folder containing this script).
set -euo pipefail

# ---------------------------------------------------------------- settings
ROLE="all"
PORT=8443
EXTRA_HOSTS=""
INSECURE=0
WITH_AGENT=1
GO_VERSION="1.27.2"
AGENT_SERVER="" AGENT_TOKEN="" AGENT_CA="" AGENT_PUB="" AGENT_ROOT=""
UNINSTALL=0 PURGE=0 STATUS=0

PREFIX=/opt/offpatch                 # binaries
ETC=/etc/offpatch                    # config, PKI, keys
SRV_DATA=/var/lib/offpatch-server    # server data (db, inbox, repository)
ACQ_DATA=/var/lib/offpatch-acq       # acquisition work dir
AGENT_STATE=/var/lib/offpatch        # local agent identity
SVC_USER=offpatch

SRC="$(cd "$(dirname "$0")" && pwd)"

c_blue=$'\033[1;34m'; c_green=$'\033[1;32m'; c_yellow=$'\033[1;33m'; c_red=$'\033[1;31m'; c_off=$'\033[0m'
step() { printf '\n%s==> %s%s\n' "$c_blue" "$*" "$c_off"; }
ok()   { printf '%s  ✔ %s%s\n' "$c_green" "$*" "$c_off"; }
warn() { printf '%s  ! %s%s\n' "$c_yellow" "$*" "$c_off"; }
die()  { printf '%s  ✘ %s%s\n' "$c_red" "$*" "$c_off" >&2; exit 1; }

usage() { sed -n '2,22p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }

while [ $# -gt 0 ]; do
  case "$1" in
    --role) ROLE="$2"; shift ;;
    --port) PORT="$2"; shift ;;
    --hosts) EXTRA_HOSTS="$2"; shift ;;
    --insecure-lab) INSECURE=1 ;;
    --no-agent) WITH_AGENT=0 ;;
    --go-version) GO_VERSION="$2"; shift ;;
    --server) AGENT_SERVER="$2"; shift ;;
    --token) AGENT_TOKEN="$2"; shift ;;
    --ca) AGENT_CA="$2"; shift ;;
    --pubkey) AGENT_PUB="$2"; shift ;;
    --root-pubkey) AGENT_ROOT="$2"; shift ;;
    --uninstall) UNINSTALL=1 ;;
    --purge) PURGE=1 ;;
    --status) STATUS=1 ;;
    -h|--help) usage 0 ;;
    *) echo "unknown option: $1"; usage 1 ;;
  esac
  shift
done

case "$ROLE" in all|server|acquisition|agent) ;; *) die "--role must be all, server, acquisition or agent" ;; esac
[ "$(id -u)" -eq 0 ] || die "run as root: sudo $0 $*"

HAVE_SYSTEMD=0
if [ -d /run/systemd/system ] && command -v systemctl >/dev/null; then HAVE_SYSTEMD=1; fi

# ---------------------------------------------------------------- status / uninstall
svc_state() { if [ $HAVE_SYSTEMD = 1 ]; then systemctl is-active "$1" 2>/dev/null || true; else pgrep -f "$2" >/dev/null && echo "running (no systemd)" || echo "not running"; fi; }

if [ $STATUS = 1 ]; then
  echo "pmserver:          $(svc_state offpatch-server 'offpatch/bin/pmserver')"
  echo "agent:             $(svc_state offpatch-agent 'offpatch/bin/pmagent run')"
  echo "acquisition timer: $( [ $HAVE_SYSTEMD = 1 ] && systemctl is-active offpatch-acquire.timer 2>/dev/null || echo 'cron/manual')"
  [ -f "$ETC/admin-token.txt" ] && echo "admin token:       $ETC/admin-token.txt"
  [ -f "$ETC/console-url.txt" ] && echo "console:           $(cat "$ETC/console-url.txt")"
  exit 0
fi

if [ $UNINSTALL = 1 ]; then
  step "Stopping and removing offpatch services"
  if [ $HAVE_SYSTEMD = 1 ]; then
    systemctl disable --now offpatch-server offpatch-acquire.timer 2>/dev/null || true
    [ -x $PREFIX/bin/pmagent ] && $PREFIX/bin/pmagent service uninstall 2>/dev/null || true
    rm -f /etc/systemd/system/offpatch-server.service /etc/systemd/system/offpatch-acquire.service /etc/systemd/system/offpatch-acquire.timer
    systemctl daemon-reload
  else
    pkill -f 'offpatch/bin/pmserver' 2>/dev/null || true
    pkill -f 'offpatch/bin/pmagent run' 2>/dev/null || true
  fi
  rm -rf "$PREFIX"
  if [ $PURGE = 1 ]; then
    rm -rf "$ETC" "$SRV_DATA" "$ACQ_DATA" "$AGENT_STATE"
    userdel "$SVC_USER" 2>/dev/null || true
    ok "removed binaries, services, configuration, keys and all data"
  else
    ok "removed binaries and services; kept $ETC and data (use --purge to delete them)"
  fi
  exit 0
fi

# ---------------------------------------------------------------- checks
step "Checking the system"
. /etc/os-release 2>/dev/null || true
[ "${ID:-}" = "ubuntu" ] || warn "this script targets Ubuntu; detected ${PRETTY_NAME:-unknown} — continuing"
case "$(uname -m)" in
  x86_64) GOARCH=amd64 ;;
  aarch64|arm64) GOARCH=arm64 ;;
  *) die "unsupported CPU architecture $(uname -m)" ;;
esac
[ -f "$SRC/go.mod" ] && [ -d "$SRC/cmd/pmserver" ] || die "run this script from the offpatch repository root"
ok "${PRETTY_NAME:-Linux} ($GOARCH), systemd: $([ $HAVE_SYSTEMD = 1 ] && echo yes || echo 'no — processes will be started directly')"

# ---------------------------------------------------------------- packages + Go
step "Installing build prerequisites"
export DEBIAN_FRONTEND=noninteractive
if command -v apt-get >/dev/null; then
  apt-get update -qq
  apt-get install -y -qq ca-certificates curl tar >/dev/null
fi
ok "curl, tar, CA certificates"

need_go=1
if command -v go >/dev/null; then
  have=$(go env GOVERSION | sed 's/^go//')
  if [ "$(printf '%s\n%s\n' "1.27.1" "$have" | sort -V | head -1)" = "1.27.1" ]; then need_go=0; GO=go; ok "Go $have already installed"; fi
fi
if [ $need_go = 1 ] && [ -x /usr/local/go/bin/go ]; then
  have=$(/usr/local/go/bin/go env GOVERSION | sed 's/^go//')
  if [ "$(printf '%s\n%s\n' "1.27.1" "$have" | sort -V | head -1)" = "1.27.1" ]; then need_go=0; GO=/usr/local/go/bin/go; ok "Go $have already installed"; fi
fi
if [ $need_go = 1 ]; then
  tgz="go${GO_VERSION}.linux-${GOARCH}.tar.gz"
  echo "  downloading $tgz from go.dev …"
  # The JSON is pretty-printed: flatten it, then split per file object.
  sha=$(curl -fsSL "https://go.dev/dl/?mode=json&include=all" | tr -d '\n ' | tr '{' '\n' | grep "\"filename\":\"$tgz\"" | grep -o '"sha256":"[0-9a-f]*"' | cut -d'"' -f4 | head -1 || true)
  [ -n "$sha" ] || die "could not find the published checksum for $tgz"
  tmp=$(mktemp -d)
  curl -fsSL -o "$tmp/$tgz" "https://go.dev/dl/$tgz"
  echo "$sha  $tmp/$tgz" | sha256sum -c --quiet - || die "Go download failed its SHA-256 check"
  rm -rf /usr/local/go && tar -C /usr/local -xzf "$tmp/$tgz" && rm -rf "$tmp"
  GO=/usr/local/go/bin/go
  ok "installed Go $GO_VERSION (SHA-256 verified)"
fi

# ---------------------------------------------------------------- build
step "Building offpatch"
mkdir -p "$PREFIX/bin"
VERSION=$(cd "$SRC" && git describe --tags --always 2>/dev/null || echo dev)
export GOFLAGS=-trimpath CGO_ENABLED=0
( cd "$SRC"
  $GO build -ldflags "-s -w -X offpatch/internal/agent.Version=0.1.0 -X offpatch/internal/server.Version=$VERSION" -o "$PREFIX/bin/pmserver" ./cmd/pmserver
  $GO build -ldflags "-s -w" -o "$PREFIX/bin/pmctl" ./cmd/pmctl
  $GO build -ldflags "-s -w -X offpatch/internal/agent.Version=0.1.0" -o "$PREFIX/bin/pmagent" ./cmd/pmagent )
ln -sf "$PREFIX/bin/pmserver" /usr/local/bin/pmserver
ln -sf "$PREFIX/bin/pmctl" /usr/local/bin/pmctl
ln -sf "$PREFIX/bin/pmagent" /usr/local/bin/pmagent
ok "pmserver, pmctl, pmagent → $PREFIX/bin (version $VERSION)"

id "$SVC_USER" >/dev/null 2>&1 || useradd --system --home "$SRV_DATA" --shell /usr/sbin/nologin "$SVC_USER"
install -d -m 0750 -o root -g "$SVC_USER" "$ETC"

SCHEME=https; [ $INSECURE = 1 ] && SCHEME=http
IP=$(hostname -I 2>/dev/null | awk '{print $1}')
HOSTS="$(hostname),localhost,127.0.0.1${IP:+,$IP}${EXTRA_HOSTS:+,$EXTRA_HOSTS}"
URL_LOCAL="$SCHEME://127.0.0.1:$PORT"
URL_PUBLIC="$SCHEME://${IP:-$(hostname)}:$PORT"

# ---------------------------------------------------------------- keys
if [ "$ROLE" = all ] || [ "$ROLE" = acquisition ] || [ "$ROLE" = server ]; then
  step "Signing keys"
  install -d -m 0750 -o root -g "$SVC_USER" "$ETC/keys"
  if [ ! -f "$ETC/keys/bundle.key" ]; then
    ( cd "$ETC/keys" && "$PREFIX/bin/pmctl" keygen -out bundle >/dev/null && "$PREFIX/bin/pmctl" keygen -out root >/dev/null )
    ok "created bundle signing key and root key in $ETC/keys"
  else
    ok "keeping existing keys in $ETC/keys"
  fi
  chown root:"$SVC_USER" "$ETC/keys"/*; chmod 0640 "$ETC/keys"/*.key; chmod 0644 "$ETC/keys"/*.pub
  # Only `pmctl trust` needs the root key; no service may read it.
  chown root:root "$ETC/keys/root.key"; chmod 0600 "$ETC/keys/root.key"
  # Only `pmctl trust` needs the root key; no service may read it.
  chown root:root "$ETC/keys/root.key"; chmod 0600 "$ETC/keys/root.key"
  if [ "$ROLE" = server ]; then
    warn "role=server: replace $ETC/keys/bundle.pub and root.pub with the PUBLIC keys from your acquisition host, then restart"
  fi
  if [ "$ROLE" = all ]; then
    warn "lab: the root key lives on this box. In production keep root.key OFFLINE (USB in a safe / HSM)"
  fi
fi

# ---------------------------------------------------------------- server
start_server() {
  if [ $HAVE_SYSTEMD = 1 ]; then
    cat > /etc/systemd/system/offpatch-server.service <<EOF
[Unit]
Description=offpatch management server
After=network-online.target
Wants=network-online.target

[Service]
User=$SVC_USER
Group=$SVC_USER
ExecStart=$PREFIX/bin/pmserver -config $ETC/pmserver.json
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=$SRV_DATA $ETC/pki
AmbientCapabilities=CAP_NET_BIND_SERVICE
UMask=0027

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable offpatch-server >/dev/null 2>&1
    systemctl restart offpatch-server
  else
    pkill -f "$PREFIX/bin/pmserver" 2>/dev/null || true
    runuser -u "$SVC_USER" -- nohup "$PREFIX/bin/pmserver" -config "$ETC/pmserver.json" >> "$SRV_DATA/pmserver.log" 2>&1 &
  fi
}

CURL_CA=()
if [ "$ROLE" = all ] || [ "$ROLE" = server ]; then
  step "Management server"
  install -d -m 0750 -o "$SVC_USER" -g "$SVC_USER" "$SRV_DATA" "$SRV_DATA/inbox" "$SRV_DATA/agent-dist" "$SRV_DATA/audit-export"
  chmod 0770 "$SRV_DATA/inbox"   # the local acquisition job (group offpatch) drops bundles here
  if [ $INSECURE = 0 ] && [ ! -f "$ETC/pki/ca.pem" ]; then
    "$PREFIX/bin/pmserver" init-pki -dir "$ETC/pki" -hosts "$HOSTS" >/dev/null
    ok "created internal CA and server certificate for: $HOSTS"
  fi
  [ -d "$ETC/pki" ] && { chown -R "$SVC_USER":"$SVC_USER" "$ETC/pki"; chmod 0700 "$ETC/pki"; chmod 0644 "$ETC/pki/ca.pem"; }
  if [ ! -f "$ETC/admin-token.txt" ]; then
    out=$("$PREFIX/bin/pmserver" new-token)
    tok=$(echo "$out" | awk '/^token:/{print $2}'); sha=$(echo "$out" | awk '/^token_sha256:/{print $2}')
    printf '%s\n' "$tok" > "$ETC/admin-token.txt"; chmod 0600 "$ETC/admin-token.txt"
    printf '%s\n' "$sha" > "$ETC/admin-token.sha256"
    ok "created break-glass admin token → $ETC/admin-token.txt"
  fi
  sha=$(cat "$ETC/admin-token.sha256")
  if [ ! -f "$ETC/pmserver.json" ]; then
    if [ $INSECURE = 1 ]; then tlsline='"insecure_http": true,'; else tlsline="\"pki_dir\": \"$ETC/pki\","; fi
    cat > "$ETC/pmserver.json" <<EOF
{
  "listen": "0.0.0.0:$PORT",
  $tlsline
  "data_dir": "$SRV_DATA",
  "trusted_keys": [{"public_key_file": "$ETC/keys/bundle.pub", "sources": ["acq-zone-1"]}],
  "root_public_key_file": "$ETC/keys/root.pub",
  "admin_tokens": [{"user": "admin", "role": "admin", "token_sha256": "$sha"}],
  "audit_export_dir": "$SRV_DATA/audit-export",
  "audit_checkpoint_interval": "1h",
  "intake_interval": "5s",
  "checkin_interval_seconds": 60
}
EOF
    chown root:"$SVC_USER" "$ETC/pmserver.json"; chmod 0640 "$ETC/pmserver.json"
    ok "wrote $ETC/pmserver.json"
  else
    ok "keeping existing $ETC/pmserver.json"
  fi
  # Offer agent binaries for download in the console (Agent setup page).
  ( cd "$SRC" && for t in windows/amd64:pmagent.exe linux/amd64:pmagent-linux-amd64 linux/arm64:pmagent-linux-arm64 darwin/arm64:pmagent-macos-arm64; do
      os=${t%%/*}; rest=${t#*/}; arch=${rest%%:*}; name=${rest#*:}
      GOOS=$os GOARCH=$arch $GO build -ldflags "-s -w" -o "$SRV_DATA/agent-dist/$name" ./cmd/pmagent || exit 1
    done ) && ok "agent binaries for Windows, Linux and macOS staged for the console's Agent setup page"
  chown -R "$SVC_USER":"$SVC_USER" "$SRV_DATA"; chmod 0770 "$SRV_DATA/inbox"
  start_server
  [ $INSECURE = 0 ] && CURL_CA=(--cacert "$ETC/pki/ca.pem")
  for i in $(seq 1 30); do
    curl -fs -o /dev/null "${CURL_CA[@]}" "$URL_LOCAL/" && break
    sleep 1
  done
  curl -fs -o /dev/null "${CURL_CA[@]}" "$URL_LOCAL/" || die "server did not start; check: journalctl -u offpatch-server (or $SRV_DATA/pmserver.log)"
  echo "$URL_PUBLIC" > "$ETC/console-url.txt"
  ok "server running at $URL_PUBLIC"
  if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
    ufw allow "$PORT"/tcp >/dev/null && ok "opened port $PORT in ufw"
  fi
fi

# ---------------------------------------------------------------- acquisition (connected zone)
if [ "$ROLE" = all ] || [ "$ROLE" = acquisition ]; then
  step "Acquisition (pmctl auto)"
  install -d -m 0750 -o "$SVC_USER" -g "$SVC_USER" "$ACQ_DATA"
  DROP="$SRV_DATA/inbox"
  [ "$ROLE" = acquisition ] && { DROP="$ACQ_DATA/outbox"; install -d -m 0750 -o "$SVC_USER" -g "$SVC_USER" "$DROP"; }
  if [ ! -f "$ETC/acquire.json" ]; then
    cat > "$ETC/acquire.json" <<EOF
{
  "work_dir": "$ACQ_DATA",
  "sequence_state": "$ACQ_DATA/sequence.json",
  "source": "acq-zone-1",
  "key": "$ETC/keys/bundle.key",
  "schedule": "daily at 07:00 (systemd timer)",
  "send": { "via": "dropdir", "to": "$DROP", "log": "$ACQ_DATA/sent.jsonl" },
  "microsoft": {
    "months": 1,
    "min_severity": "critical",
    "products": [
      { "msrc_product": "Windows 11 Version 24H2", "catalog_product": "Windows 11 Version 24H2", "arch": "x64", "min_build": 26100, "max_build": 26100 }
    ]
  },
  "apps": [
    {
      "name": "firefox-win", "title": "Mozilla Firefox (Windows x64 en-US)", "vendor": "Mozilla", "kind": "msi", "arch": "x64",
      "severity": "important", "package_name": "Mozilla Firefox (x64 en-US)",
      "version": { "url": "https://product-details.mozilla.org/1.0/firefox_versions.json", "json_path": "LATEST_FIREFOX_VERSION" },
      "download_url": "https://download-installer.cdn.mozilla.net/pub/firefox/releases/{version}/win64/en-US/Firefox%20Setup%20{version}.msi",
      "file_name": "firefox-{version}-win64-en-US.msi",
      "sha256": { "url": "https://archive.mozilla.org/pub/firefox/releases/{version}/SHA256SUMS", "regex": "([0-9a-f]{64})  win64/en-US/Firefox Setup {version}\\\\.msi" },
      "product_code": "{00000000-0000-0000-0000-000000000000}"
    }
  ]
}
EOF
    chown root:"$SVC_USER" "$ETC/acquire.json"; chmod 0640 "$ETC/acquire.json"
    ok "wrote $ETC/acquire.json (Windows 11 24H2 critical updates + Firefox for Windows) — edit it for your fleet"
    warn "Firefox MSI product codes change per version: on a Linux host set the real product_code, or run acquisition on Windows with product_code_from_msi"
  else
    ok "keeping existing $ETC/acquire.json"
  fi
  if [ $HAVE_SYSTEMD = 1 ]; then
    cat > /etc/systemd/system/offpatch-acquire.service <<EOF
[Unit]
Description=offpatch unattended patch acquisition
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
User=$SVC_USER
ExecStart=$PREFIX/bin/pmctl auto -config $ETC/acquire.json
SuccessExitStatus=2
TimeoutStartSec=4h
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=$ACQ_DATA $DROP
EOF
    cat > /etc/systemd/system/offpatch-acquire.timer <<EOF
[Unit]
Description=Daily offpatch acquisition run

[Timer]
OnCalendar=*-*-* 07:00
RandomizedDelaySec=15m
Persistent=true

[Install]
WantedBy=timers.target
EOF
    systemctl daemon-reload
    systemctl enable --now offpatch-acquire.timer >/dev/null 2>&1
    ok "daily acquisition at 07:00 (systemd timer offpatch-acquire.timer)"
  else
    warn "no systemd: run acquisition manually or from cron: $PREFIX/bin/pmctl auto -config $ETC/acquire.json"
  fi
  [ "$ROLE" = acquisition ] && warn "role=acquisition: bundles are written to $DROP — point send.to / send.command at your transfer gateway"
fi

# ---------------------------------------------------------------- local agent
enroll_agent() { # server token ca pub root
  local args=(enroll -server "$1" -token "$2" -pubkey "$4" -platform linux -state-dir "$AGENT_STATE")
  [ -n "$3" ] && args+=(-ca "$3")
  [ -n "${5:-}" ] && args+=(-root-pubkey "$5")
  "$PREFIX/bin/pmagent" "${args[@]}"
}
start_agent() {
  if [ $HAVE_SYSTEMD = 1 ]; then
    "$PREFIX/bin/pmagent" service install -state-dir "$AGENT_STATE" >/dev/null
  else
    pkill -f "$PREFIX/bin/pmagent run" 2>/dev/null || true
    nohup "$PREFIX/bin/pmagent" run -state-dir "$AGENT_STATE" >> /var/log/offpatch-agent.log 2>&1 &
  fi
}

if [ "$ROLE" = agent ]; then
  step "Endpoint agent"
  [ -n "$AGENT_SERVER" ] && [ -n "$AGENT_TOKEN" ] && [ -n "$AGENT_PUB" ] || die "--role agent needs --server, --token and --pubkey (and --ca for https)"
  if [ ! -f "$AGENT_STATE/agent.json" ]; then
    enroll_agent "$AGENT_SERVER" "$AGENT_TOKEN" "$AGENT_CA" "$AGENT_PUB" "$AGENT_ROOT"
  else
    ok "already enrolled ($AGENT_STATE/agent.json)"
  fi
  start_agent
  ok "agent running; it checks in every 60 s"
fi

if [ "$ROLE" = all ] && [ $WITH_AGENT = 1 ]; then
  step "Local agent (this machine as a managed endpoint)"
  if [ ! -f "$AGENT_STATE/agent.json" ]; then
    tokjson=$(curl -fs "${CURL_CA[@]}" -H "Authorization: Bearer $(cat "$ETC/admin-token.txt")" -H 'Content-Type: application/json' \
      -X POST "$URL_LOCAL/api/enrollment-tokens" -d '{"groups":["linux","lab"],"site":"lab","expires_in_hours":1}')
    etok=$(echo "$tokjson" | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
    [ -n "$etok" ] || die "could not create an enrollment token: $tokjson"
    ca=""; [ $INSECURE = 0 ] && ca="$ETC/pki/ca.pem"
    enroll_agent "$URL_LOCAL" "$etok" "$ca" "$ETC/keys/bundle.pub" "$ETC/keys/root.pub" >/dev/null
    ok "enrolled this machine (groups: linux, lab)"
  else
    ok "already enrolled"
  fi
  start_agent
  ok "agent running"
fi

# ---------------------------------------------------------------- summary
step "Done"
if [ "$ROLE" = all ] || [ "$ROLE" = server ]; then
  cat <<EOF
  Console:        $URL_PUBLIC
  Admin token:    sudo cat $ETC/admin-token.txt   (paste into "Break-glass / automation token")
EOF
  [ $INSECURE = 0 ] && cat <<EOF
  TLS:            the console uses the internal CA $ETC/pki/ca.pem — import it into your browser /
                  OS trust store, or accept the certificate warning once for this lab.
  Enroll others:  console → Endpoints → Create enrollment token (shows ready-to-copy commands),
                  or on another Ubuntu box:
                    sudo ./install-ubuntu.sh --role agent --server $URL_PUBLIC --token <enr_…> \\
                         --ca ca.pem --pubkey bundle.pub --root-pubkey root.pub
                  (copy ca.pem, bundle.pub, root.pub from $ETC/pki and $ETC/keys)
EOF
  [ $INSECURE = 1 ] && warn "lab mode: plain HTTP and bearer device secrets — never use outside an isolated lab"
fi
if [ "$ROLE" = all ] || [ "$ROLE" = acquisition ]; then
  echo "  Acquisition:    edit $ETC/acquire.json, test with: sudo -u $SVC_USER $PREFIX/bin/pmctl auto -config $ETC/acquire.json -dry-run"
fi
cat <<EOF
  Status:         sudo $0 --status
  Uninstall:      sudo $0 --uninstall   (add --purge to delete keys and data)
EOF
