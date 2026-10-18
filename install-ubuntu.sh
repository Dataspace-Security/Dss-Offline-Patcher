#!/usr/bin/env bash
# DSS Patcher (offpatch) setup for Ubuntu (22.04 / 24.04 / 26.04, amd64 or arm64).
#
# Production, one server (default):
#   sudo ./install-ubuntu.sh
#   = --role all: management server + console + downloader + backups on this machine, hardened:
#     egress lock (only the downloader account reaches the internet, TCP 80/443 + DNS), console
#     port limited to the local subnet when ufw is active, deployment disclosed in the compliance
#     report. Then move the offline root key off the server:
#   sudo ./install-ubuntu.sh --export-root-key /media/usb
#   Agents: console → Endpoints → Create enrollment token → run the PowerShell line on each PC.
#
# Two-machine layout (stricter: the internet-facing downloader holds no server data):
#   isolated zone   sudo ./install-ubuntu.sh --role server --hosts pm.corp.local,10.0.0.5 \
#                        --pubkey bundle.pub --root-pubkey root.pub --allow-from 10.0.0.0/16
#   connected zone  sudo ./install-ubuntu.sh --role acquisition
#   endpoint        sudo ./install-ubuntu.sh --role agent --server https://pm.example:8443 \
#                        --token enr_... --ca ca.pem --pubkey bundle.pub [--root-pubkey root.pub]
#
#   sudo ./install-ubuntu.sh --status
#   sudo ./install-ubuntu.sh --export-root-key DIR [--yes]   copy root.key to offline media, then shred it
#   sudo ./install-ubuntu.sh --uninstall [--purge [--yes]]
#
# Options:
#   --role all|server|acquisition|agent  default: the role of an earlier install, else all
#   --hosts "pm.corp.local,10.0.0.5"  extra names/IPs for the server certificate (first install)
#   --port 8443                       server port (first install; re-runs use pmserver.json)
#   --pubkey FILE / --root-pubkey FILE  role server: public keys from the acquisition host and the
#                                     offline root key (first install; never overwritten later).
#                                     role all: --root-pubkey uses an offline root key; none is created
#   --audit-dir PATH                  audit export dir (first install). Use separate / WORM storage
#   --allow-from CIDR                 ufw: allow the server port only from CIDR (repeatable; default:
#                                     the local subnet of this machine's address)
#   --no-egress-lock                  role all: do not install the nftables egress lock (remembered;
#                                     --egress-lock turns it back on)
#   --backup-dir PATH                 daily backups (default /var/lib/offpatch-backup)
#   --backup-keep N                   scheduled backups to keep (default 14)
#   --skip-backup                     upgrade without the automatic pre-upgrade backup
#   --insecure-lab                    plain HTTP (first install, isolated lab only)
#   --admin-email EMAIL               role server/all: sign-in email of the built-in super admin (vendor),
#                                     created when none exists (default superadmin@dataspacesecurity.com)
#                                     with the vendor's default password (see the vendor handbook); change
#                                     it after the first sign-in (lost: pmserver reset-admin)
#   --with-agent                      role all: also enroll this machine as a managed endpoint
#   --go-version 1.27.2               Go toolchain to install when building from source
#
# Re-running (same role) upgrades: keys, certificates, tokens, config and data are kept;
# a verified backup is taken first and the previous binaries are kept in /opt/offpatch/bin.prev.
set -euo pipefail

# ---------------------------------------------------------------- settings
ROLE=""
PORT=8443 PORT_SET=0
EXTRA_HOSTS=""
INSECURE=0 INSECURE_SET=0
WITH_AGENT=0
GO_VERSION="1.27.2"
AGENT_SERVER="" AGENT_TOKEN="" AGENT_CA="" PUBKEY_IN="" ROOTPUB_IN=""
AUDIT_DIR_IN="" BACKUP_DIR_IN="" BACKUP_KEEP_IN="" SKIP_BACKUP=0
ALLOW_FROM=()
ADMIN_EMAIL="superadmin@dataspacesecurity.com"
UNINSTALL=0 PURGE=0 STATUS=0 YES=0
EGRESS_LOCK_IN=""                    # 1 / 0 from --egress-lock / --no-egress-lock; empty = remembered or 1
EXPORT_ROOT_KEY=""                   # --export-root-key DIR

PREFIX=/opt/offpatch                 # binaries
ETC=/etc/offpatch                    # config, PKI, keys
SRV_DATA=/var/lib/offpatch-server    # server data (db, inbox, repository)
ACQ_DATA=/var/lib/offpatch-acq       # acquisition work dir
AGENT_STATE=/var/lib/offpatch        # local agent identity
SVC_USER=offpatch                    # runs pmserver
ACQ_USER=offpatch-acq                # runs pmctl auto (internet + bundle signing key)
XFER_GROUP=offpatch-inbox            # may drop files into the server inbox
ACQ_REQ_DIR=$ACQ_DATA/requests       # acquisition requests (role all: the server queues them here directly)
STATE_FILE=$ETC/install.state        # choices remembered for re-runs
EGRESS_TABLE=offpatch_egress         # nftables table (inet family) of the egress lock
EGRESS_NFT=/etc/nftables.d/offpatch.nft
EGRESS_UNIT=/etc/systemd/system/offpatch-egress.service
DEFAULT_BACKUP_DIR=/var/lib/offpatch-backup
DEFAULT_BACKUP_KEEP=14

SRC="$(cd "$(dirname "$0")" && pwd)"

c_blue=$'\033[1;34m'; c_green=$'\033[1;32m'; c_yellow=$'\033[1;33m'; c_red=$'\033[1;31m'; c_off=$'\033[0m'
step() { printf '\n%s==> %s%s\n' "$c_blue" "$*" "$c_off"; }
ok()   { printf '%s  ✔ %s%s\n' "$c_green" "$*" "$c_off"; }
warn() { printf '%s  ! %s%s\n' "$c_yellow" "$*" "$c_off"; }
die()  { printf '%s  ✘ %s%s\n' "$c_red" "$*" "$c_off" >&2; exit 1; }
banner() { # loud multi-line warning
  printf '\n%s' "$c_red"
  printf '  ************************************************************************\n'
  for l in "$@"; do printf '  * %s\n' "$l"; done
  printf '  ************************************************************************%s\n' "$c_off"
}

usage() { awk 'NR>1 && /^#/ {sub(/^# ?/, ""); print; next} NR>1 {exit}' "$0"; exit "${1:-0}"; }

while [ $# -gt 0 ]; do
  case "$1" in
    --role|--port|--hosts|--go-version|--server|--token|--ca|--pubkey|--root-pubkey|--audit-dir|--allow-from|--backup-dir|--backup-keep|--admin-email|--export-root-key)
      [ $# -ge 2 ] || die "$1 needs a value" ;;
  esac
  case "$1" in
    --role) ROLE="$2"; shift ;;
    --port) PORT="$2"; PORT_SET=1; shift ;;
    --hosts) EXTRA_HOSTS="$2"; shift ;;
    --insecure-lab) INSECURE=1; INSECURE_SET=1 ;;
    --with-agent) WITH_AGENT=1 ;;
    --no-agent) WITH_AGENT=0 ;;   # default; kept for older scripts
    --go-version) GO_VERSION="$2"; shift ;;
    --server) AGENT_SERVER="$2"; shift ;;
    --token) AGENT_TOKEN="$2"; shift ;;
    --ca) AGENT_CA="$2"; shift ;;
    --pubkey) PUBKEY_IN="$2"; shift ;;
    --root-pubkey) ROOTPUB_IN="$2"; shift ;;
    --audit-dir) AUDIT_DIR_IN="$2"; shift ;;
    --allow-from) ALLOW_FROM+=("$2"); shift ;;
    --backup-dir) BACKUP_DIR_IN="$2"; shift ;;
    --backup-keep) BACKUP_KEEP_IN="$2"; shift ;;
    --skip-backup) SKIP_BACKUP=1 ;;
    --admin-email) ADMIN_EMAIL="$2"; shift ;;
    --no-egress-lock) EGRESS_LOCK_IN=0 ;;
    --egress-lock) EGRESS_LOCK_IN=1 ;;
    --export-root-key) EXPORT_ROOT_KEY="$2"; shift ;;
    --uninstall) UNINSTALL=1 ;;
    --purge) PURGE=1 ;;
    --yes) YES=1 ;;
    --status) STATUS=1 ;;
    -h|--help) usage 0 ;;
    *) echo "unknown option: $1"; usage 1 ;;
  esac
  shift
done

state_get() { [ -f "$STATE_FILE" ] && sed -n "s/^$1=//p" "$STATE_FILE" | tail -n 1; return 0; }
if [ $STATUS = 0 ] && [ $UNINSTALL = 0 ] && [ -z "$EXPORT_ROOT_KEY" ]; then
  # No --role: keep the role of an earlier install (an upgrade), else single-server production (all).
  if [ -z "$ROLE" ]; then ROLE=$(state_get ROLE); ROLE=${ROLE:-all}; fi
  case "$ROLE" in all|server|acquisition|agent) ;; *) die "--role must be all (single server, default), server, acquisition or agent" ;; esac
  [ $WITH_AGENT = 0 ] || [ "$ROLE" = all ] || die "--with-agent is only for --role all; on other machines use --role agent"
fi
[ "$(id -u)" -eq 0 ] || die "run as root: sudo $0 $*"
EGRESS_LOCK=${EGRESS_LOCK_IN:-$(state_get EGRESS_LOCK)}; EGRESS_LOCK=${EGRESS_LOCK:-1}

# Values end up in JSON, systemd units and ufw rules: accept plain paths / numbers / CIDRs only.
safe_path() { [[ "$1" =~ ^/[A-Za-z0-9._/-]+$ ]] || die "$2 must be an absolute path of letters, digits, . _ - / (got: $1)"; }
[[ "$PORT" =~ ^[0-9]+$ ]] && [ "$PORT" -ge 1 ] && [ "$PORT" -le 65535 ] || die "--port must be 1-65535"
[ -z "$AUDIT_DIR_IN" ] || safe_path "$AUDIT_DIR_IN" --audit-dir
[ -z "$BACKUP_DIR_IN" ] || safe_path "$BACKUP_DIR_IN" --backup-dir
[ -z "$BACKUP_KEEP_IN" ] || { [[ "$BACKUP_KEEP_IN" =~ ^[0-9]+$ ]] && [ "$BACKUP_KEEP_IN" -ge 1 ]; } || die "--backup-keep must be a number >= 1"
# ufw sources given on an earlier run stay in force unless new --allow-from values are given.
if [ ${#ALLOW_FROM[@]} -eq 0 ]; then read -r -a ALLOW_FROM <<< "$(state_get ALLOW_FROM)"; fi
for c in ${ALLOW_FROM[@]+"${ALLOW_FROM[@]}"}; do
  [[ "$c" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?$ || "$c" =~ ^[0-9A-Fa-f:]+(/[0-9]{1,3})?$ ]] || die "--allow-from: not an IPv4/IPv6 address or CIDR: $c"
done

HAVE_SYSTEMD=0
if [ -d /run/systemd/system ] && command -v systemctl >/dev/null; then HAVE_SYSTEMD=1; fi

# Read a top-level key from an existing pmserver.json (booleans print as true/false).
cfg_get() {
  local f="$ETC/pmserver.json"
  [ -f "$f" ] || return 0
  if command -v python3 >/dev/null; then
    python3 -c 'import json,sys
v = json.load(open(sys.argv[1])).get(sys.argv[2])
print("" if v is None else (str(v).lower() if isinstance(v, bool) else v))' "$f" "$1" 2>/dev/null || true
  else
    sed -n "s/.*\"$1\"[[:space:]]*:[[:space:]]*\"\{0,1\}\([^\",}]*\)\"\{0,1\}.*/\1/p" "$f" | head -n 1
  fi
}
cfg_path() { local v; v=$(cfg_get "$1"); case "$v" in ""|/*) echo "$v" ;; *) echo "$ETC/$v" ;; esac; }

BACKUP_DIR=${BACKUP_DIR_IN:-$(state_get BACKUP_DIR)}; BACKUP_DIR=${BACKUP_DIR:-$DEFAULT_BACKUP_DIR}
BACKUP_KEEP=${BACKUP_KEEP_IN:-$(state_get BACKUP_KEEP)}; BACKUP_KEEP=${BACKUP_KEEP:-$DEFAULT_BACKUP_KEEP}

# ---------------------------------------------------------------- status
svc_state() { if [ $HAVE_SYSTEMD = 1 ]; then systemctl is-active "$1" 2>/dev/null || true; else pgrep -f "$2" >/dev/null && echo "running (no systemd)" || echo "not running"; fi; }

if [ $STATUS = 1 ]; then
  echo "installed role:    $(state_get ROLE || true)"
  echo "pmserver:          $(svc_state offpatch-server 'offpatch/bin/pmserver')"
  echo "agent:             $(svc_state offpatch-agent 'offpatch/bin/pmagent run')"
  echo "acquisition timer: $( [ $HAVE_SYSTEMD = 1 ] && systemctl is-active offpatch-acquire.timer 2>/dev/null || echo 'cron/manual')"
  if [ $HAVE_SYSTEMD = 1 ] && [ -f /etc/systemd/system/offpatch-acquire-requests.path ]; then
    echo "request watcher:   $(systemctl is-active offpatch-acquire-requests.path 2>/dev/null || true) (offpatch-acquire-requests.path)"
  fi
  echo "backup timer:      $( [ $HAVE_SYSTEMD = 1 ] && systemctl is-active offpatch-backup.timer 2>/dev/null || echo 'cron/manual')"
  [ -f "$BACKUP_DIR/last-success" ] && echo "last good backup:  $(head -n 1 "$BACKUP_DIR/last-success")"
  [ -f "$BACKUP_DIR/last-failure" ] && echo "last FAILED backup: $(cat "$BACKUP_DIR/last-failure")"
  if command -v nft >/dev/null && nft list table inet "$EGRESS_TABLE" >/dev/null 2>&1; then
    echo "egress lock:       active (nftables table $EGRESS_TABLE; only $ACQ_USER reaches the internet)"
  elif [ -f "$EGRESS_NFT" ]; then
    echo "egress lock:       NOT loaded ($EGRESS_NFT exists): sudo systemctl restart offpatch-egress"
  elif [ "$(state_get ROLE)" = all ]; then
    echo "egress lock:       off (--no-egress-lock)"
  fi
  [ -f "$ETC/keys/root.key" ] && echo "root key:          $ETC/keys/root.key is on this server: sudo $0 --export-root-key <offline media>"
  [ -f "$ETC/console-url.txt" ] && echo "console:           $(cat "$ETC/console-url.txt")"
  exit 0
fi

# ---------------------------------------------------------------- export the root key
# Copy root.key (+ root.pub, sha256 list) to offline media, verify the copy, then shred the
# server's copy. root.pub stays: the server and agents verify signed trust documents with it.
if [ -n "$EXPORT_ROOT_KEY" ]; then
  key="$ETC/keys/root.key" dst="$EXPORT_ROOT_KEY"
  [ -f "$key" ] || die "$key not found: nothing to export (already moved to offline media?)"
  case "$dst" in /*) ;; *) die "--export-root-key needs the absolute mount point of the offline media (e.g. /media/usb)" ;; esac
  [ -d "$dst" ] || die "$dst is not a directory: mount the offline media first"
  [ "$(stat -c %d "$dst")" != "$(stat -c %d "$ETC/keys")" ] \
    || die "$dst is on the same filesystem as $ETC: that is not offline media. Mount a USB drive / encrypted volume and give its mount point"
  if [ -e "$dst/root.key" ] && ! cmp -s "$key" "$dst/root.key"; then
    die "$dst/root.key exists and differs from $key: use an empty folder (nothing was changed)"
  fi
  step "Exporting the root key to $dst"
  sum=$(sha256sum "$key" | awk '{print $1}')
  install -m 0600 "$key" "$dst/root.key"
  [ -f "$ETC/keys/root.pub" ] && install -m 0644 "$ETC/keys/root.pub" "$dst/root.pub"
  files=(root.key); [ -f "$dst/root.pub" ] && files+=(root.pub)
  ( cd "$dst" && sha256sum "${files[@]}" > root.sha256 )
  sync
  [ "$(sha256sum "$dst/root.key" | awk '{print $1}')" = "$sum" ] || die "the copy on $dst does not match (SHA-256); $key was NOT deleted"
  ok "copied root.key$( [ -f "$dst/root.pub" ] && echo ', root.pub') and root.sha256 to $dst"
  ok "root.key SHA-256: $sum"
  if [ $YES = 0 ]; then
    [ -t 0 ] || die "confirm deleting $key from this server: re-run interactively, or add --yes"
    printf 'Store the media offline (safe / key custodian). Type DELETE to shred %s from this server: ' "$key"
    read -r answer
    [ "$answer" = DELETE ] || die "not deleted: $key is still on this server (the copy on $dst is kept)"
  fi
  if command -v shred >/dev/null; then shred -u "$key"; else rm -f "$key"; fi
  [ -e "$key" ] && die "could not delete $key"
  ok "deleted $key from this server; $ETC/keys/root.pub stays (public)"
  echo "  Keep the media offline. It is needed only for signed key rotation / revocation (runbook 03)."
  echo "  Unmount it now: sudo umount $dst"
  exit 0
fi

# ---------------------------------------------------------------- uninstall
list_secrets() {
  local f
  for f in "$ETC"/keys/*.key "$ETC/pki/ca.key" "$ETC/pki/server.key" "$SRV_DATA/audit-signing.key" "$AGENT_STATE"/*; do
    [ -e "$f" ] && warn "  still on disk: $f"
  done
  return 0
}

if [ $UNINSTALL = 1 ]; then
  AUDIT_LEFT=$(cfg_path audit_export_dir)
  if [ $PURGE = 1 ] && [ $YES = 0 ]; then
    [ -t 0 ] || die "--purge deletes signing keys, the CA key, tokens and all data. Non-interactive: add --yes"
    banner "--purge deletes $ETC (signing keys, CA key, tokens, config)," \
           "$SRV_DATA (database, repository, audit export), $ACQ_DATA and $AGENT_STATE." \
           "Backups in $BACKUP_DIR are NOT deleted."
    printf 'Type PURGE to continue: '; read -r answer
    [ "$answer" = PURGE ] || die "aborted; nothing was removed"
  fi
  step "Stopping and removing offpatch services"
  if [ $HAVE_SYSTEMD = 1 ]; then
    systemctl disable --now offpatch-server offpatch-acquire.timer offpatch-acquire-requests.path offpatch-backup.timer 2>/dev/null || true
    systemctl stop offpatch-acquire.service offpatch-acquire-requests.service offpatch-backup.service 2>/dev/null || true
    [ -x $PREFIX/bin/pmagent ] && $PREFIX/bin/pmagent service uninstall 2>/dev/null || true
    systemctl disable --now offpatch-egress.service 2>/dev/null || true
    for u in offpatch-server.service offpatch-acquire.service offpatch-acquire.timer offpatch-acquire-requests.path offpatch-acquire-requests.service offpatch-backup.service offpatch-backup.timer offpatch-backup-failed.service offpatch-egress.service; do
      rm -f "/etc/systemd/system/$u"
    done
    systemctl daemon-reload
  else
    pkill -f 'offpatch/bin/pmserver' 2>/dev/null || true
    pkill -f 'offpatch/bin/pmagent run' 2>/dev/null || true
  fi
  # Egress lock (role all): drop the nftables table and its file.
  if command -v nft >/dev/null && nft list table inet "$EGRESS_TABLE" >/dev/null 2>&1; then
    nft delete table inet "$EGRESS_TABLE" && ok "removed the egress lock (nftables table $EGRESS_TABLE)"
  fi
  rm -f "$EGRESS_NFT"
  for b in pmserver pmctl pmagent; do
    [ "$(readlink "/usr/local/bin/$b" 2>/dev/null)" = "$PREFIX/bin/$b" ] && rm -f "/usr/local/bin/$b"
  done
  rm -f /etc/logrotate.d/offpatch
  rm -rf "$PREFIX"
  if [ $PURGE = 1 ]; then
    rm -rf "$ETC" "$SRV_DATA" "$ACQ_DATA" "$AGENT_STATE"
    for u in "$SVC_USER" "$ACQ_USER"; do userdel "$u" 2>/dev/null || true; done
    groupdel "$XFER_GROUP" 2>/dev/null || true
    ok "removed binaries, services, configuration, keys and all data"
  else
    ok "removed binaries and services; kept $ETC and data (use --purge to delete them)"
    warn "secrets that remain (delete them per your key-destruction procedure, or keep them for a reinstall):"
    list_secrets
  fi
  [ -d "$BACKUP_DIR" ] && warn "backups kept in $BACKUP_DIR: they contain the CA private key and the database"
  case "$AUDIT_LEFT" in ""|"$SRV_DATA"/*) ;; *) [ -d "$AUDIT_LEFT" ] && warn "audit export kept in $AUDIT_LEFT" ;; esac
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
# A release tarball (`make dist`) ships prebuilt binaries next to this script:
# then nothing is downloaded or compiled, so it works in an offline zone.
PREBUILT="$SRC/bin/linux-$GOARCH"
if [ -f "$PREBUILT/pmserver" ] && [ -f "$PREBUILT/pmctl" ] && [ -f "$PREBUILT/pmagent" ]; then
  MODE=prebuilt
else
  MODE=source
  [ -f "$SRC/go.mod" ] && [ -d "$SRC/cmd/pmserver" ] || die "run this from the offpatch repository root or an unpacked release tarball"
fi
ok "${PRETTY_NAME:-Linux} ($GOARCH), systemd: $([ $HAVE_SYSTEMD = 1 ] && echo yes || echo 'no — processes will be started directly'), install from: $MODE"
if command -v timedatectl >/dev/null; then
  ntp=$(timedatectl show -p NTPSynchronized --value 2>/dev/null || true)
  if [ "$ntp" = yes ]; then ok "clock synchronized (NTP)"; else
    warn "clock NOT synchronized (NTPSynchronized=${ntp:-unknown}). Bundles dated >10 min in the future are rejected,"
    warn "and TLS, approvals and audit timestamps depend on it: configure an internal NTP source (chrony / timedatectl set-ntp true)"
  fi
fi

PREV_ROLE=$(state_get ROLE)
[ -z "$PREV_ROLE" ] || [ "$PREV_ROLE" = "$ROLE" ] || warn "this machine was installed with --role $PREV_ROLE; now --role $ROLE"

check_pub() { # file label
  [ -f "$1" ] || die "$2: $1 not found"
  if grep -q 'PRIVATE KEY' "$1"; then die "$2: $1 contains a PRIVATE key. Never copy private keys to this machine"; fi
  grep -q 'BEGIN OFFPATCH ED25519 PUBLIC KEY' "$1" || die "$2: $1 is not an offpatch public key (pmctl keygen writes <name>.pub)"
}

IS_SERVER=0; { [ "$ROLE" = all ] || [ "$ROLE" = server ]; } && IS_SERVER=1
IS_ACQ=0;    { [ "$ROLE" = all ] || [ "$ROLE" = acquisition ]; } && IS_ACQ=1

if [ "$ROLE" = server ]; then
  if compgen -G "$ETC/keys/*.key" >/dev/null; then
    die "role=server: private keys found in $ETC/keys: $(cd "$ETC/keys" && echo ./*.key). The management server must hold PUBLIC keys only.
     Move bundle.key to the acquisition host and root.key to offline custody (runbook 02 A1/A2), then remove them here:
       sudo shred -u $ETC/keys/*.key
     and re-run this command."
  fi
  if [ ! -f "$ETC/keys/bundle.pub" ] && [ -z "$PUBKEY_IN" ]; then
    die "role=server: first install needs --pubkey <bundle.pub> (from the acquisition host: $ETC/keys/bundle.pub) and, recommended, --root-pubkey <root.pub> (from the offline root key ceremony)"
  fi
  [ -z "$PUBKEY_IN" ] || check_pub "$PUBKEY_IN" --pubkey
  [ -z "$ROOTPUB_IN" ] || check_pub "$ROOTPUB_IN" --root-pubkey
fi
if [ "$ROLE" = agent ]; then
  [ -n "$AGENT_SERVER" ] && [ -n "$AGENT_TOKEN" ] && [ -n "$PUBKEY_IN" ] || [ -f "$AGENT_STATE/agent.json" ] || die "--role agent needs --server, --token and --pubkey (and --ca for https)"
  [ -z "$PUBKEY_IN" ] || check_pub "$PUBKEY_IN" --pubkey
  [ -z "$ROOTPUB_IN" ] || check_pub "$ROOTPUB_IN" --root-pubkey
fi

# Re-runs: listener and TLS mode come from the existing pmserver.json (it is never rewritten).
SERVER_CONFIGURED=0
LISTEN_HOST=""
if [ $IS_SERVER = 1 ] && [ -f "$ETC/pmserver.json" ]; then
  SERVER_CONFIGURED=1
  listen=$(cfg_get listen); listen=${listen:-127.0.0.1:8080}
  cfg_port=${listen##*:}; LISTEN_HOST=${listen%:*}
  [[ "$cfg_port" =~ ^[0-9]+$ ]] || die "cannot read the port from \"listen\": \"$listen\" in $ETC/pmserver.json"
  [ $PORT_SET = 0 ] || [ "$PORT" = "$cfg_port" ] || die "--port $PORT conflicts with $ETC/pmserver.json (listen $listen). Change \"listen\" there and re-run without --port"
  PORT=$cfg_port
  if [ "$(cfg_get insecure_http)" = true ]; then
    INSECURE=1
  elif [ $INSECURE_SET = 1 ]; then
    die "--insecure-lab conflicts with $ETC/pmserver.json (TLS is configured). Re-run without --insecure-lab"
  fi
  AUDIT_DIR=$(cfg_path audit_export_dir)
  [ -z "$AUDIT_DIR_IN" ] || [ "$AUDIT_DIR_IN" = "$AUDIT_DIR" ] || die "--audit-dir $AUDIT_DIR_IN conflicts with audit_export_dir \"$AUDIT_DIR\" in $ETC/pmserver.json. Change it there (see runbook 05 R5) and re-run without --audit-dir"
else
  AUDIT_DIR=${AUDIT_DIR_IN:-$SRV_DATA/audit-export}
fi

if [ "$ROLE" = all ]; then
  [ -z "$ROOTPUB_IN" ] || check_pub "$ROOTPUB_IN" --root-pubkey
  [ -z "$PUBKEY_IN" ] || die "--pubkey is for --role server/agent; role all creates its own bundle signing key"
  echo "  Single-server install: server, console and downloader on this machine (hardened)."
  echo "  A two-machine layout (--role server + --role acquisition) is stricter; see README, Install."
fi

# ---------------------------------------------------------------- users
ensure_user() { id "$1" >/dev/null 2>&1 || useradd --system --user-group --home "$2" --shell /usr/sbin/nologin "$1"; }
if [ $IS_SERVER = 1 ]; then
  ensure_user "$SVC_USER" "$SRV_DATA"
  getent group "$XFER_GROUP" >/dev/null || groupadd --system "$XFER_GROUP"
  usermod -aG "$XFER_GROUP" "$SVC_USER"
fi
if [ $IS_ACQ = 1 ]; then
  ensure_user "$ACQ_USER" "$ACQ_DATA"
  [ "$ROLE" = all ] && usermod -aG "$XFER_GROUP" "$ACQ_USER"
fi
# Lab (role all) only: pmserver queues acquisition requests straight into the acquisition
# requests folder (acquisition_requests_dir). The work dir is traversable (not listable) by
# group offpatch-inbox; the requests folder is offpatch-inbox 2770 (setgid) so the server can
# create files and offpatch-acq can read and move them. It must exist before the server
# starts: the unit's ReadWritePaths only covers paths that exist at start.
lab_requests_dir() {
  [ "$ROLE" = all ] || return 0
  [ -d "$ACQ_DATA" ] || install -d -o "$ACQ_USER" -g "$XFER_GROUP" "$ACQ_DATA"
  chgrp "$XFER_GROUP" "$ACQ_DATA"; chmod 0710 "$ACQ_DATA"
  install -d -o "$ACQ_USER" -g "$XFER_GROUP" "$ACQ_REQ_DIR"
  chgrp -R "$XFER_GROUP" "$ACQ_REQ_DIR"
  chmod 2770 "$ACQ_REQ_DIR"
  find "$ACQ_REQ_DIR" -mindepth 1 -type d -exec chmod g+s {} +
}
lab_requests_dir

# ---------------------------------------------------------------- egress lock (role all)
# nftables table inet offpatch_egress, output hook. Only the two offpatch accounts are matched
# (by uid); other users, root, SSH and every reply on an established connection (agents and
# browsers talking to the console) pass untouched. New outbound connections:
#   offpatch-acq (downloader)  loopback, TCP 80/443, DNS 53 (UDP/TCP); everything else refused
#   offpatch     (server)      loopback only
# Loaded at boot by offpatch-egress.service (no change to /etc/nftables.conf or ufw).
write_egress_rules() { # file svc-uid acq-uid
  cat > "$1" <<EOF
#!/usr/sbin/nft -f
# DSS Patcher single-server egress lock. Written by install-ubuntu.sh; re-runs rewrite it.
# Accounts: $SVC_USER (uid $2) may open new connections to loopback only;
#           $ACQ_USER (uid $3) to loopback, TCP 80/443 and DNS (53). Nothing else is matched.
table inet $EGRESS_TABLE
delete table inet $EGRESS_TABLE
table inet $EGRESS_TABLE {
  chain output {
    type filter hook output priority filter; policy accept;
    ct state established,related accept
    oifname "lo" accept
    meta skuid $3 ct state new tcp dport { 80, 443 } accept
    meta skuid $3 ct state new meta l4proto { tcp, udp } th dport 53 accept
    meta skuid { $2, $3 } limit rate 6/minute log prefix "offpatch-egress denied: "
    meta skuid { $2, $3 } counter reject with icmpx type admin-prohibited
  }
}
EOF
}

remove_egress_lock() {
  local had=0
  if [ -f "$EGRESS_UNIT" ] || [ -f "$EGRESS_NFT" ]; then had=1; fi
  if [ $HAVE_SYSTEMD = 1 ] && [ -f "$EGRESS_UNIT" ]; then
    systemctl disable --now offpatch-egress.service >/dev/null 2>&1 || true
    rm -f "$EGRESS_UNIT"; systemctl daemon-reload
  fi
  command -v nft >/dev/null && nft delete table inet "$EGRESS_TABLE" 2>/dev/null || true
  rm -f "$EGRESS_NFT"
  [ $had = 0 ] || ok "egress lock removed (nftables table $EGRESS_TABLE, offpatch-egress.service)"
  return 0
}

install_egress_lock() {
  step "Egress lock (nftables): only $ACQ_USER reaches the internet"
  if ! command -v nft >/dev/null; then
    command -v apt-get >/dev/null || die "nft not found and no apt-get: install nftables, or re-run with --no-egress-lock (not recommended)"
    export DEBIAN_FRONTEND=noninteractive
    { apt-get install -y -qq nftables >/dev/null 2>&1 || { apt-get update -qq && apt-get install -y -qq nftables >/dev/null; }; } \
      || die "nftables could not be installed (apt-get install nftables). Install it, or re-run with --no-egress-lock (not recommended)"
  fi
  local nft svc_uid acq_uid tmp
  nft=$(command -v nft)
  svc_uid=$(id -u "$SVC_USER"); acq_uid=$(id -u "$ACQ_USER")
  install -d -m 0755 "$(dirname "$EGRESS_NFT")"
  tmp=$(mktemp "$EGRESS_NFT.XXXXXX")
  write_egress_rules "$tmp" "$svc_uid" "$acq_uid"
  "$nft" -c -f "$tmp" || { rm -f "$tmp"; die "the egress ruleset failed nft's syntax check (nft $("$nft" --version 2>/dev/null)); nothing was changed. Re-run with --no-egress-lock to skip it"; }
  chmod 0644 "$tmp"; mv -f "$tmp" "$EGRESS_NFT"
  if [ $HAVE_SYSTEMD = 1 ]; then
    cat > "$EGRESS_UNIT" <<EOF
[Unit]
Description=DSS Patcher egress lock (nftables table $EGRESS_TABLE: only $ACQ_USER reaches the internet)
Documentation=file://$EGRESS_NFT
DefaultDependencies=no
Before=network-pre.target shutdown.target
Wants=network-pre.target
After=nftables.service
# Restarting nftables.service flushes the whole ruleset: load this table again after it.
PartOf=nftables.service
Conflicts=shutdown.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=$nft -f $EGRESS_NFT
ExecReload=$nft -f $EGRESS_NFT
ExecStop=-$nft delete table inet $EGRESS_TABLE

[Install]
WantedBy=multi-user.target nftables.service
EOF
    systemctl daemon-reload
    systemctl enable offpatch-egress.service >/dev/null 2>&1
    systemctl restart offpatch-egress.service || die "offpatch-egress.service failed: journalctl -u offpatch-egress"
  else
    "$nft" -f "$EGRESS_NFT"
    warn "no systemd: the egress lock is loaded now but not at boot. Load it from your init: $nft -f $EGRESS_NFT"
  fi
  "$nft" list table inet "$EGRESS_TABLE" >/dev/null 2>&1 || die "the egress lock did not load (nft list table inet $EGRESS_TABLE)"
  ok "$SVC_USER: no new outbound connections except loopback (replies to agents and browsers are unaffected)"
  ok "$ACQ_USER: outbound TCP 80/443 and DNS only; other users, root and SSH are not affected"
  ok "rules: $EGRESS_NFT, loaded at boot by offpatch-egress.service; refusals are logged as \"offpatch-egress denied:\" (journalctl -k)"
}

if [ "$ROLE" = all ] && [ "$EGRESS_LOCK" = 1 ]; then
  install_egress_lock
else
  if [ "$ROLE" = all ]; then warn "--no-egress-lock: the server and downloader accounts may open any outbound connection. Not recommended for production"; fi
  remove_egress_lock
fi

# ---------------------------------------------------------------- before upgrading
if [ -d "$PREFIX/bin" ]; then
  rm -rf "$PREFIX/bin.prev" && cp -a "$PREFIX/bin" "$PREFIX/bin.prev"
  ok "previous binaries kept in $PREFIX/bin.prev (roll back: stop the services, copy them back, start)"
fi
if [ $IS_SERVER = 1 ] && [ $SERVER_CONFIGURED = 1 ] && [ -f "$SRV_DATA/pm.db" ] && [ -x "$PREFIX/bin/pmserver" ]; then
  step "Pre-upgrade backup"
  if [ $SKIP_BACKUP = 1 ]; then
    warn "--skip-backup: upgrading without a pre-upgrade backup"
  else
    install -d -m 0700 -o "$SVC_USER" -g "$SVC_USER" "$BACKUP_DIR"
    pre="$BACKUP_DIR/pre-upgrade-$(date -u +%Y%m%dT%H%M%SZ)"
    if ( cd / && runuser -u "$SVC_USER" -- "$PREFIX/bin/pmserver" backup -config "$ETC/pmserver.json" -dir "$pre" >/dev/null \
         && runuser -u "$SVC_USER" -- "$PREFIX/bin/pmserver" verify-backup -dir "$pre" >/dev/null ); then
      ok "verified backup of the running version → $pre"
    else
      rm -rf "$pre"
      die "pre-upgrade backup failed (see above); nothing was changed. Fix it, or re-run with --skip-backup"
    fi
    # keep the 3 newest pre-upgrade backups; scheduled ones have their own retention
    find "$BACKUP_DIR" -maxdepth 1 -type d -name 'pre-upgrade-*' | sort -r | tail -n +4 | while IFS= read -r old; do rm -rf "$old"; done
  fi
fi

# ---------------------------------------------------------------- binaries
need() { command -v "$1" >/dev/null; }
if [ $MODE = source ] || ! need curl || ! need tar; then
  step "Installing prerequisites"
  export DEBIAN_FRONTEND=noninteractive
  if need apt-get; then
    apt-get update -qq
    apt-get install -y -qq ca-certificates curl tar >/dev/null
  fi
  need curl && need tar || die "curl and tar are required"
  ok "curl, tar, CA certificates"
fi

STAGE=$(mktemp -d); trap 'rm -rf "$STAGE"' EXIT
if [ $MODE = prebuilt ]; then
  step "Checking prebuilt binaries"
  VERSION=$(cat "$SRC/VERSION" 2>/dev/null || echo dev)
  # Integrity of the unpacked files. Authenticity comes from checking the tarball
  # against the published offpatch-<version>.SHA256SUMS before unpacking it.
  [ -f "$SRC/SHA256SUMS" ] || die "SHA256SUMS missing from the release folder"
  ( cd "$SRC" && sha256sum -c --quiet SHA256SUMS ) || die "release files failed their SHA-256 check (SHA256SUMS)"
  ok "release checksums verified"
  for b in pmserver pmctl pmagent; do cp "$PREBUILT/$b" "$STAGE/$b"; done
  AGENT_VER=$(cat "$SRC/AGENT_VERSION" 2>/dev/null || "$STAGE/pmagent" version)
else
  need_go=1
  for g in go /usr/local/go/bin/go; do
    [ $need_go = 1 ] && command -v "$g" >/dev/null || continue
    have=$("$g" env GOVERSION | sed 's/^go//')
    if [ "$(printf '%s\n%s\n' "1.27.1" "$have" | sort -V | head -1)" = "1.27.1" ]; then need_go=0; GO=$g; ok "Go $have already installed"; fi
  done
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
  step "Building offpatch"
  VERSION=$(cd "$SRC" && git describe --tags --always 2>/dev/null || echo dev)
  AGENT_VER=$(cat "$SRC/AGENT_VERSION" 2>/dev/null || sed -n 's/^var Version = "\(.*\)"$/\1/p' "$SRC/internal/agent/agent.go" | head -n 1)
  AGENT_VER=${AGENT_VER:-0.0.0-dev}
  export GOFLAGS=-trimpath CGO_ENABLED=0
  ( cd "$SRC"
    $GO build -ldflags "-s -w -X offpatch/internal/agent.Version=$AGENT_VER -X offpatch/internal/server.Version=$VERSION" -o "$STAGE/pmserver" ./cmd/pmserver
    $GO build -ldflags "-s -w" -o "$STAGE/pmctl" ./cmd/pmctl
    $GO build -ldflags "-s -w -X offpatch/internal/agent.Version=$AGENT_VER" -o "$STAGE/pmagent" ./cmd/pmagent )
fi

# Never downgrade a local agent that has self-upgraded past this release.
ver_gt() { [[ "${1#v}" =~ ^[0-9]+(\.[0-9]+)*$ && "${2#v}" =~ ^[0-9]+(\.[0-9]+)*$ ]] && [ "${1#v}" != "${2#v}" ] \
           && [ "$(printf '%s\n%s\n' "${1#v}" "${2#v}" | sort -V | tail -n 1)" = "${1#v}" ]; }
AGENT_UPGRADED=0
mkdir -p "$PREFIX/bin"
for b in pmserver pmctl pmagent; do
  if [ $b = pmagent ] && [ -x "$PREFIX/bin/pmagent" ]; then
    old_ver=$("$PREFIX/bin/pmagent" version 2>/dev/null || true)
    if ver_gt "$old_ver" "$AGENT_VER"; then warn "keeping the local pmagent $old_ver (newer than this release's $AGENT_VER)"; continue; fi
    cmp -s "$STAGE/pmagent" "$PREFIX/bin/pmagent" || AGENT_UPGRADED=1
  fi
  install -m 0755 "$STAGE/$b" "$PREFIX/bin/$b"
  ln -sf "$PREFIX/bin/$b" "/usr/local/bin/$b"
done
ok "pmserver, pmctl, pmagent → $PREFIX/bin (version $VERSION, agent $AGENT_VER)"

# ---------------------------------------------------------------- configuration directory
# server: group offpatch; acquisition: group offpatch-acq; single server (all): the shared group, so
# both service users can reach their own files (each file below is restricted further).
case "$ROLE" in
  server) ETC_GROUP=$SVC_USER ;;
  acquisition) ETC_GROUP=$ACQ_USER ;;
  all) ETC_GROUP=$XFER_GROUP ;;
  agent) ETC_GROUP=root ;;
esac
if [ "$ROLE" = agent ]; then
  [ -d "$ETC" ] || install -d -m 0755 -o root -g root "$ETC"
else
  install -d -m 0750 -o root -g "$ETC_GROUP" "$ETC"
fi

SCHEME=https; [ $INSECURE = 1 ] && SCHEME=http
# The address people and agents use: an IPv4 given in --hosts that this machine owns, else
# the source address of the default route, else the first address that is not loopback or
# a container/virtual bridge (docker0 172.17.x, libvirt 192.168.122.x, lxd/podman 10.x on bridges).
local_ips() {
  ip -4 -o addr show scope global 2>/dev/null | awk '$2 !~ /^(docker|br-|virbr|veth|lxdbr|cni|flannel|cali|podman)/ {sub(/\/.*/, "", $4); print $4}'
}
pick_ip() {
  local mine h src
  mine=$(local_ips)
  for h in $(printf '%s' "$EXTRA_HOSTS" | tr ',' ' '); do
    if printf '%s\n' "$mine" | grep -qxF "$h"; then echo "$h"; return; fi
  done
  src=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for (i = 1; i < NF; i++) if ($i == "src") { print $(i + 1); exit }}')
  if [ -n "$src" ] && printf '%s\n' "$mine" | grep -qxF "$src"; then echo "$src"; return; fi
  [ -n "$mine" ] && { printf '%s\n' "$mine" | head -n 1; return; }
  hostname -I 2>/dev/null | awk '{print $1}'
}
# Directly connected IPv4 subnet(s) of an address (kernel routes with that source), e.g. 10.0.5.0/24.
local_subnets() {
  ip -4 route show proto kernel scope link 2>/dev/null | awk -v ip="$1" '{for (i = 1; i < NF; i++) if ($i == "src" && $(i + 1) == ip) print $1}' | awk '!seen[$0]++'
}
IP=$(pick_ip)
OTHER_IPS=$(local_ips | grep -vxF "${IP:-}" | paste -sd' ' - || true)
HOSTS=$(printf '%s\n' "$(hostname)" localhost 127.0.0.1 "$IP" "$EXTRA_HOSTS" | tr ',' '\n' | awk 'NF && !seen[$0]++' | paste -sd, -)
case "$LISTEN_HOST" in ""|0.0.0.0|"::"|"[::]") LOCAL_HOST=127.0.0.1 ;; *) LOCAL_HOST=$LISTEN_HOST ;; esac
URL_LOCAL="$SCHEME://$LOCAL_HOST:$PORT"
URL_PUBLIC="$SCHEME://${IP:-$(hostname)}:$PORT"

# ---------------------------------------------------------------- keys
install_pub() { # source-file name
  local dst="$ETC/keys/$2"
  if [ -f "$dst" ]; then
    if [ -n "$1" ] && ! cmp -s "$1" "$dst"; then
      warn "keeping existing $dst (differs from $1): the installer never replaces a trusted key. Rotate with a signed trust document (runbook 03)"
    else
      ok "keeping $dst"
    fi
  elif [ -n "$1" ]; then
    install -m 0644 -o root -g root "$1" "$dst" && ok "installed $dst"
  fi
}
keygen() { ( cd "$ETC/keys" && "$PREFIX/bin/pmctl" keygen -out "$1" | sed 's/^/      /' ); }

if [ "$ROLE" != agent ]; then
  step "Signing keys"
  install -d -m 0750 -o root -g "$ETC_GROUP" "$ETC/keys"
  case "$ROLE" in
    server)
      install_pub "$PUBKEY_IN" bundle.pub
      install_pub "$ROOTPUB_IN" root.pub
      if [ ! -f "$ETC/keys/root.pub" ]; then
        warn "no root.pub: signed key rotation/revocation is disabled. Strongly recommended: generate the root key offline (runbook 02 A2) and re-run with --root-pubkey root.pub"
      elif [ $SERVER_CONFIGURED = 1 ] && [ -z "$(cfg_get root_public_key_file)" ]; then
        warn "$ETC/pmserver.json does not use root.pub yet: add  \"root_public_key_file\": \"$ETC/keys/root.pub\",  and restart offpatch-server"
      fi
      ;;
    acquisition)
      if [ ! -f "$ETC/keys/bundle.key" ]; then keygen bundle; ok "created the bundle signing key in $ETC/keys"; else ok "keeping $ETC/keys/bundle.key"; fi
      [ -f "$ETC/keys/root.key" ] && banner "$ETC/keys/root.key is on an internet-connected host. Move it to offline custody" \
                                           "(encrypted media in a safe / HSM) and shred it here: sudo shred -u $ETC/keys/root.key"
      ;;
    all)
      if [ ! -f "$ETC/keys/bundle.key" ]; then keygen bundle; ok "created the bundle signing key"; fi
      if [ -n "$ROOTPUB_IN" ] || [ -f "$ETC/keys/root.pub" ]; then
        install_pub "$ROOTPUB_IN" root.pub
      else
        keygen root; ok "created the root key (move it to offline media: --export-root-key, see the summary)"
      fi
      ok "keys in $ETC/keys"
      ;;
  esac
  # Public keys: world-readable. Signing keys: only the acquisition user. Root key: root only
  # (only `pmctl trust` uses it; no service may read it).
  for f in "$ETC/keys"/*.pub; do [ -e "$f" ] && { chown root:root "$f"; chmod 0644 "$f"; }; done
  for f in "$ETC/keys"/*.key; do
    [ -e "$f" ] || continue
    if [ "$(basename "$f")" = root.key ]; then chown root:root "$f"; chmod 0600 "$f"
    else chown root:"$ACQ_USER" "$f"; chmod 0640 "$f"; fi
  done
fi

# ---------------------------------------------------------------- server
write_server_unit() {
  local caps rw="$SRV_DATA -$ETC/pki"
  if [ "$PORT" -lt 1024 ]; then caps=$'CapabilityBoundingSet=CAP_NET_BIND_SERVICE\nAmbientCapabilities=CAP_NET_BIND_SERVICE'
  else caps='CapabilityBoundingSet='; fi
  case "$AUDIT_DIR" in ""|"$SRV_DATA"/*) ;; *) rw="$rw -$AUDIT_DIR" ;; esac
  if [ "$ROLE" = all ]; then rw="$rw -$ACQ_REQ_DIR"; fi
  cat > /etc/systemd/system/offpatch-server.service <<EOF
[Unit]
Description=offpatch management server
After=network-online.target
Wants=network-online.target

[Service]
User=$SVC_USER
Group=$SVC_USER
SupplementaryGroups=$XFER_GROUP
ExecStart=$PREFIX/bin/pmserver -config $ETC/pmserver.json
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
ProtectClock=true
ProtectHostname=true
RestrictSUIDSGID=true
RestrictRealtime=true
RestrictNamespaces=true
LockPersonality=true
# Remove if scan_command runs a scanner that needs a JIT (W+X memory).
MemoryDenyWriteExecute=true
SystemCallArchitectures=native
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
$caps
ReadWritePaths=$rw
UMask=0077

[Install]
WantedBy=multi-user.target
EOF
}

start_server() {
  if [ $HAVE_SYSTEMD = 1 ]; then
    write_server_unit
    systemctl daemon-reload
    systemctl enable offpatch-server >/dev/null 2>&1
    systemctl restart offpatch-server
  else
    pkill -f "$PREFIX/bin/pmserver" 2>/dev/null || true
    [ -f "$SRV_DATA/pmserver.log" ] || install -m 0640 -o "$SVC_USER" -g "$SVC_USER" /dev/null "$SRV_DATA/pmserver.log"
    runuser -u "$SVC_USER" -- nohup "$PREFIX/bin/pmserver" -config "$ETC/pmserver.json" >> "$SRV_DATA/pmserver.log" 2>&1 &
  fi
}

same_fs() { [ "$(stat -c %d "$1")" = "$(stat -c %d "$2")" ]; }

install_backup() {
  install -d -m 0700 -o "$SVC_USER" -g "$SVC_USER" "$BACKUP_DIR"
  cat > "$PREFIX/bin/offpatch-backup" <<'EOF'
#!/bin/sh
# Scheduled offpatch server backup (written by install-ubuntu.sh; runs as the server user).
# pmserver backup + verify-backup into a new timestamped directory, then keeps the newest @KEEP@.
set -eu
DIR=@BACKUP_DIR@
dest="$DIR/$(date -u +%Y%m%dT%H%M%SZ)"
need=$(du -sk --exclude=inbox @SRV_DATA@ 2>/dev/null | awk '{print $1}')
avail=$(df -Pk "$DIR" | awk 'NR==2 {print $4}')
if [ -n "$need" ] && [ -n "$avail" ] && [ "$avail" -lt "$need" ]; then
  echo "offpatch-backup: not enough space in $DIR (need ~${need} KiB, ${avail} KiB free)" >&2
  exit 1
fi
if ! @PREFIX@/bin/pmserver backup -config @CONFIG@ -dir "$dest" || ! @PREFIX@/bin/pmserver verify-backup -dir "$dest"; then
  echo "offpatch-backup: backup or verification FAILED; removing the incomplete $dest" >&2
  rm -rf -- "$dest"
  exit 1
fi
printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$dest" > "$DIR/last-success"
find "$DIR" -maxdepth 1 -type d -name '[0-9]*T*Z' | sort -r | tail -n +$((@KEEP@ + 1)) | while IFS= read -r old; do
  rm -rf -- "$old" && echo "offpatch-backup: pruned $old"
done
EOF
  sed -i -e "s|@BACKUP_DIR@|$BACKUP_DIR|g" -e "s|@SRV_DATA@|$SRV_DATA|g" -e "s|@PREFIX@|$PREFIX|g" \
         -e "s|@CONFIG@|$ETC/pmserver.json|g" -e "s|@KEEP@|$BACKUP_KEEP|g" "$PREFIX/bin/offpatch-backup"
  chmod 0755 "$PREFIX/bin/offpatch-backup"
  if [ $HAVE_SYSTEMD = 0 ]; then
    warn "no systemd: schedule daily backups from cron:  runuser -u $SVC_USER -- $PREFIX/bin/offpatch-backup"
    return 0
  fi
  cat > /etc/systemd/system/offpatch-backup.service <<EOF
[Unit]
Description=offpatch server backup (pmserver backup + verify-backup, keep newest $BACKUP_KEEP)
After=offpatch-server.service
OnFailure=offpatch-backup-failed.service

[Service]
Type=oneshot
User=$SVC_USER
Group=$SVC_USER
SupplementaryGroups=$XFER_GROUP
ExecStart=$PREFIX/bin/offpatch-backup
TimeoutStartSec=6h
Nice=10
IOSchedulingClass=idle
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
LockPersonality=true
CapabilityBoundingSet=
RestrictAddressFamilies=AF_UNIX
ReadWritePaths=$SRV_DATA $BACKUP_DIR
UMask=0077
EOF
  cat > /etc/systemd/system/offpatch-backup-failed.service <<EOF
[Unit]
Description=Record a failed offpatch backup

[Service]
Type=oneshot
ExecStart=/usr/bin/logger -p daemon.err -t offpatch-backup "offpatch-backup.service FAILED: no new verified backup. Check: journalctl -u offpatch-backup"
ExecStart=/bin/sh -c 'date -u +%%Y-%%m-%%dT%%H:%%M:%%SZ > $BACKUP_DIR/last-failure'
EOF
  cat > /etc/systemd/system/offpatch-backup.timer <<EOF
[Unit]
Description=Daily offpatch server backup

[Timer]
OnCalendar=*-*-* 02:30
RandomizedDelaySec=15m
Persistent=true

[Install]
WantedBy=timers.target
EOF
  systemctl daemon-reload
  systemctl enable --now offpatch-backup.timer >/dev/null 2>&1
  ok "daily verified backup at 02:30 → $BACKUP_DIR (keeps $BACKUP_KEEP; failures logged as offpatch-backup errors)"
  if same_fs "$BACKUP_DIR" "$SRV_DATA"; then
    warn "backups are on the same filesystem as the data: copy $BACKUP_DIR off the machine (encrypted; it holds the CA key), or use --backup-dir on other storage"
  fi
}

CURL_CA=()
ADMIN_CREATED_EMAIL="" ADMIN_CREATED_PW="" ADMIN_DEFAULT_PW=0
if [ $IS_SERVER = 1 ]; then
  step "Management server"
  install -d -m 0750 -o "$SVC_USER" -g "$SVC_USER" "$SRV_DATA" "$SRV_DATA/inbox" "$SRV_DATA/agent-dist"
  if [ $INSECURE = 0 ] && [ ! -f "$ETC/pki/ca.pem" ]; then
    "$PREFIX/bin/pmserver" init-pki -dir "$ETC/pki" -hosts "$HOSTS" >/dev/null
    ok "created internal CA and server certificate for: $HOSTS"
  elif [ -n "$EXTRA_HOSTS" ] && [ -f "$ETC/pki/ca.pem" ]; then
    ok "keeping the existing server certificate (--hosts applies to the first install; to change names: sudo -u $SVC_USER $PREFIX/bin/pmserver reissue-server-cert -dir $ETC/pki -hosts ...)"
  fi
  [ -d "$ETC/pki" ] && { chown -R "$SVC_USER":"$SVC_USER" "$ETC/pki"; chmod 0700 "$ETC/pki"; chmod 0644 "$ETC/pki/ca.pem"; }

  # MFA key: encrypts local users' authenticator (TOTP) secrets (AES-256-GCM). pmserver creates
  # it on first start when missing; created here so it exists before the first sign-in. Kept
  # in the data dir so backups include it (a restore without it loses every MFA enrolment).
  if [ ! -f "$SRV_DATA/mfa.key" ]; then
    ( umask 077; head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > "$SRV_DATA/mfa.key"; echo >> "$SRV_DATA/mfa.key" )
    ok "created the MFA key $SRV_DATA/mfa.key"
  fi
  chown "$SVC_USER":"$SVC_USER" "$SRV_DATA/mfa.key"; chmod 0600 "$SRV_DATA/mfa.key"
  # Static admin tokens were removed (only email + password sessions and SSO sign in). Upgrades
  # from earlier versions: drop admin_tokens / allow_static_tokens from the config (the new
  # pmserver refuses to start with them) and delete the old break-glass token files.
  if [ -f "$ETC/pmserver.json" ] && grep -qE '"(admin_tokens|allow_static_tokens)"' "$ETC/pmserver.json"; then
    command -v python3 >/dev/null || die "remove \"admin_tokens\" and \"allow_static_tokens\" from $ETC/pmserver.json by hand (python3 not found), then re-run"
    python3 - "$ETC/pmserver.json" <<'PY' || die "could not remove admin_tokens from $ETC/pmserver.json"
import json, sys
p = sys.argv[1]
c = json.load(open(p))
for k in ("admin_tokens", "allow_static_tokens"):
    c.pop(k, None)
json.dump(c, open(p, "w"), indent=2)
PY
    ok "removed the static admin tokens from $ETC/pmserver.json (sign in with email + password)"
  fi
  for f in "$ETC/admin-token.txt" "$ETC/admin-token.sha256"; do
    if [ -f "$f" ]; then shred -u "$f" 2>/dev/null || rm -f "$f"; ok "deleted $f (static admin tokens no longer exist)"; fi
  done

  if [ -z "$AUDIT_DIR" ]; then
    warn "audit_export_dir is not set in $ETC/pmserver.json: audit evidence lives only in the database"
  elif [ ! -d "$AUDIT_DIR" ]; then install -d -m 0750 -o "$SVC_USER" -g "$SVC_USER" "$AUDIT_DIR"
  elif ! runuser -u "$SVC_USER" -- test -w "$AUDIT_DIR"; then warn "$AUDIT_DIR is not writable by $SVC_USER: audit export will fail"; fi
  if [ -n "$AUDIT_DIR" ] && same_fs "$AUDIT_DIR" "$SRV_DATA"; then
    banner "audit_export_dir ($AUDIT_DIR) is on the SAME filesystem as the data ($SRV_DATA)." \
           "Off-box audit evidence must survive loss or tampering of this server: use a WORM" \
           "share or a separately replicated mount (--audit-dir on first install; runbook 01 step 9)."
  fi

  if [ $SERVER_CONFIGURED = 0 ]; then
    if [ $INSECURE = 1 ]; then tlsline='"insecure_http": true,'; else tlsline="\"pki_dir\": \"$ETC/pki\","; fi
    rootline=""; [ -f "$ETC/keys/root.pub" ] && rootline=$'\n'"  \"root_public_key_file\": \"$ETC/keys/root.pub\","
    mode=two-machine; [ "$ROLE" = all ] && mode=single-server
    cat > "$ETC/pmserver.json" <<EOF
{
  "listen": "0.0.0.0:$PORT",
  "deployment_mode": "$mode",
  $tlsline
  "data_dir": "$SRV_DATA",
  "trusted_keys": [{"public_key_file": "$ETC/keys/bundle.pub", "sources": ["acq-zone-1"]}],${rootline}
  "audit_export_dir": "$AUDIT_DIR",
  "audit_checkpoint_interval": "1h",
  "intake_interval": "5s",
  "checkin_interval_seconds": 60
}
EOF
    ok "wrote $ETC/pmserver.json"
  else
    ok "keeping existing $ETC/pmserver.json (listen port $PORT, $SCHEME)"
  fi
  # Single server (role all), fresh install and upgrades: direct hand-off of acquisition
  # requests, and the deployment mode the compliance report discloses (set when absent).
  # Two-machine roles keep the hand-off unset: strict one-way transfer, the operator carries the file.
  if [ "$ROLE" = all ]; then
    if command -v python3 >/dev/null; then
      if msg=$(python3 - "$ETC/pmserver.json" "$ACQ_REQ_DIR" <<'PY'
import json, sys
p, d = sys.argv[1], sys.argv[2]
c = json.load(open(p))
changed = []
if c.get("acquisition_requests_dir") != d:
    c["acquisition_requests_dir"] = d
    changed.append("acquisition requests are queued directly to " + d)
if not c.get("deployment_mode"):
    c["deployment_mode"] = "single-server"
    changed.append("deployment_mode single-server (disclosed in the compliance report)")
if changed:
    json.dump(c, open(p, "w"), indent=2)
    print("; ".join(changed))
PY
); then
        if [ -n "$msg" ]; then ok "$ETC/pmserver.json: $msg"; fi
      else
        warn "could not update $ETC/pmserver.json; set \"acquisition_requests_dir\": \"$ACQ_REQ_DIR\" and \"deployment_mode\": \"single-server\" by hand"
      fi
    else
      warn "python3 not found: set \"acquisition_requests_dir\": \"$ACQ_REQ_DIR\" and \"deployment_mode\": \"single-server\" in $ETC/pmserver.json by hand"
    fi
  fi
  chown root:"$SVC_USER" "$ETC/pmserver.json"; chmod 0640 "$ETC/pmserver.json"

  # Offer agent binaries for download in the console (Agent setup page and the
  # one-command Windows install).
  if [ $MODE = prebuilt ]; then
    cp -f "$SRC/bin/agent-dist/"* "$SRV_DATA/agent-dist/" || die "bin/agent-dist missing from the release folder"
    ok "agent binaries ($AGENT_VER) staged for the console's Agent setup page"
  else
    ( cd "$SRC" && for t in windows/amd64:pmagent.exe linux/amd64:pmagent-linux-amd64 linux/arm64:pmagent-linux-arm64 darwin/arm64:pmagent-macos-arm64; do
        os=${t%%/*}; rest=${t#*/}; arch=${rest%%:*}; name=${rest#*:}
        GOOS=$os GOARCH=$arch $GO build -ldflags "-s -w -X offpatch/internal/agent.Version=$AGENT_VER" -o "$SRV_DATA/agent-dist/$name" ./cmd/pmagent || exit 1
      done ) && ok "agent binaries ($AGENT_VER) for Windows, Linux and macOS staged for the console's Agent setup page"
  fi
  chown -R "$SVC_USER":"$SVC_USER" "$SRV_DATA"
  # Inbox: whoever delivers bundles (the transfer receiver, or the single server's acquisition user) must be
  # in group offpatch-inbox. setgid keeps dropped files readable by the server via that group.
  chgrp "$XFER_GROUP" "$SRV_DATA" "$SRV_DATA/inbox"
  chmod 0710 "$SRV_DATA"; chmod 2770 "$SRV_DATA/inbox"
  # Built-in super admin (the vendor): created on first install, and on an upgrade when no
  # local super admin exists yet, with the vendor's default password (only its PBKDF2 hash is in
  # pmserver; see the vendor handbook). The console asks for a new password at the first
  # sign-in. Lost it? pmserver reset-admin (see the summary).
  if out=$(cd / && runuser -u "$SVC_USER" -- "$PREFIX/bin/pmserver" create-admin -config "$ETC/pmserver.json" -email "$ADMIN_EMAIL" -if-none 2>&1); then
    if printf '%s\n' "$out" | grep -q '^default_password: yes'; then
      ADMIN_CREATED_EMAIL=$(printf '%s\n' "$out" | awk '/^email:/{print $2}')
      ADMIN_DEFAULT_PW=1
      ok "created the built-in super admin $ADMIN_CREATED_EMAIL with the default password"
    elif printf '%s\n' "$out" | grep -q '^password:'; then
      ADMIN_CREATED_EMAIL=$(printf '%s\n' "$out" | awk '/^email:/{print $2}')
      ADMIN_CREATED_PW=$(printf '%s\n' "$out" | awk '/^password:/{print $2}')
      ok "created the built-in super admin $ADMIN_CREATED_EMAIL (password in the summary below)"
    else
      ok "keeping the existing super admin"
    fi
  else
    die "could not create the built-in super admin ($ADMIN_EMAIL): $out"
  fi
  start_server
  [ $INSECURE = 0 ] && CURL_CA=(--cacert "$ETC/pki/ca.pem")
  for _ in $(seq 1 30); do
    curl -fs -o /dev/null ${CURL_CA[@]+"${CURL_CA[@]}"} "$URL_LOCAL/" && break
    sleep 1
  done
  curl -fs -o /dev/null ${CURL_CA[@]+"${CURL_CA[@]}"} "$URL_LOCAL/" || die "server did not start; check: journalctl -u offpatch-server (or $SRV_DATA/pmserver.log)"
  echo "$URL_PUBLIC" > "$ETC/console-url.txt"
  ok "server running at $URL_PUBLIC"
  install_backup
  # Console/agent port: only from --allow-from CIDRs, else from the local subnet(s) of $IP.
  # The installer never enables ufw (that could cut off SSH); it prints the commands instead.
  FW_SOURCES=()
  if [ ${#ALLOW_FROM[@]} -gt 0 ]; then
    FW_SOURCES=("${ALLOW_FROM[@]}")
  elif [ -n "${IP:-}" ]; then
    read -r -a FW_SOURCES <<< "$(local_subnets "$IP" | paste -sd' ' -)"
  fi
  if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
    if [ ${#FW_SOURCES[@]} -gt 0 ]; then
      for c in "${FW_SOURCES[@]}"; do ufw allow proto tcp from "$c" to any port "$PORT" >/dev/null && ok "ufw: port $PORT open from $c"; done
      if ufw status | grep -Eq "^$PORT/tcp( \(v6\))? +ALLOW +Anywhere"; then
        if [ ${#ALLOW_FROM[@]} -gt 0 ]; then
          ufw delete allow "$PORT/tcp" >/dev/null && ok "ufw: removed the earlier open-to-anywhere rule for $PORT/tcp"
        else
          warn "ufw: an earlier rule still opens $PORT/tcp to ANY source. If all PCs are in ${FW_SOURCES[*]}: sudo ufw delete allow $PORT/tcp"
        fi
      fi
      [ ${#ALLOW_FROM[@]} -gt 0 ] || warn "ufw: PCs on other subnets cannot connect yet: re-run with --allow-from <CIDR> (repeatable) for each PC/admin network"
    else
      warn "ufw: could not determine the local subnet of ${IP:-this machine}; port $PORT NOT opened. Re-run with --allow-from <CIDR>"
    fi
  else
    warn "ufw is not active (the installer does not enable it). To enable it without losing SSH:"
    printf '      sudo ufw allow OpenSSH\n'
    for c in ${FW_SOURCES[@]+"${FW_SOURCES[@]}"}; do printf '      sudo ufw allow proto tcp from %s to any port %s\n' "$c" "$PORT"; done
    [ ${#FW_SOURCES[@]} -gt 0 ] || printf '      sudo ufw allow proto tcp from <PC network CIDR> to any port %s\n' "$PORT"
    printf '      sudo ufw enable\n'
    warn "or restrict port $PORT to the PC and admin networks in your network firewall"
  fi
fi

# Lab (role all): run `pmctl auto -only-requests` as soon as the server queues a request.
# pmctl moves handled requests into done/ or rejected/, so the glob only matches pending ones.
# A request that keeps failing stays there: after a failed or partial run the service waits
# 10 min in ExecStopPost (still deactivating, so the path unit cannot retrigger it), and the
# path unit is trigger-limited as a backstop, so failures never spin. Anything the watcher
# misses is still handled by the hourly run.
write_request_units() {
  cat > /etc/systemd/system/offpatch-acquire-requests.path <<EOF
[Unit]
Description=Watch for queued offpatch acquisition requests

[Path]
PathExistsGlob=$ACQ_REQ_DIR/*.json
Unit=offpatch-acquire-requests.service
TriggerLimitIntervalSec=10min
TriggerLimitBurst=10

[Install]
WantedBy=paths.target
EOF
  cat > /etc/systemd/system/offpatch-acquire-requests.service <<EOF
[Unit]
Description=offpatch acquisition of queued requests
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
User=$ACQ_USER
Group=$ACQ_USER
SupplementaryGroups=$XFER_GROUP
ExecStart=$PREFIX/bin/pmctl auto -config $ETC/acquire.json -only-requests
# Back off after a failed, partial or skipped run (exit 2 = an item failed, the request stays;
# exit 3 = the hourly run holds the lock, the request is handled when it is free).
ExecStopPost=/bin/sh -c 'test "\$\$EXIT_STATUS" = 0 || sleep 600'
SuccessExitStatus=2 3
# "Run now" from the console makes this a full run: allow as long as offpatch-acquire.service.
TimeoutStartSec=6h
TimeoutStopSec=15min
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
LockPersonality=true
CapabilityBoundingSet=
ReadWritePaths=$ACQ_DATA $DROP
UMask=0027
EOF
}

# ---------------------------------------------------------------- acquisition (connected zone)
if [ $IS_ACQ = 1 ]; then
  step "Acquisition (pmctl auto, user $ACQ_USER)"
  if [ -d "$ACQ_DATA" ] && [ "$(stat -c %U "$ACQ_DATA")" != "$ACQ_USER" ]; then
    warn "moving acquisition from user $(stat -c %U "$ACQ_DATA") to its own user $ACQ_USER"
    if [ $HAVE_SYSTEMD = 1 ] && systemctl is-active --quiet offpatch-acquire.service; then
      warn "an acquisition run is in progress; stopping it (the next timer run starts over)"
      systemctl stop offpatch-acquire.service
    fi
  fi
  install -d -m 0750 -o "$ACQ_USER" -g "$ACQ_USER" "$ACQ_DATA"
  chown -R "$ACQ_USER":"$ACQ_USER" "$ACQ_DATA"
  if [ "$ROLE" = all ]; then
    DROP="$SRV_DATA/inbox"
  else
    DROP="$ACQ_DATA/outbox"; install -d -m 0750 -o "$ACQ_USER" -g "$ACQ_USER" "$DROP"
  fi
  if [ ! -f "$ETC/acquire.json" ]; then
    cat > "$ETC/acquire.json" <<EOF
{
  "work_dir": "$ACQ_DATA",
  "sequence_state": "$ACQ_DATA/sequence.json",
  "source": "acq-zone-1",
  "key": "$ETC/keys/bundle.key",
  "schedule": "every hour (systemd timer)",
  "send": { "via": "dropdir", "to": "$DROP", "log": "$ACQ_DATA/sent.jsonl" },
  "microsoft": {
    "months": 1,
    "min_severity": "critical",
    "products": [
      { "msrc_product": "Windows 11 Version 24H2", "catalog_product": "Windows 11 Version 24H2", "arch": "x64", "min_build": 26100, "max_build": 26100 }
    ]
  },
  "intel": {},
  "requests": "$ACQ_DATA/requests",
  "apps": []
}
EOF
    ok "wrote $ETC/acquire.json (Windows 11 24H2 critical updates; apps come from the console's acquisition requests) — edit it for your fleet"
  else
    ok "keeping existing $ETC/acquire.json"
    # Upgrades: turn on intelligence and requests, and drop app entries with
    # the all-zero placeholder product code that older installers wrote
    # (pmctl now refuses them, which would stop every run).
    if command -v python3 >/dev/null; then
      if msg=$(python3 - "$ETC/acquire.json" "$ACQ_DATA/requests" <<'PY'
import json, sys
p = sys.argv[1]
c = json.load(open(p))
changed = []
if "intel" not in c:
    c["intel"] = {}; changed.append("enabled update intelligence")
if "requests" not in c:
    c["requests"] = sys.argv[2]; changed.append("enabled acquisition requests")
if c.get("schedule") == "daily at 07:00 (systemd timer)":
    c["schedule"] = "every hour (systemd timer)"; changed.append("schedule: every hour")
nil = lambda g: isinstance(g, str) and g.strip("{}0-") == "" and "0" in g
apps = c.get("apps") or []
keep = [a for a in apps if not (a.get("kind") == "msi" and not a.get("product_code_from_msi") and nil(a.get("product_code", "")))]
if len(keep) != len(apps):
    changed.append("removed %d app(s) with a placeholder product_code: %s" % (len(apps) - len(keep), ", ".join(a.get("name", "?") for a in apps if a not in keep)))
    c["apps"] = keep
if changed:
    json.dump(c, open(p, "w"), indent=2)
    print("; ".join(changed))
PY
); then
        if [ -n "$msg" ]; then ok "$ETC/acquire.json: $msg"; fi
      else
        warn "could not update $ETC/acquire.json; check it by hand"
      fi
    fi
  fi
  # role all: pmserver (group $XFER_GROUP) reads it too, as the starting point of the console's Auto-download policy. No secrets in it.
  if [ "$ROLE" = all ]; then chown root:"$XFER_GROUP" "$ETC/acquire.json"; else chown root:"$ACQ_USER" "$ETC/acquire.json"; fi; chmod 0640 "$ETC/acquire.json"
  # Acquisition requests exported from the console's Updates page go here (role all: the
  # server queues them here itself; re-apply the shared group after the chown above).
  if [ "$ROLE" = all ]; then
    lab_requests_dir
  else
    install -d -m 0770 -o "$ACQ_USER" -g "$ACQ_USER" "$ACQ_REQ_DIR"
  fi
  if [ $HAVE_SYSTEMD = 1 ]; then
    groups_line=""; [ "$ROLE" = all ] && groups_line="SupplementaryGroups=$XFER_GROUP"
    cat > /etc/systemd/system/offpatch-acquire.service <<EOF
[Unit]
Description=offpatch unattended patch acquisition
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
User=$ACQ_USER
Group=$ACQ_USER
$groups_line
ExecStart=$PREFIX/bin/pmctl auto -config $ETC/acquire.json
# 2 = some item failed (retried next hour); 3 = skipped: the previous run still holds the lock.
SuccessExitStatus=2 3
TimeoutStartSec=4h
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
LockPersonality=true
CapabilityBoundingSet=
ReadWritePaths=$ACQ_DATA $DROP
UMask=0027
EOF
    cat > /etc/systemd/system/offpatch-acquire.timer <<EOF
[Unit]
Description=Hourly offpatch acquisition run

[Timer]
# Every hour. A run still downloading when the next one starts holds the run lock: the new
# run exits 3 (skipped, success) and the timer simply tries again the next hour.
OnCalendar=hourly
RandomizedDelaySec=5min
Persistent=true

[Install]
WantedBy=timers.target
EOF
    if [ "$ROLE" = all ]; then write_request_units; fi
    systemctl daemon-reload
    systemctl enable --now offpatch-acquire.timer >/dev/null 2>&1
    systemctl restart offpatch-acquire.timer
    ok "acquisition every hour as $ACQ_USER (systemd timer offpatch-acquire.timer; an overlapping run is skipped)"
    if [ "$ROLE" = all ]; then
      systemctl enable offpatch-acquire-requests.path >/dev/null 2>&1
      systemctl reset-failed offpatch-acquire-requests.path offpatch-acquire-requests.service 2>/dev/null || true
      systemctl restart offpatch-acquire-requests.path
      ok "queued acquisition requests are fetched right away (offpatch-acquire-requests.path watches $ACQ_REQ_DIR)"
    fi
    # First update-intelligence run now, so the console's Updates page fills
    # immediately (needs internet; harmless if it fails — the timer retries).
    if [ "$ROLE" = all ]; then
      if out=$(cd "$ACQ_DATA" && runuser -u "$ACQ_USER" -- "$PREFIX/bin/pmctl" intel -key "$ETC/keys/bundle.key" -out "$ACQ_DATA/intel" -to "$DROP" 2>&1); then
        ok "update intelligence sent (newest Windows updates and app versions)"
      else
        warn "update intelligence not collected now; the hourly run will retry. Reason:"
        printf '%s\n' "$out" | tail -n 3 | sed 's/^/      /'
      fi
    fi
  else
    warn "no systemd: run acquisition hourly from cron as $ACQ_USER: $PREFIX/bin/pmctl auto -config $ETC/acquire.json >> /var/log/offpatch-acquire.log 2>&1"
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
  if [ ! -f "$AGENT_STATE/agent.json" ]; then
    enroll_agent "$AGENT_SERVER" "$AGENT_TOKEN" "$AGENT_CA" "$PUBKEY_IN" "$ROOTPUB_IN"
  else
    ok "already enrolled ($AGENT_STATE/agent.json)"
  fi
  start_agent
  ok "agent running; it checks in every 60 s"
fi

if [ "$ROLE" = all ] && [ $WITH_AGENT = 1 ]; then
  step "Local agent (this machine as a managed endpoint)"
  if [ ! -f "$AGENT_STATE/agent.json" ]; then
    # One-use enrollment token from the server itself (as the service user; audited).
    tokout=$(cd / && runuser -u "$SVC_USER" -- "$PREFIX/bin/pmserver" enroll-token -config "$ETC/pmserver.json" -groups linux,lab -site lab -hours 1 2>&1 || true)
    etok=$(printf '%s\n' "$tokout" | awk '/^token:/{print $2}')
    [ -n "$etok" ] || die "could not create an enrollment token: $tokout"
    ca=""; [ $INSECURE = 0 ] && ca="$ETC/pki/ca.pem"
    rootpub=""; [ -f "$ETC/keys/root.pub" ] && rootpub="$ETC/keys/root.pub"
    enroll_agent "$URL_LOCAL" "$etok" "$ca" "$ETC/keys/bundle.pub" "$rootpub" >/dev/null
    ok "enrolled this machine (groups: linux, lab)"
  else
    ok "already enrolled"
  fi
  start_agent
  ok "agent running"
fi

if [ $AGENT_UPGRADED = 1 ] && [ $HAVE_SYSTEMD = 1 ] && systemctl is-active --quiet offpatch-agent; then
  systemctl restart offpatch-agent && ok "restarted offpatch-agent on $AGENT_VER"
fi

# ---------------------------------------------------------------- logs without systemd
if [ $HAVE_SYSTEMD = 0 ] && [ -d /etc/logrotate.d ]; then
  cat > /etc/logrotate.d/offpatch <<EOF
$SRV_DATA/pmserver.log {
  su $SVC_USER $SVC_USER
  weekly
  rotate 8
  compress
  delaycompress
  missingok
  notifempty
  copytruncate
}
/var/log/offpatch-agent.log /var/log/offpatch-acquire.log {
  weekly
  rotate 8
  compress
  delaycompress
  missingok
  notifempty
  copytruncate
}
EOF
  ok "log rotation: /etc/logrotate.d/offpatch"
fi

# ---------------------------------------------------------------- remember choices for re-runs
cat > "$STATE_FILE" <<EOF
# Written by install-ubuntu.sh; read by re-runs (upgrades).
ROLE=$ROLE
VERSION=$VERSION
AGENT_VERSION=$AGENT_VER
BACKUP_DIR=$BACKUP_DIR
BACKUP_KEEP=$BACKUP_KEEP
ALLOW_FROM=${ALLOW_FROM[*]+"${ALLOW_FROM[*]}"}
EGRESS_LOCK=$EGRESS_LOCK
EOF
chmod 0644 "$STATE_FILE"

# ---------------------------------------------------------------- summary
step "Done"
echo "  This machine:   $(hostname) — IP ${IP:-unknown}${OTHER_IPS:+   (other addresses: $OTHER_IPS)}"
if [ $IS_SERVER = 1 ]; then
  echo "  Console:        $URL_PUBLIC   (sign in with email + password)"
  echo "  PCs need:       TCP $PORT from every PC to ${IP:-this server} (agents connect to $URL_PUBLIC; nothing connects to the PCs)"
  [ ${#FW_SOURCES[@]} -gt 0 ] && echo "  Firewall:       port $PORT allowed from ${FW_SOURCES[*]}$( ufw status 2>/dev/null | grep -q 'Status: active' || echo ' (ufw inactive: commands above)')"
  # The certificate is made on the first install; warn if this machine's address is not in it.
  if [ $INSECURE = 0 ] && [ -n "${IP:-}" ] && [ -f "$ETC/pki/server.pem" ] && command -v openssl >/dev/null \
     && ! openssl x509 -in "$ETC/pki/server.pem" -noout -ext subjectAltName 2>/dev/null | grep -qF "IP Address:$IP"; then
    warn "the server certificate does not include $IP (the address changed since the first install?). Browsers and agents"
    warn "will refuse https://$IP:$PORT. Fix: sudo -u $SVC_USER $PREFIX/bin/pmserver reissue-server-cert -dir $ETC/pki -hosts $HOSTS"
  fi
  if [ $ADMIN_DEFAULT_PW = 1 ]; then
    echo "  Super admin:    $ADMIN_CREATED_EMAIL — default password (see the vendor handbook)"
  elif [ -n "$ADMIN_CREATED_PW" ]; then
    banner "Built-in super admin (vendor): password shown ONCE, stored only as a hash:" "" \
           "  email:    $ADMIN_CREATED_EMAIL" "  password: $ADMIN_CREATED_PW"
  else
    echo "  Super admin:    existing account kept (default $ADMIN_EMAIL)"
  fi
  echo "  Lost password:  sudo runuser -u $SVC_USER -- $PREFIX/bin/pmserver reset-admin -config $ETC/pmserver.json -email <email>"
  echo "  Backups:        daily → $BACKUP_DIR (keeps $BACKUP_KEEP); copy them off the machine (they hold the CA key)"
  [ $INSECURE = 0 ] && echo "  TLS:            internal CA $ETC/pki/ca.pem — import it into the admins' browsers (or accept the warning once)"
  [ "$ROLE" = server ] && echo "  Inbox:          the transfer receiver delivers into $SRV_DATA/inbox; add its account to group $XFER_GROUP"
  cat <<EOF

  Next steps (in the console, $URL_PUBLIC):
    1. Sign in and change the password.
    2. Settings → Users: create the bank's Admin.
    3. Endpoints → Create enrollment token → run the PowerShell line on each PC
       (Windows PowerShell as Administrator; the PC needs TCP $PORT to ${IP:-this server}).
    4. Patches → Needed → Import, Catalog → Approve, Patch this (2 approvals).

  Ubuntu endpoints: sudo ./install-ubuntu.sh --role agent --server $URL_PUBLIC --token <enr_…> \\
                         --ca ca.pem --pubkey bundle.pub --root-pubkey root.pub
                    (copy ca.pem, bundle.pub, root.pub from $ETC/pki and $ETC/keys)
EOF
  [ $INSECURE = 1 ] && warn "lab mode: plain HTTP and bearer device secrets — never use outside an isolated lab"
fi
if [ $IS_ACQ = 1 ]; then
  echo "  Acquisition:    every hour (offpatch-acquire.timer). Edit $ETC/acquire.json; test: sudo -u $ACQ_USER $PREFIX/bin/pmctl auto -config $ETC/acquire.json -dry-run"
fi
if [ "$ROLE" = all ]; then
  echo "  Requests:       console requests are queued to $ACQ_REQ_DIR and fetched right away"
  if [ "$EGRESS_LOCK" = 1 ]; then
    echo "  Egress lock:    only $ACQ_USER reaches the internet (TCP 80/443, DNS); $SVC_USER: loopback only ($EGRESS_NFT)"
  else
    warn "egress lock OFF (--no-egress-lock): re-run with --egress-lock to restore it"
  fi
  if [ -f "$ETC/keys/root.key" ]; then
    banner "The OFFLINE ROOT KEY is on this server: $ETC/keys/root.key" \
           "It signs key rotation / revocation and must not stay on an internet-connected host." \
           "Insert offline media (USB / encrypted volume), mount it, then run:" \
           "  sudo $0 --export-root-key /media/usb" \
           "(copies root.key with its SHA-256, verifies the copy, then shreds the server copy)."
  fi
  echo "  Layout:         single server. A two-machine layout (--role server + --role acquisition) is stricter (README, Install)."
fi
if [ "$ROLE" = acquisition ]; then
  cat <<EOF
  Acquisition:    this downloader is at ${IP:-$(hostname)} ($(hostname)); it needs outbound HTTPS only — no inbound ports
  Bundles go to:  $DROP (carry them through the one-way transfer to the server's inbox)
  Public key:     carry $ETC/keys/bundle.pub (public only) to the server: --role server --pubkey bundle.pub
  Root key:       NOT created here. On an offline machine: pmctl keygen -out root; keep root.key offline,
                  carry root.pub to the server (--root-pubkey) and agents (runbook 02 A2)
EOF
fi
cat <<EOF
  Status:         sudo $0 --status
  Upgrade:        re-run the same command (role $ROLE is remembered; backup first, previous binaries in $PREFIX/bin.prev)
  Uninstall:      sudo $0 --uninstall   (add --purge to delete keys and data)
EOF
