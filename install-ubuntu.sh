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
#   endpoint        sudo ./install-ubuntu.sh --role agent --server https://10.0.0.5:8443 \
#                        --token enr_... --ca ca.pem --pubkey bundle.pub [--root-pubkey root.pub]
#
#   sudo ./install-ubuntu.sh --status
#   sudo ./install-ubuntu.sh --export-root-key DIR [--yes]   copy root.key to offline media, then shred it
#   sudo ./install-ubuntu.sh --uninstall [--purge [--yes]]
#
# Options:
#   --role all|server|acquisition|agent  default: the role of an earlier install, else all
#   --domain NAME                     the console's name: browsers open https://NAME:<port>, and the
#                                     internal certificate includes it (default dsspatcher.local, or
#                                     the name of an earlier install). A *.local name is published on
#                                     this machine's network segment by mDNS (avahi): admin PCs on the
#                                     same subnet/VLAN find it with no DNS or hosts file. Any other name
#                                     (e.g. patcher.bank.example) needs internal DNS or a hosts-file line
#                                     on the ADMINS' PCs. Agents never use it: they connect to
#                                     https://<server IP>:<port> (no DNS/hosts on endpoints)
#   --no-mdns                         do not publish the *.local console name by mDNS (remembered;
#                                     --mdns turns it back on). Admin PCs then need DNS or a hosts line
#   --hosts "pm.corp.local,10.0.0.5"  extra names/IPs for the server certificate (first install)
#   --server-ip IP                    accepted for compatibility and ignored: agents connect by IP
#                                     (--server https://<server IP>:<port>); /etc/hosts is not changed
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
# Public certificate for the console (optional; role all/server with TLS). Without these options
# browsers get the internal CA's certificate (distribute ca.pem, e.g. by Group Policy). Agents
# always keep the internal CA + mTLS on the agent URL. Alone on an existing install they only add
# or replace the certificate; with other options they run as part of the install or upgrade.
#   --public-cert FILE --public-key FILE  the bank's own certificate (PEM chain, leaf first) and
#                                     unencrypted key; no internet needed (recommended for isolated
#                                     bank networks). Re-run with new files to replace them
#   --public-domain NAME              console DNS name. With --public-cert: optional (default: the
#                                     certificate's DNS names). Without: Let's Encrypt via certbot
#   --acme-challenge auto|http|cloudflare  Let's Encrypt validation (default auto: HTTP-01 when TCP 80
#                                     is free on this host, else Cloudflare DNS when the credentials
#                                     file exists, else stop and list the options)
#   --cloudflare-credentials FILE     root-owned 0600, one line "dns_cloudflare_api_token = <token>"
#                                     (default /etc/offpatch/acme/cloudflare.ini; never printed)
#   --acme-email EMAIL                Let's Encrypt account email (default: --admin-email if given)
#   --agent-url URL                   URL agents enroll against (default https://<--domain>:<port>; may
#                                     be the public name: agents ask for their certificate by TLS ALPN)
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
MDNS_IN=""                           # 1 / 0 from --mdns / --no-mdns; empty = remembered or 1
EXPORT_ROOT_KEY=""                   # --export-root-key DIR
ADMIN_EMAIL_SET=0
DEFAULT_DOMAIN="dsspatcher.local"   # --domain default: .local is resolved by mDNS on the local network (RFC 6762), never public DNS
DOMAIN_IN="" SERVER_IP_IN="" SERVER_NAME=""
PUBLIC_DOMAIN_IN="" PUBLIC_CERT_IN="" PUBLIC_KEY_IN="" ACME_CHALLENGE="" CF_CREDS="" ACME_EMAIL="" AGENT_URL_IN=""
OTHER_ARGS=0                         # 1 = an option other than the public-certificate ones was given

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
DEFAULT_CF_CREDS=$ETC/acme/cloudflare.ini
LE_HOOK=/etc/letsencrypt/renewal-hooks/deploy/offpatch.sh   # copies renewed certificates for pmserver
PUBLIC_DIR=$ETC/pki/public           # public console certificate as pmserver reads it

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
    --role|--port|--hosts|--go-version|--server|--token|--ca|--pubkey|--root-pubkey|--audit-dir|--allow-from|--backup-dir|--backup-keep|--admin-email|--export-root-key|--public-domain|--public-cert|--public-key|--acme-challenge|--cloudflare-credentials|--acme-email|--agent-url|--domain|--server-ip)
      [ $# -ge 2 ] || die "$1 needs a value" ;;
  esac
  case "$1" in
    --public-domain|--public-cert|--public-key|--acme-challenge|--cloudflare-credentials|--acme-email|--agent-url|--yes) ;;
    *) OTHER_ARGS=1 ;;
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
    --admin-email) ADMIN_EMAIL="$2"; ADMIN_EMAIL_SET=1; shift ;;
    --no-egress-lock) EGRESS_LOCK_IN=0 ;;
    --egress-lock) EGRESS_LOCK_IN=1 ;;
    --no-mdns) MDNS_IN=0 ;;
    --mdns) MDNS_IN=1 ;;
    --export-root-key) EXPORT_ROOT_KEY="$2"; shift ;;
    --uninstall) UNINSTALL=1 ;;
    --purge) PURGE=1 ;;
    --yes) YES=1 ;;
    --status) STATUS=1 ;;
    --public-domain) PUBLIC_DOMAIN_IN=$(printf '%s' "$2" | tr 'A-Z' 'a-z'); PUBLIC_DOMAIN_IN=${PUBLIC_DOMAIN_IN%.}; shift ;;
    --public-cert) PUBLIC_CERT_IN="$2"; shift ;;
    --public-key) PUBLIC_KEY_IN="$2"; shift ;;
    --acme-challenge) ACME_CHALLENGE="$2"; shift ;;
    --cloudflare-credentials) CF_CREDS="$2"; shift ;;
    --acme-email) ACME_EMAIL="$2"; shift ;;
    --agent-url) AGENT_URL_IN="${2%/}"; shift ;;
    --domain) DOMAIN_IN=$(printf '%s' "$2" | tr 'A-Z' 'a-z'); DOMAIN_IN=${DOMAIN_IN%.}; shift ;;
    --server-ip) SERVER_IP_IN="$2"; shift ;;
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
MDNS=${MDNS_IN:-$(state_get MDNS)}; MDNS=${MDNS:-1}

# Values end up in JSON, systemd units and ufw rules: accept plain paths / numbers / CIDRs only.
safe_path() { [[ "$1" =~ ^/[A-Za-z0-9._/-]+$ ]] || die "$2 must be an absolute path of letters, digits, . _ - / (got: $1)"; }
[[ "$PORT" =~ ^[0-9]+$ ]] && [ "$PORT" -ge 1 ] && [ "$PORT" -le 65535 ] || die "--port must be 1-65535"
[ -z "$AUDIT_DIR_IN" ] || safe_path "$AUDIT_DIR_IN" --audit-dir
[ -z "$BACKUP_DIR_IN" ] || safe_path "$BACKUP_DIR_IN" --backup-dir
[ -z "$BACKUP_KEEP_IN" ] || { [[ "$BACKUP_KEEP_IN" =~ ^[0-9]+$ ]] && [ "$BACKUP_KEEP_IN" -ge 1 ]; } || die "--backup-keep must be a number >= 1"
# Public console certificate (values end up in JSON and a hook: plain values only).
valid_domain() { [[ "$1" =~ ^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]([a-z0-9-]{0,61}[a-z0-9])?$ ]]; }
PUBLIC_WANTED=0; { [ -n "$PUBLIC_DOMAIN_IN" ] || [ -n "$PUBLIC_CERT_IN" ] || [ -n "$PUBLIC_KEY_IN" ]; } && PUBLIC_WANTED=1
[ -z "$PUBLIC_DOMAIN_IN" ] || valid_domain "$PUBLIC_DOMAIN_IN" || die "--public-domain must be a DNS name such as patch.bank.example (got: $PUBLIC_DOMAIN_IN)"
{ [ -n "$PUBLIC_CERT_IN" ] && [ -n "$PUBLIC_KEY_IN" ]; } || { [ -z "$PUBLIC_CERT_IN" ] && [ -z "$PUBLIC_KEY_IN" ]; } || die "--public-cert and --public-key go together"
[ -z "$PUBLIC_CERT_IN" ] || { safe_path "$PUBLIC_CERT_IN" --public-cert; safe_path "$PUBLIC_KEY_IN" --public-key; }
if [ -n "$PUBLIC_CERT_IN" ] && { [ -n "$ACME_CHALLENGE" ] || [ -n "$CF_CREDS" ] || [ -n "$ACME_EMAIL" ]; }; then
  die "--acme-challenge, --cloudflare-credentials and --acme-email are for Let's Encrypt; a provided certificate (--public-cert) needs none of them"
fi
ACME_CHALLENGE=${ACME_CHALLENGE:-auto}
case "$ACME_CHALLENGE" in auto|http|cloudflare) ;; *) die "--acme-challenge must be auto, http or cloudflare" ;; esac
[ "$ACME_CHALLENGE" = auto ] || [ -n "$PUBLIC_DOMAIN_IN" ] || die "--acme-challenge needs --public-domain"
CF_CREDS=${CF_CREDS:-$DEFAULT_CF_CREDS}; safe_path "$CF_CREDS" --cloudflare-credentials
[ -z "$ACME_EMAIL" ] || [[ "$ACME_EMAIL" =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]] || die "--acme-email is not an email address: $ACME_EMAIL"
if [ -n "$AGENT_URL_IN" ]; then
  [[ "$AGENT_URL_IN" =~ ^https://([A-Za-z0-9.-]+|\[[0-9A-Fa-f:.]+\])(:[0-9]{1,5})?$ ]] || die "--agent-url must be https://host:port with no path (got: $AGENT_URL_IN)"
  [ $PUBLIC_WANTED = 1 ] || die "--agent-url goes with --public-domain or --public-cert"
fi
PUBLIC_DOMAIN=$PUBLIC_DOMAIN_IN PUBLIC_MODE="" PUBLIC_NAMES="" ACME_METHOD=""
[ -z "$DOMAIN_IN" ] || valid_domain "$DOMAIN_IN" || die "--domain must be a DNS name such as patcher.bank.example (got: $DOMAIN_IN)"
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

# ---------------------------------------------------------------- public console certificate
# Optional. Without --public-domain / --public-cert nothing here runs: browsers get the internal
# CA's certificate as always. With it, pmserver serves a public certificate to browsers that ask
# for one of public_tls.names (TLS SNI); agents keep the internal CA + mTLS on the agent URL.
#   provided     --public-cert/--public-key: the bank's own certificate (no certbot, no internet)
#   letsencrypt  --public-domain [--acme-challenge auto|http|cloudflare]: certbot, renewed by its
#                timer; the deploy hook copies renewals to $PUBLIC_DIR and pmserver re-reads them
#                (within a minute, at once on reload). certbot runs as root: the egress lock
#                (offpatch accounts only) does not affect it.
# Secrets (private keys, the Cloudflare token) are never printed.

# TCP 80 is taken: a local listener, or NAT rules forwarding it elsewhere (e.g. Docker with the
# userland proxy off), where Let's Encrypt's HTTP-01 request would never reach certbot.
port80_busy() {
  ss -Hltn 'sport = :80' 2>/dev/null | grep -q . && return 0
  { iptables -t nat -S 2>/dev/null; nft list ruleset 2>/dev/null; } | grep -Eq -- '(--dport|dport) 80([^0-9]|$)'
}

check_cf_credentials() { # file
  local f=$1 mode
  if [ ! -f "$f" ]; then
    die "Cloudflare credentials $f not found. Create a Cloudflare API token with Zone > DNS > Edit
     for the domain's zone, then store it in that file (one line, root only):
       sudo install -d -m 0700 $(dirname "$f")
       sudo install -m 0600 /dev/null $f
       sudo nano $f      # dns_cloudflare_api_token = <token>
     and re-run."
  fi
  [ "$(stat -c %U "$f")" = root ] || die "$f must be owned by root (it holds the Cloudflare API token): sudo chown root:root $f"
  mode=$(stat -c %a "$f")
  if [ "$mode" != 600 ] && [ "$mode" != 400 ]; then chmod 0600 "$f"; warn "$f was mode $mode; now 0600"; fi
  case "$(dirname "$f")" in "$ETC"/*) chown root:root "$(dirname "$f")"; chmod 0700 "$(dirname "$f")" ;; esac
  grep -Eq '^[[:space:]]*dns_cloudflare_api_token[[:space:]]*=[[:space:]]*[^[:space:]]+' "$f" \
    || die "$f has no line \"dns_cloudflare_api_token = <token>\""
  ok "Cloudflare credentials $f (root, mode $(stat -c %a "$f"))"
}

# Let's Encrypt: pick the challenge before anything changes. An existing certificate for the
# name keeps the method certbot stored for it (unless --acme-challenge is given).
resolve_acme_challenge() {
  if [ "$ACME_CHALLENGE" = auto ] && [ -f "/etc/letsencrypt/renewal/$PUBLIC_DOMAIN.conf" ]; then
    ACME_METHOD=existing
    ok "Let's Encrypt certificate for $PUBLIC_DOMAIN exists; certbot keeps renewing it with the method it was issued with"
    return 0
  fi
  case "$ACME_CHALLENGE" in
    http)
      ! port80_busy || die "--acme-challenge http needs TCP 80 free on this host, but it is in use ($(ss -Hltnp 'sport = :80' 2>/dev/null | sed -n 's/.*users:((\"\([^\"]*\)\".*/\1/p' | head -n 1)).
     Use --acme-challenge cloudflare (DNS), or the bank's own certificate: --public-cert FILE --public-key FILE"
      ACME_METHOD=http ;;
    cloudflare) check_cf_credentials "$CF_CREDS"; ACME_METHOD=cloudflare ;;
    auto)
      if ! port80_busy; then ACME_METHOD=http; ok "TCP 80 is free: Let's Encrypt HTTP-01 (certbot standalone, no credentials)"
      elif [ -f "$CF_CREDS" ]; then check_cf_credentials "$CF_CREDS"; ACME_METHOD=cloudflare; ok "TCP 80 is in use: Let's Encrypt DNS-01 via Cloudflare"
      else
        die "cannot get a certificate for $PUBLIC_DOMAIN automatically: TCP 80 is in use on this host and there are no
     Cloudflare credentials ($CF_CREDS). Choose one:
       1. the bank's own certificate (recommended for isolated bank networks):
            --public-cert FILE --public-key FILE [--public-domain $PUBLIC_DOMAIN]
       2. DNS validation (domain on Cloudflare): create $CF_CREDS with
            dns_cloudflare_api_token = <token>   (root, 0600), then --acme-challenge cloudflare
       3. free TCP 80 on this host during issuance and renewals, then --acme-challenge http
     Without a public certificate, browsers trust the internal CA once it is distributed
     (e.g. by Group Policy: $ETC/pki/ca.pem as a Trusted Root Certification Authority)."
      fi ;;
  esac
}

install_certbot() { # method
  local pkgs="certbot"
  [ "$1" = cloudflare ] && pkgs="certbot python3-certbot-dns-cloudflare"
  if command -v certbot >/dev/null && { [ "$1" != cloudflare ] || dpkg -s python3-certbot-dns-cloudflare >/dev/null 2>&1; }; then
    ok "certbot is installed"; return 0
  fi
  command -v apt-get >/dev/null || die "install $pkgs, then re-run"
  export DEBIAN_FRONTEND=noninteractive
  # shellcheck disable=SC2086
  { apt-get update -qq && apt-get install -y -qq $pkgs >/dev/null; } || die "apt-get install $pkgs failed"
  ok "installed $pkgs"
}

write_le_hook() { # domain
  install -d -m 0755 "$(dirname "$LE_HOOK")"
  cat > "$LE_HOOK" <<HOOK
#!/bin/sh
# DSS Patcher (offpatch): console certificate for $1. Written by install-ubuntu.sh; re-runs rewrite it.
# certbot runs this after a renewal: copy the certificate to where pmserver reads it. pmserver
# re-reads it within a minute (reload: at once); agents keep the internal CA and are not affected.
set -eu
LINEAGE=/etc/letsencrypt/live/$1
[ "\${RENEWED_LINEAGE:-\$LINEAGE}" = "\$LINEAGE" ] || exit 0
DEST=$PUBLIC_DIR
install -d -m 0700 -o $SVC_USER -g $SVC_USER "\$DEST"
install -m 0600 -o $SVC_USER -g $SVC_USER "\$LINEAGE/privkey.pem" "\$DEST/key.pem.new"
install -m 0600 -o $SVC_USER -g $SVC_USER "\$LINEAGE/fullchain.pem" "\$DEST/cert.pem.new"
mv -f "\$DEST/key.pem.new" "\$DEST/key.pem"
mv -f "\$DEST/cert.pem.new" "\$DEST/cert.pem"
systemctl reload offpatch-server >/dev/null 2>&1 || true
HOOK
  chmod 0755 "$LE_HOOK"
  ok "certbot deploy hook $LE_HOOK -> $PUBLIC_DIR/{cert,key}.pem ($SVC_USER, 0600)"
}

# Bank-provided certificate: validate before anything changes. Sets PUBLIC_NAMES (comma list).
check_provided_cert() {
  local c=$PUBLIC_CERT_IN k=$PUBLIC_KEY_IN n i cur nxt pk1 pk2 split
  command -v openssl >/dev/null || die "openssl is required to check --public-cert"
  [ -f "$c" ] && [ -r "$c" ] || die "--public-cert: $c not found"
  [ -f "$k" ] && [ -r "$k" ] || die "--public-key: $k not found"
  grep -q 'PRIVATE KEY' "$c" && die "--public-cert: $c contains a private key; give the certificate chain only"
  grep -q 'ENCRYPTED' "$k" && die "--public-key: $k is encrypted; pmserver needs it unencrypted (openssl pkey -in KEY -out key.pem, keep it 0600)"
  openssl x509 -in "$c" -noout 2>/dev/null || die "--public-cert: $c is not a PEM certificate"
  openssl pkey -in "$k" -noout -passin pass: 2>/dev/null || die "--public-key: $k is not a PEM private key"
  pk1=$(openssl x509 -in "$c" -noout -pubkey 2>/dev/null | openssl pkey -pubin -outform DER 2>/dev/null | sha256sum || true)
  pk2=$(openssl pkey -in "$k" -pubout -outform DER -passin pass: 2>/dev/null | sha256sum || true)
  [ "$pk1" = "$pk2" ] || die "--public-key does not belong to --public-cert (the public keys differ)"
  openssl x509 -in "$c" -noout -checkend 0 >/dev/null 2>&1 || die "--public-cert: the certificate has expired"
  openssl x509 -in "$c" -noout -checkend $((14 * 86400)) >/dev/null 2>&1 || warn "--public-cert expires within 14 days ($(openssl x509 -in "$c" -noout -enddate | sed 's/notAfter=//'))"
  # Chain: leaf first, each certificate issued by the next one.
  split=$(mktemp -d)
  awk -v d="$split" '/-----BEGIN CERTIFICATE-----/ {n++; f = sprintf("%s/%02d.pem", d, n)} n {print > f} /-----END CERTIFICATE-----/ {close(f)}' "$c"
  n=$(find "$split" -name '*.pem' | wc -l)
  for i in $(seq 1 $((n - 1))); do
    cur=$(openssl x509 -in "$split/$(printf %02d "$i").pem" -noout -issuer -nameopt RFC2253 | sed 's/^issuer=//')
    nxt=$(openssl x509 -in "$split/$(printf %02d $((i + 1))).pem" -noout -subject -nameopt RFC2253 | sed 's/^subject=//')
    [ "$cur" = "$nxt" ] || { rm -rf "$split"; die "--public-cert: certificate $i is not issued by certificate $((i + 1)) (put the server certificate first, then its intermediates in order)"; }
  done
  cur=$(openssl x509 -in "$split/01.pem" -noout -issuer -nameopt RFC2253 | sed 's/^issuer=//')
  nxt=$(openssl x509 -in "$split/01.pem" -noout -subject -nameopt RFC2253 | sed 's/^subject=//')
  rm -rf "$split"
  if [ "$n" = 1 ] && [ "$cur" != "$nxt" ]; then
    warn "--public-cert holds only the server certificate: fine if it is issued directly by a root CA the browsers trust; otherwise append the intermediate CA certificate(s)"
  fi
  if [ -n "$PUBLIC_DOMAIN_IN" ]; then
    openssl x509 -in "$c" -noout -checkhost "$PUBLIC_DOMAIN_IN" 2>/dev/null | grep -q 'does match' \
      || die "--public-cert does not cover $PUBLIC_DOMAIN_IN (its names: $(openssl x509 -in "$c" -noout -ext subjectAltName 2>/dev/null | tail -n +2 | tr -d ' '))"
    PUBLIC_NAMES=$PUBLIC_DOMAIN_IN
  else
    PUBLIC_NAMES=$(openssl x509 -in "$c" -noout -ext subjectAltName 2>/dev/null | tr ',' '\n' | sed -n 's/^[[:space:]]*DNS:\(.*\)$/\1/p' \
      | tr 'A-Z' 'a-z' | { grep -v '^\*' || true; } | while read -r n; do if valid_domain "$n"; then echo "$n"; fi; done | paste -sd, - || true)
    [ -n "$PUBLIC_NAMES" ] || die "--public-cert has no DNS names usable as console names (wildcards are not): add --public-domain NAME"
  fi
  ok "certificate checked: key matches, valid until $(openssl x509 -in "$c" -noout -enddate | sed 's/notAfter=//'), names $PUBLIC_NAMES"
}

install_provided_cert() {
  install -d -m 0700 -o "$SVC_USER" -g "$SVC_USER" "$PUBLIC_DIR"
  install -m 0600 -o "$SVC_USER" -g "$SVC_USER" "$PUBLIC_KEY_IN" "$PUBLIC_DIR/key.pem.new"
  install -m 0600 -o "$SVC_USER" -g "$SVC_USER" "$PUBLIC_CERT_IN" "$PUBLIC_DIR/cert.pem.new"
  mv -f "$PUBLIC_DIR/key.pem.new" "$PUBLIC_DIR/key.pem"
  mv -f "$PUBLIC_DIR/cert.pem.new" "$PUBLIC_DIR/cert.pem"
  ok "installed the provided certificate in $PUBLIC_DIR ($SVC_USER, 0600)"
  if [ -f "$LE_HOOK" ]; then
    rm -f "$LE_HOOK"
    warn "removed the certbot deploy hook (it would overwrite the provided certificate); the Let's Encrypt certificate itself is kept: sudo certbot delete --cert-name <name> if unused"
  fi
}

# Let's Encrypt issuance (or keep), hook and timer.
obtain_le_cert() {
  local out email_args=()
  if [ -n "$ACME_EMAIL" ]; then email_args=(-m "$ACME_EMAIL")
  elif [ "$ADMIN_EMAIL_SET" = 1 ]; then email_args=(-m "$ADMIN_EMAIL")
  else email_args=(--register-unsafely-without-email); fi
  write_le_hook "$PUBLIC_DOMAIN"
  if [ "$ACME_METHOD" != existing ]; then
    local how=(--standalone --preferred-challenges http)
    [ "$ACME_METHOD" = cloudflare ] && how=(--dns-cloudflare --dns-cloudflare-credentials "$CF_CREDS" --dns-cloudflare-propagation-seconds 30)
    if [ "$ACME_METHOD" = http ] && command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
      ufw allow 80/tcp comment 'certbot HTTP-01 (offpatch console certificate)' >/dev/null && ok "ufw: TCP 80 open for certbot (issuance and renewals)"
    fi
    if ! out=$(certbot certonly "${how[@]}" -d "$PUBLIC_DOMAIN" --cert-name "$PUBLIC_DOMAIN" --non-interactive --agree-tos \
         "${email_args[@]}" --keep-until-expiring 2>&1); then
      warn "certbot could not obtain a certificate for $PUBLIC_DOMAIN ($ACME_METHOD):"
      printf '%s\n' "$out" | tail -n 8 | sed 's/^/      /'
      warn "check the DNS A record$([ "$ACME_METHOD" = http ] && echo ' and that TCP 80 reaches this host from the internet' || echo " and the token's Zone > DNS > Edit permission") (log: /var/log/letsencrypt/letsencrypt.log)"
      return 1
    fi
  fi
  [ -f "/etc/letsencrypt/live/$PUBLIC_DOMAIN/fullchain.pem" ] || { warn "no certificate in /etc/letsencrypt/live/$PUBLIC_DOMAIN"; return 1; }
  RENEWED_LINEAGE="/etc/letsencrypt/live/$PUBLIC_DOMAIN" "$LE_HOOK" || { warn "copying the certificate to $PUBLIC_DIR failed"; return 1; }
  ok "Let's Encrypt certificate for $PUBLIC_DOMAIN ($(openssl x509 -in "$PUBLIC_DIR/cert.pem" -noout -enddate 2>/dev/null | sed 's/notAfter=/expires /'))"
  if [ $HAVE_SYSTEMD = 1 ]; then
    if systemctl enable --now certbot.timer >/dev/null 2>&1; then
      ok "renewal: certbot.timer (twice a day; renews 30 days before expiry)"
    elif systemctl list-unit-files snap.certbot.renew.timer 2>/dev/null | grep -q snap.certbot.renew.timer; then
      ok "renewal: snap.certbot.renew.timer"
    else
      warn "no certbot timer found: add a daily 'certbot renew -q' (cron) so the certificate renews"
    fi
  fi
  [ "$ACME_METHOD" != http ] || warn "renewals use HTTP-01 too: TCP 80 must stay free on this host and reachable from the internet"
  return 0
}

# Merge public_tls and agent_url into pmserver.json (other keys untouched).
write_public_config() { # names(comma) explicit-agent-url
  python3 - "$ETC/pmserver.json" "$1" "$PUBLIC_DIR" "$2" <<'PY'
import json, os, sys
p, names, d, explicit = sys.argv[1:5]
names = [n for n in names.split(",") if n]
c = json.load(open(p))
changed = []
want = {"names": names, "cert_file": d + "/cert.pem", "key_file": d + "/key.pem"}
if c.get("public_tls") != want:
    c["public_tls"] = want
    changed.append("public_tls " + ",".join(names))
if explicit and c.get("agent_url") != explicit:
    c["agent_url"] = explicit
    changed.append("agent_url " + explicit)
if changed:
    tmp = p + ".tmp"
    with open(tmp, "w") as f:
        json.dump(c, f, indent=2)
        f.write("\n")
    os.replace(tmp, p)
    print("; ".join(changed))
PY
}

# Checks that must pass before anything is changed (sets PUBLIC_MODE and PUBLIC_NAMES).
public_precheck() {
  [ "$(cfg_get insecure_http)" != true ] || die "a public certificate needs TLS; this server runs with insecure_http (lab)"
  command -v python3 >/dev/null || die "python3 is required to edit $ETC/pmserver.json"
  if [ -n "$PUBLIC_CERT_IN" ]; then
    PUBLIC_MODE=provided; check_provided_cert
  else
    PUBLIC_MODE=letsencrypt; PUBLIC_NAMES=$PUBLIC_DOMAIN; resolve_acme_challenge
  fi
}

# Install the certificate and configure pmserver. Non-zero: no certificate (config unchanged).
setup_public_tls() { # agent URL to show when agent_url is not set
  local msg
  if [ "$PUBLIC_MODE" = provided ]; then
    install_provided_cert
  else
    [ "$ACME_METHOD" = existing ] || install_certbot "$ACME_METHOD"
    obtain_le_cert || return 1
  fi
  msg=$(write_public_config "$PUBLIC_NAMES" "$AGENT_URL_IN") || die "could not update $ETC/pmserver.json"
  chown root:"$SVC_USER" "$ETC/pmserver.json"; chmod 0640 "$ETC/pmserver.json"
  [ -z "$msg" ] || ok "$ETC/pmserver.json: $msg"
  AGENT_URL_NOW=$(cfg_get agent_url); AGENT_URL_NOW=${AGENT_URL_NOW:-$1}
  systemctl reload offpatch-server >/dev/null 2>&1 || true
  return 0
}

remember_public() {
  [ -f "$STATE_FILE" ] || return 0
  sed -i '/^PUBLIC_MODE=/d; /^PUBLIC_NAMES=/d' "$STATE_FILE"
  { echo "PUBLIC_MODE=$PUBLIC_MODE"; echo "PUBLIC_NAMES=$PUBLIC_NAMES"; } >> "$STATE_FILE"
}

public_summary() { # port
  local first=${PUBLIC_NAMES%%,*} exp
  exp=$(openssl x509 -in "$PUBLIC_DIR/cert.pem" -noout -enddate 2>/dev/null | sed 's/notAfter=//' || true)
  if [ "$PUBLIC_MODE" = provided ]; then
    echo "  Console:        https://$first:$1   (provided certificate, expires ${exp:-?}; to replace it re-run with --public-cert/--public-key)"
  else
    echo "  Console:        https://$first:$1   (public certificate, renews automatically)"
  fi
  [ "$first" = "$PUBLIC_NAMES" ] || echo "                  names: $PUBLIC_NAMES"
  echo "  Agents connect to: ${AGENT_URL_NOW:-?}   (internal CA + client certificates; the enrollment command uses it)"
}

# Browsers: the public name must verify against the system trust store (checked locally).
check_public_https() { # port
  local first=${PUBLIC_NAMES%%,*}
  if curl -fsS -o /dev/null --max-time 10 --resolve "$first:$1:127.0.0.1" "https://$first:$1/" 2>/dev/null; then
    ok "https://$first:$1 serves the public certificate (verified)"
  elif [ "$PUBLIC_MODE" = provided ]; then
    ok "https://$first:$1 serves the provided certificate (not verifiable here unless this host trusts its CA)"
  else
    warn "https://$first:$1 did not verify locally; pmserver serves the internal certificate until the public one is usable (journalctl -u offpatch-server)"
  fi
}

BACKUP_DIR=${BACKUP_DIR_IN:-$(state_get BACKUP_DIR)}; BACKUP_DIR=${BACKUP_DIR:-$DEFAULT_BACKUP_DIR}
BACKUP_KEEP=${BACKUP_KEEP_IN:-$(state_get BACKUP_KEEP)}; BACKUP_KEEP=${BACKUP_KEEP:-$DEFAULT_BACKUP_KEEP}

# ---------------------------------------------------------------- console name on the LAN (mDNS)
# A *.local console name (default dsspatcher.local) is answered by avahi-daemon on the network
# segment of the chosen IP: offpatch-mdns.service runs `avahi-publish -a -R NAME IP` (an extra
# address record; the host's own name record is left alone). Windows 10/11, macOS and Linux
# desktops resolve *.local by mDNS out of the box. Multicast does not cross routers: PCs on other
# subnets/VLANs still need a DNS record or a hosts-file line.
MDNS_UNIT=/etc/systemd/system/offpatch-mdns.service
AVAHI_CONF=/etc/avahi/avahi-daemon.conf
MDNS_MARK="# offpatch: the next line is set by install-ubuntu.sh (console name over mDNS); --uninstall removes it"
MDNS_PKGS_NOW=$(state_get MDNS_PKGS)   # packages this installer installed for mDNS (removed only by --purge)
MDNS_UFW_NOW=$(state_get MDNS_UFW)     # ufw sources opened for UDP 5353 (remembered: MDNS_UFW)
MDNS_ACTIVE=0                          # 1 = the console name resolves by mDNS (checked)
MDNS_NOTE=""                           # why not, for the summary

pkg_installed() { dpkg-query -W -f='${Status}' "$1" 2>/dev/null | grep -q 'install ok installed'; }
iface_of_ip() { ip -4 -o addr show 2>/dev/null | awk -v ip="$1" '{a = $4; sub(/\/.*/, "", a); if (a == ip) { print $2; exit }}'; }
# Uncommented allow-interfaces in [server] of avahi-daemon.conf: "ours|theirs|none<TAB>value".
avahi_allow_line() {
  [ -f "$AVAHI_CONF" ] || { printf 'none\t\n'; return 0; }
  awk -v mark="$MDNS_MARK" '
    /^[[:space:]]*\[/ { sec = $0; gsub(/[][[:space:]]/, "", sec) }
    sec == "server" && /^[[:space:]]*allow-interfaces[[:space:]]*=/ {
      v = $0; sub(/^[^=]*=[[:space:]]*/, "", v); sub(/[[:space:]]+$/, "", v)
      printf "%s\t%s\n", (prev == mark ? "ours" : "theirs"), v; found = 1; exit }
    { prev = $0 }
    END { if (!found) printf "none\t\n" }' "$AVAHI_CONF"
}
avahi_strip_ours() { # file: drop our marker and the allow-interfaces line after it
  awk -v mark="$MDNS_MARK" '$0 == mark { skip = 1; next }
    skip { skip = 0; if ($0 ~ /^[[:space:]]*allow-interfaces[[:space:]]*=/) next } { print }' "$1"
}
avahi_set_allow() { # iface; returns 0 when the file changed
  local tmp; tmp=$(mktemp)
  [ -f "$AVAHI_CONF" ] || : > "$AVAHI_CONF"
  avahi_strip_ours "$AVAHI_CONF" | awk -v mark="$MDNS_MARK" -v line="allow-interfaces=$1" '
    { print }
    /^[[:space:]]*\[server\][[:space:]]*$/ && !done { print mark; print line; done = 1 }
    END { if (!done) { print ""; print "[server]"; print mark; print line } }' > "$tmp"
  if cmp -s "$tmp" "$AVAHI_CONF"; then rm -f "$tmp"; return 1; fi
  cat "$tmp" > "$AVAHI_CONF"; rm -f "$tmp"   # keep owner and mode
  return 0
}
avahi_unset_allow() { # returns 0 when the file changed
  [ -f "$AVAHI_CONF" ] && grep -qxF "$MDNS_MARK" "$AVAHI_CONF" || return 1
  local tmp; tmp=$(mktemp)
  avahi_strip_ours "$AVAHI_CONF" > "$tmp"; cat "$tmp" > "$AVAHI_CONF"; rm -f "$tmp"
  return 0
}
mdns_resolve() { command -v avahi-resolve >/dev/null || return 0; timeout 6 avahi-resolve -4 -n "$1" 2>/dev/null | awk '{print $2; exit}' || true; }

# Stop publishing and undo this installer's avahi/ufw changes; avahi itself stays installed.
remove_mdns() {
  local had=0 c
  if [ -f "$MDNS_UNIT" ]; then
    had=1
    [ $HAVE_SYSTEMD = 0 ] || systemctl disable --now offpatch-mdns.service >/dev/null 2>&1 || true
    rm -f "$MDNS_UNIT"; [ $HAVE_SYSTEMD = 0 ] || systemctl daemon-reload
  fi
  if avahi_unset_allow; then
    ok "avahi-daemon.conf: removed the allow-interfaces line this installer added"
    if [ $HAVE_SYSTEMD = 1 ] && systemctl is-active --quiet avahi-daemon; then systemctl restart avahi-daemon || true; fi
  fi
  for c in $MDNS_UFW_NOW; do
    command -v ufw >/dev/null && ufw delete allow proto udp from "$c" to any port 5353 >/dev/null 2>&1 && ok "ufw: removed the mDNS rule (UDP 5353 from $c)"
  done
  MDNS_UFW_NOW=""
  [ $had = 0 ] || ok "stopped publishing the console name by mDNS (offpatch-mdns.service removed)"
  return 0
}

# --purge: remove the avahi packages this installer added, unless something else now needs them.
purge_mdns_pkgs() { # packages
  local p left="" n
  for p in "$@"; do pkg_installed "$p" && left="$left $p"; done
  [ -n "$left" ] || return 0
  n=$(apt-get -s remove $left 2>/dev/null | grep -c '^Remv ' || true)
  if [ "$n" = "$(wc -w <<< "$left")" ] && apt-get remove --purge -y -qq $left >/dev/null 2>&1; then
    ok "removed$left (installed by this installer for mDNS)"
  else
    warn "kept$left: other packages depend on them (sudo apt-get remove$left to see what)"
  fi
  return 0
}

install_mdns_pkgs() { # returns 1 when avahi is not available
  local p missing=""
  for p in avahi-daemon avahi-utils; do pkg_installed "$p" || missing="$missing $p"; done
  [ -n "$missing" ] || return 0
  if ! command -v apt-get >/dev/null; then MDNS_NOTE="avahi not installed"; warn "install$missing, then re-run (no apt-get)"; return 1; fi
  export DEBIAN_FRONTEND=noninteractive
  if apt-get install -y -qq --no-install-recommends $missing >/dev/null 2>&1 \
     || { apt-get update -qq >/dev/null 2>&1 && apt-get install -y -qq --no-install-recommends $missing >/dev/null 2>&1; }; then
    MDNS_PKGS_NOW=$(printf '%s\n' $MDNS_PKGS_NOW $missing | awk 'NF && !seen[$0]++' | paste -sd' ' -)
    ok "installed$missing"
    return 0
  fi
  MDNS_NOTE="could not install$missing"
  warn "could not install$missing (no package source reachable?). Install them (offline: apt-get download on a"
  warn "connected Ubuntu of the same release, then sudo dpkg -i *.deb), then re-run this installer"
  return 1
}

# Interfaces: announce only on the interface carrying $IP (a second / public interface stays
# silent). An allow-interfaces the admin set is respected; ours is added only when the host has
# other interfaces with addresses.
configure_avahi_ifaces() { # iface; sets AVAHI_CHANGED
  local iface=$1 others st val
  AVAHI_CHANGED=0
  others=$(ip -o addr show scope global 2>/dev/null | awk '{print $2}' | awk '!seen[$0]++' | grep -vxF "$iface" | paste -sd' ' - || true)
  IFS=$'\t' read -r st val <<< "$(avahi_allow_line)"
  if [ "$st" = theirs ]; then
    if printf '%s\n' "$val" | tr ', ' '\n\n' | grep -qxF "$iface"; then
      ok "avahi-daemon.conf: allow-interfaces=$val kept (set by an admin; includes $iface)"
    else
      warn "avahi-daemon.conf has allow-interfaces=$val (set by an admin) without $iface: the console name is"
      warn "not announced there. Add $iface to it and: sudo systemctl restart avahi-daemon (not changed by this installer)"
    fi
  elif [ -n "$others" ] || [ "$st" = ours ]; then
    if avahi_set_allow "$iface"; then
      AVAHI_CHANGED=1; ok "avahi-daemon.conf: allow-interfaces=$iface (not announced on: ${others:-no other interface})"
    else
      ok "avahi-daemon.conf: already limited to $iface"
    fi
  else
    ok "avahi: $iface is the only network interface; avahi-daemon.conf unchanged"
  fi
  if grep -Eq "^[[:space:]]*deny-interfaces[[:space:]]*=.*(^|[=, ])$iface([, ]|$)" "$AVAHI_CONF" 2>/dev/null; then
    warn "avahi-daemon.conf: deny-interfaces lists $iface: the console name is not announced there"
  fi
  return 0
}

# ufw (only when active; never enabled here): mDNS queries (UDP 5353) from the local subnet of $IP.
mdns_firewall() {
  command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q "Status: active" || return 0
  local c old prev=$MDNS_UFW_NOW
  MDNS_UFW_NOW=""
  for c in $(local_subnets "$IP"); do
    ufw allow proto udp from "$c" to any port 5353 comment 'mDNS: DSS Patcher console name' >/dev/null \
      && { ok "ufw: UDP 5353 (mDNS) open from $c"; MDNS_UFW_NOW="${MDNS_UFW_NOW:+$MDNS_UFW_NOW }$c"; }
  done
  for old in $prev; do   # the subnet changed since the last run
    case " $MDNS_UFW_NOW " in *" $old "*) ;; *) ufw delete allow proto udp from "$old" to any port 5353 >/dev/null 2>&1 && ok "ufw: removed the old mDNS rule for $old" ;; esac
  done
  return 0
}

write_mdns_unit() { # avahi-publish name ip
  cat > "$MDNS_UNIT" <<EOF
[Unit]
Description=DSS Patcher console name $2 -> $3 on the local network (mDNS)
Documentation=man:avahi-publish(1)
Requires=avahi-daemon.service
After=avahi-daemon.service
# avahi-daemon restarted: publish again
PartOf=avahi-daemon.service

[Service]
ExecStart=$1 -a -R $2 $3
Restart=always
RestartSec=10
DynamicUser=yes
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
RestrictAddressFamilies=AF_UNIX
CapabilityBoundingSet=
SystemCallArchitectures=native

[Install]
WantedBy=multi-user.target avahi-daemon.service
EOF
  chmod 0644 "$MDNS_UNIT"
}

setup_mdns() {
  step "Console name on the local network (mDNS): $SERVER_NAME → ${IP:-?}"
  local iface pub host_rec other got
  if [ $HAVE_SYSTEMD = 0 ]; then
    MDNS_NOTE="no systemd"; warn "no systemd: $SERVER_NAME is not published. Run from your init: avahi-publish -a -R $SERVER_NAME ${IP:-<IP>}"; return 0
  fi
  [ -n "${IP:-}" ] && iface=$(iface_of_ip "$IP") && [ -n "$iface" ] \
    || { MDNS_NOTE="no interface for ${IP:-the server IP}"; warn "cannot find the network interface of ${IP:-the server IP}: $SERVER_NAME is not published"; return 0; }
  install_mdns_pkgs || return 0
  if [ "$(systemctl is-enabled avahi-daemon.service 2>/dev/null || true)" = masked ]; then
    MDNS_NOTE="avahi-daemon is masked"; warn "avahi-daemon is masked on this host (local policy?): $SERVER_NAME is not published. Unmask it and re-run, or use --no-mdns"; return 0
  fi
  configure_avahi_ifaces "$iface"
  systemctl enable avahi-daemon.service >/dev/null 2>&1 || true
  if [ $AVAHI_CHANGED = 1 ]; then systemctl restart avahi-daemon.service; else systemctl start avahi-daemon.service; fi \
    || { MDNS_NOTE="avahi-daemon did not start"; warn "avahi-daemon did not start (journalctl -u avahi-daemon): $SERVER_NAME is not published"; return 0; }
  mdns_firewall
  # The host's own mDNS name (avahi publishes <hostname>.local itself): no alias needed, and a
  # second record with the same name would collide.
  host_rec=$(sed -n 's/^[[:space:]]*host-name[[:space:]]*=[[:space:]]*//p' "$AVAHI_CONF" 2>/dev/null | tail -n 1)
  host_rec=$(printf '%s.local' "${host_rec:-$(hostname -s)}" | tr 'A-Z' 'a-z')
  if [ "$host_rec" = "$SERVER_NAME" ]; then
    if [ -f "$MDNS_UNIT" ]; then systemctl disable --now offpatch-mdns.service >/dev/null 2>&1 || true; rm -f "$MDNS_UNIT"; systemctl daemon-reload; fi
    ok "$SERVER_NAME is this host's own mDNS name (published by avahi-daemon); no alias needed"
  else
    # Someone else on the segment already answering to the name: do not fight over it.
    [ ! -f "$MDNS_UNIT" ] || systemctl stop offpatch-mdns.service >/dev/null 2>&1 || true
    other=$(mdns_resolve "$SERVER_NAME")
    if [ -n "$other" ] && [ "$other" != "$IP" ]; then
      MDNS_NOTE="another device answers to $SERVER_NAME ($other)"
      warn "another device on this network already answers to $SERVER_NAME ($other): not published."
      warn "Re-run with --domain <other-name>.local (or --no-mdns and a DNS record)"
      if [ -f "$MDNS_UNIT" ]; then systemctl disable offpatch-mdns.service >/dev/null 2>&1 || true; rm -f "$MDNS_UNIT"; systemctl daemon-reload; fi
      return 0
    fi
    pub=$(command -v avahi-publish || echo /usr/bin/avahi-publish)
    write_mdns_unit "$pub" "$SERVER_NAME" "$IP"
    systemctl daemon-reload
    systemctl enable offpatch-mdns.service >/dev/null 2>&1 || true
    systemctl restart offpatch-mdns.service || true
  fi
  for _ in 1 2 3 4 5; do got=$(mdns_resolve "$SERVER_NAME"); [ "$got" = "$IP" ] && break; sleep 1; done
  if [ "$got" = "$IP" ]; then
    MDNS_ACTIVE=1
    ok "$SERVER_NAME → $IP answered by mDNS on $iface (offpatch-mdns.service; avahi runs as user avahi, the egress lock does not apply)"
  else
    MDNS_NOTE="published, but not confirmed"
    warn "$SERVER_NAME did not resolve to $IP yet (got: ${got:-nothing}). Check: systemctl status offpatch-mdns; avahi-resolve -n $SERVER_NAME"
    journalctl -u offpatch-mdns.service -n 3 -o cat 2>/dev/null | sed 's/^/      /' || true
  fi
  return 0
}

# ---------------------------------------------------------------- status
svc_state() { if [ $HAVE_SYSTEMD = 1 ]; then systemctl is-active "$1" 2>/dev/null || true; else pgrep -f "$2" >/dev/null && echo "running (no systemd)" || echo "not running"; fi; }

if [ $STATUS = 1 ]; then
  echo "installed role:    $(state_get ROLE || true)"
  [ -z "$(cfg_get server_name)" ] || echo "console name:      $(cfg_get server_name) (browsers only)"
  st_agent=$(cfg_get agent_url)
  [ -n "$st_agent" ] || [ -z "$(cfg_get agent_ip)" ] || st_agent="https://$(cfg_get agent_ip):$(cfg_get listen | sed 's/.*://')"
  [ -z "$st_agent" ] || echo "agents connect to: $st_agent"
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
  if [ -f "$MDNS_UNIT" ]; then
    echo "console by mDNS:   $(svc_state offpatch-mdns 'avahi-publish') ($(sed -n 's/^ExecStart=[^ ]* -a -R //p' "$MDNS_UNIT"); offpatch-mdns.service; test: avahi-resolve -n $(cfg_get server_name))"
  elif [ "$(state_get MDNS)" = 0 ]; then
    echo "console by mDNS:   off (--no-mdns)"
  fi
  [ -f "$ETC/keys/root.key" ] && echo "root key:          $ETC/keys/root.key is on this server: sudo $0 --export-root-key <offline media>"
  [ -f "$ETC/console-url.txt" ] && echo "console:           $(cat "$ETC/console-url.txt")"
  if [ -n "$(state_get PUBLIC_NAMES)" ]; then
    exp=$(openssl x509 -in "$PUBLIC_DIR/cert.pem" -noout -enddate 2>/dev/null | sed 's/notAfter=//' || true)
    echo "public console:    https://$(state_get PUBLIC_NAMES | cut -d, -f1):$(cfg_get listen | sed 's/.*://') ($(state_get PUBLIC_MODE), expires ${exp:-unknown}; agents: $(cfg_get agent_url))"
  fi
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
  for f in "$ETC"/keys/*.key "$ETC/pki/ca.key" "$ETC/pki/server.key" "$PUBLIC_DIR/key.pem" "$DEFAULT_CF_CREDS" "$SRV_DATA/audit-signing.key" "$AGENT_STATE"/*; do
    [ -e "$f" ] && warn "  still on disk: $f"
  done
  return 0
}

if [ $UNINSTALL = 1 ]; then
  AUDIT_LEFT=$(cfg_path audit_export_dir)
  PUB_MODE_LEFT=$(state_get PUBLIC_MODE); PUB_LEFT=$(state_get PUBLIC_NAMES); PUB_LEFT=${PUB_LEFT%%,*}
  MDNS_PKGS_LEFT=$(state_get MDNS_PKGS)
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
  # Console name by mDNS: the unit, our avahi-daemon.conf line and ufw rules always go; the avahi
  # packages only with --purge and only when this installer installed them.
  remove_mdns
  if [ -n "$MDNS_PKGS_LEFT" ]; then
    if [ $PURGE = 1 ]; then purge_mdns_pkgs $MDNS_PKGS_LEFT
    else warn "kept $MDNS_PKGS_LEFT (installed by this installer for mDNS): removed by --purge, or: sudo apt-get remove $MDNS_PKGS_LEFT"; fi
  fi
  for b in pmserver pmctl pmagent; do
    [ "$(readlink "/usr/local/bin/$b" 2>/dev/null)" = "$PREFIX/bin/$b" ] && rm -f "/usr/local/bin/$b"
  done
  rm -f /etc/logrotate.d/offpatch
  rm -rf "$PREFIX"
  # Public console certificate: the certbot deploy hook always goes; a Let's Encrypt certificate
  # only with --purge (the local account too, unless other certbot certificates use it).
  if [ -f "$LE_HOOK" ]; then rm -f "$LE_HOOK"; ok "removed the certbot deploy hook $LE_HOOK"; fi
  if [ "$PUB_MODE_LEFT" = letsencrypt ] && [ -n "$PUB_LEFT" ] && [ -d "/etc/letsencrypt/live/$PUB_LEFT" ]; then
    if [ $PURGE = 1 ] && command -v certbot >/dev/null; then
      certbot delete --cert-name "$PUB_LEFT" --non-interactive >/dev/null 2>&1 && ok "deleted the Let's Encrypt certificate for $PUB_LEFT"
      if ! compgen -G "/etc/letsencrypt/renewal/*.conf" >/dev/null; then
        rm -rf /etc/letsencrypt/accounts && ok "deleted the local Let's Encrypt account (no other certbot certificates on this host)"
      else
        warn "kept the Let's Encrypt account in /etc/letsencrypt/accounts: other certbot certificates on this host use it"
      fi
    else
      warn "kept the Let's Encrypt certificate for $PUB_LEFT (certbot keeps renewing it): sudo certbot delete --cert-name $PUB_LEFT, or --purge"
    fi
  fi
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

# ---------------------------------------------------------------- public certificate only
# Only public-certificate options on an existing server: add or replace the console
# certificate and change nothing else.
if [ $PUBLIC_WANTED = 1 ] && [ $OTHER_ARGS = 0 ] && [ -f "$ETC/pmserver.json" ]; then
  step "Public certificate for the console"
  { [ -x "$PREFIX/bin/pmserver" ] && grep -aq 'public_tls' "$PREFIX/bin/pmserver"; } \
    || die "the installed pmserver does not support public certificates yet: upgrade first by re-running this installer from the new release with the same options"
  listen=$(cfg_get listen); port=${listen##*:}
  [[ "$port" =~ ^[0-9]+$ ]] || die "cannot read the port from \"listen\": \"$listen\" in $ETC/pmserver.json"
  public_precheck
  default_agent=""
  aip=$(cfg_get agent_ip)
  [ -z "$aip" ] || default_agent="https://$aip:$port"   # agents: by IP, never the console name
  cp -p "$ETC/pmserver.json" "$ETC/pmserver.json.before-public-tls"
  setup_public_tls "$default_agent" || { rm -f "$ETC/pmserver.json.before-public-tls"; die "no certificate obtained; nothing was changed"; }
  if [ $HAVE_SYSTEMD = 1 ]; then systemctl restart offpatch-server; else
    pkill -f "$PREFIX/bin/pmserver" 2>/dev/null || true
    runuser -u "$SVC_USER" -- nohup "$PREFIX/bin/pmserver" -config "$ETC/pmserver.json" >> "$SRV_DATA/pmserver.log" 2>&1 &
  fi
  for _ in $(seq 1 30); do curl -fs -o /dev/null --cacert "$ETC/pki/ca.pem" "https://127.0.0.1:$port/" && break; sleep 1; done
  if ! curl -fs -o /dev/null --cacert "$ETC/pki/ca.pem" "https://127.0.0.1:$port/"; then
    cp -p "$ETC/pmserver.json.before-public-tls" "$ETC/pmserver.json"
    [ $HAVE_SYSTEMD = 0 ] || systemctl restart offpatch-server
    die "pmserver did not start with the public certificate; restored the previous $ETC/pmserver.json (journalctl -u offpatch-server)"
  fi
  rm -f "$ETC/pmserver.json.before-public-tls"
  check_public_https "$port"
  remember_public
  step "Done"
  public_summary "$port"
  [ "$PUBLIC_MODE" = provided ] || echo "  Renewal:        certbot timer + $LE_HOOK; test: sudo certbot renew --dry-run"
  warn "browsers need TCP $port to this server from where admins work: check ufw (--allow-from) and any network firewall"
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

# The server's name: --domain, else the name of an earlier install, else the default.
if [ $IS_SERVER = 1 ]; then
  SERVER_NAME=${DOMAIN_IN:-$(cfg_get server_name)}; SERVER_NAME=${SERVER_NAME:-$DEFAULT_DOMAIN}
elif [ -n "$DOMAIN_IN" ]; then
  die "--domain is for --role all or server (the console's name); agents connect by IP: --server https://<server IP>:<port>"
fi
[ -z "$SERVER_IP_IN" ] || warn "--server-ip is ignored: agents connect by IP (--server https://<server IP>:<port>); /etc/hosts is not changed"

if [ $PUBLIC_WANTED = 1 ]; then
  [ $IS_SERVER = 1 ] || die "--public-domain / --public-cert are for --role all or server (the console)"
  [ $INSECURE = 0 ] || die "a public certificate needs TLS; it cannot be combined with --insecure-lab"
  public_precheck   # fail before changing anything
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
# The address agents use (and the console name resolves to): an IPv4 given in --hosts that this machine owns, else
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
HOSTS=$(printf '%s\n' "$SERVER_NAME" "$(hostname)" localhost 127.0.0.1 "$IP" "$EXTRA_HOSTS" | tr ',' '\n' | awk 'NF && !seen[$0]++' | paste -sd, -)
case "$LISTEN_HOST" in ""|0.0.0.0|"::"|"[::]") LOCAL_HOST=127.0.0.1 ;; *) LOCAL_HOST=$LISTEN_HOST ;; esac
URL_LOCAL="$SCHEME://$LOCAL_HOST:$PORT"
URL_PUBLIC="$SCHEME://${SERVER_NAME:-${IP:-$(hostname)}}:$PORT"   # the console (browsers)
URL_AGENT="$SCHEME://${IP:-$(hostname)}:$PORT"                      # agents: always the IP, never the name

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
# reload = re-read the public console certificate (certbot deploy hook)
ExecReload=/bin/kill -HUP \$MAINPID
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
PUBLIC_OK=0 AGENT_URL_NOW=""
ADMIN_CREATED_EMAIL="" ADMIN_CREATED_PW="" ADMIN_DEFAULT_PW=0
if [ $IS_SERVER = 1 ]; then
  step "Management server"
  install -d -m 0750 -o "$SVC_USER" -g "$SVC_USER" "$SRV_DATA" "$SRV_DATA/inbox" "$SRV_DATA/agent-dist"
  if [ $INSECURE = 0 ] && [ ! -f "$ETC/pki/ca.pem" ]; then
    "$PREFIX/bin/pmserver" init-pki -dir "$ETC/pki" -hosts "$HOSTS" >/dev/null
    ok "created internal CA and server certificate for: $HOSTS"
  elif [ $INSECURE = 0 ] && [ -f "$ETC/pki/server.pem" ] && command -v openssl >/dev/null; then
    # The certificate must name server_name (browsers) and this machine's IP (agents).
    # Reissue (same CA: agents pin the CA, not this certificate) when not.
    sans=$(openssl x509 -in "$ETC/pki/server.pem" -noout -ext subjectAltName 2>/dev/null | tail -n +2 | tr ',' '\n' \
           | sed -n 's/^[[:space:]]*DNS://p; s/^[[:space:]]*IP Address://p' | tr -d ' ' || true)
    need=""
    for h in "$SERVER_NAME" ${IP:+"$IP"}; do printf '%s\n' "$sans" | grep -qixF "$h" || need="$need $h"; done
    if [ -n "$need" ]; then
      keep=$(printf '%s\n' "$SERVER_NAME" $sans "$IP" "$(printf '%s' "$EXTRA_HOSTS" | tr ',' '\n')" | awk 'NF && !seen[tolower($0)]++' | paste -sd, -)
      if "$PREFIX/bin/pmserver" reissue-server-cert -dir "$ETC/pki" -hosts "$keep" >/dev/null; then
        ok "server certificate reissued for: $keep (added:$need; agents keep working: they pin the CA)"
      else
        warn "could not reissue the server certificate with$need; agents and browsers may refuse that name: pmserver reissue-server-cert -dir $ETC/pki -hosts $keep"
      fi
    elif [ -n "$EXTRA_HOSTS" ]; then
      ok "keeping the existing server certificate (it names $SERVER_NAME; to change names: sudo -u $SVC_USER $PREFIX/bin/pmserver reissue-server-cert -dir $ETC/pki -hosts ...)"
    fi
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
    ipline=""; [ -n "${IP:-}" ] && ipline=$'\n'"  \"agent_ip\": \"$IP\","
    mode=two-machine; [ "$ROLE" = all ] && mode=single-server
    cat > "$ETC/pmserver.json" <<EOF
{
  "listen": "0.0.0.0:$PORT",
  "server_name": "$SERVER_NAME",${ipline}
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
  # The server's name (and the IP endpoints map it to): set on upgrades when missing, or
  # changed by --domain. Other settings are kept.
  if command -v python3 >/dev/null; then
    if msg=$(python3 - "$ETC/pmserver.json" "$SERVER_NAME" "${IP:-}" "$DOMAIN_IN" <<'PY'
import json, sys
p, name, ip, explicit = sys.argv[1:5]
c = json.load(open(p))
changed = []
if c.get("server_name") != name and (explicit or not c.get("server_name")):
    c["server_name"] = name
    changed.append("server_name " + name)
if ip and not c.get("agent_ip"):
    c["agent_ip"] = ip
    changed.append("agent_ip " + ip)
if changed:
    json.dump(c, open(p, "w"), indent=2)
    print("; ".join(changed))
PY
); then
      if [ -n "$msg" ]; then ok "$ETC/pmserver.json: $msg"; fi
    else
      warn "could not update $ETC/pmserver.json; set \"server_name\": \"$SERVER_NAME\" by hand"
    fi
  else
    warn "python3 not found: set \"server_name\": \"$SERVER_NAME\" in $ETC/pmserver.json by hand"
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
  if [ $PUBLIC_WANTED = 1 ]; then
    step "Public certificate for the console"
    if setup_public_tls "$URL_AGENT"; then PUBLIC_OK=1
    else warn "continuing without the public certificate; once fixed, re-run with the same --public-* options"; fi
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
  [ $PUBLIC_OK = 0 ] || check_public_https "$PORT"
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

# ---------------------------------------------------------------- console name by mDNS
# Only a *.local name is published (a DNS name such as patcher.bank.example keeps relying on DNS).
if [ $IS_SERVER = 1 ] && [ "$MDNS" = 1 ] && [[ "$SERVER_NAME" == *.local ]]; then
  setup_mdns
else
  if [ $IS_SERVER = 1 ] && [ "$MDNS" = 0 ]; then MDNS_NOTE="--no-mdns"
  elif [ $IS_SERVER = 1 ]; then MDNS_NOTE="$SERVER_NAME is not a .local name"; fi
  remove_mdns
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
MDNS=$MDNS
MDNS_PKGS=$MDNS_PKGS_NOW
MDNS_UFW=$MDNS_UFW_NOW
PUBLIC_MODE=$( [ $PUBLIC_OK = 1 ] && echo "$PUBLIC_MODE" || state_get PUBLIC_MODE )
PUBLIC_NAMES=$( [ $PUBLIC_OK = 1 ] && echo "$PUBLIC_NAMES" || state_get PUBLIC_NAMES )
EOF
chmod 0644 "$STATE_FILE"

# ---------------------------------------------------------------- summary
step "Done"
echo "  This machine:   $(hostname) — IP ${IP:-unknown}${OTHER_IPS:+   (other addresses: $OTHER_IPS)}"
if [ $IS_SERVER = 1 ]; then
  if [ $PUBLIC_OK = 1 ]; then
    public_summary "$PORT"
    echo "                  also $URL_PUBLIC (internal CA); sign in with email + password"
    echo "  Browsers:       need TCP $PORT from the admins' networks (ufw: --allow-from; network firewall)"
  elif [ $MDNS_ACTIVE = 1 ]; then
    echo "  Console:        $URL_PUBLIC — found automatically on this network (mDNS); from other subnets add a DNS record or hosts line"
    echo "                  (sign in with email + password)"
  else
    echo "  Console:        $URL_PUBLIC   (sign in with email + password)"
  fi
  AGENT_URL_NOW=${AGENT_URL_NOW:-$(cfg_get agent_url)}; AGENT_URL_NOW=${AGENT_URL_NOW:-$URL_AGENT}
  [ $PUBLIC_OK = 1 ] || echo "  Agents connect to: $AGENT_URL_NOW   (by IP: no DNS or hosts-file entry on the PCs)"
  echo "  PCs need:       TCP $PORT from every PC to ${IP:-this server} (nothing connects to the PCs)"
  if [ $MDNS_ACTIVE = 1 ] && [ -n "${IP:-}" ]; then
    echo "  Console name:   $SERVER_NAME answers by mDNS on this server's network segment (one subnet/VLAN; Windows 10/11,"
    echo "                  macOS, Linux resolve it with no setup). Test on a PC: Resolve-DnsName $SERVER_NAME (Windows),"
    echo "                  avahi-resolve -n $SERVER_NAME (Linux). Admin PCs on OTHER subnets: internal DNS A record, or:"
    echo "                    $IP $SERVER_NAME # DSS Patcher"
  elif [ -n "$SERVER_NAME" ] && [ -n "${IP:-}" ]; then
    echo "  Console name:   $SERVER_NAME is for the admins' browsers only: it must resolve to $IP on the ADMIN PCs"
    [ -z "$MDNS_NOTE" ] || [[ "$SERVER_NAME" != *.local ]] || echo "                  (not published by mDNS: $MDNS_NOTE)"
    echo "                  (internal DNS A record, or this hosts-file line on each admin PC; never needed on endpoints):"
    echo "                    $IP $SERVER_NAME # DSS Patcher"
    echo "                  Windows (PowerShell as Administrator):"
    echo "                    Add-Content -Path \"\$env:SystemRoot\\System32\\drivers\\etc\\hosts\" -Value \"$IP $SERVER_NAME # DSS Patcher\""
    echo "                  Linux / macOS:"
    echo "                    echo '$IP $SERVER_NAME # DSS Patcher' | sudo tee -a /etc/hosts"
  fi
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
  if [ $INSECURE = 0 ] && [ $PUBLIC_OK = 0 ] && [ -z "$(state_get PUBLIC_NAMES)" ]; then
    echo "  TLS:            internal CA $ETC/pki/ca.pem — distribute it to the admins' browsers (Group Policy: Trusted Root"
    echo "                  Certification Authorities), or give the console a public certificate: re-run with"
    echo "                  --public-cert FILE --public-key FILE (bank's certificate, recommended for isolated networks)"
    echo "                  or --public-domain NAME (Let's Encrypt; needs internet and TCP 80 or Cloudflare DNS)"
  elif [ $INSECURE = 0 ]; then
    echo "  TLS:            agents: internal CA $ETC/pki/ca.pem; browsers on $(state_get PUBLIC_NAMES): public certificate"
  fi
  [ "$ROLE" = server ] && echo "  Inbox:          the transfer receiver delivers into $SRV_DATA/inbox; add its account to group $XFER_GROUP"
  cat <<EOF

  Next steps (in the console, $URL_PUBLIC):
    1. Sign in and change the password.
    2. Settings → Users: create the bank's Admin.
    3. Endpoints → Create enrollment token → run the PowerShell line on each PC
       (Windows PowerShell as Administrator; the PC needs TCP $PORT to ${IP:-this server}).
    4. Patches → Needed → Import, Catalog → Approve, Patch this (2 approvals).

  Ubuntu endpoints: sudo ./install-ubuntu.sh --role agent --server $AGENT_URL_NOW --token <enr_…> \\
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
