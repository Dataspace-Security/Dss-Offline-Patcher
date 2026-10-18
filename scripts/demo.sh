#!/usr/bin/env bash
# End-to-end demo with the real binaries on one machine:
#   acquisition (pmctl) → drop-dir "diode" → pmserver intake/quarantine →
#   approval → staged deployment → simulated Windows agents → verification → audit.
# Leaves pmserver running so you can explore the console.
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT=$PWD
BIN=$ROOT/bin
DEMO=${DEMO_DIR:-$ROOT/demo}
PORT=${PORT:-8080}
URL=http://127.0.0.1:$PORT

# demo/ may be someone's live environment (server data, signing key, users,
# acquisition config): never delete it silently.
if [ -e "$DEMO" ]; then
  if pgrep -f "pmserver.*$(basename "$DEMO")/mgmt/pmserver.json" >/dev/null 2>&1; then
    echo "refusing: a pmserver is running from $DEMO. Stop it first, or use DEMO_DIR=/tmp/offpatch-demo PORT=18080." >&2
    exit 1
  fi
  if [ "${DEMO_RESET:-}" != "yes" ]; then
    echo "refusing: $DEMO already exists and would be deleted (server data, signing key, users, acquire.json)." >&2
    echo "Use another folder (DEMO_DIR=/tmp/offpatch-demo PORT=18080 $0), or DEMO_RESET=yes $0 to really start over." >&2
    exit 1
  fi
fi
if curl -s -o /dev/null "$URL"; then echo "port $PORT busy — stop the other server or set PORT=…" >&2; exit 1; fi

[ -x "$BIN/pmserver" ] || make build >/dev/null
make windows >/dev/null 2>&1 || true   # Windows agent, offered for download in the console
rm -rf "$DEMO" && mkdir -p "$DEMO"/{acq/downloads,acq/out,mgmt,agents}
step() { printf '\n\033[1;34m== %s\033[0m\n' "$*"; }
json() { sed -n "s/.*\"$1\":\"\([^\"]*\)\".*/\1/p"; }
# api METHOD PATH JAR [curl args]: a call as the user signed in with cookie jar JAR.
api() { local m=$1 p=$2 j=$3; shift 3; curl -sS -X "$m" -b "$j" -c "$j" -H 'X-Offpatch-CSRF: 1' -H 'Content-Type: application/json' "$URL$p" "$@"; }
# totp BASE32SECRET [offset seconds]: the authenticator code (RFC 6238), as an app would show it.
totp() { python3 -c 'import base64,hmac,hashlib,struct,sys,time
k=base64.b32decode(sys.argv[1]+"="*(-len(sys.argv[1])%8)); c=int(time.time()+int(sys.argv[2]))//30
h=hmac.new(k,struct.pack(">Q",c),hashlib.sha1).digest(); o=h[-1]&15
print("%06d"%((struct.unpack(">I",h[o:o+4])[0]&0x7fffffff)%1000000))' "$1" "${2:-0}"; }
command -v python3 >/dev/null || { echo "python3 is needed (authenticator codes for the demo users)"; exit 1; }

step "Acquisition zone: generate bundle-signing key"
"$BIN/pmctl" keygen -out "$DEMO/acq/bundle"

step "Acquisition zone: 'download' vendor files (fake payloads for the demo)"
head -c 200000 /dev/urandom > "$DEMO/acq/downloads/windows10.0-kb5044273-x64.msu"
head -c 50000 /dev/urandom > "$DEMO/acq/downloads/acme-agent-2.1.msi"
cat > "$DEMO/acq/spec.json" <<'EOF'
[
  {"package_id":"KB5044273-x64","title":"2026-10 Cumulative Update for Windows 10 22H2 x64","vendor":"Microsoft","kind":"msu",
   "version":"19045.5011","kb":"KB5044273","severity":"critical","release_date":"2026-10-08","supersedes":["KB5043064"],
   "applicability":{"os":"windows","arch":"x64","min_build":19045,"max_build":19045},
   "source_url":"https://catalog.update.microsoft.com/","vendor_signature":{"status":"not_checked"},"path":"downloads/windows10.0-kb5044273-x64.msu"},
  {"package_id":"AcmeAgent-2.1","title":"Acme Endpoint Agent 2.1","vendor":"Acme","kind":"msi","version":"2.1.0",
   "product_code":"{11111111-2222-3333-4444-555555555555}","severity":"important","release_date":"2026-10-01",
   "applicability":{"os":"windows","arch":"any"},"vendor_signature":{"status":"not_checked"},"path":"downloads/acme-agent-2.1.msi"}
]
EOF
"$BIN/pmctl" build -key "$DEMO/acq/bundle.key" -spec "$DEMO/acq/spec.json" -state "$DEMO/acq/state.json" -out "$DEMO/acq/out/october.pmb"
"$BIN/pmctl" inspect -bundle "$DEMO/acq/out/october.pmb" -pub "$DEMO/acq/bundle.pub"

step "Management zone: configure pmserver"
cp "$DEMO/acq/bundle.pub" "$DEMO/mgmt/bundle.pub"
cat > "$DEMO/mgmt/pmserver.json" <<EOF
{
  "listen": "127.0.0.1:$PORT",
  "insecure_http": true,
  "data_dir": "data",
  "trusted_keys": [{"public_key_file": "bundle.pub", "sources": ["acq-zone-1"]}],
  "deployment_approvals": 1,
  "intake_interval": "1s",
  "checkin_interval_seconds": 15
}
EOF
mkdir -p "$DEMO/mgmt/data/agent-dist"
[ -f "$BIN/windows/pmagent.exe" ] && cp "$BIN/windows/pmagent.exe" "$DEMO/mgmt/data/agent-dist/"
SA_EMAIL=superadmin@demo.test
SA_PW=$(cd "$DEMO/mgmt" && "$BIN/pmserver" create-admin -config pmserver.json -email "$SA_EMAIL" -password-random | awk '/^password:/{print $2}')
[ -n "$SA_PW" ] || { echo "could not create the demo super admin"; exit 1; }

if curl -s -o /dev/null "$URL"; then echo "port $PORT busy — stop the other server or set PORT=…"; exit 1; fi
"$BIN/pmserver" -config "$DEMO/mgmt/pmserver.json" > "$DEMO/mgmt/pmserver.log" 2>&1 &
echo $! > "$DEMO/mgmt/pmserver.pid"
for _ in $(seq 50); do curl -s -o /dev/null "$URL" && break; sleep 0.1; done

step "Sign-in: the super admin (no MFA needed) creates the bank user alice; alice enrols an authenticator"
SA="$DEMO/mgmt/sa.cookies"; ALICE="$DEMO/mgmt/alice.cookies"
api POST /api/auth/login "$SA" -d "{\"email\":\"$SA_EMAIL\",\"password\":\"$SA_PW\"}" >/dev/null
ALICE_PW="alice demo passphrase 1"
api POST /api/users "$SA" -d "{\"email\":\"alice@demo.test\",\"role\":\"user\",\"password\":\"temporary password 1\"}" >/dev/null
api POST /api/auth/login "$ALICE" -d '{"email":"alice@demo.test","password":"temporary password 1"}' >/dev/null
api POST /api/auth/password "$ALICE" -d "{\"current\":\"temporary password 1\",\"new\":\"$ALICE_PW\"}" >/dev/null
ALICE_SECRET=$(api POST /api/auth/mfa/enroll/start "$ALICE" -d '{}' | json secret_base32)
api POST /api/auth/mfa/enroll/confirm "$ALICE" -d "{\"code\":\"$(totp "$ALICE_SECRET")\"}" > "$DEMO/alice-recovery-codes.json"
cat > "$DEMO/users.txt" <<EOF
super admin  $SA_EMAIL  $SA_PW
alice (user) alice@demo.test  $ALICE_PW  authenticator secret $ALICE_SECRET
EOF
chmod 600 "$DEMO/users.txt" "$DEMO/alice-recovery-codes.json"

step "Transfer boundary: send bundle through the one-way drop directory"
"$BIN/pmctl" send -bundle "$DEMO/acq/out/october.pmb" -to "$DEMO/mgmt/data/inbox"
sleep 2.5
api GET /api/bundles "$SA" | grep -o '"state":"[a-z]*"' | head -1

step "Replay attack: re-send the same bundle (renamed) → must be rejected"
cp "$DEMO/acq/out/october.pmb" "$DEMO/acq/out/october-replay.pmb"
"$BIN/pmctl" send -bundle "$DEMO/acq/out/october-replay.pmb" -to "$DEMO/mgmt/data/inbox" >/dev/null
sleep 2.5
api GET /api/bundles "$SA" | grep -o '"error":"[^"]*"' | head -1

step "Endpoints: enroll three simulated Windows agents"
for spec in "pc-pilot-01:pilot:" "pc-fin-01:broad:" "pc-fin-02:broad:-sim-reboot"; do
  IFS=: read -r host group extra <<<"$spec"
  TOK=$(api POST /api/enrollment-tokens "$SA" -d "{\"groups\":[\"$group\"],\"site\":\"hq\",\"expires_in_hours\":1}" | json token)
  "$BIN/pmagent" enroll -server "$URL" -token "$TOK" -pubkey "$DEMO/acq/bundle.pub" -state-dir "$DEMO/agents/$host" -platform sim -hostname "$host" $extra
  "$BIN/pmagent" run -once -state-dir "$DEMO/agents/$host" 2>/dev/null
done

step "Approval: alice approves the cumulative update (published to repository)"
api POST /api/packages/KB5044273-x64/approve "$ALICE" -d '{"reason":"CHG-1042 lab-tested on reference images"}' | json state

step "Deployment: pilot ring, then broad ring"
DEP=$(api POST /api/deployments "$SA" -d '{"package_id":"KB5044273-x64","name":"October CU","rings":[{"name":"pilot","groups":["pilot"]},{"name":"broad","groups":["broad"]}],"max_failure_pct":20,"max_retries":2,"window_start":"","window_end":"","emergency":false,"justification":""}' | json deployment_id)
echo "deployment $DEP"
api POST "/api/deployments/$DEP/approve" "$ALICE" -d '{"reason":"CHG-1042 approved"}' | json state
"$BIN/pmagent" run -once -state-dir "$DEMO/agents/pc-pilot-01" 2>/dev/null
"$BIN/pmagent" run -once -state-dir "$DEMO/agents/pc-pilot-01" 2>/dev/null
api POST "/api/deployments/$DEP/advance" "$SA" -d '{"reason":"pilot verified"}' >/dev/null
for h in pc-fin-01 pc-fin-02; do "$BIN/pmagent" run -once -state-dir "$DEMO/agents/$h" 2>/dev/null; done
for h in pc-fin-01 pc-fin-02; do "$BIN/pmagent" run -once -state-dir "$DEMO/agents/$h" 2>/dev/null; done
for h in pc-fin-01 pc-fin-02; do "$BIN/pmagent" run -once -state-dir "$DEMO/agents/$h" 2>/dev/null; done
api GET "/api/deployments/$DEP" "$SA" | sed "s/.*\"targets\"://" | grep -o '"hostname":"[^"]*"\|"state":"[a-z_]*"' | paste - - | sed 's/"//g'

step "Audit chain"
api GET /api/audit/verify "$SA"; echo
api GET "/api/audit/export?package_id=KB5044273-x64" "$SA" > "$DEMO/lifecycle-KB5044273-x64.json"
echo "lifecycle evidence: demo/lifecycle-KB5044273-x64.json"

step "Done"
cat <<EOF
pmserver is running (pid $(cat "$DEMO/mgmt/pmserver.pid")) — console: $URL
Sign in with a user from demo/users.txt (super admin: $SA_EMAIL)
Keep agents polling:  $BIN/pmagent run -state-dir demo/agents/pc-pilot-01
Stop the server:      kill \$(cat demo/mgmt/pmserver.pid)
EOF
