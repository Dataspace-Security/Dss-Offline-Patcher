#!/usr/bin/env bash
# End-to-end demo with the real binaries on one machine:
#   acquisition (pmctl) → drop-dir "diode" → pmserver intake/quarantine →
#   approval → staged deployment → simulated Windows agents → verification → audit.
# Leaves pmserver running so you can explore the console.
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT=$PWD
BIN=$ROOT/bin
DEMO=$ROOT/demo
PORT=${PORT:-8080}
URL=http://127.0.0.1:$PORT

[ -x "$BIN/pmserver" ] || make build >/dev/null
make windows >/dev/null 2>&1 || true   # Windows agent, offered for download in the console
rm -rf "$DEMO" && mkdir -p "$DEMO"/{acq/downloads,acq/out,mgmt,agents}
step() { printf '\n\033[1;34m== %s\033[0m\n' "$*"; }
json() { sed -n "s/.*\"$1\":\"\([^\"]*\)\".*/\1/p"; }
api() { local m=$1 p=$2 t=$3; shift 3; curl -sS -X "$m" -H "Authorization: Bearer $t" -H 'Content-Type: application/json' "$URL$p" "$@"; }

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
read -r ADMIN_TOK ADMIN_SHA < <("$BIN/pmserver" new-token | awk '{print $2}' | xargs)
read -r APPR_TOK APPR_SHA < <("$BIN/pmserver" new-token | awk '{print $2}' | xargs)
read -r OPER_TOK OPER_SHA < <("$BIN/pmserver" new-token | awk '{print $2}' | xargs)
cp "$DEMO/acq/bundle.pub" "$DEMO/mgmt/bundle.pub"
cat > "$DEMO/mgmt/pmserver.json" <<EOF
{
  "listen": "127.0.0.1:$PORT",
  "insecure_http": true,
  "data_dir": "data",
  "trusted_keys": [{"public_key_file": "bundle.pub", "sources": ["acq-zone-1"]}],
  "admin_tokens": [
    {"user": "admin",  "role": "admin",    "token_sha256": "$ADMIN_SHA"},
    {"user": "alice",  "role": "approver", "token_sha256": "$APPR_SHA"},
    {"user": "otto",   "role": "operator", "token_sha256": "$OPER_SHA"}
  ],
  "intake_interval": "1s",
  "checkin_interval_seconds": 15
}
EOF
mkdir -p "$DEMO/mgmt/data/agent-dist"
[ -f "$BIN/windows/pmagent.exe" ] && cp "$BIN/windows/pmagent.exe" "$DEMO/mgmt/data/agent-dist/"
cat > "$DEMO/tokens.txt" <<EOF
admin    $ADMIN_TOK
alice    $APPR_TOK   (approver)
otto     $OPER_TOK   (operator)
EOF
chmod 600 "$DEMO/tokens.txt"

if curl -s -o /dev/null "$URL"; then echo "port $PORT busy — stop the other server or set PORT=…"; exit 1; fi
"$BIN/pmserver" -config "$DEMO/mgmt/pmserver.json" > "$DEMO/mgmt/pmserver.log" 2>&1 &
echo $! > "$DEMO/mgmt/pmserver.pid"
for _ in $(seq 50); do curl -s -o /dev/null "$URL" && break; sleep 0.1; done

step "Transfer boundary: send bundle through the one-way drop directory"
"$BIN/pmctl" send -bundle "$DEMO/acq/out/october.pmb" -to "$DEMO/mgmt/data/inbox"
sleep 2.5
api GET /api/bundles "$ADMIN_TOK" | grep -o '"state":"[a-z]*"' | head -1

step "Replay attack: re-send the same bundle (renamed) → must be rejected"
cp "$DEMO/acq/out/october.pmb" "$DEMO/acq/out/october-replay.pmb"
"$BIN/pmctl" send -bundle "$DEMO/acq/out/october-replay.pmb" -to "$DEMO/mgmt/data/inbox" >/dev/null
sleep 2.5
api GET /api/bundles "$ADMIN_TOK" | grep -o '"error":"[^"]*"' | head -1

step "Endpoints: enroll three simulated Windows agents"
for spec in "pc-pilot-01:pilot:" "pc-fin-01:broad:" "pc-fin-02:broad:-sim-reboot"; do
  IFS=: read -r host group extra <<<"$spec"
  TOK=$(api POST /api/enrollment-tokens "$OPER_TOK" -d "{\"groups\":[\"$group\"],\"site\":\"hq\",\"expires_in_hours\":1}" | json token)
  "$BIN/pmagent" enroll -server "$URL" -token "$TOK" -pubkey "$DEMO/acq/bundle.pub" -state-dir "$DEMO/agents/$host" -platform sim -hostname "$host" $extra
  "$BIN/pmagent" run -once -state-dir "$DEMO/agents/$host" 2>/dev/null
done

step "Approval: alice approves the cumulative update (published to repository)"
api POST /api/packages/KB5044273-x64/approve "$APPR_TOK" -d '{"reason":"CHG-1042 lab-tested on reference images"}' | json state

step "Deployment: pilot ring, then broad ring"
DEP=$(api POST /api/deployments "$OPER_TOK" -d '{"package_id":"KB5044273-x64","name":"October CU","rings":[{"name":"pilot","groups":["pilot"]},{"name":"broad","groups":["broad"]}],"max_failure_pct":20,"max_retries":2,"window_start":"","window_end":"","emergency":false,"justification":""}' | json deployment_id)
echo "deployment $DEP"
"$BIN/pmagent" run -once -state-dir "$DEMO/agents/pc-pilot-01" 2>/dev/null
"$BIN/pmagent" run -once -state-dir "$DEMO/agents/pc-pilot-01" 2>/dev/null
api POST "/api/deployments/$DEP/advance" "$OPER_TOK" -d '{"reason":"pilot verified"}' >/dev/null
for h in pc-fin-01 pc-fin-02; do "$BIN/pmagent" run -once -state-dir "$DEMO/agents/$h" 2>/dev/null; done
for h in pc-fin-01 pc-fin-02; do "$BIN/pmagent" run -once -state-dir "$DEMO/agents/$h" 2>/dev/null; done
for h in pc-fin-01 pc-fin-02; do "$BIN/pmagent" run -once -state-dir "$DEMO/agents/$h" 2>/dev/null; done
api GET "/api/deployments/$DEP" "$ADMIN_TOK" | sed "s/.*\"targets\"://" | grep -o '"hostname":"[^"]*"\|"state":"[a-z_]*"' | paste - - | sed 's/"//g'

step "Audit chain"
api GET /api/audit/verify "$ADMIN_TOK"; echo
api GET "/api/audit/export?package_id=KB5044273-x64" "$ADMIN_TOK" > "$DEMO/lifecycle-KB5044273-x64.json"
echo "lifecycle evidence: demo/lifecycle-KB5044273-x64.json"

step "Done"
cat <<EOF
pmserver is running (pid $(cat "$DEMO/mgmt/pmserver.pid")) — console: $URL
Sign in with a token from demo/tokens.txt (admin: $ADMIN_TOK)
Keep agents polling:  $BIN/pmagent run -state-dir demo/agents/pc-pilot-01
Stop the server:      kill \$(cat demo/mgmt/pmserver.pid)
EOF
