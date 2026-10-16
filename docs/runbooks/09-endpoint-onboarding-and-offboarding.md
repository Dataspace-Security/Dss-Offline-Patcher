# Runbook 09 — Endpoint onboarding and offboarding

## Purpose

Enroll endpoints (one at a time or in bulk) so they get a unique identity and an mTLS client
certificate, and retire them cleanly when they leave.

## When to use

- New endpoints, site rollouts, rebuilt machines.
- Re-enrollment after a `401` (retired, restored server, expired certificate) or a key change.
- Decommissioning, reimaging or renaming a machine.

## How enrollment works (from the code)

- An operator creates an **enrollment token** (`enr_…`) bound to a set of groups and a site.
  Only its hash is stored; the token is shown once.
- `pmagent enroll` (over `https://`) generates a private key on the endpoint (it never leaves the
  machine), sends a CSR with the token, and receives a client certificate signed by the server's
  internal CA, valid **365 days**. Over `http://` (lab mode only) it receives a bearer secret.
- The agent pins the bundle signing key(s) given with `-pubkey`, the server CA from `-ca`, and the
  root key from `-root-pubkey`. All are stored in `agent.json` in the state directory.
- The agent renews its certificate automatically during the last 30 days, at check-in
  (`endpoint.cert_renewed`). The old certificate stops working immediately. If a certificate is
  within 14 days of expiry and not renewed (agent not checking in), the server raises a
  `cert_expiring` alert; after expiry the endpoint must be re-enrolled.
- Token limits: `max_uses` 1 (default) to 10,000; single-use tokens valid up to 720 h, multi-use
  tokens up to 336 h (14 days); default 24 h.

Default state directories: Windows `C:\ProgramData\offpatch`, Linux `/var/lib/offpatch`, macOS
`/Library/Application Support/offpatch`.

## Prerequisites and roles

| Item | Notes |
|---|---|
| Operator role | Create tokens, edit endpoint groups, retire endpoints. |
| Local admin / root on the endpoint | Enrollment and service install. |
| `bundle.pub`, `ca.pem`, `root.pub` | Console → **Agent setup** offers `bundle.pub` and `ca.pem`; `root.pub` comes from the acquisition zone (runbook 02). |
| Agent binary or package | From `<data_dir>/agent-dist/` (Agent setup page) or your software distribution. |
| Network | Endpoint → server `listen` port only. Endpoint → internet denied. |
| Groups decided | Group names drive rings and maintenance windows (e.g. `pilot`, `broad`, `servers-prod`). Lower case; normalised by the server. |

## Onboarding — single endpoint

1. **Token** (console **Endpoints → Create enrollment token**, or API):

   ```bash
   curl --cacert ca.pem -H "Authorization: Bearer $TOK" -H 'Content-Type: application/json' \
     -d '{"groups":["pilot"],"site":"hq","expires_in_hours":24,"max_uses":1}' \
     https://pm.corp.internal:8443/api/enrollment-tokens
   # {"token":"enr_…","expires_at":"…","max_uses":1}
   ```

2. **Windows** (elevated PowerShell, binary and key files in the current directory):

   ```powershell
   .\pmagent.exe enroll -server https://pm.corp.internal:8443 -token enr_… `
     -pubkey bundle.pub -ca ca.pem -root-pubkey root.pub
   .\pmagent.exe service install       # registers "offpatch-agent", auto start, restart on failure (incl. non-crash)
   sc.exe start offpatch-agent
   ```

   Install the binary in a protected location (e.g. `C:\Program Files\offpatch\`) **before**
   `service install`: the service runs the binary from where `service install` was run.
3. **Linux** (root):

   ```bash
   install -m 0755 pmagent /usr/sbin/pmagent
   pmagent enroll -server https://pm.corp.internal:8443 -token enr_… \
     -pubkey /etc/offpatch/bundle.pub -ca /etc/offpatch/ca.pem -root-pubkey /etc/offpatch/root.pub -platform linux
   pmagent service install             # writes /etc/systemd/system/offpatch-agent.service, enables and starts it
   ```

4. **macOS** (root): `pmagent enroll … -platform macos`, then `pmagent service install`
   (`/Library/LaunchDaemons/com.offpatch.agent.plist`, started immediately). The macOS agent installs
   `.pkg` packages only; it does not handle macOS system updates.
5. Several bundle keys: `-pubkey a.pub,b.pub`.

Always give `-root-pubkey`. Without it the endpoint cannot follow key rotation or revocation and must
be re-enrolled when keys change (runbooks 03, 04).

## Onboarding — mass rollout

1. **One token per site and group set**, `max_uses` slightly above the machine count, short expiry:

   ```json
   {"groups":["broad","site-plant2"],"site":"plant2","expires_in_hours":168,"max_uses":450}
   ```

   Anyone with the token can enroll machines into those groups until it expires or is used up.
   Distribute it through your deployment tool's secret handling, not in scripts on shares.
2. **Windows — MSI** (`packaging/windows/`, being written; check that folder for the current
   properties and build steps). As written now: built per environment with `build-msi.ps1 -Version
   <v> -ConfigDir <dir>` where the directory holds `bundle.pub` (required), `ca.pem` and `root.pub`
   (baked into the MSI). It installs `pmagent.exe` under `C:\Program Files\offpatch\`, registers and
   starts the `offpatch-agent` service, and on first install with both properties set, enrolls:

   ```powershell
   msiexec /i offpatch-agent-1.2.0.msi SERVER=https://pm.corp.internal:8443 TOKEN=enr_… /qn /l*v install.log
   ```

   `TOKEN` is marked hidden so it is not written to the MSI log. Without `TOKEN`/`SERVER` the agent is
   installed but not enrolled. Sign the MSI before distribution. Deploy via GPO, SCCM or Intune.
   The MSI also sets the service's restart-on-non-crash-failure flag (`sc.exe failureflag
   offpatch-agent 1`), needed for agent self-upgrade (runbook 08). Agents installed with an older
   MSI need that command run once.
3. **Linux — `.deb` / `.rpm`** (`packaging/linux/`, built with `make linux-packages`): before
   installing the package, place `/etc/offpatch/enroll.env` (mode 0600) and the key files with your
   configuration management:

   ```sh
   SERVER=https://pm.corp.internal:8443
   TOKEN=enr_…
   PUBKEY=/etc/offpatch/bundle.pub
   CA=/etc/offpatch/ca.pem
   ROOT=/etc/offpatch/root.pub
   ```

   On install, if the device is not yet enrolled, the post-install script runs `pmagent enroll …
   -platform linux`, deletes `enroll.env` on success, and installs/starts the systemd unit. If
   enrollment fails it prints a message and the package install still succeeds; fix `enroll.env` and
   run `pmagent enroll …` and `pmagent service install` by hand.
4. **Track progress:** Endpoints page (filter by site/group), `GET /api/reports/endpoints.csv`, and
   audit `endpoint.enrolled` / `endpoint.enroll_denied` events.

## After enrollment

- Check owner, criticality, site and groups on the endpoint page (operator can edit). Changing
  groups adds the endpoint to rings of active deployments.
- First check-in sends inventory; status leaves `stale` once inventory arrives.

## Verification

- Endpoint appears with the expected hostname, OS, groups and site; status is not `stale`/`offline`
  after one check-in interval.
- `cert_not_after` is about one year ahead (TLS mode).
- Agent log shows `checked in` lines without errors.

## Offboarding

1. **Retire** in the console (Endpoint → Retire, operator, reason) or:

   ```bash
   curl --cacert ca.pem -H "Authorization: Bearer $TOK" -H 'Content-Type: application/json' \
     -d '{"reason":"CHG-2201 decommissioned"}' \
     https://pm.corp.internal:8443/api/endpoints/e-…/retire
   ```

   Effects: certificate and secret invalid at once; outstanding targets in active/paused deployments
   become `not_applicable` ("endpoint retired: …"); history kept; excluded from fleet totals; status
   `retired`. Retirement cannot be undone.
2. **Remove the agent** from the machine (if it still exists):

| Platform | Commands |
|---|---|
| Windows (MSI) | Uninstall "offpatch Endpoint Agent" (Programs and Features, or `msiexec /x` with the MSI) |
| Windows (manual) | `sc.exe stop offpatch-agent` then `pmagent.exe service uninstall` (it only deletes the service; stop it first) |
| Linux (package) | `apt remove offpatch-agent` / `dnf remove offpatch-agent` (the pre-remove script stops and removes the unit) |
| Linux (manual) | `pmagent service uninstall` |
| macOS | `pmagent service uninstall` |

3. Delete the state directory (`agent.json`, client key, cache). The package removal keeps
   `/var/lib/offpatch`; delete it yourself.

## Re-enrollment (rebuilt, renamed, restored, or 401)

1. Retire the old endpoint record if it is still active.
2. Stop the agent, delete (or move aside) the old state directory.
3. Enroll with a new token as above. The endpoint gets a **new** endpoint ID; its history stays
   under the old one.

## Rollback / escape hatch

- Wrong groups or site on a token: retire the endpoints enrolled with it, create a correct token,
  re-enroll. Or simply edit the endpoints' groups/site (operator).
- Token leaked: there is no API to revoke an enrollment token. It stops working when it expires or
  its uses are spent. Watch `endpoint.enrolled` events and retire unexpected endpoints. Keep expiry
  short.

## Evidence to keep

- Token creation events (`enrollment_token.created`: groups, site, expiry, max uses, creator).
- Enrollment events and the endpoint list per rollout wave.
- Retirement reason and change reference per decommissioned endpoint.
