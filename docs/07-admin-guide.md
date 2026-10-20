# 07 — Administrator and endpoint-support training guide (roadmap D4)

Audience: Windows and Linux administrators and endpoint support staff who are new to offpatch.
After this guide you should be able to run the daily checks, approve and roll out a patch, handle
failures and exceptions, run the monthly Patch Tuesday cycle, enroll and retire endpoints, and
produce audit evidence.

Step-by-step procedures for less frequent tasks are in [runbooks/](runbooks/README.md). The API is
specified in [05-api.md](05-api.md) and the state machines in [03-state-model.md](03-state-model.md).

Everything here describes what the code does today. Where a feature is missing, the guide says so.

---

## 0. Installation (production, one command)

The OS administrator installs everything on **one Ubuntu server** with one command from the
release folder (details: [runbook 01, method A1](runbooks/01-install-management-server.md#method-a1-single-server-one-command-production-default)):

```bash
sudo ./install-ubuntu.sh
```

It installs the server and console, the downloader (`pmctl auto`, **every hour**, as its own
account `offpatch-acq`), daily verified backups and the hardening: only the downloader account may
open outbound internet connections (TCP 80/443, DNS; nftables egress lock), the console port is
limited to the local subnet when ufw is active, and the compliance report discloses the
single-server deployment. Then:

1. Move the offline root key off the server: `sudo ./install-ubuntu.sh --export-root-key /media/usb`.
2. Sign in at the URL the installer prints (`https://<server name>:8443`; the name is `--domain`,
   default `dsspatcher.local`, which the server announces by mDNS so admin PCs on the same
   network segment find it with no setup; from other subnets use internal DNS or the hosts-file
   line the installer prints, see §5.5) as
   `superadmin@dataspacesecurity.com` with the default password (vendor handbook) **and the
   one-time setup code** the installer prints in a box at the end of its summary (the console shows
   a "Setup code" field for this email). The first sign-in requires a new password and MFA
   enrolment (authenticator app). This account is created
   on a **fresh install only** (no database yet); upgrades never create or re-enable accounts.
3. **Settings → Users**: create the bank's Admin.
4. **Endpoints → Create enrollment token** → run the PowerShell line on each PC as Administrator
   (§5.1). Each PC needs TCP 8443 to the server's IP. Agents connect by that IP
   (`https://<server IP>:8443`), never by the server name: no DNS or hosts-file entry on PCs.
5. **Patches → Needed → Import**, **Catalog → Approve**, **Patch this** (2 approvals).

A two-machine layout (`--role server` in the isolated zone, `--role acquisition` in the connected
zone, one-way transfer between them) is stricter and is described in the README and runbooks 01/02.

**Install checks and upgrades.** Re-running the same command upgrades in place with the saved
settings (role, domain, ports, `--console-proxy-port`, public certificate, firewall sources); no new
options are needed. What the installer checks or refuses:

- **Fresh install:** stops when the server port (or `--console-proxy-port`) is already in use on the
  host. On a **public IP** with ufw active it needs `--allow-from <CIDR>` (the provider's "local
  subnet" is shared with other customers); on a private IP the local subnet stays the default. On an
  upgrade, existing ufw rules for the port are kept. `--insecure-lab` is refused on a public IP.
- **Upgrade:** a verified backup comes first. If anything fails after the new binaries are copied
  but before the server restarts, the previous binaries and `pmserver.json` are put back; the
  running server is not interrupted.
- **Files of the service accounts:** the installer refuses to follow a symbolic link inside
  `/var/lib/offpatch-server`, `/var/lib/offpatch-acq`, the backup directory or `/etc/offpatch/pki`
  and stops with the path; changes there run as the owning service account. The public console
  certificate (`/etc/offpatch/pki/public`) is `root:offpatch` 0750 with 0640 files: pmserver reads
  and reloads it but cannot change it; the certbot hook writes it as root without following links.
- **Backups:** `--backup-dir PATH` uses its own folder `PATH/offpatch` (PATH may be shared
  storage); earlier installs' backups in PATH are moved there on the next upgrade (afterwards give
  PATH back its previous owner, as the installer prints). An existing non-empty folder that does
  not belong to DSS Patcher is refused. The default `/var/lib/offpatch-backup` is unchanged.
- **Source builds** use a temporary Go toolchain; `/usr/local/go` is never changed.
- The Cloudflare token file must be a root-owned 0600 file (not a link) in a root-owned folder
  that is not group/world writable.

## 1. Concepts

### 1.1 Zones

| Zone | What runs there | What you do there |
|---|---|---|
| Connected acquisition zone | `pmctl` | Find vendor updates (`pmctl msrc`, `catalog-search`), download them (`fetch`, `fetch-url`), sign a bundle (`build`), send it across the boundary (`send`). This zone holds the **bundle signing key** (or uses an HSM through `-key exec:…`). |
| Transfer boundary | Data diode, gateway, or (in the MVP) a drop directory | Files flow one way only: into the isolated zone. Nothing flows back. |
| Isolated management zone | `pmserver` and its web console | Intake, quarantine, approval, repository, deployments, reports, audit. |
| Endpoint zone | `pmagent` | Inventory, download from `pmserver` only, verify, install, report. The agent has no internet or Windows Update fallback. Network egress denial must still be enforced by firewalls. |

On a **single server** (the default install) the acquisition zone is the account `offpatch-acq`
on the management server: it is the only account allowed out to the internet (TCP 80/443, DNS),
and the "transfer boundary" is the server's inbox, which that account can only drop files into.
The compliance report says so (scope limitations, PM-04).

### 1.2 Bundles and packages

- A **bundle** (`.pmb`) is a signed tar file. It holds `manifest.json`, an Ed25519 signature and one
  payload file per package. One bundle can carry up to 500 packages.
- A **package** is one installable file plus its metadata: `package_id`, `kind`, severity, KB or
  product code, applicability (OS, arch, build range, editions), supersedence and prerequisites.
- Package kinds:

| `kind` | Platform | Installed by the agent with | Identified in inventory by |
|---|---|---|---|
| `msu` | Windows | `wusa.exe <file> /quiet /norestart` | KB number (`Win32_QuickFixEngineering`) |
| `msi` | Windows | `msiexec.exe /i <file> /qn /norestart /l*v <log>` | MSI product code `{GUID}` |
| `deb` | Linux | `dpkg --force-confold -i <file>` | `package_name` and version (`dpkg-query`) |
| `rpm` | Linux | `rpm -U --replacepkgs <file>` | `package_name` and version (`rpm -qa`) |
| `pkg` | macOS | `/usr/sbin/installer -pkg <file> -target /` | receipt id (`package_name`) and version (`pkgutil`) |
| `agent` | any | the agent replaces its own binary (self-upgrade) | agent version |

> The Windows agent (`wusa`/`msiexec`) has so far only been exercised through the simulated
> platform; roadmap item B1 (validation on real Windows VMs) is still open. Test on a VM before any
> pilot.

### 1.3 Quarantine and approval

Nothing is deployable when it arrives. The pipeline is:

```
.pmb appears in <data_dir>/inbox
   → moved to <data_dir>/received/<sha256>.pmb   (evidence copy, kept even if rejected)
   → extracted to <data_dir>/quarantine/…         (never served to endpoints)
   → checks run (see §8, "bundle rejected")
   → bundle "validated" → each new package is "quarantined" in the Catalog
   → a bank user approves → content is copied to <data_dir>/repository/ (read-only, by SHA-256)
   → package "approved" → only now can a deployment be created
```

Package states: `quarantined` → `approved` → `revoked`, or `quarantined` → `rejected`. `rejected` and
`revoked` are final. There is no way to put a package back into quarantine. To re-release fixed
content you need a **new `package_id`**: re-sending the same `package_id` with different content
is rejected (`catalog_conflict`), and re-sending identical content is skipped as a duplicate.

The endpoint does not trust the server for content. Before installing, the agent re-verifies the
original manifest signature against the keys it pinned at enrollment, and checks the payload
SHA-256. A tampered repository file is refused ("content does not match signed manifest — possible
tampering").

### 1.4 Deployments, rings and targets

**Glossary (console wording):**

- **Stage (ring)**: one step of a deployment. The console says "stage"; the API, the audit log and
  this guide's technical sections say "ring" (`rings`, `current_ring`). "Start next stage" in the
  console is the **Advance** action.
- **Test machines**: the endpoints in group `pilot`. Standard deployments patch them first
  (stage 1 "Test machines", groups `pilot`), then everything else (stage 2 "All machines",
  groups `all`). Older deployments show the stored names `pilot` / `broad` as the same labels.

- A **deployment** installs one approved package. It has 1–10 ordered **rings**, for example `pilot`
  then `broad`. Each ring names one or more endpoint **groups**. The group `all` matches every
  endpoint.
- An endpoint lands in the **first** ring whose groups match one of its groups. If it matches no
  ring, the deployment does not touch it at all.
- Only rings up to the **current ring** get work. You move to the next ring with **Advance**.
- Each endpoint × deployment pair is a **target**. Target states:

| Target state | Meaning | Set by |
|---|---|---|
| `pending` | Waiting to be picked up (window closed, concurrency cap, prerequisite missing, endpoint offline, …) | server |
| `downloading`, `downloaded`, `installing` | In progress | agent |
| `installed` | Installer succeeded; **not yet verified** | agent |
| `pending_reboot` | Installed, reboot required; not verified until after the reboot | agent |
| `verified` | A **fresh inventory** shows the KB / product code / package version (machine-wide or per-user install), or a KB that supersedes it (transitively), or (Windows cumulative updates with `expected_ubr`) the machine reports that build revision or later | **server only** |
| `failed` | Installer or download failed. Retried while `attempts ≤ max_retries` | agent |
| `not_applicable` | OS/arch/build/edition does not match, or the installer said "not applicable", or the endpoint was retired | server or agent |
| `exception` | Covered by an active exception | server |
| `deferred` | A pre-install check failed (not enough free disk space, laptop on battery below the minimum). Retried at every check-in; **not** a failure (§3.8) | agent |
| `lost_after_install` | The endpoint reported `installed` / `pending_reboot` and then went silent for `lost_after_install` (default 2 h). Counts as a failure towards auto-pause (§3.8) | server |
| `rolled_back` | The package was removed from this endpoint by a verified rollback deployment; no longer counted as patched | server |

A deployment is either an **install** (default) or a **rollback**: a rollback uninstalls the package, ring by ring (§3.8). Its targets use the same states; the console shows them as *uninstalling*, *uninstalled* and *verified removed*.

Deployment states: `active`, `paused`, `cancelled`, `completed`. A deployment completes on its own
when every target in the **last** ring is `verified`, `not_applicable`, `exception`, or `failed`
with retries exhausted.

### 1.5 Endpoint status — silence is never compliance

Each endpoint gets one derived status. The first matching rule wins:

| Status | Rule |
|---|---|
| `retired` | The endpoint was retired. Excluded from fleet totals. |
| `lost_after_install` | Any target `lost_after_install`: it went silent right after installing (§3.8). Highest priority. |
| `awaiting_checkin` | Enrolled less than 24 h ago and has not sent its first inventory yet (console: "Waiting for first check-in"). Not compliant, but not alerted on as offline / stale. After 24 h without a check-in it is `offline`. |
| `offline` | No check-in for longer than `offline_after` (default 30 min) |
| `stale` | Inventory older than `stale_inventory_after` (default 24 h) |
| `failed` | Any target `failed` (in a deployment that is not cancelled) |
| `pending_reboot` | Any target `pending_reboot`, or the OS reports a reboot pending |
| `exception` | Any target covered by an exception |
| `noncompliant` | Any target `pending`/`deferred`/`downloading`/`downloaded`/`installing`/`installed` (rollback targets excepted) |
| `out_of_support` | Would be compliant, but the update intelligence says its Windows build no longer gets updates from Microsoft (console: "Windows no longer updated") |
| `updates_available` | Would be compliant, but the update intelligence says it is missing Windows or app updates nobody has deployed yet (console: "Updates available") |
| `compliant` | Otherwise |

`lost_after_install`, `offline` and `stale` beat everything else. An endpoint that stops talking is **never** shown as
compliant, and the reports count it as not reporting. `out_of_support` and `updates_available` only ever replace
`compliant` (never `failed`, `pending_reboot`, `offline`, ...), come from the latest update intelligence, and are used
everywhere the console counts endpoints (overview, endpoint list and detail, `endpoints.csv`, metrics). Without update
intelligence a machine with nothing deployed to it is `compliant`.

---

## 2. Roles and sign-in

Roles are cumulative: `viewer` < `user` < `admin` < `super_admin`. The bank has Admins, Users and
Viewers; the **super admin is the vendor** (setup and support). These are the only role names: the
old names `operator` and `approver` were removed. pmserver refuses to start when the config or
`oidc.role_groups` still uses one (the error names the old value); users and sessions stored with an
old name are moved to `user` automatically.

| Role | Can do (in addition to the roles below it) |
|---|---|
| `viewer` | Read: Overview, Patches → Needed and Catalog, Deployments, Windows, Exceptions, Endpoints, Agent setup (and download staged agent files), Reports (incl. CSV and PDF, the auditor report and evidence ZIP), Alerts, Audit (incl. verify, lifecycle export and PDF). No action buttons. **Not Imports** (bundles, transfer reconciliation, acquisition requests: user and up) and **not the Library** (vendor super admin only). |
| `user` (bank) | Patches → Imports; import what the machines need (not from the Library: the vendor's); create enrollment tokens; edit endpoint groups/site/owner/criticality; retire endpoints; export acquisition requests; approve and reject packages; create deployments and rollbacks (they wait for two approvals); **approve or reject other people's deployments and rollbacks** (not agent versions); pause, resume, cancel, advance and retry deployments; create and delete maintenance windows; acknowledge alerts. |
| `admin` (bank) | Users page: create, disable / enable and delete local users, reset passwords and MFA, change roles of Users, Viewers and Admins; create and revoke exceptions; revoke packages; **approve or reject agent-version deployments** (only bank admins can). |
| `super_admin` (vendor) | Everything, including super admin accounts, the **Library** and **agent versions** (approve, reject, revoke, deploy and roll back packages of kind `agent`). Not a deployment approver, agent-version deployments included. |

The console shows each role only what it can use; the server enforces the same table (a refused call
is HTTP 403 and audited `access.denied`). The full matrix is in
[roles-and-permissions.md](roles-and-permissions.md).

### Email + password sign-in (local users)

- The sign-in page asks for **email and password**, then for the 6-digit code from an
  **authenticator app** (TOTP, RFC 6238, 30 s; any standard app). An Admin creates users on
  **Settings → Users** (email, name, role, temporary password, or let the server generate one: it is
  shown once).
- **MFA is required for every local user, `super_admin` included** (by default). Only
  `"require_mfa": false` in `pmserver.json` makes it optional for super admins (pmserver logs a
  warning at every start; not recommended). At the first sign-in without an authenticator the user
  can only enrol: the console shows a QR code (and the secret for manual entry); the user confirms
  with a code and gets **10 recovery codes**, shown once. Each recovery code works once in place of an
  authenticator code; they are stored hashed only.
- At first sign-in with a temporary password the user must choose their own (at least 12 characters,
  not the email) first, then enrol the authenticator. Until then nothing else works.
- **Sign-in protection.** Five wrong passwords in a row from one client address lock the account
  **for that address** for 15 minutes (the user can still sign in from their own PC); 50 wrong
  passwords within 15 minutes from any addresses lock the account everywhere for 15 minutes and raise
  a critical alert `auth.account_locked`. Authenticator codes have their **own** counter, which a
  correct password does not reset: five wrong codes in a row lock the code step for 15 minutes,
  doubling at each further lockout (up to 24 hours), and raise a critical alert `auth.mfa_locked`
  (someone probably knows the password: have it changed). Only a correct code resets it. One
  password step allows at most 3 codes (then the password again); the step works once. An Admin
  clears every lock with **Enable** (also **Reset MFA** for the code lock). Sign-in attempts are
  also limited per client address, and at most 4 password checks run at a time (busy: 503, try
  again). Failed sign-ins are audited at most once a minute per account and address
  (`suppressed` counts the folded ones); locks are always audited. The error is always "wrong email
  or password" (or "wrong or expired code"), so nobody can find out which emails exist.
- **Reset MFA** (lost phone) removes the user's authenticator and recovery codes and signs them out;
  they enrol again at the next sign-in. Admins reset bank roles; only a super admin resets a super
  admin. A super admin may switch its own MFA off (with a current code) only on a server with
  `"require_mfa": false`.
- **Reset password** gives a new temporary password and signs the user out everywhere. **Change role**
  signs the user out (the new role applies at the next sign-in). **Delete** removes a local user's
  account, sessions and MFA; the audit history stays (`user.deleted`) and the email can be reused. SSO
  users cannot be deleted: disable them. Nobody can disable, demote, reset or delete themselves, and the
  last super admin cannot be disabled, demoted or deleted.
- Authenticator secrets are encrypted at rest (AES-256-GCM) with the key file `mfa_key_file`
  (default `<data_dir>/mfa.key`), created by the installer or at first start. At the default path it is part of
  `pmserver backup`; losing it loses every enrolment (everyone must be reset).
- The installer creates the **built-in super admin** (`--admin-email`, default
  `superadmin@dataspacesecurity.com`) with the vendor's **default password** (in the vendor
  handbook; only its hash is in `pmserver`). The server forces a password change at the first
  sign-in (nothing else works until then), then the authenticator set-up; pmserver logs a warning at
  every start while the default is in use.
- **One-time setup code.** The default password is the same everywhere, so on its own it does not
  sign in: while the account still has it, the sign-in also needs a setup code (12 characters,
  `XXXX-XXXX-XXXX`), which only someone with root on the server can get. The installer prints one
  in a box at the end of its summary on a fresh install, and again on every upgrade while the
  default password is still in use (a new code replaces the old one). A lost or expired code:
  `runuser -u offpatch -- /opt/offpatch/bin/pmserver setup-code -config /etc/offpatch/pmserver.json`
  (printed once; audited `user.setup_code_created`). Only its hash is stored; it expires after
  7 days and is deleted when the password is changed. A missing or wrong code gets the same
  "wrong email or password" answer as a wrong password and counts towards the lockout (audited
  `auth.login_failed`, reason "default password without a valid setup code"), so the code field
  never tells anyone whether the default password was right. Other accounts never need a code. An account created by an earlier version that still has
  the default password gets the same forced change at the next start (audited
  `user.password_change_forced`). The super admin then creates the bank's first Admin. `pmserver create-admin -password-random` creates it with a random
  password printed once instead.
- **Nobody can sign in** (lost password or authenticator): on the server, as root,
  `runuser -u offpatch -- /opt/offpatch/bin/pmserver reset-admin -config /etc/offpatch/pmserver.json -email <email>`
  prints a new random password once, re-enables the account, clears the lockout and clears its MFA
  (audited `user.password_reset` by `system:cli`). `pmserver create-admin` creates the built-in super
  admin when none exists.
- `require_mfa: true` additionally refuses SSO sessions without MFA from the IdP (local users need
  the authenticator step anyway). `require_mfa: false` makes it optional for local super admins only.
  Email + password sign-in stays available.

Nobody can change the server configuration, trusted keys or audit settings from the console. Those
live in `pmserver.json` and need OS access to the server plus a restart.

### Single sign-on (SSO)

- When `oidc` is configured, the login page shows **Sign in with SSO** (OIDC authorization-code flow
  with PKCE, against AD FS, Entra ID, Okta, Keycloak or any standards-based IdP reachable from the
  isolated zone).
- Your role comes from your IdP groups (`oidc.role_groups`, keys `viewer`, `user`, `admin`,
  `super_admin`). If you are in several mapped groups you get the highest role. If you are in none,
  sign-in is refused and audited as `auth.login_denied`.
- MFA for SSO users is the IdP's. With `require_mfa: true`, a login without MFA evidence in the ID
  token (`amr`, or `acr` if configured) is refused.
- Your role is taken at sign-in. A group change in the IdP applies at your next sign-in. Sessions
  last `session_ttl` (default 8 h).
- An admin can **disable** a user on the Users page. That revokes their sessions at once. You cannot
  disable yourself.

### No static admin tokens (removed in v1.9)

Static admin tokens no longer exist. pmserver refuses to start while `pmserver.json` contains
`admin_tokens` or `allow_static_tokens` (delete them and sign in with email + password); the
installer removes both keys on upgrade and shreds the old token files. A request to `/api/*` with
`Authorization: Bearer …` gets 401 `static admin tokens were removed; sign in with email and
password`. `pmserver new-token` and the console's token sign-in are gone.

Scripts sign in like a person: `POST /api/auth/login`, then `POST /api/auth/mfa` with a code for
bank roles, and send the `offpatch_session` cookie plus header `X-Offpatch-CSRF: 1` (see
[runbooks/README.md](runbooks/README.md)). For an enrollment token without the console, run
`pmserver enroll-token -config /etc/offpatch/pmserver.json -groups pilot -site hq -hours 1` on the
server as the service user (one use, audited). Agents (mTLS, or a bearer device secret in lab mode)
and the `metrics_token` for `GET /metrics` are unchanged.

---

## 3. Daily tasks

### 3.1 Morning check (10 minutes)

1. **Overview.** Read the endpoint status counts. Look at `lost_after_install` first, then `offline`,
   `stale`, `failed` and `pending_reboot`, not only `compliant`. Check that the audit chain shows OK.
2. **Alerts** (badge in the navigation). Work through open alerts. Each one names an object. Alert
   kinds raised by the server:

| Kind | Severity | Raised when |
|---|---|---|
| `deployment_auto_paused` | critical | A ring crossed its failure threshold |
| `lost_after_install` | critical | Endpoints stopped checking in after an install (the message names them; updated and re-sent while open) |
| `signing_key_compromised` | critical | A trust document revoked a bundle key as compromised (raised again if a revocation interrupted by a restart is completed later) |
| `manifest_verification_failed` | critical | An endpoint refused an assignment because the signed manifest or the downloaded content did not verify (tampering until shown otherwise) |
| `server_cert_expiring` | warning / critical | The server TLS certificate expires within 30 days (critical once expired): run `pmserver reissue-server-cert` and restart |
| `public_cert_expiring` | warning / critical | The public console certificate (§5.5) expires within 14 days, i.e. renewal is failing or the bank's certificate needs replacing (critical once expired or unusable: browsers get the internal certificate). Closes itself once a valid certificate is loaded |
| `audit_export_failed` | critical | Writing audit export files failed |
| `install_failed` | warning | An agent reported `failed` |
| `health_check_failed` | warning | A post-install health check failed |
| `bundle_rejected` | warning | Intake rejected a bundle |
| `trust_rejected` | warning | A trust document did not verify or was a replay |
| `intake_rate_limited` | warning | Inbox rate limit reached; bundles wait in the inbox |
| `endpoints_offline` / `inventory_stale` | warning | Fleet sweep found offline / stale endpoints (the message names them) |
| `install_unverified` | warning | Endpoints reported an install more than 6 h ago and inventory has not confirmed it (counts as a failure for auto-pause) |
| `out_of_support` | warning | Endpoints run a Windows build Microsoft no longer updates: plan the upgrade |
| `acquisition_stale` | warning | No acquisition status report for `acquisition_stale_after` (default 3 h on a single server, i.e. three missed hourly runs; 26 h in the two-machine layout, where reports arrive with carried files). Check `systemctl status offpatch-acquire.timer offpatch-acquire.service` |
| `intel_stale` | warning | The update intelligence is more than 8 days old: what the console says is missing may be out of date; ask the acquisition team |
| `cert_expiring` | warning | An endpoint's client certificate expires within 14 days and has not been renewed (agent offline?) |
| `exception_expiring` | info | An active exception expires within 7 days |

   An identical alert (same kind and object) is not raised again while one is open. Alerts about
   endpoints name up to five hosts (then "+N more"); the console links them. **Condition alerts
   close themselves** when the condition clears (shown as resolved by `system:scheduler`, audited
   `alert.resolved`): offline / stale endpoints back, an install that failed and later verified,
   health checks that pass after the restart, lost endpoints back, intelligence fresh again, no
   out-of-support build left, unconfirmed installs confirmed, a renewed certificate. Event alerts
   (rejected bundle, auto-pause, key compromise, ...) stay until you acknowledge them (role `user`)
   with a short note once you have acted. Acknowledging does not fix anything, and the same
   condition raises a new alert if it is still true at the next sweep (every
   `alert_sweep_interval`, default 5 min).
3. **Reports.** Check compliance by severity against the deadlines (`patch_deadlines`, default:
   critical 7 days, important 30, moderate 60, low 90, counted from the vendor release date).
   `overdue` targets are the priority. Compliance per package counts every endpoint that **needs**
   the package, not only the targeted ones: needed machines nobody deployed to are outstanding
   (`not_targeted`). Export `compliance.csv` / `endpoints.csv` if your change board wants them,
   and **Download evidence (CSV)** (`targets.csv`: per endpoint and package the state, when it
   verified, the inventory line that proved it and who approved it) for auditors. Every export is
   audited.
4. **Intake.** Any rejected bundle since yesterday? Is the transfer reconciliation clean (no
   receipt without a bundle, no bundle without a receipt)?
5. **Deployments.** Any `paused` deployments? Any active deployment with targets stuck in `pending`
   (see §8)?

### 3.2 Approving a patch

1. **Catalog** → filter `quarantined` → open the package.
2. Check: title, KB / product code, severity, applicability (OS, arch, build range, editions),
   supersedes, prerequisites, vendor signature (`valid`, or `not_checked` when the bundle was built
   on a non-Windows host), size and SHA-256, and the source bundle on the Intake page.
3. **Approve…** with a reason (mandatory), for example your change number: `CHG-1042 tested on
   reference images`. Use **Reject…** with a reason for content you will not deploy.

**Two-person approval.** `approval_policy` sets the number of approvals per severity (1–5, default 1),
for example `{"critical": 2, "important": 2}`. The first approval is recorded
(`package.approval_recorded`) and the package stays `quarantined` showing "Approvals · 1 of 2". A
second, **different** approver must approve. The same person approving twice gets HTTP 409. Only
the last required approval publishes the content to the repository.

**Separation of duties.** With `separation_of_duties: true`, anyone who approved a package cannot
create a deployment for it (HTTP 409 "separation of duties: … a different operator must deploy
it"). Plan who approves and who deploys.

### 3.3 Creating a staged deployment

**Deployments → New** (user). The new deployment waits for approval (below). Fields:

| Field | Meaning and rules |
|---|---|
| Package | Must be `approved`. |
| Name | Free text, required. |
| Rings | 1–10 rings, each with a name and at least one group. Typical: `pilot` → `broad`. |
| `max_failure_pct` | 0–100. The deployment auto-pauses when (failed targets with retries exhausted + targets with a failed health check) in the current ring exceed this percentage of considered targets (not counting `not_applicable` and `exception`). **0 means the first exhausted failure pauses it.** |
| `max_retries` | 0–10. A failed target is offered again while `attempts ≤ max_retries`. "Installer busy" failures (another installation running on the machine) do not use up retries for the first 10 in a row; the target shows `waiting: another installation is running on this machine (try N)`. |
| `auto_advance` | Default off. When on, a ring that finished within `max_failure_pct` starts the next ring by itself (audited as `deployment.advanced` by `system:scheduler`). A ring that finished over the threshold waits for you. "Patch this → every compatible machine that needs it" turns it on when 10 or more machines need the update: first max(5, 5 %) of them ("First machines"), then everything else. |
| Window (`window_start`/`window_end`) | `HH:MM` **UTC**, both or neither. May cross midnight. Outside it, no assignments are handed out. |
| `deadline` | RFC 3339, optional. After it, **endpoint maintenance windows** no longer hold installs back. It does **not** override the deployment window above. |
| `max_concurrent` | Cap on endpoints downloading/installing at once (0 = no cap). |
| `reboot_policy` | `never` (default), `in_window` (the agent may reboot inside a maintenance window with `allow_reboot`), `at_deadline` (in such a window, or at any time once the deadline has passed; needs a deadline). |
| `ignore_windows` | Ignore endpoint maintenance windows entirely. |
| `health_checks` | Up to 20 fixed checks run after install: `service_running` (Windows service name, systemd unit, or launchd label) or `tcp_listening` (port on 127.0.0.1). No arbitrary commands. |
| `emergency` + `justification` | Emergency deployments need a justification, are audited as `deployment.created_emergency`, flagged in the UI, and handed out before other work. |

**Maintenance windows** (Windows page, role `user`) belong to endpoint groups, not to deployments:
name, groups (or `all`), days (`mon`…`sun`), start and end `HH:MM` in an IANA time zone (may cross
midnight), and `allow_reboot`. If an endpoint is in any group that has a window, it only receives
installs while one of its windows is open, unless the deployment ignores windows or is past its
deadline.

**When does the agent reboot?** Only when the deployment's `reboot_policy` allows it: the server
sends `reboot_now`, or an install returned "reboot required" and the assignment allows a reboot.
The agent schedules a restart in 10 minutes with a warning (Windows `shutdown /r /t 600`, Linux and
macOS `shutdown -r +10`). With `reboot_policy: never` it never reboots and the target waits in
`pending_reboot` until someone reboots the machine. A `pending_reboot` target becomes `verified` only
when inventory shows the update **and** the OS no longer reports a pending reboot. With `in_window`
(or `at_deadline` before the deadline) on a machine that has **no** maintenance window with
`allow_reboot`, no automatic restart can ever happen: the target detail says so ("no maintenance
window allows automatic restarts (restart the machine or add a window)"), and the console's "Patch
this" defaults to `never` in that case. The console shows `pending_reboot` as "Restart needed".

**Two-person approval of deployments and rollbacks.** Every deployment and rollback (emergency too)
starts as **Waiting for approval (0 of 2)**: no machine gets anything yet. Two **different** bank
Users or Admins, neither of them the creator, open it and **Approve** with a reason (the change
number). The second approval starts it (audited `deployment.approved` twice and
`deployment.activated` with both names). **Reject** (with a reason) ends it for good; the creator can
**Cancel** it instead. The super admin (vendor) and Viewers cannot approve. While it waits, it counts
as running: a second deployment of the same package and operation is refused until it is approved
and finished, rejected or cancelled. `deployment_approvals` in `pmserver.json` sets the count
(default 2, 1–5; an isolated single-person lab may use 1). An `info` alert
`deployment_awaiting_approval` is open while it waits.

### 3.4 Advancing, pausing, resuming, cancelling

| Action | Who | Rules |
|---|---|---|
| Advance | user | Deployment `active`, not on the last ring, and no target in the current ring is `downloading`/`downloaded`/`installing`. Failed targets do **not** block advance; look at them first. Reason optional. |
| Pause | user | From `active`. Reason required. Agents get no new assignments. An agent that already received an assignment may still be working on it; content downloads it starts after the pause are refused, so such a target can show `failed`. |
| Resume | user | From `paused`. Reason required. Resuming does not immediately re-pause; only a **new** failure re-evaluates the threshold. |
| Cancel | user | From `pending_approval`, `active` or `paused`. Reason required. Final. Targets of cancelled deployments no longer count in endpoint status or compliance reports. |

Pilot gate before advancing: every pilot target is `verified`, `not_applicable` or `exception`;
failures explained; health checks `ok`; pilot owners have confirmed their applications work.

### 3.5 Handling failed targets

1. Open the deployment → **Targets**. Read `detail` and `exit_code` (see the exit-code table in §8).
2. Open the endpoint → **Deployment targets** and **Inventory**.
3. Fix the cause on the endpoint (free disk, stop a conflicting installer, install the prerequisite).
   While attempts remain, the agent retries at its next check-in.
4. Retries exhausted and the deployment still `active`/`paused`: if the update gets installed some
   other way, the next check-in still verifies it. To have offpatch try again, create a new
   deployment for the package that targets that endpoint's group.
5. Deployment already `completed`: its `failed` targets are still re-checked at every check-in.
   If you fix the endpoint by hand (or another deployment installs the update), the next
   inventory marks the target `verified` and the endpoint status recovers. An exception created
   for the endpoint applies to those targets at its next check-in.
6. If the endpoint must not get the patch, raise an exception (§3.7).

### 3.6 Pending reboots, offline and stale endpoints

- **`pending_reboot`:** either schedule the reboot with the endpoint owner, or use `reboot_policy`
  with a maintenance window that has `allow_reboot`. The status clears after the reboot and the
  next check-in.
- **`offline`:** the agent has not checked in for `offline_after`. Check the machine is powered on,
  the service is running (Windows `sc query offpatch-agent`, Linux
  `systemctl status offpatch-agent`, macOS `launchctl print system/com.offpatch.agent`), it can
  reach the server port, and the agent log (§8) shows no `401`. Offline endpoints keep their
  pending targets. They are never counted as compliant.
- **`stale`:** the endpoint checks in but inventory is older than `stale_inventory_after`. Each
  check-in sends inventory, so this normally means inventory collection is failing. Read the agent
  log for `inventory:` errors (PowerShell / WMI on Windows, `dpkg-query`/`rpm` on Linux).
- Decommissioned machines: **retire** them (§5.3). Do not leave them offline forever.

### 3.7 Exceptions

**Deployments → Exceptions → New exception** (admin; everyone else reads the list). Required: endpoint, owner, reason, compensating controls,
and expiry (in the future and at most one year away). Package is optional: empty means **all**
packages for that endpoint. Exceptions are per endpoint; there are no group-wide exceptions.

- Applied immediately to that endpoint's `pending` and `failed` targets in active or paused
  deployments (state → `exception`).
- An `exception_expiring` alert is raised 7 days before expiry. Review it with the owner and either
  revoke it, let it lapse, or create a new one.
- When an exception expires or is revoked, the target goes back to `pending` and will be installed.

### 3.8 Install safety: pre-install checks, lost endpoints, rollback

**Pre-install checks (deferral).** Before downloading, the agent checks:

- free space on the system volume (Windows `%SystemDrive%`, else `/`) and on its cache directory
  ≥ the larger of **2 × the package size** and `preinstall.min_free_disk_mb` for the endpoint's OS
  (defaults: Windows 5120, macOS 2048, Linux 1024 MB);
- on laptops: **AC power**, or battery ≥ `preinstall.min_battery_pct` (default 40; `0` turns the
  battery check off). Windows reads `GetSystemPowerStatus` (the source of `Win32_Battery`), macOS
  `pmset -g batt`, Linux `/sys/class/power_supply`. Desktops, servers and VMs have no battery and pass.

If a check fails the target becomes `deferred` with the reason (for example `not enough free disk
space on C:\: 3.2 GB free, need 5.0 GB …` or `on battery at 23% (need AC power or at least 40%)`)
and is offered again at every check-in. Deferral uses no attempt, raises no alert and does not count
towards auto-pause. A long-deferred endpoint stays `noncompliant`: free disk space or ask the user to
plug in. If the OS cannot report disk or power the check is skipped and logged, not enforced.

```json
"preinstall": {"min_free_disk_mb": {"windows": 5120, "macos": 2048, "linux": 1024}, "min_battery_pct": 40}
```

**Lost after install.** If an endpoint reported `installed` or `pending_reboot` and then shows no
activity (check-in or report) for `lost_after_install` (default `"2h"`, counted from the later of the
install report, its last check-in and the reboot request), the alert sweep marks the target
`lost_after_install`, raises a **critical** alert naming the hosts, and counts it as a failure in
its ring — so a patch that stops machines from booting auto-pauses the rollout. What to do:

1. Look at the named machines (console / hypervisor / hands on): boot loop, blue screen, no network
   after the reboot? Use your normal recovery (Safe Mode, System Restore, `DISM /Remove-Package`,
   restore from backup).
2. Consider a rollback deployment for machines that still boot (below).
3. When a machine comes back and its agent checks in, its target recovers by itself (`verified`, or
   back to `pending_reboot` / `installed`). The deployment stays paused until you resume it.

Set `lost_after_install` longer than your longest install + reboot, and expect laptops that are
simply switched off after patching to show up here too; the auto-recovery handles them.

**Rollback.** On a package (Catalog) or an install deployment, **Roll back…** opens a new
deployment with operation *Roll back (uninstall)*. It goes through rings, windows, concurrency,
reboot policy, health checks and auto-pause like an install, needs role `user` and a
**justification** (change ticket / incident), and is audited as `deployment.created_rollback`.

| Kind | Uninstall | Notes |
|---|---|---|
| `msu` | `wusa /uninstall /kb:N /quiet /norestart` | Some combined SSU+LCU packages cannot be removed with wusa; such targets fail and need `DISM /Remove-Package` by hand |
| `msi` | `msiexec /x {ProductCode} /qn /norestart` (verbose log in the agent log directory) | |
| `deb` / `rpm` | `dpkg -r` / `rpm -e` | Removes the package (it does not reinstall the previous version). Refused when other packages depend on it. Only endpoints at exactly this version are targeted |
| `pkg` (macOS) | — | **Not supported**: macOS installer packages have no uninstall. Deploy the previous version's `.pkg` or remove the app by hand |

Only endpoints whose inventory shows the package are targeted; the others are `not_applicable`. A
rollback target is `verified` when a fresh inventory no longer shows the package; the matching
install targets then become `rolled_back` and reports stop counting them as patched. An install and
a rollback of the same package cannot run at the same time: cancel one first. Revoking a package
cancels its install deployments but not its rollbacks, and a revoked package can still be rolled
back — the usual order for a bad patch is *revoke*, then *roll back*.

---

### 3.9 Acquisition requests: carried file or direct hand-off

**Updates → Export acquisition request** lists what the fleet is missing for the acquisition
zone ([08-acquisition.md](08-acquisition.md)). How it gets there depends on one setting in
`pmserver.json`:

| `acquisition_requests_dir` | What happens on export | Use it for |
|---|---|---|
| unset (default) | The browser downloads `<request_id>.json`; the operator carries it on approved media into the acquisition host's `requests` folder. The console says "Strict one-way transfer". | **Two-machine layout.** Keep it unset: the isolated server never writes anything towards the connected zone. |
| absolute path, e.g. `/var/lib/offpatch-acq/requests` | The server also writes the request into that folder (atomically, mode 0640); the console says "Queued for download". | Only when acquisition runs **on the same machine** (the single-server install sets it), or the organisation has formally approved an outbound folder. |

- The audit event `acquisition.request_exported` records `queued_to` (the folder, or empty). If
  the write fails, the export still succeeds as a download, and the event carries `queued_error`;
  check the folder's permissions (the server user needs write access; `pmctl auto` needs read and
  rename).
- The path must be absolute (the server refuses to start otherwise). If it is not writable at
  startup the server logs a warning and keeps running.
- Requests queued this way are handled by the next hourly `pmctl auto` run; the single-server
  install also starts `pmctl auto -only-requests` as soon as a file appears
  (`offpatch-acquire-requests.path`).
- **Imports** shows each request item as requested, seen, fulfilled, can't import (with the
  reason), or **Not picked up**: the newest acquisition run, finished more than 10 minutes after
  the request, did not list it (the file never reached the acquisition host, or was set aside).
  Use **Ask again** (a new request) after checking with the acquisition team.

### 3.10 Library: importing something new

**Patches → Library** lists everything the update intelligence knows (about 16 000 winget apps
and the Windows cumulative updates per build), not only what the fleet is missing. It is an
**untrusted index**: names, descriptions and links come from the winget community. The server
never opens a link and never installs anything from the Library; links are shown as text
(https only).

- **Available** (default) shows what offpatch can import (*Importable: yes*: an MSI installer, or
  an EXE installer that installs per machine and has a documented silent switch) or what is
  installed in the fleet. *Importable: no* says why (for example "installs per user only" or
  "EXE installer without a documented silent switch"); *unknown* means the acquisition zone has
  not looked the app up yet (it does so for configured, requested and about 200 common
  enterprise apps). Patches → Needed shows the same verdict: "Can't import: <reason>" replaces
  the Import button, and the server refuses such a request.
- **Import** creates an acquisition request (§3.9). For an app that no machine has installed,
  pick the architecture (default x64). What arrives is a signed bundle in **quarantine**, to be
  reviewed and approved like any other package.
- The row then shows requested → seen → in catalog (or Not picked up).

### 3.11 Auto-download: what the downloader fetches (super admin)

**Settings → Auto-download** decides what the downloader fetches on every run, on top of the
installer's settings (`acquire.json`, which stay in force underneath):

- **Windows updates**: add the Windows releases your machines run (security updates, or all
  severities); switch a release **Off** to stop downloading it even if `acquire.json` lists it.
- **Apps**: search the Library and add an app by its winget id (the "can import" badge says
  whether it has an MSI). It is kept at its newest version; tick the architectures you need.
- **Download sources**: point winget or Microsoft at a bank-approved **internal mirror**, or
  add a **vendor download link** for software that is not in winget (MSI or MSU only; enter the
  SHA-256 the vendor publishes, or, on a Windows downloader, the code-signing name).
- **Limits**: the most GB one run downloads, and how many old versions the downloader keeps.

**Save** creates a new version (History shows who changed what). If someone else saved in the
meantime you are asked to reload. On one server the version is handed to the downloader at
once, and **Status** shows "Applied by the downloader at …" after its next run (usually within
a minute); **Run now** asks for a full run immediately. With a separate downloader machine,
click **Download policy file** and copy it into the downloader's `requests` folder like a
request file; it is applied on the next scheduled run. A refused file (damaged, edited by hand)
shows under Status as **Refused**; the previous version stays in force.

Nothing here weakens the checks: every file is still verified by its hash or signature and
arrives in quarantine for approval. See docs/08-acquisition.md "Auto-download policy".

What the policy **cannot** do, whoever edits it (the downloader's own `acquire.json` decides):

- **Point downloads at a new host.** Mirrors, catalog / MSRC addresses and vendor download
  links must be on the downloader's `allowed_source_hosts` (by default only the official
  Microsoft, winget and GitHub hosts). Anything else shows under Status as **failed: refused**
  and the default address stays. To use a bank mirror, the downloader's operator adds its host
  to `acquire.json` first. Private, loopback and link-local addresses are always refused unless
  listed in `allowed_private_hosts`.
- **Jump the version.** A policy file more than 100 versions past the last one the downloader
  applied is refused (Status: Refused); older versions are ignored.
- **Change who signs an app.** The downloader remembers the code-signing name (CN and O) of
  every winget EXE/MSI and signed vendor download the first time it fetches it. A later version
  signed by someone else is refused and shown as a failure under Status until the downloader's
  operator runs `pmctl trust-signer <winget id>` (or `vendor:<source id>`); `pmctl trust-signer
  -list` shows what is pinned and pending. A revoked signing certificate is always refused.
  The package's **Signer** in the Catalog shows the verified name, its organisation, the winget
  publisher (and whether they agree), the certificate fingerprint and the revocation result:
  check them when you approve.

### 3.12 EXE packages (WebView2, VC++ runtimes, Git, ...)

Apps that winget publishes only as EXE installers (plain exe, Inno Setup, NSIS, WiX Burn) are
imported as packages of **kind EXE** when they install per machine and have a documented silent
switch. The acquisition zone checks the download against the winget SHA-256 and verifies its
**Authenticode signature** (on Linux too); the verified signer is recorded in the package.

- **Review before approving.** The package detail shows the installer type, the **signer**
  (e.g. "Microsoft Corporation"), the silent arguments, how the installed app is detected (Apps &
  features name, ARP key, version) and whether rollback is supported. Approve only if the signer
  is the vendor you expect.
- **Agent 0.9.0 or later.** Older agents cannot run EXE packages: their targets show
  *not applicable — agent too old for EXE packages: upgrade the agent to 0.9.0 or later*, and they
  are never offered the package. Upgrade the agent (§5); the targets then come back into scope by
  themselves.
- **Rollback** is available only for installers that register a silent uninstall (Burn bundles
  such as the VC++ runtimes, Inno Setup); otherwise the console says "rollback not supported for
  this installer (no silent uninstall)". To undo such an install, remove the app by hand or deploy
  the previous version.
- **Signature failures on the endpoint** ("signature check failed: … — possible tampering") raise
  the critical *manifest verification failed* alert: treat them like a tampered bundle (§8.1).
- EXE packages always arrive in bundles of their own, so endpoints with older agents keep
  receiving every other update.

## 4. Monthly Patch Tuesday workflow (end to end)

The full commands are in [runbooks/02-acquisition-zone-setup-and-monthly-run.md](runbooks/02-acquisition-zone-setup-and-monthly-run.md).

| # | Where | Who | Step |
|---|---|---|---|
| 1 | Acquisition | acquisition operator | `pmctl msrc -month 2026-Nov -product "Windows 10 Version 22H2" -arch x64` — list KBs, severity and CVE counts for your products. |
| 2 | Acquisition | acquisition operator | `pmctl fetch -kb KB… -product … -arch x64 -min-build … -max-build … -msrc-month 2026-Nov -out acq/downloads -spec acq/spec.json` for each KB. Third-party: `pmctl fetch-url … -sha256 <vendor hash>`. |
| 3 | Acquisition | acquisition operator + second person | Review `acq/spec.json`. `pmctl build -key … -spec acq/spec.json -out acq/out/2026-11.pmb -state acq/state.json`. `pmctl inspect -bundle … -pub bundle.pub`. |
| 4 | Boundary | acquisition operator | `pmctl send -bundle acq/out/2026-11.pmb -to <drop dir> -key <bundle key>` (or `-via command` for a gateway). Keep `sent.jsonl`. |
| 5 | Isolated | user | Intake page: bundle `validated`, every check green. Transfer reconciliation: receipt matched. |
| 6 | Isolated | user(s) | Catalog: review and approve each package with the change reference. Critical patches may need two approvals by different people. |
| 7 | Isolated | user (not a package approver, if SoD is on) | Create the deployment: rings `pilot` → `broad`, deadline from your policy, `max_failure_pct`, `max_retries`, reboot policy, health checks for the business services on pilot machines. |
| 7a | Isolated | two other bank users / admins | Approve the deployment with the change reference (two-person rule; nothing installs before). |
| 8 | Isolated | user | Watch the pilot ring. Fix failures. Get sign-off from pilot owners. |
| 9 | Isolated | user | Advance to `broad` (console: **Start next stage**). Watch for auto-pause, `install_failed`, `health_check_failed`. |
| 10 | Isolated | user / support | Work the remainder: offline endpoints, pending reboots, failures, exceptions. |
| 11 | Isolated | viewer | Reports: compliance by severity, overdue targets, latency (release → received → approved → first verified → 90 % verified). Export CSV and the lifecycle JSON per package for the change record. |

---

## 5. Endpoints

### 5.1 Enrolling a single endpoint

1. **Endpoints → Create enrollment token** (role `user`): groups (for example `pilot`), site, expiry
   in hours, max uses 1 (more for several PCs). The token (`enr_…`) is shown **once**. The dialog shows ready-to-run
   commands. **Agent setup** shows the same commands and offers `bundle.pub`, `ca.pem` and any agent
   binaries staged in `<data_dir>/agent-dist/` for download.
2. **Windows (usual way):** paste the one-line PowerShell command from the dialog into **Windows
   PowerShell as Administrator** on the PC. It pins the server's CA by SHA-256 fingerprint,
   downloads `pmagent.exe` from the server and checks its SHA-256, enrolls the PC and starts the
   `offpatch-agent` service. The command uses the agent URL from the server (`agent_url`, by
   default `https://<server IP>:8443`), also when the console is open on the server name, and the
   generated installer downloads from and enrolls against that same URL. Nothing else changes on
   the PC: no hosts-file or DNS entry (the IP is in the internal certificate). The PC needs TCP
   8443 (the server port) to the server's IP. Manual alternative, in an elevated shell:

```powershell
pmagent.exe enroll -server https://10.0.0.5:8443 -token enr_… -pubkey bundle.pub -ca ca.pem -root-pubkey root.pub
pmagent.exe service install
sc.exe start offpatch-agent
```

   `service install` also configures the service to restart after an error exit, which is how an
   agent self-upgrade takes effect (runbook 08).

   On Linux (as root): `pmagent enroll … -platform linux` then `pmagent service install` (creates
   and starts the systemd unit `offpatch-agent`). On macOS (as root): `pmagent enroll …` then
   `pmagent service install` (launchd `com.offpatch.agent`).
3. The endpoint appears on the Endpoints page within one check-in interval.

Always pass `-root-pubkey`. Without it the agent cannot apply signed key rotations and has to be
re-enrolled when the bundle signing key changes.

### 5.2 Mass rollout

- Create one token per site and group set with **max uses** above 1 (up to 10,000). Multi-use
  tokens can be valid for at most 336 hours (14 days); single-use tokens for up to 720 hours.
- Windows: the agent MSI (`packaging/windows/`, being written) takes `SERVER` and `TOKEN` properties:
  `msiexec /i offpatch-agent-<version>.msi SERVER=https://pm.corp.internal:8443 TOKEN=enr_… /qn /l*v install.log`.
- Linux: the `.deb`/`.rpm` (`packaging/linux/`) enrolls on install when `/etc/offpatch/enroll.env`
  is present.
- Details: [runbooks/09-endpoint-onboarding-and-offboarding.md](runbooks/09-endpoint-onboarding-and-offboarding.md).

Treat a multi-use token like a password: anyone holding it can enroll machines into those groups
until it expires or is used up.

### 5.3 Retiring an endpoint

Endpoint detail → **Retire** (role `user`, reason required). Its certificate and secret stop working at
once, its outstanding targets become `not_applicable` ("endpoint retired: …"), history is kept, and
it leaves the fleet totals. Retirement cannot be undone. A machine that comes back must be
enrolled again and gets a new endpoint ID. Then uninstall the agent from the machine.

### 5.4 Certificates

With TLS (the normal mode) each agent has an mTLS client certificate valid for one year. It renews
itself automatically at check-in during the last 30 days (`endpoint.cert_renewed` in the audit
log). The alert sweep raises `cert_expiring` for any active endpoint whose certificate expires
within 14 days, which normally means the agent has not checked in for a long time. An endpoint
that was offline past its certificate expiry cannot renew and must be re-enrolled.

### 5.5 Server name and certificates

**The name is for the console; agents use the IP.** The installer's `--domain NAME` (default
`dsspatcher.local`, or the name an earlier install used: upgrades keep the recorded name unless
`--domain` is given) becomes `server_name` in
`pmserver.json`: browsers open the console at `https://<server name>:8443`. Agents never use the
name: they connect to `agent_url`, by default `https://<agent_ip>:8443`, where `agent_ip` is the
server's IP (detected; set it in `pmserver.json` on servers with several addresses). The
enrollment commands use that URL whatever address the console is open on, so endpoints need no
DNS record and no hosts-file entry. The internal server certificate always names both the server
name and the IP (`init-pki`; on upgrades the installer reissues it when either is missing; agents
pin the CA, not this certificate, so they keep working). `agent_url` can still be set explicitly
(for example to a name the endpoints resolve); agents then select their certificate by ALPN.

**Do not pick a name under a public domain that sends HSTS with `includeSubDomains`** (check:
`curl -sI https://example.com | grep -i strict-transport`) unless the console gets a public or
bank certificate. Browsers then accept only certificates they already trust for every subdomain
and remove "Proceed anyway", so the internal certificate is blocked outright until the internal
CA is trusted on that PC. That is why the default is `dsspatcher.local`: `.local` is reserved for
multicast DNS on the local link (RFC 6762) and never has public DNS or HSTS. (`.internal`, the
previous default, is equally safe when the name is served by internal DNS.)

The name must resolve to the server's IP **on the admins' PCs only** (browsers).

**Found automatically on the local network (mDNS).** When the name ends in `.local` (the default)
the installer (role all/server) installs `avahi-daemon` and `avahi-utils` if missing and runs
`offpatch-mdns.service` (`avahi-publish -a -R <name> <IP>`): the server answers multicast DNS
queries for the name with its IP. Windows 10/11, macOS and Linux desktops resolve `*.local` names by
mDNS out of the box, so admin PCs **on the same network segment** open `https://dsspatcher.local:8443`
with no DNS record and no hosts file. Details and limits:

- mDNS is multicast (224.0.0.251 / ff02::fb, UDP 5353) and does not cross routers: it works within
  one subnet / VLAN. PCs on other subnets need an internal DNS A record or a hosts-file line (below),
  unless the network team runs an mDNS gateway/reflector between the VLANs.
- Windows: name resolution by mDNS must not be disabled by policy (registry
  `HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\EnableMDNS` = 0 turns it off), and the
  Windows Firewall rule *mDNS (UDP-In)* must allow the answers; it is on for Domain/Private
  networks and often blocked on networks marked Public. If the bank's own DNS domain ends in
  `.local` (old AD naming), Windows may send the name to DNS instead: use a DNS record then.
- Only the interface carrying the server's IP announces the name: when the server has other
  interfaces, the installer sets `allow-interfaces=<that interface>` in
  `/etc/avahi/avahi-daemon.conf` (marked by a comment; an `allow-interfaces` an administrator set
  is respected and only warned about). The host's own name record (`<hostname>.local`) is not
  changed; if the console name is the host's own mDNS name, no extra record is published. The name
  is not published when another device already answers to it (the installer warns: pick another
  `--domain <name>.local`).
- When ufw is active the installer allows UDP 5353 from the server's local subnet (it never
  enables ufw). The egress lock (§0) does not affect avahi: it matches only the `offpatch` and
  `offpatch-acq` accounts, and avahi runs as user `avahi`.
- `--no-mdns` turns it off (remembered; `--mdns` turns it back on). A name that does not end in
  `.local` (for example `--domain patcher.bank.example`) is never published by mDNS and relies on
  DNS or hosts files as before. If the server's IP changes, re-run the installer to publish the new
  address. `--uninstall` removes the unit, the `avahi-daemon.conf` line and the ufw rule; the avahi
  packages are removed only by `--purge`, and only when this installer installed them.
- Test from an admin PC: Windows PowerShell `Resolve-DnsName dsspatcher.local` (or
  `ping dsspatcher.local`), Linux `avahi-resolve -n dsspatcher.local`, macOS
  `dns-sd -G v4 dsspatcher.local`. On the server: `systemctl status offpatch-mdns`,
  `sudo ./install-ubuntu.sh --status`.

**Other subnets, or a non-`.local` name:** an internal DNS A record, or one hosts-file line on each
admin PC, which the installer prints, for example:

```text
10.0.0.5 patcher.bank.example # DSS Patcher
```

- Windows (PowerShell as Administrator):
  `Add-Content -Path "$env:SystemRoot\System32\drivers\etc\hosts" -Value "10.0.0.5 patcher.bank.example # DSS Patcher"`
- Linux / macOS: `echo '10.0.0.5 patcher.bank.example # DSS Patcher' | sudo tee -a /etc/hosts`

Endpoints never need it: the Windows enrollment command does not touch the hosts file, and
Ubuntu agents are installed with `install-ubuntu.sh --role agent --server https://<server IP>:8443`
(`--server-ip` is still accepted and ignored). An agent keeps the server URL it was enrolled with
(it cannot be told a new one). Agents enrolled by IP keep working unchanged; an agent that was
enrolled by the name under an earlier release keeps needing that name to resolve until it is
re-enrolled: run the current one-line command with a new token (the installer sees the different
server URL and enrolls the PC afresh against the IP).

**Browsers and the certificate.** Without anything else, browsers see the internal CA's
certificate. Choose one:

| Option | Use when | How |
|---|---|---|
| Internal CA in the browsers | No public name; managed Windows PCs | Distribute `/etc/offpatch/pki/ca.pem` by Group Policy (Computer Configuration > Windows Settings > Security Settings > Public Key Policies > Trusted Root Certification Authorities) |
| **Bank's own certificate** (recommended for isolated bank networks) | The bank's PKI issues server certificates | `--public-cert FILE --public-key FILE [--public-domain NAME]` |
| Let's Encrypt | The name is public DNS and the server can reach the internet | `--public-domain NAME [--acme-challenge auto\|http\|cloudflare]` |

The last two serve that certificate only to browsers; agents keep the internal CA and mTLS
(below). Alone on an existing install the options only add or replace the certificate and change
nothing else; together with other options they run as part of the install or upgrade.

*Bank's own certificate.* `--public-cert` is the PEM chain (server certificate first, then the
intermediates), `--public-key` its unencrypted PEM key. The installer checks that the key belongs
to the certificate, that it has not expired (warning under 14 days), that the chain is in order
(warning when only the server certificate is given: fine if it is issued directly by a root the
browsers trust), copies both to `/etc/offpatch/pki/public/{cert,key}.pem` (owner `offpatch`,
0600; the key is never printed) and sets `public_tls.names` to `--public-domain` (which the
certificate must cover) or else to the certificate's DNS names (wildcards excluded). No certbot,
no internet. To renew, re-run with the new files: pmserver picks them up without a restart.

*Let's Encrypt.* `--acme-challenge auto` (default) uses HTTP-01 with `certbot --standalone` when
TCP 80 is free on the host (no listener, no NAT rule forwarding it elsewhere; with ufw active the
installer allows 80/tcp), else DNS-01 through Cloudflare when the credentials file exists, else it
stops and lists the options. Cloudflare: a token with Zone > DNS > Edit for the zone in
`/etc/offpatch/acme/cloudflare.ini` (or `--cloudflare-credentials FILE`), root-owned, 0600, one
line `dns_cloudflare_api_token = <token>`; never printed. The account email is `--acme-email`,
else `--admin-email` when given, else none. certbot runs as root, so the egress lock (which
only restricts the offpatch accounts) does not affect it. Renewals use the method the certificate
was issued with (certbot stores it; HTTP-01 needs TCP 80 free at renewal time too): `certbot.timer`
renews 30 days before expiry, the deploy hook `/etc/letsencrypt/renewal-hooks/deploy/offpatch.sh`
copies the files to `/etc/offpatch/pki/public/` and reloads pmserver. Test:
`sudo certbot renew --dry-run`.

**How a connection gets its certificate** (`public_tls` set):

| Client | TLS handshake | Certificate | Client certificate |
|---|---|---|---|
| Agent 0.9.1+ (any name) | ALPN `dss-agent/1` | internal CA (pinned by the agent) | requested |
| Agent 0.9.0 or older (enrolled by IP) | no SNI | internal CA | requested |
| Anything on a name not in `public_tls.names` | SNI | internal CA | requested |
| Browser on a `public_tls` name | SNI, no agent ALPN | public | not requested (no certificate picker) |

So the server name may also be the public name. The agent API answers **421 Misdirected Request**
on a connection that got the public certificate. The PowerShell enrollment command cannot offer
ALPN; on a public name its pin also accepts a chain that Windows fully trusts for that name, and
the agent it installs then pins the internal CA. pmserver re-reads the public certificate files
within a minute of a change (at once on `systemctl reload offpatch-server`). A missing,
unreadable, wrong-name or expired public certificate is never served: pmserver logs an ERROR and
uses the internal certificate (a renewal whose files are half-written keeps the previous
certificate). The **Server** page shows the server name, agent URL and the public certificate's
issuer, expiry and any problem. Alert `public_cert_expiring`: warning under 14 days, critical when
expired or unusable; it closes itself once a valid certificate is loaded.

Configuration (method B, or by hand):

```json
"server_name": "patcher.bank.example",
"agent_ip": "10.0.0.5",
"public_tls": {"names": ["patcher.bank.example"], "cert_file": "/etc/offpatch/pki/public/cert.pem", "key_file": "/etc/offpatch/pki/public/key.pem"}
```

`server_name`: a DNS name (no IP), for the console only. `agent_ip`: an IP, not loopback
(default: detected). `agent_url` (optional override): the URL agents enroll against, default
`https://<agent_ip>:<port>`; it is never derived from `server_name`. `public_tls.names`: DNS names
(no IPs, no wildcards), matched case-insensitively against the SNI; `cert_file`/`key_file`
default to `<pki_dir>/public/cert.pem` and `key.pem`. pmserver warns at start when the internal
certificate does not name `server_name` or the agent URL's host.

Remove: `--uninstall` deletes the certbot hook; `--purge` also deletes the Let's Encrypt
certificate (and the local account when no other certbot certificate on the host uses it). To stop
serving a public certificate, delete `public_tls` from `pmserver.json` and restart.

### 5.6 Console behind a reverse proxy (Temps, nginx, load balancer)

Use this when pmserver shares a host with a reverse proxy that already owns port 443 and
terminates TLS for the console's public name (for example Temps for
`patch.dataspacesecurity.com`) and forwards to an upstream over **plain HTTP**. pmserver then
opens a second listener, `console_proxy`, on loopback for that proxy only:

- **Console only.** It serves the console (SPA), the admin API (`/api/*`), `/auth/*` and
  `/api/auth/*`. The agent API (`/api/agent/*`) and the enrollment bootstrap downloads
  (`/api/agent-setup/bootstrap/*`) answer **421**, `/metrics` **404**. Agents are unchanged: they
  keep connecting directly to `https://<server IP>:8443` with mutual TLS (open that port to the
  PCs as before). The listener is plain HTTP and never asks for a client certificate.
- **Only the proxy may connect.** Connections from outside `trusted_proxies` get 403.
- **Forwarded headers, only there.** For requests from a trusted proxy on this listener the
  client address is the right-most address in `X-Forwarded-For` that is not a trusted proxy
  (else `X-Real-IP`); it is used for the sign-in rate limit and in the logs. A request with
  neither header (or no valid address in it) is refused with **400** and a warning in the log,
  so users never share the proxy's address as one rate-limit bucket. The scheme comes from the
  right-most `X-Forwarded-Proto` value (the one the proxy wrote). The main listener (8443) ignores
  all these headers, so they cannot be spoofed there.
- **One sign-in limit for the whole listener.** Sign-in steps through it (`POST /api/auth/login`,
  `/api/auth/mfa`, `/api/auth/password`, MFA confirm / disable) are first checked against the
  client's own limit (10, then 1 every 6 seconds); only requests that pass it count against a
  bucket shared by the whole listener (30, then 1 per second): any local process can send a made-up
  `X-Forwarded-For`, so per-client limits alone do not stop guessing, but one client can never
  drain the shared bucket. When many addresses drain it at once, addresses that signed in
  successfully through the proxy in the last 24 hours still get a reserved share (10, then 1 every
  3 seconds). Over a limit: **429** with `Retry-After`. Refusals by the shared bucket for a minute
  or more are logged as an error and raise one alert (`auth.signin_flood`).
- **Never plain HTTP to the browser.** When `X-Forwarded-Proto` is not `https` (Temps also
  forwards its port 80 to the same upstream), `GET`/`HEAD` get **308** to
  `https://<name><path>` when the `X-Forwarded-Host` (else `Host`) is `server_name` or one of
  `public_tls.names` (any case, port ignored), otherwise **400** (no open redirect: set
  `server_name` to the console's public name). Every other method gets **403**: no password, MFA
  code or cookie is accepted over plain HTTP. Over HTTPS, responses carry
  `Strict-Transport-Security: max-age=31536000`, session cookies keep `Secure`, `HttpOnly`,
  `SameSite=Strict`, and the CSRF rule (`X-Offpatch-CSRF: 1`) is unchanged.

Install (role all/server):

```
sudo ./install-ubuntu.sh --console-proxy-port 8090
```

This writes the following into `pmserver.json` (remembered for upgrades; `--no-console-proxy`
removes it) and restarts pmserver. ufw is not changed (loopback).

```json
"console_proxy": {"listen": "127.0.0.1:8090", "trusted_proxies": ["127.0.0.1/32", "::1/128"]}
```

`listen` must be a loopback or private address and port (pmserver refuses to start with
`0.0.0.0`, `::`, a public address, or the main listener's port). `trusted_proxies` (required) are
CIDRs of the proxy (`0.0.0.0/0` is refused). If the proxy runs on another machine of a private
network, use that network's address for `listen` and the proxy's address for `trusted_proxies`.

Point the proxy at `http://127.0.0.1:8090`. Temps:

```
temps load-balancer create -d <name> -t http://127.0.0.1:8090
```

nginx (inside the `server { listen 443 ssl; ... }` block of the console name):

```
location / {
    proxy_pass http://127.0.0.1:8090;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header X-Forwarded-Host $host;
    client_max_body_size 64m;
}
```

The proxy must send `X-Forwarded-Proto` (Temps and nginx as above do). Check:
`curl -sI https://patch.dataspacesecurity.com/` shows `strict-transport-security`;
`curl -sI http://patch.dataspacesecurity.com/` answers 308 to `https://`. The **Server** page
shows "Console via reverse proxy" with the listener, and `GET /api/system` has
`console_proxy.listen`.

SSO behind the proxy: set `oidc.redirect_url` to the public HTTPS name
(`https://patch.dataspacesecurity.com/auth/callback`) and register it at the identity provider;
pmserver never derives it from request headers. Enrollment commands shown in the console always
use the agent URL (`agent_url` / `agent_ip`), never the proxy's name or port.

---

## 6. Audit log and evidence

- Every state change is an **audit event** with actor, action, object, outcome and details, chained
  by SHA-256 (each event includes the previous event's hash).
- **Audit** page: filter by object, action (prefix match, for example `deployment.`), actor or
  package. **Verify** runs `GET /api/audit/verify`: `ok`, event count, and the first broken
  sequence number if someone edited the database.
- **Lifecycle export** (Audit page → Export lifecycle, or `GET /api/audit/export?package_id=…`):
  one JSON file with the package, source bundle and its checks, deployments with every target,
  exceptions, all related audit events and the chain status. This is the evidence for one patch
  from receipt to verified endpoints. The export itself is audited (`audit.exported`).
- With `audit_export_dir` set, the server also writes the events and signed checkpoints off the
  server every `audit_checkpoint_interval`. These are verified with `pmserver verify-audit`. See
  [runbooks/07-audit-verification-and-evidence.md](runbooks/07-audit-verification-and-evidence.md).

Useful actions to search for: `bundle.validated`, `bundle.rejected`, `package.approval_recorded`,
`package.approved`, `package.revoked`, `deployment.created`, `deployment.created_emergency`,
`deployment.auto_paused`, `target.failed`, `target.verified`, `target.install_unverified`,
`alert.resolved`, `report.exported`, `exception.created`,
`endpoint.enrolled`, `endpoint.retired`, `auth.login`, `auth.login_denied`, `access.denied`,
`trust.updated`, `audit.checkpoint`, `audit.pruned`.

---

## 7. Where the logs are

| Component | Log |
|---|---|
| pmserver (systemd) | `journalctl -u pmserver` |
| Windows agent (service) | `C:\ProgramData\offpatch\agent.log`; MSI installer logs in `C:\ProgramData\offpatch\logs\<package>-<time>.log`; Windows servicing log `C:\Windows\Logs\CBS\CBS.log` for `wusa` |
| Linux agent | `journalctl -u offpatch-agent`; `/var/log/dpkg.log` or the RPM/DNF logs |
| macOS agent | `/Library/Application Support/offpatch/agent.log`; `/var/log/install.log` |
| Agent state | `agent.json` in the state directory (`C:\ProgramData\offpatch`, `/var/lib/offpatch`, `/Library/Application Support/offpatch`) — holds endpoint ID, pinned keys, `trust_seq` |

---

## 8. Troubleshooting

### 8.1 Bundle rejected at intake

Open **Intake** → the bundle → **Validation checks**. The first failing check is also the bundle's
`error`. The rejected file stays in `<data_dir>/received/<sha256>.pmb` as evidence.

| Check | Likely cause | What to do |
|---|---|---|
| `size` | Bundle larger than `max_bundle_bytes` (default 32 GiB) | Split the spec into several bundles, or raise the limit. |
| `structure` | Tar layout not allowed: extra entries, directories other than `payload/`, links, devices, traversal, more than `max_files` (500) or a file over `max_file_bytes` (16 GiB), or a truncated file | Rebuild with `pmctl build`. Never hand-edit a bundle. A truncated file points to a transfer problem. |
| `manifest_parse` | `manifest.json` not strict JSON or has unknown fields | Rebuild with a `pmctl` of the same version as the server. |
| `manifest_schema` | Expired (`expires_at` passed — the bundle sat too long; `pmctl build -ttl` default 720h, max 90 days), `created_at` in the future (acquisition clock ahead by more than 10 minutes), invalid field, or `vendor_signature` recorded as `invalid` | Fix clocks, rebuild, send promptly. For `invalid` vendor signatures, find out why before anything else. |
| `trusted_key` | Bundle signed with a key the server does not trust | Wrong key used, or the rotation trust document was not sent. See runbook 03. |
| `key_status` | Key is retired by a trust document | Sign with the current active key. |
| `source_authorized` | `-source` of the bundle is not in the key's `sources` | Use the right `-source`, or authorize it in the trust document / `trusted_keys`. |
| `signature` | Manifest changed after signing, or signed by a different key than its `key_id` | Treat as possible tampering. Rebuild and resend; investigate the transfer path. |
| `payload_hashes` | A payload file is missing, has a different size or SHA-256, or an extra file is present | Corruption or tampering in transit. Resend; compare with `sent.jsonl`. |
| `content_scan` | `scan_command` exited non-zero for a file, could not run, or ran longer than `scan_timeout` (per file, default `30m`) | Treat as potential malware until proven otherwise. Check the scanner output in the detail. |
| `replay` | `sequence` not greater than the last accepted one for that source (e.g. state file lost, new acquisition host, or an old bundle resent) | Rebuild with `pmctl build -seq <last+1>` or restore `state.json`. A deliberately resent old bundle is correctly refused. |
| `duplicate_bundle` | The same `bundle_id` was already accepted | Nothing to do if it was a duplicate send. |
| `catalog_conflict` | A `package_id` already exists with different content | Give the new content a new `package_id`. |

A bundle that never shows up: it may still be `*.part` (transfer incomplete), have the wrong
extension (only `*.pmb`, `*.receipt.json` and `*.trust.json` are read), or be held back by the
inbox rate limit (`intake_rate_limited` alert; it is processed later, nothing is dropped).

Stopping or restarting pmserver mid-intake loses nothing: on stop it waits (up to 30 s for
requests) for intake, alerting and audit export to finish; a bundle that was already moved to
`received/` but not recorded is re-ingested on the next start ("re-ingesting a received bundle"
in the log), and trust documents, receipts, status reports and update intelligence leave the inbox
only after their result is recorded.

### 8.2 Agent problems

| Symptom (agent log or console) | Likely cause | What to do |
|---|---|---|
| `server 401: client certificate not valid for an active endpoint` | Endpoint retired; or its certificate was replaced by a renewal and the agent uses an older one (agent state restored from backup); or the server database was restored from a backup older than the enrollment or the last renewal | Check the endpoint in the console. If retired or unknown: create a token and re-enroll. Retire any stale record. |
| `server 401: client certificate required` | Agent was enrolled over `http://` (lab mode) but the server now runs TLS | Re-enroll with the `https://` URL and `-ca ca.pem`. |
| `server 401: unknown device credential` | Lab mode only: endpoint retired or unknown | Re-enroll. |
| TLS handshake error, `certificate has expired` | Client certificate expired (offline for more than a year) | Re-enroll. |
| TLS error `certificate signed by unknown authority` | Wrong or missing `-ca` | Re-enroll with the server's `ca.pem` (Agent setup page). |
| Enrollment: `enrollment token invalid, used or expired` | Token expired, already used (single-use) or `max_uses` reached | Create a new token. |
| `manifest verification failed: manifest signed by untrusted key …` | Agent does not have the bundle key: enrolled with the wrong `bundle.pub`, or key was rotated and the agent has no root key | Re-enroll with the right keys and `-root-pubkey`. |
| `manifest signed by revoked key` | Key revoked as compromised | Expected. See runbook 04. |
| Windows endpoint goes `offline` right after an agent upgrade target reached `installed` | The service stopped after the self-upgrade and Windows did not restart it. Only services installed by an older `pmagent service install` or MSI lack the "restart on non-crash failure" flag | `sc.exe failureflag offpatch-agent 1` and `sc.exe start offpatch-agent`. See runbook 08. |
| `download/verify failed: content does not match signed manifest … possible tampering` | Repository file differs from the signed hash | Security incident. Do not work around it. Check `<data_dir>/repository` integrity; restore from backup. |

### 8.3 Target stuck in `pending`

Check in this order:

| Cause | How to tell | What to do |
|---|---|---|
| Deployment paused | Deployment state `paused` | Resume (with reason) or cancel. |
| Deployment window closed | Settings show `window_start`–`window_end` (UTC) | Wait, or create a new deployment without a window. The deadline does not override this window. |
| Endpoint maintenance window closed | Endpoint's groups have windows on the Windows page, none open now | Wait; or the deployment's deadline passes; or use `ignore_windows` (new deployment). |
| Prerequisite missing | Target detail `waiting for prerequisite(s) KB…` | Deploy the prerequisite first; this target continues by itself once inventory shows it. |
| Concurrency cap | `max_concurrent` reached by other endpoints | Wait. Leases on endpoints that went quiet expire after 15 minutes. |
| Endpoint offline | Endpoint status `offline` | See §3.6. |
| Ring not reached | No target for this endpoint yet | Targets only exist up to the current ring. Advance. |
| Endpoint in no ring | No target at all | Fix the endpoint's groups (Endpoints → edit groups). A group change adds it to active deployments. |
| Retries exhausted | State `failed`, not `pending` | See §3.5. |

### 8.4 Windows installer exit codes (`platform_windows.go`)

| Exit code | Kind | Target state | Detail shown |
|---|---|---|---|
| 0 | msu, msi | `installed` | `<kind> installed` |
| 3010 | msu, msi | `pending_reboot` | `installed; reboot required` |
| 1641 | msu, msi | `pending_reboot` | `installed; reboot required` |
| 0x00240006 (2359302) `WU_S_ALREADY_INSTALLED` | msu | `installed` | `already installed` |
| 0x80240017 (2149842967) `WU_E_NOT_APPLICABLE` | msu | `not_applicable` | `wusa: update not applicable to this computer` |
| 1618 | msi | `failed` (retried while retries remain) | `another installation is in progress (will retry)` |
| 1638 | msi | `failed` | `another version of this product is already installed` |
| 0x00240007 (2359303) `WU_S_ALREADY_UNINSTALLED` | msu rollback | `installed` | `not installed; nothing to remove` |
| 1605 `ERROR_UNKNOWN_PRODUCT` | msi rollback | `installed` | `not installed; nothing to remove` |
| any other | msu, msi | `failed` | `installer exit code N (0xNNNNNNNN)` |
| -1 | any | `failed` | Agent-side error: installer could not start, unsupported kind, manifest verification or download failure |

Notes:
- `WU_E_NOT_APPLICABLE` usually means the update is superseded, already included in a newer
  cumulative update, or a prerequisite (for example a servicing stack update) is missing. Check the
  KB article and the package's prerequisites.
- 1618: another MSI or Windows servicing operation was running. It is retried at the next
  check-in while attempts remain. Raise `max_retries` for busy machines.
- 1638: the installed version of the product blocks this MSI. The vendor's upgrade package, or
  removing the old version first, is needed. Grant an exception meanwhile if required.
- For any other code, look up the Windows / MSI error code, then read `CBS.log` (msu) or the MSI
  verbose log in `C:\ProgramData\offpatch\logs\` (msi).

### 8.5 Other failures

| Symptom | Likely cause | What to do |
|---|---|---|
| Linux `deb` failed, detail mentions `dependency problems` / `depends on … not installed` | `dpkg -i` does not resolve dependencies and the agent never uses network repositories. After a failure the agent runs `dpkg --configure -a` to leave dpkg consistent. | Ship the missing dependency as its own `deb` package, list it in `prerequisites`, deploy it first. |
| `rpm` failed with `Failed dependencies` | Same: `rpm -U` does not resolve dependencies | Same approach. |
| Deployment `paused`, reason `auto-pause: N/M endpoints failed (x install, y health check, z lost after install) in ring "…" (threshold P%)` | Failures in the current ring crossed `max_failure_pct` | Investigate the failed targets first. Resume (reason required) only when the cause is understood; or cancel / revoke the package. |
| Target health `failed`, alert `health_check_failed` | A `service_running` service/unit/label is not running, or nothing listens on a `tcp_listening` port, after install | Check the service on the endpoint; check you used the service **name**, not the display name. A failed health check counts toward auto-pause but does **not** make the target `failed`; it can still become `verified`. |
| Target stays `installed`, never `verified` (after 6 h: "installed but not confirmed by inventory after 6 h", alert `install_unverified`, counts toward auto-pause) | Inventory does not show the KB / product code / package version. Some updates do not appear in `Win32_QuickFixEngineering` (cumulative updates built with `expected_ubr` verify by build revision instead); the MSI product code in the manifest may not match the installed product | Check the endpoint's Inventory tab. Fix the package metadata (new `package_id`) if it is wrong. |
| Target `deferred`, detail `not enough free disk space …` / `on battery …` | Pre-install check (§3.8) | Free disk space (Disk Cleanup, clear old profiles) or plug the laptop in; the next check-in proceeds. Adjust `preinstall` in the server config if the minimum is wrong for your fleet. |
| Target `lost_after_install`, critical alert | Endpoint silent since the install / reboot (§3.8) | Check the machine; it recovers automatically when it checks in. |
| Create rollback returns 409 `rollback not supported` | macOS `.pkg`, the agent, or a package without KB / product code / package name | Remove by hand or deploy the previous version. |
| Target stays `pending_reboot` | `reboot_policy: never`, or no maintenance window with `allow_reboot` is open (detail `no maintenance window allows automatic restarts` when none ever is) | Reboot through your normal process, or add a maintenance window with `allow_reboot`. |
| Target `failed`, detail `waiting: another installation is running on this machine (try N)` | Another installer or Windows Update is running on the machine (msiexec 1618, servicing busy) | Nothing: it is retried at the next check-in without using up retries, 10 times in a row; after that it counts as a normal failure. |
| Package `rejected`, operator clicked "Import again" | The next acquisition run sends it again | The package returns to `quarantined` for a new review (audit `package.reimported`, earlier approvals cleared). A `revoked` package is never imported again. |
| Endpoint `awaiting_checkin` for a long time | Agent installed but not running, or cannot reach the server | As for `offline` (§3.6). After 24 h it is shown `offline`. |
| Approve returns 409 `already approved this package; a different approver is required` | Two-person rule | A different bank user approves. |
| Create deployment returns 409 `separation of duties` | You approved the package | Another user creates the deployment. |
| Approve deployment returns 409 `you created this deployment` / `you already approved` | Two-person rule for deployments | Two other bank users or admins approve it. |
| Approve deployment returns 403 | Your role is viewer or super_admin (vendor); or, for an agent version (`agent version deployments are approved by bank admins`), your role is `user` | A bank user or admin approves it; an agent-version deployment needs bank admins. |
| Approve / deploy an agent version returns 403 `agent versions are managed by the vendor (super admin)` | Agent packages (`offpatch-agent-*`) are the vendor's | The super admin approves and deploys them. |
| Every call returns 403 `mfa_enrollment_required` | First sign-in of a bank user without an authenticator | Enrol the authenticator app (the console shows the QR code). |
| Code refused: "wrong or expired code" | Wrong code, a code already used, the phone clock is off, or the account is locked | Wait for the next code; check the phone's time; use a recovery code; or ask an admin to **Reset MFA**. |
| Every call returns 403 `password_change_required` | Signed in with a temporary password | Change the password (the console shows the form). |
| Sign-in says "wrong email or password" with the right password | Account locked for this address after 5 wrong passwords (or everywhere after 50 from many addresses; 15 min), or a typo in the email | Wait, or ask an admin to **Enable** / **Reset password**. |
| "Too many wrong codes: two-step sign-in is locked" | 5 wrong authenticator codes in a row (15 min, doubling each time); alert `auth.mfa_locked` | Wait, or ask an admin to **Enable** the user after checking with them; if they did not cause it, have the password changed. |
| 400 "the reverse proxy did not name the client address" (console via proxy) | The proxy sends neither `X-Forwarded-For` nor `X-Real-IP` | Configure the proxy to send `X-Forwarded-For` (see 5.6). |

---

## 9. Self-check quiz

1. **An endpoint has not checked in for two hours but its last report showed every patch installed.
   What status does it show, and why?**
   `offline`. Silence is never compliance: `offline` (and `stale`) take precedence over all other
   statuses.
2. **A bundle arrives. Can a user deploy its packages straight away?**
   No. Packages arrive `quarantined`. A bank user must approve (with a reason), which publishes the
   content to the repository. Only `approved` packages can be deployed.
3. **`approval_policy` has `"critical": 2`. Alice approves a critical package. What is its state,
   and what happens if Alice approves again?**
   Still `quarantined` with 1 of 2 approvals. Alice approving again is refused (409); a different
   bank user must approve.
4. **With `separation_of_duties` on, who may create the deployment for a package Alice and Bob
   approved?**
   Any user (or higher) other than Alice and Bob.
5. **Your deployment has `max_failure_pct: 10`, `max_retries: 2`. In a 20-endpoint pilot ring, one
   endpoint fails its first install. Does the deployment pause?**
   No. Only failures with retries exhausted (and failed health checks) count, and the threshold is
   "more than 10 %". It would pause once three endpoints exhausted their retries (3/20 = 15 %).
6. **A target is `pending` with detail `waiting for prerequisite(s) KB5005112`. What do you do?**
   Deploy KB5005112 to the endpoint first. The target continues by itself once inventory shows it.
7. **`wusa` returned 0x80240017. What target state results?**
   `not_applicable` ("update not applicable to this computer").
8. **An agent log shows `server 401: client certificate not valid for an active endpoint`. Name two
   possible causes.**
   The endpoint was retired; its certificate was superseded by a renewal (e.g. the agent's state
   was restored from an old backup); or the server database was restored from a backup older than
   the enrollment/renewal. Fix: re-enroll.
9. **A package was approved and deployed, then found to break an application. What does revoking
   it do, and what does it not do?**
   Revoking (admin, reason required) stops new installs and cancels all its waiting, active and
   paused deployments. It does **not** uninstall anything; offpatch has no automated rollback. Recovery is
   the manual per-class procedure (runbook 06).
10. **What is the difference between the deployment window and a maintenance window, and which one
    does the deadline override?**
    The deployment window (`window_start`/`window_end`, UTC) applies to one deployment. Maintenance
    windows belong to endpoint groups and have their own time zone and reboot permission. The
    deadline only overrides maintenance windows.
