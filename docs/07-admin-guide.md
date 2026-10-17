# 07 — Administrator and endpoint-support training guide (roadmap D4)

Audience: Windows and Linux administrators and endpoint support staff who are new to offpatch.
After this guide you should be able to run the daily checks, approve and roll out a patch, handle
failures and exceptions, run the monthly Patch Tuesday cycle, enroll and retire endpoints, and
produce audit evidence.

Step-by-step procedures for less frequent tasks are in [runbooks/](runbooks/README.md). The API is
specified in [05-api.md](05-api.md) and the state machines in [03-state-model.md](03-state-model.md).

Everything here describes what the code does today. Where a feature is missing, the guide says so.

---

## 1. Concepts

### 1.1 Zones

| Zone | What runs there | What you do there |
|---|---|---|
| Connected acquisition zone | `pmctl` | Find vendor updates (`pmctl msrc`, `catalog-search`), download them (`fetch`, `fetch-url`), sign a bundle (`build`), send it across the boundary (`send`). This zone holds the **bundle signing key** (or uses an HSM through `-key exec:…`). |
| Transfer boundary | Data diode, gateway, or (in the MVP) a drop directory | Files flow one way only: into the isolated zone. Nothing flows back. |
| Isolated management zone | `pmserver` and its web console | Intake, quarantine, approval, repository, deployments, reports, audit. |
| Endpoint zone | `pmagent` | Inventory, download from `pmserver` only, verify, install, report. The agent has no internet or Windows Update fallback. Network egress denial must still be enforced by firewalls. |

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
   → an approver approves → content is copied to <data_dir>/repository/ (read-only, by SHA-256)
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
| `verified` | A **fresh inventory** shows the KB / product code / package version, or a KB that supersedes it (transitively) | **server only** |
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
| `offline` | No check-in for longer than `offline_after` (default 30 min) |
| `stale` | Inventory older than `stale_inventory_after` (default 24 h), or never received |
| `failed` | Any target `failed` (in a deployment that is not cancelled) |
| `pending_reboot` | Any target `pending_reboot`, or the OS reports a reboot pending |
| `exception` | Any target covered by an exception |
| `noncompliant` | Any target `pending`/`deferred`/`downloading`/`downloaded`/`installing`/`installed` (rollback targets excepted) |
| `compliant` | Otherwise |

`lost_after_install`, `offline` and `stale` beat everything else. An endpoint that stops talking is **never** shown as
compliant, and the reports count it as not reporting.

---

## 2. Roles and sign-in

Roles are cumulative: `viewer` < `operator` < `approver` < `admin`.

| Role | Can do (in addition to the roles below it) |
|---|---|
| `viewer` | Read everything: Overview, Intake (bundles and transfer reconciliation), Catalog, Deployments, Windows, Endpoints, Agent setup (and download staged agent files), Exceptions, Reports (incl. CSV), Alerts, Audit (incl. verify and lifecycle export). |
| `operator` | Create enrollment tokens; edit endpoint groups/site/owner/criticality; retire endpoints; create, pause, resume, cancel and advance deployments; create and delete maintenance windows; acknowledge alerts. |
| `approver` | Approve, reject and revoke packages; create and revoke exceptions. |
| `admin` | Users page: list SSO users, disable or enable them. |

Nobody can change the server configuration, trusted keys or audit settings from the console. Those
live in `pmserver.json` and need OS access to the server plus a restart.

### Single sign-on (SSO)

- When `oidc` is configured, the login page shows **Sign in with SSO** (OIDC authorization-code flow
  with PKCE, against AD FS, Entra ID, Okta, Keycloak or any standards-based IdP reachable from the
  isolated zone).
- Your role comes from your IdP groups (`oidc.role_groups`). If you are in several mapped groups you
  get the highest role. If you are in none, sign-in is refused and audited as `auth.login_denied`.
- With `require_mfa: true`, a login without MFA evidence in the ID token (`amr`, or `acr` if
  configured) is refused.
- Your role is taken at sign-in. A group change in the IdP applies at your next sign-in. Sessions
  last `session_ttl` (default 8 h).
- An admin can **disable** a user on the Users page. That revokes their sessions at once. You cannot
  disable yourself.

### Static tokens (break-glass and automation)

`pmserver new-token` prints a token and its SHA-256. The hash goes in `admin_tokens` in the config.
Tokens are sent as `Authorization: Bearer <token>` and are what scripts use against the API. Notes:

- They are managed only in the config file. Adding or removing one needs a server restart.
- `allow_static_tokens: false` disables all of them.
- By design, `require_mfa` is **not** applied to static tokens (they are the break-glass path for
  when the IdP is unavailable). Keep them for break-glass and automation, store
  them in a safe, and watch the audit log for their use (`actor` = `user:<name>` from the config).

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
| `signing_key_compromised` | critical | A trust document revoked a bundle key as compromised |
| `audit_export_failed` | critical | Writing audit export files failed |
| `install_failed` | warning | An agent reported `failed` |
| `health_check_failed` | warning | A post-install health check failed |
| `bundle_rejected` | warning | Intake rejected a bundle |
| `trust_rejected` | warning | A trust document did not verify or was a replay |
| `intake_rate_limited` | warning | Inbox rate limit reached; bundles wait in the inbox |
| `endpoints_offline` / `inventory_stale` | warning | Fleet sweep found offline / stale endpoints |
| `cert_expiring` | warning | An endpoint's client certificate expires within 14 days and has not been renewed (agent offline?) |
| `exception_expiring` | info | An active exception expires within 7 days |

   An identical alert (same kind and object) is not raised again while one is open. Acknowledge
   (operator) with a short note once you have acted. Acknowledging does not fix anything, and the
   same condition raises a new alert if it is still true at the next sweep (every
   `alert_sweep_interval`, default 5 min).
3. **Reports.** Check compliance by severity against the deadlines (`patch_deadlines`, default:
   critical 7 days, important 30, moderate 60, low 90, counted from the vendor release date).
   `overdue` targets are the priority. Export `compliance.csv` / `endpoints.csv` if your change
   board wants them (the export is audited).
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

**Deployments → New** (operator). Fields:

| Field | Meaning and rules |
|---|---|
| Package | Must be `approved`. |
| Name | Free text, required. |
| Rings | 1–10 rings, each with a name and at least one group. Typical: `pilot` → `broad`. |
| `max_failure_pct` | 0–100. The deployment auto-pauses when (failed targets with retries exhausted + targets with a failed health check) in the current ring exceed this percentage of considered targets (not counting `not_applicable` and `exception`). **0 means the first exhausted failure pauses it.** |
| `max_retries` | 0–10. A failed target is offered again while `attempts ≤ max_retries`. |
| Window (`window_start`/`window_end`) | `HH:MM` **UTC**, both or neither. May cross midnight. Outside it, no assignments are handed out. |
| `deadline` | RFC 3339, optional. After it, **endpoint maintenance windows** no longer hold installs back. It does **not** override the deployment window above. |
| `max_concurrent` | Cap on endpoints downloading/installing at once (0 = no cap). |
| `reboot_policy` | `never` (default), `in_window` (the agent may reboot inside a maintenance window with `allow_reboot`), `at_deadline` (in such a window, or at any time once the deadline has passed; needs a deadline). |
| `ignore_windows` | Ignore endpoint maintenance windows entirely. |
| `health_checks` | Up to 20 fixed checks run after install: `service_running` (Windows service name, systemd unit, or launchd label) or `tcp_listening` (port on 127.0.0.1). No arbitrary commands. |
| `emergency` + `justification` | Emergency deployments need a justification, are audited as `deployment.created_emergency`, flagged in the UI, and handed out before other work. |

**Maintenance windows** (Windows page, operator) belong to endpoint groups, not to deployments:
name, groups (or `all`), days (`mon`…`sun`), start and end `HH:MM` in an IANA time zone (may cross
midnight), and `allow_reboot`. If an endpoint is in any group that has a window, it only receives
installs while one of its windows is open, unless the deployment ignores windows or is past its
deadline.

**When does the agent reboot?** Only when the deployment's `reboot_policy` allows it: the server
sends `reboot_now`, or an install returned "reboot required" and the assignment allows a reboot.
The agent schedules a restart in 10 minutes with a warning (Windows `shutdown /r /t 600`, Linux and
macOS `shutdown -r +10`). With `reboot_policy: never` it never reboots and the target waits in
`pending_reboot` until someone reboots the machine. A `pending_reboot` target becomes `verified` only
when inventory shows the update **and** the OS no longer reports a pending reboot.

### 3.4 Advancing, pausing, resuming, cancelling

| Action | Who | Rules |
|---|---|---|
| Advance | operator | Deployment `active`, not on the last ring, and no target in the current ring is `downloading`/`downloaded`/`installing`. Failed targets do **not** block advance; look at them first. Reason optional. |
| Pause | operator | From `active`. Reason required. Agents get no new assignments. An agent that already received an assignment may still be working on it; content downloads it starts after the pause are refused, so such a target can show `failed`. |
| Resume | operator | From `paused`. Reason required. Resuming does not immediately re-pause; only a **new** failure re-evaluates the threshold. |
| Cancel | operator | From `active` or `paused`. Reason required. Final. Targets of cancelled deployments no longer count in endpoint status or compliance reports. |

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

**Exceptions → New exception** (approver). Required: endpoint, owner, reason, compensating controls,
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
reboot policy, health checks and auto-pause like an install, needs the operator role and a
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

## 4. Monthly Patch Tuesday workflow (end to end)

The full commands are in [runbooks/02-acquisition-zone-setup-and-monthly-run.md](runbooks/02-acquisition-zone-setup-and-monthly-run.md).

| # | Where | Who | Step |
|---|---|---|---|
| 1 | Acquisition | acquisition operator | `pmctl msrc -month 2026-Nov -product "Windows 10 Version 22H2" -arch x64` — list KBs, severity and CVE counts for your products. |
| 2 | Acquisition | acquisition operator | `pmctl fetch -kb KB… -product … -arch x64 -min-build … -max-build … -msrc-month 2026-Nov -out acq/downloads -spec acq/spec.json` for each KB. Third-party: `pmctl fetch-url … -sha256 <vendor hash>`. |
| 3 | Acquisition | acquisition operator + second person | Review `acq/spec.json`. `pmctl build -key … -spec acq/spec.json -out acq/out/2026-11.pmb -state acq/state.json`. `pmctl inspect -bundle … -pub bundle.pub`. |
| 4 | Boundary | acquisition operator | `pmctl send -bundle acq/out/2026-11.pmb -to <drop dir> -key <bundle key>` (or `-via command` for a gateway). Keep `sent.jsonl`. |
| 5 | Isolated | operator | Intake page: bundle `validated`, every check green. Transfer reconciliation: receipt matched. |
| 6 | Isolated | approver(s) | Catalog: review and approve each package with the change reference. Critical patches may need two approvers. |
| 7 | Isolated | operator (not an approver, if SoD is on) | Create the deployment: rings `pilot` → `broad`, deadline from your policy, `max_failure_pct`, `max_retries`, reboot policy, health checks for the business services on pilot machines. |
| 8 | Isolated | operator | Watch the pilot ring. Fix failures. Get sign-off from pilot owners. |
| 9 | Isolated | operator | Advance to `broad`. Watch for auto-pause, `install_failed`, `health_check_failed`. |
| 10 | Isolated | operator / support | Work the remainder: offline endpoints, pending reboots, failures, exceptions. |
| 11 | Isolated | viewer | Reports: compliance by severity, overdue targets, latency (release → received → approved → first verified → 90 % verified). Export CSV and the lifecycle JSON per package for the change record. |

---

## 5. Endpoints

### 5.1 Enrolling a single endpoint

1. **Endpoints → Create enrollment token** (operator): groups (for example `pilot`), site, expiry
   in hours, max uses 1. The token (`enr_…`) is shown **once**. The dialog shows ready-to-run
   commands. **Agent setup** shows the same commands and offers `bundle.pub`, `ca.pem` and any agent
   binaries staged in `<data_dir>/agent-dist/` for download.
2. On a Windows endpoint, in an elevated shell:

```powershell
pmagent.exe enroll -server https://pm.corp.internal:8443 -token enr_… -pubkey bundle.pub -ca ca.pem -root-pubkey root.pub
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

Endpoint detail → **Retire** (operator, reason required). Its certificate and secret stop working at
once, its outstanding targets become `not_applicable` ("endpoint retired: …"), history is kept, and
it leaves the fleet totals. Retirement cannot be undone. A machine that comes back must be
enrolled again and gets a new endpoint ID. Then uninstall the agent from the machine.

### 5.4 Certificates

With TLS (the normal mode) each agent has an mTLS client certificate valid for one year. It renews
itself automatically at check-in during the last 30 days (`endpoint.cert_renewed` in the audit
log). The alert sweep raises `cert_expiring` for any active endpoint whose certificate expires
within 14 days, which normally means the agent has not checked in for a long time. An endpoint
that was offline past its certificate expiry cannot renew and must be re-enrolled.

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
`deployment.auto_paused`, `target.failed`, `target.verified`, `exception.created`,
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
| `size` | Bundle larger than `max_bundle_bytes` (default 8 GiB) | Split the spec into several bundles, or raise the limit. |
| `structure` | Tar layout not allowed: extra entries, directories other than `payload/`, links, devices, traversal, more than `max_files` (500) or a file over `max_file_bytes` (4 GiB), or a truncated file | Rebuild with `pmctl build`. Never hand-edit a bundle. A truncated file points to a transfer problem. |
| `manifest_parse` | `manifest.json` not strict JSON or has unknown fields | Rebuild with a `pmctl` of the same version as the server. |
| `manifest_schema` | Expired (`expires_at` passed — the bundle sat too long; `pmctl build -ttl` default 720h, max 90 days), `created_at` in the future (acquisition clock ahead by more than 10 minutes), invalid field, or `vendor_signature` recorded as `invalid` | Fix clocks, rebuild, send promptly. For `invalid` vendor signatures, find out why before anything else. |
| `trusted_key` | Bundle signed with a key the server does not trust | Wrong key used, or the rotation trust document was not sent. See runbook 03. |
| `key_status` | Key is retired by a trust document | Sign with the current active key. |
| `source_authorized` | `-source` of the bundle is not in the key's `sources` | Use the right `-source`, or authorize it in the trust document / `trusted_keys`. |
| `signature` | Manifest changed after signing, or signed by a different key than its `key_id` | Treat as possible tampering. Rebuild and resend; investigate the transfer path. |
| `payload_hashes` | A payload file is missing, has a different size or SHA-256, or an extra file is present | Corruption or tampering in transit. Resend; compare with `sent.jsonl`. |
| `content_scan` | `scan_command` exited non-zero for a file (or the scanner could not run) | Treat as potential malware until proven otherwise. Check the scanner output in the detail. |
| `replay` | `sequence` not greater than the last accepted one for that source (e.g. state file lost, new acquisition host, or an old bundle resent) | Rebuild with `pmctl build -seq <last+1>` or restore `state.json`. A deliberately resent old bundle is correctly refused. |
| `duplicate_bundle` | The same `bundle_id` was already accepted | Nothing to do if it was a duplicate send. |
| `catalog_conflict` | A `package_id` already exists with different content | Give the new content a new `package_id`. |

A bundle that never shows up: it may still be `*.part` (transfer incomplete), have the wrong
extension (only `*.pmb`, `*.receipt.json` and `*.trust.json` are read), or be held back by the
inbox rate limit (`intake_rate_limited` alert; it is processed later, nothing is dropped).

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
| Target stays `installed`, never `verified` | Inventory does not show the KB / product code / package version. Some updates do not appear in `Win32_QuickFixEngineering`; the MSI product code in the manifest may not match the installed product | Check the endpoint's Inventory tab. Fix the package metadata (new `package_id`) if it is wrong. |
| Target `deferred`, detail `not enough free disk space …` / `on battery …` | Pre-install check (§3.8) | Free disk space (Disk Cleanup, clear old profiles) or plug the laptop in; the next check-in proceeds. Adjust `preinstall` in the server config if the minimum is wrong for your fleet. |
| Target `lost_after_install`, critical alert | Endpoint silent since the install / reboot (§3.8) | Check the machine; it recovers automatically when it checks in. |
| Create rollback returns 409 `rollback not supported` | macOS `.pkg`, the agent, or a package without KB / product code / package name | Remove by hand or deploy the previous version. |
| Target stays `pending_reboot` | `reboot_policy: never`, or no maintenance window with `allow_reboot` is open | Reboot through your normal process. |
| Approve returns 409 `already approved this package; a different approver is required` | Two-person rule | A second approver approves. |
| Create deployment returns 409 `separation of duties` | You approved the package | Another operator creates the deployment. |

---

## 9. Self-check quiz

1. **An endpoint has not checked in for two hours but its last report showed every patch installed.
   What status does it show, and why?**
   `offline`. Silence is never compliance: `offline` (and `stale`) take precedence over all other
   statuses.
2. **A bundle arrives. Can an operator deploy its packages straight away?**
   No. Packages arrive `quarantined`. An approver must approve (with a reason), which publishes the
   content to the repository. Only `approved` packages can be deployed.
3. **`approval_policy` has `"critical": 2`. Alice approves a critical package. What is its state,
   and what happens if Alice approves again?**
   Still `quarantined` with 1 of 2 approvals. Alice approving again is refused (409); a different
   approver must approve.
4. **With `separation_of_duties` on, who may create the deployment for a package Alice and Bob
   approved?**
   Any operator (or higher) other than Alice and Bob.
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
   Revoking (approver, reason required) stops new installs and cancels all its active and paused
   deployments. It does **not** uninstall anything; offpatch has no automated rollback. Recovery is
   the manual per-class procedure (runbook 06).
10. **What is the difference between the deployment window and a maintenance window, and which one
    does the deadline override?**
    The deployment window (`window_start`/`window_end`, UTC) applies to one deployment. Maintenance
    windows belong to endpoint groups and have their own time zone and reboot permission. The
    deadline only overrides maintenance windows.
