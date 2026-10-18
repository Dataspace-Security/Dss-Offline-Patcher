# 03 — State model

Every transition below is enforced in code (`internal/store`) and writes an audit event with actor and, where marked **R**, a mandatory reason.

## Bundle (transfer unit)

```
received ──validate ok──► validated
    └──────validate fail─► rejected     (terminal; file kept in received/ as evidence)
```

## Package (catalog entry)

```
quarantined ──approve (R, user)──► approved ──revoke (R, admin)──► revoked
     └────────reject (R, user)───► rejected
```
- `quarantined`: in the catalog and visible, but not in the repository and not deployable.
- `approved`: copied to the immutable repository and deployable.
- `revoked`: no new assignments are issued. Active **install** deployments of it are cancelled automatically; rollback deployments keep running (removing a bad package is often why it was revoked), and a rollback may be created for a revoked package.
- **Import again** (`rejected ──delivered again in a validated bundle (intake)──► quarantined`): a rejected package whose `package_id` arrives in a new validated bundle goes back to `quarantined` for a new review, audited as `package.reimported` (actor `system:intake`; details: old and new bundle and SHA-256, `content_changed`, `approvals_cleared`). Every field, the quarantined file and the signed manifest come from the new bundle; if the content changed, the new content replaces the old (safe: a rejected package was never published or deployed, and it is reviewed again from scratch — earlier partial approvals are cleared). A `revoked` package is **never** re-imported (a security decision): it is listed as a skipped duplicate ("revoked; not imported again") whatever its content, and stays revoked. For `quarantined` and `approved` packages the old rules apply: identical content is a skipped duplicate, different content is a `catalog_conflict` that rejects the bundle.

## Deployment

```
pending_approval ──approve (deployment_approvals different bank users/admins, not the creator)──► active
pending_approval ──reject (R)──► rejected   (final)
pending_approval ──cancel (R)──► cancelled
active ◄──resume (R)── paused
  │ ──pause (R)──────────► paused
  │ ──auto-pause (failure threshold exceeded in current ring)──► paused
  │ ──advance (user; only when current ring has no in-flight targets)──► active (next ring)
  │ ──auto-advance (auto_advance: current ring finished within the failure threshold)──► active (next ring)
  │ ──cancel (R)─────────► cancelled   (from active or paused)
  └──last ring done──────► completed   (also: current ring done and no endpoint in any later ring)
```
- A deployment has ordered **rings** (e.g. `pilot`, `broad`). Each ring targets endpoints by group; rings up to and including the current ring receive assignments.
- `advance` takes an optional reason (pause, resume and cancel require one). It is refused while any target in the current ring is `downloading`, `downloaded` or `installing`; failed targets do not block it.
- `emergency: true` requires a justification. It is flagged in the audit log and the UI.
- Every deployment and rollback is created in `pending_approval` with no targets (nothing is dispatched). Each approval is recorded (`approvals`); the one that reaches `approvals_required` (config `deployment_approvals`, default 2) makes it `active` (`activated_at`) and creates its targets. Approvers are bank `user` or `admin` accounts, never the creator and each person once; `rejected` is final.
- `operation` is `install` (default) or `rollback` (see "Rollback" below). A rollback requires a justification. An install and a rollback of the same package cannot be waiting for approval, active or paused at the same time (409: cancel the other first). There is also at most **one running (pending_approval, active or paused) deployment per package and operation** (409: open it, wait for it to finish, or cancel it first); a new one is allowed once the running one is `cancelled` or `completed`.
- `auto_advance: true` ("first machines, then everything else"): when every target of the current ring is finished (the completion test below), the ring stayed within `max_failure_pct` (the auto-pause test) and it is not the last ring, the deployment moves to the next ring by itself — audited as `deployment.advanced` with actor `system:scheduler` and details `{"ring": n, "auto": true}`. It is evaluated wherever completion is (agent reports, creation, resume, the periodic sweep), and repeats if the next ring is already finished. An empty first ring does not advance (its endpoints may not have enrolled yet); an empty later ring is skipped. A ring that finished **over** the threshold does not advance by itself, even after an operator resumes the deployment; the operator advances it by hand. Default `false`: rings wait for an explicit advance. The console's "every compatible machine that needs it" uses it when 10 or more machines need the update: ring 1 "First machines" = the first max(5, ceil(5 % of N)) of them by `endpoint:<id>`, ring 2 "Everything else" = `all`.
- Completion: when every target of the current ring is finished (`verified`, `not_applicable`, `exception`, or `failed` with retries exhausted) and it is the last ring — or no active endpoint belongs to any later ring — the deployment is `completed` (`state_reason` says which). A deployment with no targets at all stays `active` (endpoints may still enroll). This is evaluated on every agent report, right after the deployment is created (every target may already be `verified` from inventory, or `not_applicable`), after advance/resume, and by the periodic sweep (`alert_sweep_interval`) for active deployments whose current ring has no target left in a non-terminal state, so a deployment with nothing left to do never stays `active` waiting for a report that will not come.
- Auto-pause counts, per ring: install failures with retries exhausted, failed health checks, and `lost_after_install` targets. It is evaluated on a **new** failure (an agent report, or the sweep marking an endpoint lost); the lost endpoint's own ring is evaluated, even if the deployment has advanced past it.

## Deployment target (one endpoint × one deployment)

```
pending ─► downloading ─► downloaded ─► installing ─► installed ─► verified
   │            │              │             ├──────► pending_reboot ─► verified
   │            └──────────────┴─────────────┴──────► failed ──retry (agent, ≤ max_retries)──► pending
   ├──agent: pre-install check not met──► deferred ──next check-in──► (offered again, as pending)
   ├──agent: already present / not applicable──► not_applicable | verified
   ├──server: kind exe and agent < 0.9.0──► not_applicable ("agent too old for EXE packages: …") ──agent reports ≥ 0.9.0──► pending
   └──active exception──► exception

installed | pending_reboot ──no activity for lost_after_install (server)──► lost_after_install
lost_after_install ──endpoint checks in (server)──► verified | pending_reboot | installed
verified | installed | pending_reboot | lost_after_install ──rollback verified on that endpoint (server)──► rolled_back
```
- `verified` is set **only by the server** when a fresh inventory shows the package's KB/product code (or, for `deb`/`rpm`/`pkg`/`agent`, the package name / agent at the same or a newer version; for `exe`, the Apps & features entry — by `exe.detect.product_code`, else by display name with the same x86/x64 tag, machine-wide only — at `exe.detect.display_version` or newer), or a KB that supersedes it (transitively). This check runs at every check-in for targets of `active`, `paused` and `completed` deployments, so an endpoint fixed by hand after its deployment completed still verifies.
  - A Windows cumulative update with `expected_ubr` also verifies by **build revision**: the endpoint's build equals the package's `min_build` and the UBR in its `os_version` (`"… (26300.9711)"`) is ≥ `expected_ubr`, even when Windows does not list the KB.
  - Per-user installs (`InventoryItem.scope` `"user"`, found in loaded user hives) count like machine-wide ones, for needs and targeting too; an MSI deployment still installs per machine.
  - The **evidence** (the matching inventory line, e.g. `product {GUID} "Google Chrome" 130.0.1 (user)`, or `os_version build 26300.9711`) is kept on the target (`evidence`, and appended to the detail as `[…]`) and listed in `GET /api/reports/targets.csv`.
- **Installed but not confirmed** (server, alert sweep): a target `installed` for more than 6 h of an active or paused install deployment whose inventory has not confirmed it keeps the state `installed` (a later check-in may still verify it) with detail `installed but not confirmed by inventory after 6 h` (audited once, `target.install_unverified`; `updated_at` unchanged). It counts toward the ring's failure threshold like a failure, and one `install_unverified` alert per deployment names the hosts; the alert closes itself when none is left.
- **Health checks after the restart**: the agent re-runs the deployment's health checks after the restart it asked for and reports `installed` with `health` again. If the target has verified meanwhile, only `health` / `health_detail` are recorded (the state stays `verified`); a failure raises `health_check_failed` and counts toward the threshold. Any passing result closes an open `health_check_failed` alert for that target.
- `failed` counts toward the ring failure threshold only once retries are exhausted (`attempts > max_retries`). Until then the failed target is offered to the agent again.
- **Installer busy**: a `failed` report whose detail starts with `retry later: installer busy` (another installer or Windows servicing is running: msiexec 1618, CBS busy, ...) does **not** count as an attempt for the first 10 consecutive busy results of that target (the attempt counted at `installing` is given back): no `install_failed` alert, no failure-threshold check, detail `waiting: another installation is running on this machine (try N)`, offered again at the next check-in. Only the first of a run is audited (`target.installer_busy`, with the agent's own detail and exit code). From the 11th consecutive busy result on it counts as an ordinary failure, so a machine that is always busy still runs out of retries. Any other result (installed, pending_reboot, another failure, not_applicable) ends the run.
- `attempts`: +1 when the installer starts (`installing`), and +1 for a `failed` report that did not come from `installing` (signed-manifest verification, download or hash check failed) — so those failures exhaust retries and reach auto-pause too. The same failure reported again (same detail and exit code) still counts an attempt but writes no new audit event or alert. A failure whose detail says the signed manifest did not verify, or that the content does not match it ("possible tampering"), raises a **critical** `manifest_verification_failed` alert instead of `install_failed`.
- Stuck in flight (server, alert sweep): a target `downloading`, `downloaded` or `installing` with no agent report and no check-in or heartbeat from its endpoint for 6 h is set `failed` ("no report from the endpoint…"), counting an attempt (unless it was `installing`, already counted) and freeing its `max_concurrent` slot; it is retried if retries remain.
- `deferred` (agent): before downloading, the agent checks free disk space ≥ max(2 × package size, `preinstall.min_free_disk_mb` for the OS; defaults Windows 5 GB, macOS 2 GB, Linux 1 GB) on the system volume and its cache directory, and — on laptops — AC power or battery ≥ `preinstall.min_battery_pct` (default 40 %). If either fails it reports `deferred` with the reason and is offered the target again at the next check-in. Deferral is **not** a failure: it does not consume an attempt, does not count toward auto-pause, raises no alert and blocks neither advance nor completion of other targets. A target that keeps being deferred keeps the endpoint `noncompliant`. Repeated deferrals refresh the detail without new audit events. Where the OS cannot report disk or power, the check is skipped (logged) rather than blocking the install.
- `pending_reboot` with `reboot_policy` `in_window` (or `at_deadline` before its deadline) on an endpoint with **no** maintenance window that allows reboots: the server never asks for the restart, so the target detail says `installed; waiting for a restart: no maintenance window allows automatic restarts (restart the machine or add a window)` (set at check-in, without an audit event; back to `installed; waiting for a restart` once a window that allows reboots applies). The console shows `pending_reboot` as "Restart needed".
- `lost_after_install` (server, alert sweep every `alert_sweep_interval`, default 5 min): a target in `installed` or `pending_reboot` of an active or paused deployment whose endpoint has shown no activity for `lost_after_install` (default 2 h). Activity = the latest of its last check-in, its last reboot request, and its last agent report on any target. It counts toward the ring's failure threshold (and so can auto-pause the deployment) and raises a **critical** `lost_after_install` alert naming every lost host of the deployment (while the alert is open, it is updated and re-sent when more hosts are lost). When the endpoint checks in again the target **recovers by itself**: `verified` if inventory shows the change and no reboot is pending, `pending_reboot` if one still is, otherwise `installed` (awaiting verification). An auto-paused deployment stays paused until an operator resumes it.
- `rolled_back` (server): an install target whose package was removed from that endpoint by a verified rollback. Reports no longer count it as patched. If the package reappears in inventory (reinstalled by hand), it is `verified` again.

## Rollback deployment

A deployment with `operation: rollback` uninstalls an approved (or revoked) package through the normal rings, windows, concurrency cap, reboot policy, health checks and auto-pause. It is created by an operator (separation of duties applies as for installs) and requires a justification; it is audited as `deployment.created_rollback`.

| Package kind | Agent runs | Supported |
|---|---|---|
| `msu` | `wusa.exe /uninstall /kb:<N> /quiet /norestart` | yes (needs `kb`) |
| `msi` | `msiexec.exe /x {ProductCode} /qn /norestart /l*v <log>` | yes (needs `product_code`) |
| `deb` | `dpkg -r <package_name>` (refused by dpkg if other packages depend on it → `failed`) | yes (needs `package_name`) |
| `rpm` | `rpm -e <package_name>` (same) | yes (needs `package_name`) |
| `pkg` (macOS) | — macOS installer packages have no uninstall | **no** (409; shown as "Rollback not supported") |
| `agent` | — | **no** |
| `exe` | the app's `QuietUninstallString` from Apps & features | only with `exe.uninstall.quiet_uninstall` (burn, inno); otherwise **no** (409, "rollback not supported for this installer (no silent uninstall)") |

Targets of a rollback use the same states with these meanings: only endpoints whose inventory shows the package (deb/rpm: at exactly this version) are `pending`, others are `not_applicable`; `installing` = uninstalling, `installed` = uninstaller succeeded, `verified` = a fresh inventory no longer shows it (and no reboot it asked for is pending). Pre-install checks (with no package size) apply. Nothing is downloaded: the agent verifies the signed manifest and takes the KB / product code / package name from it. Rollback targets do not make an endpoint `noncompliant`; their `failed`, `pending_reboot` and `lost_after_install` do count in endpoint status. Rollback deployments are excluded from compliance reports and "available patches".

## Derived endpoint status (fleet view)

Precedence, highest first:

| Status | Rule |
|---|---|
| `lost_after_install` | any target `lost_after_install` |
| `awaiting_checkin` | enrolled less than 24 h ago and has never sent an inventory (agent still starting) |
| `offline` | `last_seen` older than `offline_after` (default 30 min); also an endpoint that enrolled more than 24 h ago and never sent an inventory |
| `stale` | inventory older than `stale_inventory_after` (default 24 h) |
| `failed` | any target in `failed` |
| `pending_reboot` | any target `pending_reboot`, or the OS reports a reboot pending |
| `exception` | active exception covering an outstanding package |
| `noncompliant` | an approved package with an active deployment covers it and is not yet verified (includes `deferred`) |
| `out_of_support` | (API) would be `compliant`, but update intelligence says its Windows build no longer gets updates (`missing.os_support` = `out_of_support`) |
| `updates_available` | (API) would be `compliant`, but update intelligence says it is missing Windows or app updates (`missing.os` + `missing.apps` > 0), or it needs an approved or quarantined catalog package (`missing.catalog` > 0) |
| `compliant` | otherwise |

Silence is never compliance: `lost_after_install`, `offline` and `stale` take precedence over everything else. A lost endpoint is also counted in the `endpoints_offline` alert. `awaiting_checkin` is not compliant either, but it is **not** counted in the `endpoints_offline` / `inventory_stale` alerts (or as reporting in the compliance report) until it has checked in once — or 24 h have passed since enrollment, when it becomes `offline`.

`out_of_support` and `updates_available` refine `compliant` only, in the API layer (endpoint list and detail, `endpoints.csv`, `/api/summary` counts and the `offpatch_endpoints` metric), because they come from update intelligence, not deployment targets. They never override `failed`, `pending_reboot`, `offline`, `stale` or any other status that already says something is wrong. Without update intelligence an endpoint stays `compliant` (unless it needs a catalog package).

## Acquisition request item (Imports)

Computed on read for every item of a tracked request (`GET /api/acquisition-requests`):

```
requested ─► seen ─► fulfilled
    │          ├────► unsupported | failed        (per-item result of the newest report listing it)
    └──────────┴────► stale ──asked again / picked up──► seen | fulfilled
```

- `seen`: an acquisition status report listed the request (`request` feed), or an item result says `fetched` / `already_sent` (on its way).
- `stale` ("Not picked up"): still `requested` / `seen`, not on its way, and the newest acquisition status report (by `finished_at`), finished more than 10 minutes after the request was created, lists the request neither in a `request` feed nor in `items`. Reason: `the acquisition run at <time> did not pick this request up`. The operator asks again (a new request).
- `fulfilled` (the package arrived in a bundle received after the request) wins over everything else.

## Alerts

- An alert is **open** while `acknowledged_at` is empty; an identical one (kind + object) is not raised while one is open.
- **Condition alerts** describe something that is true now and **close themselves** when it is no longer true: the alert sweep sets `resolved_at` (and `acknowledged_by` = `system:scheduler`) and audits `alert.resolved` with the reason. Open condition alerts about endpoints name up to five hostnames, then `+N more`, and carry `details.endpoint_ids`; the message follows the current hosts while open (not delivered again).

| Kind | Object | Closes when |
|---|---|---|
| `endpoints_offline`, `inventory_stale` | fleet | no endpoint is offline / stale any more |
| `out_of_support` | fleet | no endpoint runs an out-of-support Windows build (needs usable intelligence) |
| `intel_stale` | intel | update intelligence no older than 8 days arrived |
| `install_unverified` | deployment | no target of the deployment is installed-but-unconfirmed |
| `lost_after_install` | deployment | every lost endpoint of the deployment checked in again |
| `install_failed` | target | the target verified |
| `health_check_failed` | target | its health checks passed |
| `cert_expiring` | endpoint | the client certificate was renewed (or the endpoint retired) |
| `acquisition_stale` | acquisition source | a fresh acquisition status report arrived |

Event alerts (bundle rejected, key compromised, auto-paused, …) stay open until an operator acknowledges them.
