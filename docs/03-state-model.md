# 03 — State model

Every transition below is enforced in code (`internal/store`) and writes an audit event with actor and, where marked **R**, a mandatory reason.

## Bundle (transfer unit)

```
received ──validate ok──► validated
    └──────validate fail─► rejected     (terminal; file kept in received/ as evidence)
```

## Package (catalog entry)

```
quarantined ──approve (R, approver)──► approved ──revoke (R, approver)──► revoked
     └────────reject (R, approver)───► rejected
```
- `quarantined`: in the catalog and visible, but not in the repository and not deployable.
- `approved`: copied to the immutable repository and deployable.
- `revoked`: no new assignments are issued. Active **install** deployments of it are cancelled automatically; rollback deployments keep running (removing a bad package is often why it was revoked), and a rollback may be created for a revoked package.

## Deployment

```
active ◄──resume (R)── paused
  │ ──pause (R)──────────► paused
  │ ──auto-pause (failure threshold exceeded in current ring)──► paused
  │ ──advance (operator; only when current ring has no in-flight targets)──► active (next ring)
  │ ──cancel (R)─────────► cancelled   (from active or paused)
  └──last ring done──────► completed
```
- A deployment has ordered **rings** (e.g. `pilot`, `broad`). Each ring targets endpoints by group; rings up to and including the current ring receive assignments.
- `advance` takes an optional reason (pause, resume and cancel require one). It is refused while any target in the current ring is `downloading`, `downloaded` or `installing`; failed targets do not block it.
- `emergency: true` requires a justification. It is flagged in the audit log and the UI.
- `operation` is `install` (default) or `rollback` (see "Rollback" below). A rollback requires a justification. An install and a rollback of the same package cannot be active or paused at the same time (409: cancel the other first).
- Auto-pause counts, per ring: install failures with retries exhausted, failed health checks, and `lost_after_install` targets. It is evaluated on a **new** failure (an agent report, or the sweep marking an endpoint lost); the lost endpoint's own ring is evaluated, even if the deployment has advanced past it.

## Deployment target (one endpoint × one deployment)

```
pending ─► downloading ─► downloaded ─► installing ─► installed ─► verified
   │            │              │             ├──────► pending_reboot ─► verified
   │            └──────────────┴─────────────┴──────► failed ──retry (agent, ≤ max_retries)──► pending
   ├──agent: pre-install check not met──► deferred ──next check-in──► (offered again, as pending)
   ├──agent: already present / not applicable──► not_applicable | verified
   └──active exception──► exception

installed | pending_reboot ──no activity for lost_after_install (server)──► lost_after_install
lost_after_install ──endpoint checks in (server)──► verified | pending_reboot | installed
verified | installed | pending_reboot | lost_after_install ──rollback verified on that endpoint (server)──► rolled_back
```
- `verified` is set **only by the server** when a fresh inventory shows the package's KB/product code (or, for `deb`/`rpm`/`pkg`/`agent`, the package name / agent at the same or a newer version), or a KB that supersedes it (transitively). This check runs at every check-in for targets of `active`, `paused` and `completed` deployments, so an endpoint fixed by hand after its deployment completed still verifies.
- `failed` counts toward the ring failure threshold only once retries are exhausted (`attempts > max_retries`). Until then the failed target is offered to the agent again.
- `deferred` (agent): before downloading, the agent checks free disk space ≥ max(2 × package size, `preinstall.min_free_disk_mb` for the OS; defaults Windows 5 GB, macOS 2 GB, Linux 1 GB) on the system volume and its cache directory, and — on laptops — AC power or battery ≥ `preinstall.min_battery_pct` (default 40 %). If either fails it reports `deferred` with the reason and is offered the target again at the next check-in. Deferral is **not** a failure: it does not consume an attempt, does not count toward auto-pause, raises no alert and blocks neither advance nor completion of other targets. A target that keeps being deferred keeps the endpoint `noncompliant`. Repeated deferrals refresh the detail without new audit events. Where the OS cannot report disk or power, the check is skipped (logged) rather than blocking the install.
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

Targets of a rollback use the same states with these meanings: only endpoints whose inventory shows the package (deb/rpm: at exactly this version) are `pending`, others are `not_applicable`; `installing` = uninstalling, `installed` = uninstaller succeeded, `verified` = a fresh inventory no longer shows it (and no reboot it asked for is pending). Pre-install checks (with no package size) apply. Nothing is downloaded: the agent verifies the signed manifest and takes the KB / product code / package name from it. Rollback targets do not make an endpoint `noncompliant`; their `failed`, `pending_reboot` and `lost_after_install` do count in endpoint status. Rollback deployments are excluded from compliance reports and "available patches".

## Derived endpoint status (fleet view)

Precedence, highest first:

| Status | Rule |
|---|---|
| `lost_after_install` | any target `lost_after_install` |
| `offline` | `last_seen` older than `offline_after` (default 30 min) |
| `stale` | inventory older than `stale_inventory_after` (default 24 h) |
| `failed` | any target in `failed` |
| `pending_reboot` | any target `pending_reboot`, or the OS reports a reboot pending |
| `exception` | active exception covering an outstanding package |
| `noncompliant` | an approved package with an active deployment covers it and is not yet verified (includes `deferred`) |
| `compliant` | otherwise |

Silence is never compliance: `lost_after_install`, `offline` and `stale` take precedence over everything else. A lost endpoint is also counted in the `endpoints_offline` alert.
