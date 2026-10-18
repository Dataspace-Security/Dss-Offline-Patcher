# Runbook 06 — Failed or harmful update: stop, recover, record

## Purpose

When an update fails widely or breaks endpoints after installing: stop the rollout, keep the
evidence, recover the affected endpoints per package class, and record the outcome.

**offpatch has no automated rollback** (decision D12). It can stop a rollout and stop new installs.
Removing an installed update is a manual, per-package-class procedure, described below. It can also
not push a downgrade: for `deb`, `rpm`, `pkg` and `agent` packages a newer installed version counts
as "already present", and `msu`/`msi` presence is by KB / product code.

## When to use

- A deployment auto-paused (`deployment_auto_paused` alert).
- `install_failed` or `health_check_failed` alerts across several endpoints.
- Reports from users or monitoring that an updated application or service is broken.

## Prerequisites and roles

| Role | Tasks |
|---|---|
| Operator | Pause/cancel deployments, collect target lists. |
| Approver | Revoke the package, create exceptions. |
| Endpoint support | Run the recovery steps on endpoints (local admin/root). |
| Application owner | Confirms the service works again. |

## Steps

### 1. Stop the rollout (minutes)

| Situation | Action | API |
|---|---|---|
| Unsure yet, want to investigate | **Pause** the deployment (reason) | `POST /api/deployments/{id}/pause {"reason": "INC-123 investigating"}` |
| This deployment should not continue | **Cancel** it (reason) | `POST /api/deployments/{id}/cancel {"reason": "…"}` |
| The package must not be installed anywhere | **Revoke** the package (role `admin`, reason). Cancels **all** its active and paused deployments. Final. | `POST /api/packages/{id}/revoke {"reason": "…"}` |

Already-paused by auto-pause: leave it paused until step 4.

Note: targets of cancelled deployments (and therefore of revoked packages) no longer count in
endpoint status or compliance reports. Export the evidence (step 2) **before** cancelling if you want
the per-target picture in its live form; it remains available in the deployment detail and the
lifecycle export afterwards.

### 2. Preserve evidence

1. Deployment detail → Targets: note every endpoint with state, `detail`, `exit_code`, `health`.
   Download the lifecycle export: `GET /api/audit/export?package_id=<id>`.
2. `GET /api/reports/endpoints.csv` for the fleet state.
3. On affected endpoints, copy before any recovery step:

| Platform | Copy |
|---|---|
| Windows | `C:\ProgramData\offpatch\agent.log`, `C:\ProgramData\offpatch\logs\*.log` (MSI verbose logs), `C:\Windows\Logs\CBS\CBS.log`, Setup and System event logs (`wevtutil epl Setup setup.evtx`, `wevtutil epl System system.evtx`), application logs |
| Linux | `journalctl -u offpatch-agent`, `/var/log/dpkg.log` and `/var/log/apt/` or `/var/log/dnf.rpm.log`, application logs |
| macOS | `/Library/Application Support/offpatch/agent.log`, `/var/log/install.log` |

4. Keep the payload: it is in the repository as `<data_dir>/repository/<sha[:2]>/<sha>` and in
   `received/<bundle sha>.pmb`. Do not delete it.

### 3. Recover endpoints, per package class

Run as local administrator / root. Test the procedure on one endpoint first.

#### `msu` (Windows update)

```powershell
wusa.exe /uninstall /kb:5046613 /quiet /norestart
# then reboot in a maintenance window
```

- Many cumulative updates cannot be removed with `wusa` (for example combined servicing-stack and
  cumulative packages). Then use DISM:
  `dism /online /get-packages /format:table` to find the package name, and
  `dism /online /remove-package /packagename:<name> /norestart`.
- Some updates cannot be removed at all. Then the options are system restore from backup or reimage.
- Check Microsoft's KB article for known issues and documented workarounds first; a configuration
  workaround is often safer than removal.

#### `msi`

```powershell
msiexec.exe /x {PRODUCT-CODE-GUID} /qn /norestart /l*v C:\Temp\uninstall.log
```

Then reinstall the previous version from your own software store (offpatch cannot push the older
version back if its product code is the same). Some vendor MSIs block removal or need the vendor's
uninstaller; follow the vendor documentation.

#### `deb` (Debian/Ubuntu)

The endpoint has no network repository. Copy the previous version's `.deb` (and any dependencies at
matching versions) to the endpoint, then:

```bash
dpkg -i ./openssl_3.0.11-1_amd64.deb          # dpkg allows the downgrade and warns
# or, resolving against local files only:
apt-get install --allow-downgrades ./openssl_3.0.11-1_amd64.deb
apt-mark hold openssl                          # optional: prevent re-upgrade by other tooling
dpkg --audit                                   # must print nothing
```

#### `rpm` (RHEL family)

```bash
rpm -Uvh --oldpackage ./openssl-3.0.7-25.el9.x86_64.rpm
rpm -V openssl
```

Dependencies at matching versions must be present locally too.

#### macOS `pkg`

macOS has no uninstall for `.pkg` installers. Use the vendor's uninstaller or documented removal
steps, reinstall the previous version's `.pkg`, or restore/reimage the Mac. `pkgutil --forget <id>`
only removes the receipt, not the files.

#### `agent` (offpatch agent self-upgrade)

The previous binary is kept next to the new one as `<binary>.old`:

| Platform | Binary | Rollback |
|---|---|---|
| Windows (MSI install) | `C:\Program Files\offpatch\pmagent.exe` | `sc stop offpatch-agent`, rename `pmagent.exe` → `pmagent.exe.bad`, `pmagent.exe.old` → `pmagent.exe`, `sc start offpatch-agent` |
| Windows (manual install) | wherever `service install` was run from | same |
| Linux (`.deb`/`.rpm`) | `/usr/sbin/pmagent` | `systemctl stop offpatch-agent; mv /usr/sbin/pmagent /usr/sbin/pmagent.bad; mv /usr/sbin/pmagent.old /usr/sbin/pmagent; systemctl start offpatch-agent` |
| macOS | wherever `service install` was run from | `launchctl bootout system/com.offpatch.agent`, swap the files, `launchctl bootstrap system /Library/LaunchDaemons/com.offpatch.agent.plist` |

Only one `.old` is kept: the next self-upgrade overwrites it. Cancel the agent deployment first, or
the agent will upgrade itself again. See [runbook 08](08-agent-upgrade.md).

### 4. Decide what happens to the package and the rollout

| Outcome | Action |
|---|---|
| Problem was local / environmental, package is fine | Fix the endpoints, **resume** the paused deployment (reason). Failed targets with attempts left retry; for exhausted ones see admin guide §3.5. |
| Package is bad for some endpoints only | Create **exceptions** (role `admin`) for those endpoints with owner, reason, compensating controls and expiry; resume. Or cancel and create a new deployment whose rings exclude those groups. |
| Package is bad | **Revoke** it (if not already). If a fixed version comes from the vendor, acquire it as a **new `package_id`**. A revoked package cannot return to quarantine or be re-approved. |
| Package was never approved | Approver **rejects** it with the reason. |

### 5. Record the outcome

The offpatch actions (pause, cancel, revoke, exceptions) are audited automatically. Actions taken on
the endpoints are **not**. Record in the incident/change ticket:

- Package ID, deployment ID, timeline, who decided what.
- Affected endpoint list with recovery method and result per endpoint.
- Whether the package was revoked/rejected, and the replacement `package_id` if any.
- Note that targets of the cancelled deployment stay as they were: a target that reached `verified`
  stays `verified` in that deployment's history even after you removed the update.

## Verification

- The deployment is `paused`/`cancelled`, or the package `revoked`, with your reason in the audit log.
- Affected services confirmed working by the application owner.
- Endpoint inventory (Endpoint → Inventory) no longer shows the KB / shows the previous version.
- No new `install_failed` alerts for the package.

## Rollback / escape hatch

- Pause can be undone (resume). Cancel and revoke cannot.
- If an uninstall makes things worse, stop and restore/reimage the endpoint from backup.

## Evidence to keep

- Lifecycle export (before and after), `endpoints.csv`, deployment target list.
- Endpoint logs copied in step 2.
- Per-endpoint recovery record and the application owner's confirmation.
- Ticket with the decision on the package (revoked / rejected / resumed / exceptions).
