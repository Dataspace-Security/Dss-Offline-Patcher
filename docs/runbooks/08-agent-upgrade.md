# Runbook 08 — Upgrade the endpoint agent (signed self-upgrade)

## Purpose

Roll out a new `pmagent` version through the same controlled path as any patch: signed bundle,
quarantine, approval, staged deployment, verification.

## When to use

- A new agent release (bug fixes, security fixes in the Go toolchain, new features).

## How it works (from the code)

- The new binary travels as a package with `kind: agent` and a `version` like `1.2.3`.
- The agent verifies the signed manifest and SHA-256 as for any package. If its own version is
  already at or above the package version, it reports `installed` without changing anything.
- Otherwise it stages the new binary as `<binary>.new` (fsynced) and runs `<binary>.new version`:
  the output must equal the package `version`. A binary for the wrong OS/arch, or one built without
  `-X offpatch/internal/agent.Version=…`, is refused here and the target reports `failed` (before
  this check such a binary was swapped in and re-installed at every check-in, restarting the agent
  each time).
- It then writes `<state-dir>/upgrade.json` (`state: pending`), renames its running binary to
  `<binary>.old` (only one `.old` is kept), moves the new binary into place, reports `installed`,
  and **exits** so the service manager starts the new version: `pmagent run` exits with code **3**;
  the Windows service stops with an error code.
- The new binary counts its starts in `upgrade.json`. It is confirmed healthy after its first
  successful check-in or 10 minutes of running, and the marker is removed. If it is started
  3 times without becoming healthy (it keeps crashing), the next start restores `<binary>.old`
  (the failing binary is kept as `<binary>.failed`), marks the upgrade `failed`, and restarts the
  old version, which reports the target `failed` with the reason. If the agent comes back with a
  version other than the package version, the upgrade is also marked `failed`. A failed upgrade
  of the same binary (same SHA-256) is not retried on that endpoint; publish a rebuilt package.
  Restart then comes from:
  - Windows: SCM recovery actions (restart after 15 s, 60 s, 5 min), set by `pmagent service install`
    and by the MSI (`util:ServiceConfig`). The service stops cleanly with exit code 1, so Windows
    must also apply recovery actions to non-crash failures: `pmagent service install` sets this
    flag, and the MSI runs `sc.exe failureflag offpatch-agent 1` after installing the service.
    Services installed by an older agent version or MSI lack the flag; on those endpoints run
    `sc.exe failureflag offpatch-agent 1` once (or reinstall), otherwise the service stays stopped
    after the upgrade and the endpoint goes `offline`. This path has not yet been exercised on real
    Windows (roadmap B1); test it on a VM.
  - Linux: systemd `Restart=always`, `RestartSec=15` (unit written by `pmagent service install`).
  - macOS: launchd `KeepAlive`.
- Each check-in reports the agent version in inventory. The server marks the target `verified` once
  the reported version is at least the package version.
- If staging or swapping the binary fails, the agent puts the old one back and reports `failed`.

## Prerequisites and roles

| Item | Notes |
|---|---|
| Build environment | Go **1.27.2+**. |
| Acquisition operator | Builds the bundle. |
| Approver, operator | As for any patch (two-person rule and SoD apply). |
| Endpoints running as a service | An agent started by hand with `pmagent run` exits with code 3 and is not restarted. |
| Pilot group | Endpoints of each OS/arch you run. |

## Steps

1. **Build the binaries with the version stamped in.** The version must be in the binary, otherwise
   the agent keeps reporting the old version and the target never verifies.

   ```bash
   make release VERSION=1.2.0      # all platforms, -X offpatch/internal/agent.Version=1.2.0
   # or one platform:
   GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "-s -w -X offpatch/internal/agent.Version=1.2.0" \
     -o pmagent-1.2.0-windows-amd64.exe ./cmd/pmagent
   ./dist/release/pmagent-1.2.0-linux-amd64 version   # prints 1.2.0
   ```

   Sign the Windows binary with your code-signing certificate if your policy requires it.
2. **Write one spec entry per OS/arch** (each package carries one binary):

   ```json
   [
    {"package_id": "offpatch-agent-1.2.0-windows-x64", "title": "offpatch agent 1.2.0 (Windows x64)",
     "vendor": "offpatch", "kind": "agent", "version": "1.2.0", "severity": "important",
     "release_date": "2026-11-20", "applicability": {"os": "windows", "arch": "x64"},
     "path": "agent/pmagent-1.2.0-windows-amd64.exe"},
    {"package_id": "offpatch-agent-1.2.0-linux-x64", "title": "offpatch agent 1.2.0 (Linux x64)",
     "vendor": "offpatch", "kind": "agent", "version": "1.2.0", "severity": "important",
     "release_date": "2026-11-20", "applicability": {"os": "linux", "arch": "x64"},
     "path": "agent/pmagent-1.2.0-linux-amd64"}
   ]
   ```

   Or let `pmctl fetch-url` write the entry when the binary is on an internal HTTPS server
   (`-kind agent -os windows|linux|macos -version 1.2.0 -arch x64 -sha256 …`; without `-os`,
   `agent` entries default to `windows`).

   - `applicability.os` and `arch` must match exactly; a wrong binary on an endpoint would replace the
     agent with one that cannot start.
   - `pmctl build` records `vendor_signature: not_checked` for `agent` packages automatically
     (Authenticode is only run for `msu`/`msi`). Never set `valid` by hand.
3. **Build, inspect, send** ([runbook 02](02-acquisition-zone-setup-and-monthly-run.md) B6–B8).
4. **Approve** (Catalog) with the release reference.
5. **Deploy in rings**: e.g. `pilot` (a few endpoints per OS) → `broad`. Suggested settings:
   `max_failure_pct` 5, `max_retries` 1, a health check is not needed (verification by version is
   built in). Use `max_concurrent` if you have many endpoints on slow links (agent binaries are small,
   but every agent restarts).
6. **Watch the pilot:** targets go `installing` → `installed` → `verified` after the restarted agent's
   next check-in. The Endpoints page shows the new `agent_version`. If a target stays `installed` and
   the endpoint goes `offline`, the new binary did not start (step "Rollback").
7. **Advance** to the next ring when the pilot is verified on every platform.
8. **Update packaging and agent-dist:** put the new binaries/MSI/deb/rpm in `<data_dir>/agent-dist/`
   and rebuild packaging for new endpoints.

## Verification

- Deployment `completed`, all targets `verified`.
- `GET /api/reports/endpoints.csv`: `agent_version` column shows the new version for all active
  endpoints. Old versions left = endpoints that were offline or not in a ring.

## Rollback / escape hatch

1. **Pause or cancel** the deployment first, otherwise the agent upgrades itself again.
2. Endpoints where the new binary keeps crashing restore `<binary>.old` by themselves (see above).
   Otherwise, on each affected endpoint, swap `<binary>.old` back (table in
   [runbook 06](06-failed-update-recovery.md#agent-offpatch-agent-self-upgrade)), delete
   `<state-dir>/upgrade.json`, and restart the service.
3. offpatch cannot push an older agent version: a package with a lower version than the running
   agent is treated as already installed.
4. Interactions with OS packaging:
   - Linux packages: the self-upgrade replaces `/usr/sbin/pmagent` outside dpkg/rpm. `rpm -V` /
     `dpkg --verify` will report the file as changed, and installing or upgrading the `.deb`/`.rpm`
     later overwrites it with the package's version.
   - Windows MSI: an MSI repair or reinstall puts the MSI's `pmagent.exe` back. Upgrade the MSI in
     your software distribution to the same version.

## Evidence to keep

- Build log with Go version and `VERSION`; SHA-256 of each binary (`SHA256SUMS`).
- Lifecycle export of each agent package.
- Final `endpoints.csv` showing versions.
