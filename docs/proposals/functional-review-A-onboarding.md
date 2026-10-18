# Functional review A — onboarding and endpoint management

Scope: a new bank operator installs pmserver, enrolls Windows PCs, reads the console per machine, keeps the fleet healthy, upgrades agents. Read-only review of source + lab (`192.168.88.129`, agents 0.6.2 on `DESKTOP-JMR591K` and `aadesh`). `go test ./internal/{agent,server,store}` passes (run on the VM against this tree).

## 1. Server install and console login

| Operator action | What happens | Verdict |
|---|---|---|
| `install-ubuntu.sh --role server --hosts … --pubkey --root-pubkey --audit-dir --allow-from` | Refuses private keys on the box, creates CA + server cert, prints the break-glass token once (`install-ubuntu.sh:666-688`), writes `pmserver.json` with `admin_tokens` only (`:709`), ufw, backup timer. | OK |
| Open console, paste token | `App.tsx:289`; `/auth/config` lists methods (`auth.go:104`). Roles viewer<operator<approver<admin (`config.go:90`). | OK |
| Add `oidc` to `pmserver.json` for SSO | Discovery at first login (`auth.go:45`), role from IdP groups, MFA check. **But** `allow_static_tokens` defaults to **false once `oidc` is set** (`config.go:141-146`): the break-glass token printed at install silently stops working. Runbook 01 says default `true` and "IdP unreachable → break-glass still works". | **BUG** (docs vs code) |

## 2. Enrolling a Windows PC

| Operator action | What happens | Verdict |
|---|---|---|
| Endpoints → Create enrollment token (groups, site, hours, uses) | `POST /api/enrollment-tokens` (operator), hash stored, shown once (`store/endpoints.go:311-340`). Groups/site are free text with no suggestions → typos create new groups. | GAP |
| Copy one-liner into elevated PS 5.1 | `AgentSetup.tsx:67`: C# callback pins the CA SHA-256, `irm …/bootstrap/windows.ps1` with `X-Enrollment-Token`; server checks the token is usable without consuming it (`bootstrap.go:33`) and templates URL, exe hash, keys, CA (`:54-92`). Script locks folders, verifies the exe SHA-256, enrolls, installs the service with recovery flags, starts it (`bootstrap_windows.ps1.tmpl:171-256`). Offered only with an internal-CA server cert and a staged `pmagent.exe` (`setup.go:98`). | OK |
| Token in the pasted command | `$t='enr_…'` stays in PSReadLine history; `Remove-Variable t` (`:277`) does not clear it. | GAP |
| Proxy on the endpoint | Agent never uses a proxy (`agent.go:126`). Bootstrap `irm`/`iwr` honour the WinINET proxy; a PAC that does not bypass the server fails with an opaque error. | GAP |
| Wrong clock on the endpoint | No time check; `NotTimeValid` makes the pin callback return false (`AgentSetup.tsx:63`) → "could not establish trust relationship", nothing says "fix the clock". | GAP |
| Bad/used/expired token | 401, per-IP rate limit, audited once per minute per source (`server.go:630-660`, `identity.go:75-82`). | OK |
| Re-run one-liner on an enrolled PC | Same server URL → "keeping the existing identity" (`tmpl:206`). If that identity was **retired, expired or the server rebuilt**, the agent keeps getting 401 and the re-run changes nothing, although README/console promise it "repairs the install". Only runbook 09's manual path works; `enroll -force` is not in the console. | **BUG** |
| MSI mass rollout | `offpatch-agent.wxs:119-131`: a bad token fails the whole install (`Return="check"`); failure flag and locked state dir set. Not built or staged in the lab. | OK (note) |
| Record visible right after enrollment | Row inserted at enroll without `inventory_at` (`identity.go:67`) → status **`stale`** until first check-in (`endpoints.go:163`); the sweep counts it in `inventory_stale`. Lab: alert #1 raised 0.3 s after `aadesh` enrolled. | **BUG** (minor) |
| First check-in | `Cycle`: renew check, facts, inventory (KBs + Uninstall registry, `platform_windows.go:111-180`), hardware, `POST /api/agent/checkin` (`agent.go:625-690`); server updates hostname/OS/inventory/`last_seen` (`deployments.go:924`). | OK |

## 3. What the console shows per machine

| Item | What happens | Verdict |
|---|---|---|
| Status pill | `deriveStatus` (`endpoints.go:144-184`): retired → lost_after_install → offline (30 m) → stale (24 h) → failed → pending_reboot → exception → noncompliant → compliant. | OK |
| `pending_reboot` with no deployment | Windows' own flag sets it (`:171`). Lab `aadesh` is `pending_reboot` permanently with no open target; nothing says it comes from outside offpatch. | GAP |
| Hardware card | Model/serial/CPU/RAM/disks/IPs/MAC/boot/user/TZ, bounded server-side (`endpoints.go:365-400`). Lab data correct. | OK |
| Inventory table | `kb` + `product` rows (MSI GUIDs, EXE `…_is1`/name ids); 185 items on `aadesh`. | OK |
| Outdated column / Updates table | From update intelligence (`updates.go:385-393`); lab: 30 app updates missing, matched by product code. | OK |
| Out-of-support Windows flag | `intel.OSSupport` (`match.go:353-380`) needs `release_date` on the build's intel entry and 75 days since the newest CU. Lab: `DESKTOP-JMR591K` is **Windows 11 21H2 (22000.3260, last CU 2024-10)** and is **not** flagged; `os_support` is absent for both PCs, so the banner (`EndpointDetail.tsx:66`) never shows. Most likely the intel entries lack `release_date` (no API to read the doc). "Unknown" is invisible. | **BUG** |
| Groups / site / owner / criticality | Editable per endpoint, bulk for groups (`Endpoints.tsx:177`); audited. | OK |
| Certificate | 365-day cert, renewed at half-life or 30 days before expiry (`agent.go:408`), old serial valid until the new one is used (`identity.go:185-210`), `cert_expiring` at 14 days. | OK |
| Retire | Credentials die at once, open targets `not_applicable`, no undo (`identity.go:243`). The agent keeps retrying ≤15 min forever; uninstall is manual (documented). | OK |

## 4. Health over time

| Item | What happens | Verdict |
|---|---|---|
| Offline / stale detection | Thresholds from config, status derived on read; `/api/system` shows them. | OK |
| `lost_after_install` | Targets silent >2 h after `installed`/`pending_reboot`; critical alert names hosts, counts toward auto-pause, recovers on check-in (`safety.go:94-160`). | OK |
| `endpoints_offline` / `inventory_stale` alerts | One fleet alert "N endpoint(s)…" with **no hostnames**, no link (`Alerts.tsx:19`), never auto-closes, count never updated (`alerts.go:36-46`), re-raised after ack. Lab: alert #2 still open with both PCs online. | GAP |
| What to do when an agent goes silent | Admin guide §3.6 is good (service, port, 401 in log). Console gives no per-endpoint hint. | GAP |
| Notification | SMTP relay / webhook, min severity. | OK |

## 5. Agent upgrade path

| Item | What happens | Verdict |
|---|---|---|
| Signed `kind: agent` package → deployment | Stage `.new`, version check, swap, exit 3, SCM restart, health marker, auto-restore (`selfupgrade.go`). **Lab proves it on real Windows**: `aadesh` went 0.4.2→…→0.6.2, every target `verified`. | OK |
| README / runbook 08 / roadmap B1 say "not yet exercised on real Windows" | Stale. | **BUG** (docs) |
| Seeing agent versions | Detail page and `endpoints.csv` only; runbook 08 step 6 promises an Endpoints column that does not exist (`Endpoints.tsx:125`). | GAP |

## Prioritised gaps and bugs

1. **Break-glass token dies when SSO is configured** (BUG, S). Installer: write `"allow_static_tokens": true` into `pmserver.json`; runbook 01: fix the default in the table and the "IdP unreachable" sentence; log a startup warning when `admin_tokens` are present but disabled.
2. **Re-running the one-liner does not repair a retired/expired/rebuilt identity** (BUG, M). In the template, after "already enrolled", run `pmagent.exe run -once`; on `server 401` move the state dir aside and enroll with the new token (the `$previous` restore path already exists). Add `enroll -force` to the console's "Remove/repair" section.
3. **Out-of-support flag silently off** (BUG, M). Make `OSSupport` return `"unknown"` when the build is known but has no `release_date`; show "support unknown" in the OS cell; have `pmctl` refuse to build intel windows entries without `release_date`; add a go test for a 22000 endpoint. Verify the lab intel doc.
4. **Fresh enrollment shows `stale` and raises an alert** (BUG, S). In `deriveStatus`, treat `InventoryAt==""` with `enrolled_at` younger than `offline_after` as a new status `enrolling` (pill "awaiting first check-in"); exclude it from the stale sweep.
5. **Fleet offline/stale alerts are not actionable** (GAP, M). Include up to 10 hostnames in the message, update the message/count on each sweep, auto-acknowledge (`system:sweep`) when the count returns to 0, and link `object_type=fleet` to `/endpoints?status=offline`.
6. **Agent version not visible fleet-wide** (GAP, S). Add an "Agent" column and an "agent < latest approved agent package" chip on Endpoints; fix runbook 08 step 6.
7. **Stale "not validated on real Windows" statements** (BUG docs, S). README, runbook 08, roadmap B1: replace with the lab evidence (self-upgrade chain, MSI still untested).
8. **Bootstrap robustness** (GAP, S each): compare `Get-Date` with the server's `Date` header and stop with "clock is off by N min"; set `[Net.WebRequest]::DefaultWebProxy = $null` for the bootstrap requests; hint that the pasted line is in PowerShell history and should be cleared (`Clear-History`, delete `ConsoleHost_history.txt`) or read the token with `Read-Host -AsSecureString`.
9. **`pending_reboot` from outside offpatch** (GAP, S). When `reboot_pending` is set but no target is `pending_reboot`, label the pill "pending reboot (Windows)" with a tooltip, and let a maintenance window reboot it like any other.
10. **Token/group ergonomics** (GAP, S). Datalist of existing groups and sites in the token and edit forms; a read-only list of unexpired tokens (groups, site, uses left), since there is no revoke.
11. **MSI** (GAP, S): document that a bad `TOKEN` fails the install, and stage a built MSI on the lab server.
