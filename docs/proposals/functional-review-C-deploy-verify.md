# Functional review C — approval → deployment → install → verification → reporting

Read-only review of the working tree (HEAD `3cba28b` plus uncommitted changes in `internal/store/deployments.go`, `internal/server/ux.go`, console) against the lab server `192.168.88.129` (binary **0.6.0**, agents 0.6.2, two Windows 11 endpoints). Evidence: today's 7-Zip 26.04, Chrome and agent 0.5.0→0.6.2 deployments, `/api/audit`, `/api/reports/compliance`, `/api/packages-needs`, endpoint inventories. `go test` for `internal/store`, `internal/agent`, `internal/server` passes on the working tree (run with the VM's Go 1.27; none installed locally).

Verdicts: **OK** · **GAP** missing or misleading · **BUG** wrong.

## 1. Approval

| Action | What happens | Verdict |
|---|---|---|
| Approve | Reason required (`catalog.go:399`); same user cannot approve twice (`:433`); approvals needed = policy per severity, default **1** (`:330`; lab `approval_policy: null`). Content is published *before* the state flips (`:414-421`), so "approved" always means "content present". Audit `package.approved` carries sha256 and reason. | OK |
| Reject / revoke | Reject only from quarantined, revoke only from approved (`:405-409`). Revoke cancels every active/paused *install* deployment, audited each (`:462-484`); rollbacks keep running. A machine already `installing` finishes (the agent never kills an installer, `agent.go:782`); its report is accepted (`:1222`) but never verified (`Checkin` reconciles only active/paused/completed, `:940`) and is excluded from status and compliance. | OK; GAP: no "installed after revoke" alert (S) |
| Defaults | Single approver, SoD off, and the drawer lets one person approve *and* deploy (lab: `user:admin` did both every time). | GAP (S) |

## 2. Creating a deployment

| Action | What happens | Verdict |
|---|---|---|
| "Every compatible machine that needs it" | One ring `all`, policy deadline (release + 30 d: 7-Zip → 2026-11-05 ✔), `in_window` reboot, 10 % failure, 2 retries (`patchPlan.ts:128-150`). `ensureTarget` (`deployments.go:675-723`) decides per endpoint: not applicable (`:541`); already present → `verified` (`:705`); app not installed → `not_applicable` (`:709`); app-store managed; exception. Late enrolments get targets at check-in (`:937`); retired skipped. The preview mirrors this (`TargetPreview.tsx`) and blocks "nothing to do" client-side (`PatchThis.tsx:166`). | OK |
| Duplicate prevention | Working tree: one active/paused deployment per package+operation (`:352-357`); the 409 becomes "Open the running deployment" (`PatchThis.tsx:60-73`). **Lab 0.6.0 lacks it**: three 7-Zip deployments coexist, two on one endpoint. | BUG (deployed); fixed uncommitted |
| Nothing-to-do | Working tree evaluates at creation (`:395`); `sweepDeployments` (`:407`) completes them. Lab 0.6.0: `d-54485d15a574`, `d-d656492ac80e` have their only target `verified` yet stay `active` forever. The server still accepts what the preview knows is pointless. | BUG (deployed); GAP: server 409 (S) |
| Deadlines, windows, emergency, SoD | Group windows hold installs until the deadline (`:1087-1090`); deployment HH:MM UTC window (`:1071`); emergency = justification, ignore windows, 24 h deadline, `at_deadline` (`:246`, `patchPlan.ts:143`); SoD server-side (`:358`). | OK |
| Reboot policy default | `in_window` reboots only inside a window that *allows reboots* (`:1167`). The lab has **no maintenance windows**: the preset promises "reboot in window" and never reboots. `d-60ffbf59d201` (aadesh, exit 3010) has sat in `pending_reboot` since 19:05; the deployment never completes; the drawer gives no warning. | BUG (M) |

## 3. Rollout mechanics

| Action | What happens | Verdict |
|---|---|---|
| Stages | First matching ring wins (`:526`); advance refused while targets download/install (`:487-491`); next ring's targets created on advance (`:505`). | OK |
| Auto-pause | `evaluate` (`:753-783`): bad = retries exhausted + health failed + lost; above `max_failure_pct` → paused, critical alert, audit; only on a *new* failure, so resume isn't undone. | OK |
| Retries | Attempt counted at `installing`; download/manifest failures count too (`:1289`); identical repeats don't flood audit (`:1240`). `retry_failed` resets attempts, reactivates a completed deployment, audits the list (`retry.go`). | OK |
| Pickup latency | `next_checkin_seconds = 10` for 2 min after create/advance/resume/retry and while busy (`retry.go:104-137`). Lab: created 19:00:38 → downloading 19:00:47. | OK |
| Live progress | Heartbeats carry stage/bytes (`progress.go:196`); shown live in `DeploymentDetail.tsx:108`. | OK |
| Pause/resume/cancel | Reason required, audited with counts (`:450-517`); cancel final, running installers finish. | OK |
| Silence | `sweepStuck` fails after 6 h without report; `sweepLost` → `lost_after_install` after 2 h + critical alert; check-in recovers (`safety.go`). | OK |

## 4. The install on Windows

| Step | What happens | Verdict |
|---|---|---|
| Download + verify | Same-origin, resumable, idle timeout, size+sha256 against the **endpoint-verified signed manifest** (`agent.go:873, 1035`); mismatch → `failed "… possible tampering"` → critical alert (`deployments.go:1258`). | OK |
| Run installer | `wusa /quiet /norestart`; `msiexec /i /qn /norestart /l*v <log>` (`platform_windows.go:229-236`); one at a time; never killed on agent stop; 2 h timeout → `failed "timed out … stopped"` (`:217-226`). | OK |
| Exit codes | `exitcodes.go`: 0 installed; 3010/1641/0x80070BC2 pending_reboot; already-installed → installed; not-applicable HRESULTs → `not_applicable`; busy (1618, CBS) → **failed** "retry later"; else "installer exit code N (0x…)". Busy counts as an attempt, so a 10-minute servicing operation exhausts 2 retries in ~3 min and can auto-pause a ring. No log excerpt reaches the console. | GAP: busy → defer (S); log excerpt (S) |
| Reboot | `reboot_now` granted ≤ every 30 min, only where policy allows (`:1127-1152`); agent runs `shutdown /r /t 600` with a message (`:270`); long installs defer the decision to the next check-in (`agent.go:687`). No user deferral. | OK; GAP (M) |
| Operator view | State, exit code, detail, health, live stage; `install_failed` alert; paused deployments list failing targets with a fix/retry/resume walkthrough (`DeploymentDetail.tsx:148-177`). | OK |

## 5. Post-deployment verification

"Verified" never comes from the agent's exit code. The agent reports `installed`; at the next check-in the server compares the *fresh inventory* (`presentIn`, `:599-622`): KB in the QFE list or a superseding KB; MSI by `SameAppName` + `DisplayVersion ≥ version` or product code + version; agent by reported version. Held while the endpoint still flags a pending reboot (`:954, :981`). Lab: `target.installed` 18:37:36 → `target.verified "inventory shows 7-Zip 26.04 (x64 edition) 26.04.00.0"` 18:37:48. Orphan ARP entries (aadesh still lists `7-Zip 24.09 (x64)`) are correctly ignored by verification and "needs it" (`available.go`).

| Case | Behaviour | Verdict |
|---|---|---|
| DisplayVersion ≠ manifest version (Java "8.0.4310" vs "8u431") | Target stays `installed` forever: no timeout, no alert, deployment never completes. | GAP (M) |
| Per-user installs (HKCU: Chrome/Teams per user) | Inventory scans HKLM only (`platform_windows.go:117`); machine becomes `not_applicable "app not installed"` and leaves the denominator → false 100 %. | GAP (M) |
| KBs absent from `Win32_QuickFixEngineering` (Defender platform, Edge, .NET Core); UBR | Only QFE + supersedence chain; UBR is in `os_version` but never compared, so such LCUs stay `installed`. | GAP (M) |
| Lost after install | 2 h silence → `lost_after_install`, critical alert, counts toward pause; recovers on check-in, episode audited. | OK |
| Health checks | `service_running` / `tcp_listening`, run once after the installer and before any reboot (`agent.go:863`); failure alerts and counts toward pause but the target still verifies; not re-run after reboot. | GAP (S) |
| Auditor evidence | Hash-chained audit per transition (actor, from, detail, exit code, hostname); hourly checkpoint files with sha256; `/api/audit/verify` (lab: ok, 242 events); lifecycle JSON per package. Missing: the inventory line that proved it and the msiexec log. | OK; GAP (S) |

## 6. Rollback and exceptions

Rollback (`operation=rollback`) needs a justification, works on approved/revoked packages, msu via `wusa /uninstall /kb`, msi via `msiexec /x {code}`; pkg/agent refused with a reason (`safety.go:24-45`). Verified when inventory no longer shows it; install targets become `rolled_back` (`markRolledBack`); install and rollback are mutually exclusive (`:343`). **OK**, but for apps it is an uninstall, not a downgrade — say so in the console (S).

Exceptions: approver role; owner, reason, compensating controls, expiry ≤ 1 year required; applied immediately to open targets; revoke/expiry returns them to `pending`; compliance counts them separately with "expiring in 7 d". **OK**. GAP: single-person, per-endpoint only (S).

## 7. Reporting

Compliance (`reports.go`): best state per package×endpoint over non-cancelled install deployments; exceptions separate; overdue = outstanding past release + policy deadline; latency metrics; CSV with formula-injection guard; every export audited. Lab: 7-Zip 50 % (aadesh `pending_reboot`), Chrome 100 % — honest. Endpoint CSV, chain verify, lifecycle export and the Catalog timeline all exist.

Would an auditor accept it? Mostly, with two objections:
- **Denominator is "targeted", not "needed"** (`pct(0,0)=100`, `reports.go:88`). A package never deployed to machines that need it, or machines dropped by a per-user install, reports 100 %. `packages-needs` already knows `needed`. **GAP (M)**
- No per-endpoint×package evidence export (who verified what, when, from which inventory) and no dated report artifact. **GAP (M)**

## Prioritised gaps and fixes

| # | Item | Fix | Effort |
|---|---|---|---|
| 1 | **BUG** lab 0.6.0: duplicate deployments; nothing-to-do deployments never complete | Ship the uncommitted `deployments.go` (`:352`, `:395`, `sweepDeployments`); store test: all-terminal-at-creation → `completed`. | S |
| 2 | **BUG** `in_window` with no reboot-capable window → stuck `pending_reboot` | Drawer: if no `allow_reboot` window covers the targeted groups, warn and default to `at_deadline`; server alert at creation. | M |
| 3 | Compliance ignores "needed but not targeted" | Merge `packages-needs` into `Compliance`: outstanding += needed endpoints without a target. | M |
| 4 | `installed` never verified is silent | `installed_unverified` threshold (6 h): alert, detail, counts toward pause. | M |
| 5 | Per-user installs invisible | Scan loaded `HKU\*\…\Uninstall` hives (`Source: user`); count for targeting and needs. | M |
| 6 | Installer-busy exits consume retries | Map busy codes to `deferred` with a 10-min backoff. | S |
| 7 | LCU verification without QFE | `expected_ubr` in manifests; verify by `build.UBR ≥ expected`. | M |
| 8 | Per-endpoint evidence | Keep the matching inventory line in `target.detail`; add `/api/reports/targets.csv` (endpoint, package, state, verified_at, evidence, approver). | S/M |
| 9 | Installer log excerpt | Append the last ~20 msiexec log lines to `detail` on failure. | S |
| 10 | Bank defaults | Example config: 2 approvals for critical/important, `separation_of_duties: true`. | S |
| 11 | Health checks only before reboot | Re-run after the requested reboot. | S |
| 12 | End-user reboot deferral | "Restart now / in 4 h" prompt, bounded by the deadline. | M |
