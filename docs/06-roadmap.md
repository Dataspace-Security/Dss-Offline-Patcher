# 06 — Roadmap and remaining work

Status as of 2026-10-16 (second pass). Milestones refer to [00-product-workflow.md §10](00-product-workflow.md).
**Owner:** *Org* means a decision for security/operations/management; *Eng* means engineering. Evidence names the test or file that proves an item.

## Milestone status

| Milestone | Status | Notes |
|---|---|---|
| M1 — Scope agreed | ⚠️ Waiting on the organisation | Working assumptions are in [01-decisions.md](01-decisions.md). Section A needs sign-off. |
| M2 — Design approved | ⚠️ Waiting on the organisation | Docs 01–05, 08, 09 and the [pen-test scope](security/README.md) are ready for security review (A7). |
| M3 — Vertical slice | ✅ Done | — |
| M4 — Security controls | ✅ Built and tested | **Exception:** B1, validation on real Windows, which needs a Windows machine. |
| M5 — Pilot operations | 🟡 Ready for exercise | Runbooks, backup/restore and recovery procedures exist. They still have to be exercised by operations in a non-production zone (D5). |
| M6 — Controlled rollout | 🔴 Not started | Needs the pilot. |

## A. Decisions only the organisation can make — *Org* (all still open)

The software now supports each choice; it no longer blocks on any of them. Each decision just picks a configuration.

| # | Decision | What the software supports |
|---|---|---|
| A1 | Transfer product | `transfer.Adapter`: drop directory, or `pmctl send -via command` for a vendor upload CLI. Both use signed receipts and reconciliation. |
| A2 | Identity provider and MFA | Generic OIDC (AD FS, Entra ID, Okta, Keycloak). `require_mfa`; role mapping from groups. Local email + password users with a built-in authenticator app (TOTP) step, required for bank roles. |
| A3 | Signing-key custody | `pmctl -key exec:<hsm-cli>` external signer. Offline root key with trust documents. |
| A4 | Scale | 20k endpoints measured at ~2,000 check-ins/s, about 60k at a 60 s interval ([09-capacity.md](09-capacity.md)). |
| A5 | Maintenance and reboot policy | Per-group windows (time zones, reboot permission), deadlines, `reboot_policy`, per-severity `patch_deadlines`. |
| A6 | Audit retention and scanner | `audit_retention` (at least 30 days), `audit_export_dir` (WORM), `scan_command` (e.g. ClamAV). |
| A7 | Security review sign-off | Pen-test scope is in `docs/security/README.md`. |

## B. Engineering — required before a pilot (M4)

| | Item | Status | Evidence |
|---|---|---|---|
| B1 | Validate the agent on real Windows | ⏳ **Blocked: needs a Windows VM.** The Windows build compiles and vets. Exit codes follow Microsoft documentation. The same agent core is validated for real on Linux (dpkg, rpm, self-upgrade) and on macOS (read-only inventory). | `platform_windows.go` |
| B2 | IdP login, MFA, separation of duties | ✅ Local users: TOTP authenticator required for bank roles; static admin tokens removed (v1.9). | `e2e/sso_test.go`, `oidc/oidc_test.go`, `server/mfa_test.go`, `store/mfa_test.go` |
| B3 | mTLS agent identity with renewal; retire endpoint | ✅ | `e2e/mtls_test.go` |
| B4 | TLS mandatory | ✅ Plain HTTP only with an explicit `insecure_http` lab flag. | `TestTLSRequiredByDefault` |
| B5 | HSM signing; key rotation and revocation; agent trust updates | ✅ Compromised keys auto-revoke their packages. | `e2e/keys_test.go`, `cmd/pmctl/signer_test.go` |
| B6 | Signed agent self-upgrade | ✅ Validated in a real Linux container. Windows uses SCM recovery. | `keys_test.go`; Linux container run |
| B7 | Gateway adapter framework, receipts, reconciliation, rate limits | ✅ (framework) | `e2e/ops_test.go` |
| B8 | Content scanner hook | ✅ `scan_command`. Choice of scanner is A6. | `intake.go` |
| B9 | Signed off-box audit checkpoints and retention | ✅ Detects a fully recomputed (rewritten) chain. | `TestAuditCheckpointsAndRetention` |
| B10 | Backup and restore with integrity check | ✅ | `TestBackupRestore` |
| B11 | Fuzzing, SBOM, dependency audit | ✅ Fuzzing found and fixed 2 bugs; npm has 0 vulnerabilities. ⏳ **Penetration test: people** (scope ready). ⚠️ **Install Go 1.27.2** to clear 10 standard-library CVEs. | `docs/security/README.md` |

## C. Product features for pilot operations (M5) — all ✅

| | Item | Evidence |
|---|---|---|
| C1 | Per-group maintenance windows, deadlines, reboot policy | `e2e/scheduling_test.go` |
| C2 | Concurrency cap (leased), per-site bandwidth limits | `scheduling_test.go`, `agent/throttle_test.go` |
| C3 | Transitive supersedence, prerequisites, editions | `scheduling_test.go`, `keys_test.go` |
| C4 | Acquisition: Update Catalog, MSRC feed, third-party; **unattended `pmctl auto`** with daily scheduler, superseded-KB skipping and automatic send (WSUS-export import not done) | `internal/acquire/*_test.go`, [08-acquisition.md](08-acquisition.md) |
| C5 | Compliance by severity and deadline, latency metrics, CSV, printable report | `e2e/reports_test.go` |
| C6 | In-zone alerts (console, internal SMTP relay, SIEM webhook) | `reports_test.go` |
| C7 | Post-install health checks feeding auto-pause | `scheduling_test.go` |
| C8 | Console: users, retire, bulk groups, alerts, reports, windows | `web/src/pages/*`. The signed-in screens have not been clicked through in a browser yet. |

## D. Operational readiness (Phases 7–8)

| | Item | Status |
|---|---|---|
| D1 | Runbooks | ✅ `docs/runbooks/` |
| D2 | Packaging | ✅ Agent `.deb`/`.rpm` (validated by installing in Debian 13 and Rocky 9 with auto-enroll), server systemd unit, `make release`. ⏳ Windows MSI (`packaging/windows/`) written but **not built**: WiX needs Windows. ⏳ Server Dockerfile written but not built. |
| D3 | Metrics endpoint and capacity test | ✅ `/metrics`; [09-capacity.md](09-capacity.md). A bug that made check-in cost grow with fleet size was found and fixed. |
| D4 | Training | ✅ Material in `docs/07-admin-guide.md` (with a self-check quiz). ⏳ Delivering the training: people. |
| D5 | Pilot | ⏳ Organisation. Follow runbooks and the workflow §Phase 8. |

## E. Later (Phase 9)

| Item | Status |
|---|---|
| Linux agent (deb/rpm) | ✅ Validated in containers |
| macOS agent (.pkg) | ✅ Validated for real on macOS 27.2 (Apple Silicon): enroll, available-patch detection (incl. drag-installed apps), signed install, verified; runs as a launchd service. ⏳ Policy reboot not exercised. |
| PostgreSQL / high availability | ❌ Not started. Measured capacity (about 60k endpoints per server) makes this unnecessary below that scale. Revisit if A4 exceeds it or HA is mandated. |
| Multi-site replication / site caches | ❌ Not started. Today: one server, plus per-site bandwidth limits. |

## Open task list (2026-10-17)

Priority: **P1** must happen before a pilot · **P2** needed for production rollout · **P3** improvement / later.
Owner: **You** = whoever runs this project · **Org** = security / operations / management · **Eng** = engineering.

### P1 — before a pilot
| # | Task | Owner | Notes |
|---|---|---|---|
| T1 | **Push the code to a private repository** | You | Committed locally on branch `offpatch-initial`; no remote configured yet. `demo/`, `bin/`, `dist/` are git-ignored. |
| T2 | **Validate on real Windows** (B1): agent install, `.msu` and `.msi` installs, Windows service + restart after self-upgrade, build and install the **MSI** (`packaging/windows`), Authenticode check in `pmctl build`, `product_code_from_msi` | Eng | Needs a Windows 10/11 and a Windows Server test VM. Linux and macOS are already validated for real. |
| T3 | **Upgrade to Go 1.27.2** and rerun `scripts/security-check.sh` | Eng | Clears 10 standard-library CVEs flagged by govulncheck. |
| T4 | **Settle section A decisions** (A1–A7): transfer product, IdP + MFA, key custody (HSM), scale, maintenance/reboot policy, audit retention + scanner, security review | Org | The software already supports each choice via config. |
| T5 | **Production install**: TLS + PKI (`pmserver init-pki`), SSO and/or local users with MFA, the built-in super admin's default password changed, audit export to WORM storage, backups scheduled | Eng + Org | Runbooks 01, 05, 07. The demo runs in `insecure_http` lab mode. |
| T6 | **Penetration test** against the scope in `docs/security/README.md` | Org (external) | B11. |

### P2 — for production rollout
| # | Task | Owner | Notes |
|---|---|---|---|
| T7 | **macOS agent installer package** (`.pkg` for MDM/mass rollout, like the Windows MSI and Linux deb/rpm) | Eng | Today the Mac agent is installed with `pmagent service install` from the binary. |
| T8 | **Enable Windows updates in `pmctl auto`** for your real Windows versions | You | `demo/acq/acquire-with-windows.json` is ready; first run downloads ~1.4 GB. |
| T9 | **More third-party app feeds** (Teams, Office, Edge, OneDrive, Acrobat, VS Code…) | Eng | Chrome, Zoom, Firefox done. Some vendors ship `.zip`/`.dmg` — see T10. |
| T10 | **`.dmg` / `.zip` app support** on macOS (copy `.app` into /Applications, verify Apple code signature) | Eng | Needed for apps that don't ship `.pkg` installers. |
| T11 | **Server Docker image**: build and test `packaging/server/Dockerfile` | Eng | Written, not built. |
| T12 | **Pilot** in a non-production isolated zone, then a small production pilot (D5) | Org | Follow runbooks; exercise restore and failed-update recovery (Phase 7 exit gate). |
| T13 | **Train administrators** with `docs/07-admin-guide.md` (D4) | Org | Material ready, including a quiz. |

### P3 — improvements and later
| # | Task | Owner | Notes |
|---|---|---|---|
| T14 | Revoke unused enrollment tokens from the console | Eng | Tokens currently just expire (multi-use ≤ 14 days). |
| T15 | Server view of which agents applied the latest trust document | Eng | Agents apply it; the server doesn't show per-agent status yet. |
| T16 | Group-wide exceptions (today: per endpoint) | Eng | |
| T17 | Cache fleet summary / compliance report above ~50k endpoints | Eng | O(fleet) today; fine at 20k (see 09-capacity). |
| T18 | WSUS-export import as an alternative acquisition source | Eng | Only if you already run WSUS. |
| T19 | Exercise policy-driven reboot on macOS and Linux | Eng | Code exists; not run on real machines. |
| T20 | PostgreSQL / high availability; multi-site replication (Phase 9) | Eng | Not needed below ~60k endpoints per server unless HA is mandated. |

### Housekeeping on this machine (demo)
| # | Task | Notes |
|---|---|---|
| H1 | Approve or reject the waiting Mac packages (`chrome-mac-156…`, `firefox-mac-158.0`) | Chrome would really update this Mac's Chrome when deployed. |
| H2 | Remove the test package when done: `sudo pkgutil --forget com.offpatch.test && sudo rm -rf /Users/Shared/offpatch-test` | |
| H3 | Stop the demo when not needed: server `kill $(cat demo/mgmt/pmserver.pid)`, agent `sudo bin/pmagent service uninstall`, daily job `launchctl bootout gui/$(id -u)/com.offpatch.acquire` | The agent service and daily job keep running otherwise. |
