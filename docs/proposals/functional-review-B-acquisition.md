# Functional review B — from "what is missing" to "package in the catalog"

Read-only review of main, 2026-10-18, checked against the lab (192.168.88.129, role all; 21H2 VM and 26H2 PC) with GET calls only. Go tests not run (no Go toolchain on this workstation). **OK** = as expected · **GAP** = works but the operator is left guessing · **BUG** = wrong result.

## 1. Update intelligence

| Operator action | What happens | Verdict |
|---|---|---|
| `pmctl auto` with `"intel": {}` | `cmd/pmctl/auto.go:493` → `buildIntel` (`cmd/pmctl/intel.go:28`): newest CU per build from the Update Catalog (`internal/acquire/intel.go:92`, hard-coded product list `:53`) + full winget index (`:139`). Signed with the bundle key (`internal/intel/intel.go:87`), sent through the same adapter. | OK |
| Document arrives | `internal/intake/intel.go:62`: signature against active keys, future-dated (>24 h) refused, must be newer than current; accepted → audit `intel.accepted`; rejected → alert `intel_rejected` + audit. Index reloaded on change (`internal/server/updates.go:75`). | OK |
| Intel missing | Updates banner with the exact config to enable (`PatchUpdates.tsx:127`). | OK |
| Intel stale (acquisition stopped sending it) | Nothing: `IntelSource` prints "from 3 weeks ago" in grey (`UpdatesAvailable.tsx:19`); `acquisition_stale` only covers status reports (`store/acquisition.go:115`). Fleet keeps showing "up to date" against an old CU. | GAP |
| Catalog hiccup for one product | Warning, feed "sent incomplete" (`auto.go:529`); that build silently has no row. | GAP (minor) |

Lab: intel generated 19:46:39Z, accepted 11 s later, 10 builds / 15 687 apps; 21H2 VM correctly `out_of_support`.

## 2. Patches → Updates

Rows = `buildFleet` (`internal/server/updates.go:372`) over `intel.Index.Match` (`internal/intel/match.go:109`) + `catalogIndex` (`:158`); per-endpoint status by `endpointStatus` (`ux.go:146`).

- **KB rows**: current when the KB is in inventory *or* installed UBR ≥ release UBR (`match.go:129-137`). Lab: KB5127648 up to date on the PC, KB5044280 verified on the VM. OK. Only the newest CU per build gets a row; older quarantined CUs (lab: KB5127694) appear only in Catalog.
- **Duplicate installs** (EXE next to MSI, per-user + machine): highest installed version per matched app wins (`match.go:144-172`). OK.
- **EXE vs MSI**: inventory key = product code *or* uninstall-registry key name; winget `productcodes2` has both, so EXE installs match by code (`match.go:212`). Name fallback refuses ambiguous candidates unless all non-variant packages agree on the version (`:255`). OK.
- Installed item with empty version counts as **current** (`match.go:184`): silently "up to date". GAP (S).
- **Catalog link** by product code, else by normalised `package_name` when newer (`updates.go:195`); `SameAppName` (`store/available.go:280`) does the same for needs. Lab: firefox-win-158.0 (rejected, nil product code) is linked to the Firefox row by name → "rejected · Import again". OK.
- **Verified**: 7-Zip row verified 2 (one "already present"). OK.

## 3. Import

| Action | What happens | Verdict |
|---|---|---|
| Import (direct mode) | `POST /api/acquisition-requests` (`server/acqrequest.go:29`) builds the request from the fleet view only (ids, versions, arches, installed forms; no hostnames), writes `<dir>/<id>.json` atomically (`acqqueue.go:26`), records + audits in one tx. `offpatch-acquire-requests.path` (`install-ubuntu.sh:791`) fires `pmctl auto -only-requests`. Lab: VLC requested 19:47:13 → fulfilled 19:47:44. | OK |
| Import (carry mode) | `queued_to` empty → browser download, banner says carry the file (`RequestResultBanner.tsx:33`). | OK |
| Nobody carries the file | Row stays "requested · 25 h ago" forever (lab: Microsoft.Edge from 18:45, exported before direct mode existed). No ageing, no alert. | GAP |
| Tracking | `store/acqrequests.go:69`: `seen` from a `request` feed in a status report, `fulfilled` when a validated bundle received *after* the request carries the package id (`:200`). Computed, never stored. | OK |
| Item unsupported (EXE-only installer, no ProductCode on a Linux host, version gone from winget-pkgs) | `requests.go:137`: `UnsupportedError` → warning, item dropped, request moved to `done/`. Console: feed row "nothing packageable: …" on Transfers only; the Updates row and request item stay **"seen by downloader"** forever. Lab candidates: VCRedist 2015+, Notepad++, WinRAR (EXE/burn). | GAP (high) |
| Hash mismatch / HTTP error / disk full | `fail()`, request stays, retried next run; feed `failed` with a precise detail (lab: "not enough disk space … 7.3 GB free, need 11.7 GB"), alert `acquisition_partial`. Visible on Transfers only; Updates row stays "seen". | OK (Transfers only) |
| Network down / host off | No report → after 26 h "stale" pill + alert. | OK |
| Request file corrupt | Moved to `rejected/`, warning in the report; no per-request state. | GAP (minor) |
| **Import again** for a rejected/revoked package, same version | `PipelineAction.tsx:66` offers it; pmctl skips the id because `state.json` lists it as done (`requests.go:124`) → "everything requested was sent earlier". Even if re-sent, intake treats an identical sha as a duplicate (no state change) and rejects the whole bundle on a different sha (`store/catalog.go:102-118`). The button can never succeed until the version changes. | BUG |

## 4. pmctl auto

- **Windows CUs** (`msauto.go:40`): MSRC months × configured products, min severity, supersedence deferral, checkpoint prerequisites as separate packages with `Prerequisites` (`acquire/fetch.go:113,239`), never hidden by supersedence (`fetch.go:181`, `msauto.go:82`). OK. Products are configured by hand, not derived from the fleet: the lab downloads the 4.77 GB 26H2 CU that no endpoint is missing. GAP (M).
- **Requested KBs** (`requests.go:303`): product = intel title, build pinned (0 when one KB spans builds, `updates.go:397`). OK.
- **winget resolution** (`acquire/winget.go:84,219`): per-version manifest over HTTPS, MSI/WiX only, x86 MSI accepted for x64, `InstallerSha256` enforced, ProductCode from manifest or the MSI (Windows host only), `package_name` from ARP name → agreeing inventory names → PackageName (`requests.go:261`). OK. A version 404 (winget-pkgs moved on) is terminal although pmctl already holds the index with `latest_version`. GAP (M).
- **Signing/sending** (`bundles.go:46`): per-package schema check, invalid Authenticode excluded (Windows host only), split by size/count, state saved after every bundle. OK. On a Linux host every package is `not_checked` (lab: all 13). GAP (M).
- **Status report** signed, sent even on failure; exit 2 on partial. OK.

## 5. Intake

`intake.go:307`: size → tar layout → strict JSON → schema → trusted key → not retired → source authorised → Ed25519 → every payload hash and nothing extra → optional scan → replay (sequence) → duplicate bundle id → catalog conflict (`store/catalog.go:78-125`). Rejection = bundle `rejected` with the failing check first, alert `bundle_rejected`, audit; Transfers expands the bundle to the ✓/✕ check list (`Intake.tsx:60`). Identical duplicate packages are skipped yet still fulfil a request (`acqrequests.go:157`); interrupted intake is re-ingested from `received/`. OK. A rejection is not linked back to the request item (stays "seen"). GAP (S).

## 6. Catalog

Package panel (`Catalog.tsx:155`): kind, version, KB/product code, prerequisites, SHA-256, size, source URL, vendor signature (status/signer/checked, "recorded by pmctl, not re-executed"), bundle id (links to Transfers, not to the bundle), state/reason/by/at, approvals, fleet counts, lifecycle (`LifecycleTimeline.tsx`: needed → requested → downloaded → received → approved → deploying → verified). Rejected: reason shown, never deployable; revoked: deployments cancelled, rollback offered. OK. "Vendor signature: not_checked" in grey reads as neutral; a bank approver should see a warning. GAP (S).

## Prioritised fixes

| # | Fix | Effort |
|---|---|---|
| 1 | Terminal request-item states `unsupported` / `failed` (with pmctl's detail): extend `acqstatus.Feed` with per-id results, derive them in `ListAcqRequests`, show on the Updates row and request table instead of "seen". | M |
| 2 | "Import again": hide it when the version is unchanged, or send `force: true` so pmctl drops the id from `state.json` and bumps the package id (`-r2`) so intake accepts it. | M |
| 3 | Manifest 404: resolve `latest_version` from the local winget index (already downloaded for intel) and fetch that; report "requested 1.2, sent 1.3". | M |
| 4 | Age requests: `requested` older than N days (default 3) → "not seen by the downloader for 3 d — was the file carried?" + alert. | S |
| 5 | Intel staleness: banner on Updates and alert when `generated_at` is older than 7 d or than the last status report. | S |
| 6 | Authenticode on Linux (`osslsigncode verify` in `signatureFor`); until then render `not_checked` amber: "signature not verified at acquisition". | M |
| 7 | Count empty-version installs as *unknown*, not current. | S |
| 8 | Link a rejected bundle to the request items it carried (manifest ids are in `arrivedPackages`). | S |
| 9 | Warn in `pmctl auto` and the console when a configured Microsoft product matches no endpoint build. | M |

## "Library" tab (browse the whole winget index + Import)

**Browsing is feasible now.** The server already holds the full index in the current intel document (`intel.Doc.Apps`: id, name, latest version, ARP range, product codes, publishers; 15 687 entries). `GET /api/library?q=` over `ix.Doc.Apps` (substring on name/publisher/id, paged) with per-hit annotations from `fleetSnapshot` and `catalogIndex` (installed on N, outdated on M, catalog state) plus a `Doc.Windows` section: S/M.

**Import from the Library needs three changes:**
1. `exportAcqRequest` refuses keys no endpoint needs (`acqrequest.go:52`). Allow a `source: "library"` request with the fleet's architectures and no `installed` entries (pmctl copes: `msiDisplayName` falls back to the manifest).
2. The index carries no installer type, so the Library cannot promise an MSI exists; fix #1 makes the outcome visible after the run. Optionally add a per-app `installer_types` field to the intel document if the index v2 schema exposes it (verify first).
3. `needs()` is update-only by design (`available.go:45`). "Install where absent" needs an explicit per-package flag set at approval, honoured in `needs()`/`appInstalled()` and the target preview: L, and it should stay opt-in per package for a bank.

Recommended order: fixes 1, 2, 4, 5 (what the operator is waiting for), then Library browse, then 3 and 6.
