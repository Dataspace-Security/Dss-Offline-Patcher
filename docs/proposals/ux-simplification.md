# Proposal: end-to-end UX simplification of the offpatch console

Status: proposal (review only, nothing implemented). Scope: `web/src` console and the API behind it. Fleet assumed: Windows only; Windows cumulative updates (CUs) and third-party apps (Chrome, 7-Zip, Firefox…) count the same.

## 0. Findings that matter most

1. **"Compliant" doesn't mean "up to date".** `deriveStatus` (`internal/store/endpoints.go:127-160`) only looks at deployment targets, silence and reboot. An endpoint missing this month's CU and running an old Chrome is `compliant` if no deployment targets it. The Overview "fleet patch score" (`Overview.tsx:55-68`) is built on this status. For a bank, that is the biggest UX risk.
2. **The Needed tab is a dead end.** A row that is already in the catalog shows only a pill linking to the Catalog (`Updates.tsx:150`). It has no approve or deploy action.
3. **There are two deploy paths with opposite defaults.** The full form defaults to pilot → broad, 20 % max failure, 2 retries and no deadline (`Deployments.tsx:106-118`). The one-click buttons ("Deploy to the N endpoints that need it", `Catalog.tsx:142-156`, and "Deploy here", `AvailablePatches.tsx:86-90`) create **one ring with no pilot** of `endpoint:<id>` groups, capped at 500, with reboot `never` (`AvailablePatches.tsx:17-25`). The fastest path is also the riskiest one.
4. **An empty pilot ring stalls the deployment.** If no endpoint is in group `pilot`, ring 1 gets no targets. `remainingRingsEmpty` returns false when there are no targets (`deployments.go:762-772`), so the deployment sits `active` until someone presses Advance. Nothing on screen says why.
5. **"Up to date" and "verified" are computed but not shown.** The matcher only counts current apps (`intel/match.go:148-151`); `Needs()` drops endpoints that already have a package (`available.go:199-207`); verified-per-package lives only on Reports (`Reports.tsx:121-163`).
6. **Acquisition requests are untracked** after export: an audit event (`acqrequest.go:75-81`) plus a `request` feed row on Downloads (`Acquisition.tsx:64-78`).
7. **Failure recovery needs workarounds:** no retry once retries are exhausted (the guide says create a new deployment, `docs/07-admin-guide.md` §3.5); exceptions are approver-only (`server.go:164`) with no action on target rows; separation of duties (SoD) is only explained after a 409 (`Deployments.tsx:373-382`).

## 1. Journey map, one function at a time

Each function: today's screens and clicks, what the user must know or decide, friction, and missing visibility.

### 1.1 First setup: agent enrollment (operator)
- **Today:** Endpoints → "Create enrollment token" modal (`Endpoints.tsx:247-325`). It asks for groups, site, expiry and uses, then shows the token and a Windows one-liner (`components/AgentSetup.tsx:67`). The Agent setup page is a guide with a link back to the modal (`AgentSetup.tsx`).
- **Must decide:** group names, which later drive rings (`pilot`, `all`) and maintenance windows.
- **Friction:** free-text groups, no suggestions, nothing says "put 2–5 machines in `pilot`" although default rings depend on it (finding 4).
- **Missing:** a "first check-in ✓, inventory ✓" confirmation after enrolling.

### 1.2 See what the fleet needs (all roles)
- **Today:** Patches → Needed (`Updates.tsx`, `/api/updates`) with Windows/Applications chips, endpoints and catalog state per row; Catalog "Needed by" (`Catalog.tsx:69`); Endpoint detail shows **two** overlapping lists, intel "Updates available" and catalog "Available patches" (`EndpointDetail.tsx:88-89`).
- **Must know:** "not imported" = must be acquired; "in catalog" = can be approved or deployed.
- **Friction:** two vocabularies (update vs. package); no "missing" column on Endpoints (`Endpoints.tsx:99-100`); Catalog filters only by state, not Windows/app (`Catalog.tsx:28-35`).
- **Missing:** nothing lists what is up to date; "The whole fleet is up to date" appears only when the list is empty (`Updates.tsx:111`).

### 1.3 Request acquisition and track downloads/receipt (operator, viewer)
- **Today:** on Needed, tick rows that are not imported and export a JSON request to carry out (`Updates.tsx:50-66, 100-109`). Downloads (`Acquisition.tsx`) shows run cards, feeds and history. Received (`Intake.tsx`) shows reconciliation and bundle checks.
- **Friction:** fine for the security model, but after export the row looks unchanged. Requests, feeds and bundles sit on three tabs and are not linked.
- **Missing:** a "requested by X on D" state per row, and the chain request → feed `new version sent` → bundle → packages in quarantine in one place.

### 1.4 Review and approve (approver; multi-approver)
- **Today:** Catalog → row → panel → "Approve…" with reason (`Catalog.tsx:133-141`); "n of m approvals" and two-person hint (`Catalog.tsx:177-193`); button disabled if you already approved (`Catalog.tsx:116, 135`).
- **Must know:** severity, supersedence, vendor signature, endpoints needing it, rollback support; all are in the panel.
- **Friction:** the tab badge counts all quarantined packages, not "awaiting **my** approval" (`Patches.tsx:25-30`); one-by-one approval; no warning that approving bars you from deploying when SoD is on.
- **Missing:** a next-step prompt: "Approved. 37 endpoints need it. Deploy, or hand off to an operator".

### 1.5 Deploy (operator): rings, windows, deadline, emergency, max failure, retries
- **Today:** the full form (`Deployments.tsx:96-396`), about 14 inputs, with live TargetPreview; the quick buttons of finding 3.
- **Must decide:** rings/groups; deadline (not defaulted although `Policy.Deadlines` exists, `store/db.go:183-185`); reboot policy; max failure; retries; a deployment window in **UTC** next to maintenance windows in an **IANA** zone (`Deployments.tsx:282-289` vs. `MaintenanceWindows.tsx:79-83`).
- **Friction:** two window concepts, mandatory free-text name, no presets, emergency is a checkbox at the bottom, empty-pilot stall.
- **Missing:** how many targets still need it vs. will be auto-verified; the preview only mentions it (`TargetPreview.tsx:94`).

### 1.6 Watch progress (operator, viewer)
- **Today:** the list shows a count bar and "% patched" (`Deployments.tsx:67-82`); detail shows ring steps, settings and targets (`DeploymentDetail.tsx:102-180`).
- **Friction:** Advance is manual by design, but nothing says "ring 1 finished: 5/5 verified, ready to advance". The list has no state or package filter.
- **Missing:** what is held back by windows, deferred, or offline.

### 1.7 Handle failures (operator, approver)
- **Today:** Pause/Resume/Cancel/Advance with reasons (`DeploymentDetail.tsx:62-72`); rollback = new deployment; lost/deferred banners (`DeploymentDetail.tsx:89-100`); Exceptions page (approver only).
- **Friction:** no retry for exhausted targets; no "raise exception" on a target row; operators cannot create or request exceptions.
- **Missing:** after auto-pause, which targets caused it, and a recovery checklist.

### 1.8 Verify, compliance and reporting (viewer)
- **Today:** Reports (`Reports.tsx`) shows severity tiles, fleet, exceptions, intake, and a per-package latency table with CSVs.
- **Friction:** everything is computed from targets only (`reports.go:107-170`). A package nobody has deployed has `targets=0` and shows "—", so a missing CU never counts as overdue.
- **Missing:** a per-app and per-KB view, and a per-endpoint "outdated" count.

### 1.9 Audit (viewer)
- **Today:** filters for actor, action, object and package; the Catalog and deployment pages link to filtered audit.
- **Friction:** "Export lifecycle" needs a typed package id on the Audit page (`Audit.tsx:126-133`).

**Roles.** Actions are hidden correctly by role, but every role lands on the same Overview. Approvers need "awaiting my approval"; operators need "ready to deploy / ready to advance / paused / failed"; viewers need "compliance and overdue".

## 2. Gap: lifecycle and the per-app / per-KB picture

### 2a. One package's lifecycle, end to end
Today it is spread across six screens:

| Stage | Where it is today |
|---|---|
| needed | Needed tab |
| requested | audit event only |
| downloaded | Downloads feeds |
| received | Received |
| approved | Catalog panel |
| deploying | Deployments |
| verified on N endpoints | Reports |

The data already exists. `GET /api/audit/export?package_id=` returns the package, bundle, deployments with targets, exceptions and events (`types.ts:121-124`). The only missing link is **requested**: the exported request names `winget_id@version` and `KB/arch` (`acqrequest.go:67-77`), not a package id.

### 2b. Fleet picture per app and per KB
Proposed states per (item, endpoint), computed on the server from data it already holds:

| State | Source today |
|---|---|
| **up to date** | Windows: the build has a known release in intel and no newer CU is missing (`match.go:117-129`). App: `ix.lookup` matched and the version is current (`match.go:148-151`, counted only). Catalog package: `presentIn` is true (`deployments.go:539`). |
| **outdated, not imported** | intel match with `catalog == null` |
| **outdated, awaiting approval / ready** | intel match + `catalogLink.state` |
| **being patched** | target in an active or paused deployment, not in a terminal state |
| **verified** | target `verified` (inventory confirmed) |
| **failed / lost / pending reboot / exception** | target states |
| **not installed** (apps) | `appInstalled` false: never offered (`available.go:233-261`) |
| **unknown** | endpoint offline or stale (silence is never compliance) |

Show both: "verified" = an offpatch deployment installed it and inventory confirmed it; "up to date" = inventory shows it, however it got there. Note that targets created as `verified` with detail "already present" should count as up to date, not as offpatch installs, in reports.

**New API fields needed:**
- `intel.Result.CurrentApps []{app_id, installed_name, installed_version}` alongside `Current`, plus `OSCurrent {kb, build, ubr}` when the endpoint's build is at the latest known release.
- `GET /api/packages-needs` (or a new `/api/packages-status`): add `up_to_date`, `not_installed`, `deploying`, `verified`, `failed`, `exception` counts and `active_deployment_id` per package, next to `needed`.
- **New** `GET /api/fleet/status?kind=os|app`: one row per KB/app with counts per state above. `?key=` drills down to endpoints. It reuses the cached `fleet()` (`updates.go:277-350`) plus `queryTargets`.
- `Endpoint.missing {os, apps, ready}` on `/api/endpoints`, to drive an "Outdated" column and an honest score.

## 3. Proposals (prioritised)

All proposals keep the security model: approve and deploy stay separate, audited human actions, and the server still enforces SoD and states.

### P1: biggest win for the least change

| # | Change | Screens | API | Effort | Risk |
|---|---|---|---|---|---|
| P1.1 | **Honest status.** Keep `compliant` (meaning "no open deployment problem") but add an "Up to date" figure: endpoints with `missing.os+apps == 0`. Overview shows both ("82 % no open issues · 41 % fully up to date"), and the Endpoints list gets an "Outdated" column. | Overview, Endpoints, Endpoint detail | `Endpoint.missing` | S–M | Low; uses the cached fleet view |
| P1.2 | **Needed rows become actionable.** The action depends on the catalog state: not imported → select/request; quarantined → "Review & approve" (approvers) or "Awaiting approval" (others); approved → **"Patch this…"**; deploying → link to the deployment. | Needed | none | S | Low |
| P1.3 | **Guided "Patch this" drawer.** One place, opened from Needed rows, the Catalog panel and Endpoint detail (see the design below). It replaces the no-pilot quick buttons. | Catalog, Needed, Endpoint detail | `GET /api/policy` | M | Medium: it changes the quick-deploy behaviour (on purpose) |
| P1.4 | **Smarter form defaults and presets.** Deadline defaults to release date + policy deadline for the severity. Name is auto-filled. The window is shown in local time and moved under "Advanced". If ring 1 has 0 endpoints, warn and offer "remove empty ring". Presets: Standard, Emergency, Pilot only. | New deployment | `GET /api/policy` | S | Low |
| P1.5 | **Catalog shows fleet status per package.** Columns Needed / Up to date / Deploying / Verified / Failed, plus a Windows/Apps/Agent kind filter. The panel gets a "Fleet" section. | Catalog | extended `packages-needs` | M | Low |
| P1.6 | **Next-step prompts and empty states.** After approval: "N endpoints need it → Patch this / hand off". Empty Deployments → "Catalog · approved & needed (N)"; empty Catalog → Downloads/Received; empty Endpoints → enrollment token. Ring done → "5 verified, 0 failed. Advance to broad?". Paused → the failing targets with detail and exit code. | many | none | S | None |

**The "Patch this" drawer (P1.3).**

1. **Header:** package, severity, release date, KB or product. Fleet line: "needs it 37 · up to date 12 · not installed 4 · offline 2".
2. **Step 1: Approve** (only if quarantined and the user is an approver who hasn't approved): existing approve call with reason, "n of m approvals"; stops at "Waiting for a second approver" if needed.
3. **Step 2: Plan**, with three presets.
   - **Standard:** `pilot` (group `pilot`) → `broad` (group `all`), deadline = release + policy, reboot `in_window`, max failure 10 %, retries 2. Group `all` instead of `endpoint:<id>` lists removes the 500 cap; already-patched endpoints become `verified` at once (`deployments.go:645-646`) and machines without the app `not_applicable` (`:649-650`). If `pilot` is empty: "No pilot group: deploy in one ring, or tag pilot machines first" (links to bulk group edit).
   - **Emergency:** one ring `all`, ignore maintenance windows, deadline now + 24 h, reboot `at_deadline`, justification required, red confirm button.
   - **Custom:** opens the full form prefilled with query parameters (it already accepts `package_id` and `operation`; add the rest).
4. **Preview:** the existing `TargetPreview` with the counts above.
5. **Confirm:** one `POST /api/deployments`, then go to the deployment page.
6. **SoD:** if on and this user approved, Step 2 becomes "You approved this; an operator must deploy it" with a copyable link. The server still enforces it (`deployments.go:349-355`).

### P2

| # | Change | Screens | API | Effort | Risk |
|---|---|---|---|---|---|
| P2.1 | **Per-package lifecycle timeline** in the Catalog panel: needed → requested → downloaded → received → approved (n/m) → deploying (ring k) → verified N/M → 90 % date, each with time and actor. Includes a "Download lifecycle JSON" button. | Catalog panel | first version none (built on `/api/audit/export` and `PackageReport`); later, request linkage | M | Low |
| P2.2 | **Fleet status matrix**: a new Patches → "Status" tab. One row per KB or app; columns up to date / outdated (not imported / awaiting approval / ready) / being patched / verified / failed / exception / unknown; cells open the endpoint list. A per-endpoint grid comes later. | new tab | **new** `/api/fleet/status` | M–L | Low; read-only; watch performance at about 10k endpoints (use the cache) |
| P2.3 | **Track acquisition requests**: persist exports (**new** table); "seen" from `request` feed rows, "fulfilled" when the KB/app arrives in a validated bundle; Needed rows show "requested 2 d ago". | Needed, Downloads | **new** `GET /api/acquisition-requests` | M | Low |
| P2.4 | **Failure recovery**: **new** action `retry_failed` (operator, reason, audited) resets attempts of exhausted targets in the current ring; target rows get "Raise exception…" (approver) / "Request exception" (operator → alert or draft). | Deployment detail | new action; optional exception-request object | M | Medium: retry must re-check the auto-pause threshold |
| P2.5 | **Role starting page**: Overview "Your work" card from existing APIs. Approver: awaiting my approval. Operator: approved & needed, rings ready to advance, paused, exhausted failures. Viewer: overdue, up to date. | Overview | none | S | None |
| P2.6 | **Merge the endpoint lists**: one "Updates" table on Endpoint detail (intel and catalog), with a pipeline column and a single "Patch this" action. | Endpoint detail | none | S | Low |

### P3 (optional, flag clearly)

| # | Change | Effort | Risk |
|---|---|---|---|
| P3.1 | **Saved deployment templates** (admin-managed, audited), e.g. "Monthly CU", "Browser update". | M | Low |
| P3.2 | **Optional auto-approve policy** (**new**, off by default, configured by admin + approver, audited as `system:policy/<id>`): e.g. third-party apps from a named source, severity ≤ important, valid vendor signature, after 24 h quarantine. **It never deploys.** Shown as "approved by policy" in Catalog and audit. Banks may forbid it. | M | High (governance) |
| P3.3 | **Optional auto-advance** (**new**, operator opt-in per deployment): advance when the ring is fully terminal, under the failure threshold, health ok, after a soak time. Default stays manual. | M | Medium |
| P3.4 | **Bulk approve** with one reason; one audit event per package, SoD and multi-approver rules unchanged. | S | Medium (rubber-stamping) |

## 4. Recommended first iteration (build now)

**Goal:** from the Needed tab or the Catalog, an operator can patch Windows CUs and apps safely in at most three clicks. Every screen tells the truth about "up to date".

**Server (Go)**
1. `GET /api/policy` (viewer) → `{approvals_required: {sev: n}, separation_of_duties: bool, deadlines: {sev: "168h"}}` from `store.Policy`.
2. Extend `Store.Needs` (`available.go:183-212`). For each endpoint with inventory, classify it as `needed` (current behaviour), `up_to_date` (`presentIn`), or `not_installed` (`!appInstalled`). Then join `queryTargets(d.state IN ('active','paused','completed') AND operation='install')` to add `deploying`, `verified`, `failed`, `exception` and `active_deployment_id`. Keep `needed`, `endpoint_ids` and `hostnames` for compatibility.
3. `Endpoint.missing {os, apps, ready}` on `/api/endpoints`, from the cached `fleet()` result (count per endpoint id) plus `Needs` for `ready` (approved and needed).
4. Table tests for the classification (msu present/superseded; msi older/current/not installed).

**Console (React)**
1. `components/PatchThis.tsx`: the drawer described in P1.3, with Standard, Emergency and Custom presets, TargetPreview, empty-ring detection and SoD handling. Wire it into:
   - `Updates.tsx` row actions (P1.2);
   - the `Catalog.tsx` panel, replacing the "Deploy to the N endpoints" button at `:142-156`;
   - `AvailablePatches.tsx`, replacing `deployToEndpoints` for "Deploy here". Deploying to one endpoint stays possible as a one-ring `endpoint:<id>` preset labelled "This endpoint only".
2. `Deployments.tsx`: deadline default from policy, auto-name, local-time window under "Advanced", empty-ring warning, and read the remaining settings from query parameters.
3. `Catalog.tsx`: kind filter (Windows / Apps / Agent) and Fleet columns, with a Fleet section in the panel.
4. `Overview.tsx` and `Endpoints.tsx`: an "Up to date" tile next to the existing score, an "Outdated" column, and wording that says what `compliant` means.
5. Empty states and next steps (P1.6), including "Ring finished → Advance?" on `DeploymentDetail.tsx`.

**Acceptance**
- Needed tab, approved Chrome row: Patch this → Standard → Create gives pilot → broad with a policy deadline and no 500 cap.
- A CU awaiting approval can be approved in the drawer; with SoD on, that approver is told to hand off and gets no Create.
- With no `pilot` group, Standard offers one ring; no deployment stalls silently.
- An endpoint missing a CU that no deployment covers is no longer shown only as compliant.
- Every action uses existing, audited endpoints; nothing deploys without a human pressing Create.

Next iteration: P2.1 timeline, P2.2 fleet status matrix, P2.4 retry and exception from target rows.
