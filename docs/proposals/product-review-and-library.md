# Product review and Library spec (PM view)

Status: proposal. Sources: `web/src`, `internal/server`, `internal/intel`, `internal/acquire`, and the live lab API (2026-10-18). Items marked **NEW** do not exist yet.

## 1. Information architecture

**Verdict: the six areas are right; the Patches tabs are not.** Overview, Deployments, Endpoints, Reports and Settings match how operators, approvers and auditors split the work. Patches mixes three things under unclear names: fleet needs, trusted content and transport evidence. The Library adds a fourth: everything that exists upstream.

| Today | Proposal | Why |
|---|---|---|
| Patches → Updates | **Patches → Needed** | "Updates" also names other lists; "Needed" says what this one is for. |
| — | **Patches → Library (NEW)** | An untrusted index of everything you could import (§3). |
| Patches → Catalog | keep | Signed content only. |
| Patches → Transfers | **Patches → Imports** | Matches the Import button: request → downloaded → arrived → in catalog. |
| Agent packages in Catalog | **Settings → Agent versions** | The lab catalog lists 7 `offpatch-agent` versions next to Chrome. Plumbing, not patching. |
| Deployments → Exceptions | **Reports → Exceptions** | Approvers and auditors own risk acceptance. |
| Deployments → Maintenance windows | **Deployments → Schedule** (calendar, NEW) | Operators think in dates, not rule lists. |

**Where the product still confuses (verified):**

1. **"Compliant" is not honest.** In the lab, `DESKTOP-JMR591K` is `compliant` while `missing = {apps: 6, os_support: out_of_support, os_last_update: 2024-10-08}`. An auditor reads "compliant" as "patched", but `deriveStatus` (`internal/store/endpoints.go`) only looks at open deployments.
2. **Import is offered for apps that can never be imported.** 27 apps are outdated in the lab (Notepad++, WinRAR, Docker Desktop…). `PatchUpdates.tsx` shows Import on every row without a catalog package, but `pmctl` accepts MSI/WiX only (`acquire/winget.go` `msiTypes`). Everything else becomes a run-report warning that never appears on the row.
3. **Requests go stale silently.** The Microsoft.Edge request (17 Oct 18:45) is still `requested` with an empty `seen_at`, although later runs saw newer requests.
4. **Test machines are still the default story.** `PatchThis.tsx` offers "Test machines first, then all". `STAGES_HINT` (`components/deployLabels.ts`) and admin guide §4, steps 7–9, describe pilot → broad.
5. **The one-ring preset has no throttle.** `buildPreset("one_ring")` sets `max_concurrent: 0`, so every machine installs at once and `max_failure_pct` can only pause after the damage is done. Without test machines, this is the biggest safety gap.
6. **The console asks operators to run shell commands** they cannot run from the isolated zone: `pmctl auto` and `launchctl kickstart` on Transfers, editing `acquire.json` on Needed.
7. **Vocabulary drift.** Stage, ring, pilot and broad name the same idea, and "Updates available" sits next to "Available patches" on Endpoint detail.

## 2. Monthly workflow (Patch Tuesday + third-party)

Two people run it: one **operator** and **one approver** (SoD off and 1 approval for every severity, as in the lab policy).

| # | When / who | Step | Product must guarantee |
|---|---|---|---|
| 1 | Wed after PT, 07:00, system | `pmctl auto` fetches CUs, refreshes intel, runs requests | Hash and Authenticode checked, MSRC severity, disk precheck, failures visible in the console the same morning |
| 2 | System / transfer owner | One-way transfer | Signed receipt; alert when sent but not arrived (exists) |
| 3 | System | Intake → quarantine | Nothing is deployable; reject reasons in plain words |
| 4 | Approver, day 1 | Approve from one queue | On one screen: severity, CVEs, supersedence, machines that need it, deadline from policy; a required reason; **delegation** when the approver is away |
| 5 | Operator, day 1–2 | **Deploy to every compatible machine that needs it** | First-wave throttle, auto-pause, pre-install checks, maintenance windows, reboot policy, health checks, MSI rollback |
| 6 | Operator | Watch live progress | Stage and % per target (exists), and why a target is waiting |
| 7 | Operator, day 3–7 | Work the remainder | Retry failures (exists), offline and pending-reboot lists, exception from the target row |
| 8 | Approver / auditor, by deadline | Report and close | SLA per severity that counts **never-deployed** gaps, unsupported OS, evidence export (exists) |
| 9 | Weekly, operator | Third-party: Needed / Library → Import → approve → deploy | Import offered only when importable; request tracked until fulfilled |

**What replaces test machines (opinion).** The one-ring default gets a **first-wave cap**: `max_concurrent = max(5, 5 %)` until that wave is finished. The failure threshold is checked **before** more machines are released. That is an automatic canary that needs no pilot group. Only Emergency stays uncapped.

**Gaps a bank tender will raise**

| Rank | Capability | Today |
|---|---|---|
| Must | **EXE / Inno / Nullsoft / Burn / MSIX** installers, with silent switches and a detection rule | MSI only; most of the third-party estate is excluded |
| Must | SLA per severity that includes updates nobody has deployed | Reports count deployment targets only |
| Must | Out-of-support OS report | The data exists (`missing.os_support`); no report or CSV |
| Must | Software inventory CSV (endpoint × app × version) | Only `endpoints.csv` |
| Must | Approval delegation with expiry (one approver is a single point of failure) | NEW |
| Must | Reboot UX: user notice, postpone up to the deadline, pending-reboot view | Reboot policy only (`never` / `in_window` / `at_deadline`) |
| Must | Notifications: awaiting approval, paused, SLA at risk, import failed | SMTP and webhook exist, for alerts only (`server/ops.go`) |
| Should | Maintenance-window calendar, planned deployment start | Rule list only |
| Should | Windows feature upgrades (in-place, e.g. 22H2 → 24H2) | NEW; the cure for unsupported OS |
| Should | Microsoft 365 Apps (Click-to-Run) and Defender definitions, offline | NEW; banks run both |
| Should | New-software distribution (install an app that is not there yet) | Machines without the app (`not_installed`) are never offered it |
| Should | Branch distribution points (content cache per site) | NEW |
| Nice | ServiceNow change link, scheduled report e-mail, drivers / BIOS | NEW |

## 3. LIBRARY design spec (NEW)

**Purpose.** One searchable list of what exists upstream. Operators can import software without knowing in advance which vendors and packages exist.

| | Library | Catalog |
|---|---|---|
| Trust | Untrusted index: the document is signed, the content comes from the winget community | Signed, hash-verified packages |
| Contents | ~15.7k winget apps + Windows CUs per build | What arrived through the transfer |
| Action | **Import** (creates an acquisition request) | Approve → deploy |
| Installs anything? | Never | Only after approval |

**Data source.** The update intelligence document that already arrives (`internal/intel` `Doc`; lab: 15 687 apps and 10 Windows releases).

- **Apps:** `id`, name, latest version, ARP min/max, product codes, normalised names and publishers.
- **Windows:** product, build, arch, KB, UBR, release date, title, size.
- **Missing:** homepage, display publisher, installer type and URL. The winget v2 index does not contain them; they are only in the per-version manifests.

**How installer details get there (NEW `resolved` section in the intel document).**

- `pmctl` already reads installer manifests when it handles a request (`FetchWingetManifest`, `WingetInstaller`). Extend it to read the `defaultLocale` manifest too (`Publisher`, `PublisherUrl`, `PackageUrl`, `License`, `ShortDescription`).
- Record the result in `Doc.Resolved[]`: `{id, version, publisher, homepage, publisher_url, license, description, installers:[{arch, type, scope, url, sha256}], resolved_at}`.
- Apps to resolve, in this order:
  1. the configured `apps`;
  2. every id ever requested;
  3. a curated list of about 500 enterprise apps shipped with pmctl;
  4. optionally, a `library_ids` list of the winget ids installed in the fleet, carried in the request file. This is opt-in because it sends software inventory outbound.
- Cache by `id@version` in `state.json` and look up at most 300 new entries per run.
- **The isolated server never fetches anything.**

**What each entry shows.**

- Name, publisher, latest version and description.
- Homepage and vendor link (from `resolved`).
- The winget manifest link (`manifests/<l>/<Publisher>/<Name>/<version>`). Computable without a lookup.
- Installer types per arch, with URL and SHA-256 when resolved.
- **Importable:** `yes (MSI)`, `no: EXE only`, or `unknown: not resolved yet`.
- **Installed on N machines** (M of them outdated), from the cached fleet snapshot.
- Catalog state and request state: requested / seen / fulfilled / stale.
- Windows rows: product, build, KB, release date, size, an end-of-servicing flag, and the Update Catalog search link.

**"It shows only available packages."** The default view, **Available**, lists entries that have a resolved installer offpatch supports. Chips: Available · Installed in fleet · In catalog · All (15.7k) · Windows.

**Search and filter UX.**

- One search box over name, id, publisher and product code (250 ms debounce).
- A publisher facet.
- Sort by installed count (the default), name or date.
- The row drawer has the details, the links as copyable text (the isolated console has no internet) and Import.

**Import action.**

- Calls the existing `POST /api/acquisition-requests` with `{apps:[id]}` or `{kbs:[kb]}`.
- **NEW:** an optional `arch` per item, for apps that are not installed anywhere yet.
- The button is disabled, with the reason, when `importable = no`.
- After Import, the row shows `requested` → `seen` → `in catalog`. It shows **stale** when a later acquisition run missed the request (the Edge case).
- **"Downloads automatically"** works only where the bank approves an outbound request channel. That means the co-located `acquisition_requests_dir` (as in the lab) or a **NEW** configurable drop folder or reverse diode for small signed JSON. Strict sites keep the carried file; there the button reads "Download request file".

**API.**

```
GET /api/library?q=&kind=app|os&view=available|installed|catalog|all&publisher=&sort=installed|name|date&page=1&per_page=50
→ {source, generated_at, total, page, per_page,
   items:[{kind, id, name, publisher, latest_version, description,
           links:{homepage, publisher_url, manifest},
           installers:[{arch,type,scope,url,sha256}] | null, resolved_at,
           importable:"yes"|"no"|"unknown", importable_reason,
           installed:{endpoints, outdated}, catalog:{package_id,state} | null,
           requested:{request_id, at, status} | null}]}
GET /api/library/{kind}/{id}   → the item plus the endpoints with their installed versions
```

Role: viewer. Import still needs the operator role.

**Size and performance.**

- The index is already in memory (`intelIndex`). Build lower-cased search keys once per intel generation; a linear scan of 15.7k entries takes under 5 ms.
- Installed counts come from the cached fleet snapshot.
- `per_page` is at most 100 (about 30 KB per response).
- `resolved` adds about 1 KB per app: 3 000 apps add about 3 MB, well inside `MaxDocument` (64 MB).

**Security.**

- Links are **informational**, labelled "unverified, winget community". The server and agents never use them.
- Agents install only signed catalog content, re-verified on the endpoint.
- Render only `https:` URLs up to 2 KB, with `rel="noopener noreferrer"`.
- Never render with `dangerouslySetInnerHTML`: names and descriptions are community text.
- `resolved` is covered by the intel signature and re-verified on load.
- `library_ids` is off by default and is listed as an outbound flow for the boundary review.

**MVP.**

- `GET /api/library` built from the existing intel fields: name, id, version, installed count, catalog and request state, manifest link.
- The Library tab, with Import.
- `importable` is known only from catalog packages and run-report warnings.

**Later.**

- `resolved` in pmctl.
- Homepage and installers in the UI, and the Available default view.
- `arch` per request item.
- Stale requests and the request channel.
- End-of-servicing data.
- EXE rows become importable once that package kind ships.

## 4. Roadmap: next 10

| # | Item | Effort | Why |
|---|---|---|---|
| 1 | **Honest endpoint status:** "Up to date" / "Missing updates" / "Unsupported OS" replace bare `compliant` | S | It is an audit finding waiting to happen |
| 2 | **Safe one-click deploy without test machines:** remove the pilot preset, add the first-wave cap, rewrite `STAGES_HINT` and admin guide §4 | S–M | The owner's direction; closes the `max_concurrent: 0` gap |
| 3 | **Library MVP** (§3) | M | Finds software nobody knew to ask for |
| 4 | **Importability:** pmctl `resolved`; Import explained or hidden for EXE-only rows | M | Stops dead-end Imports |
| 5 | **EXE / Inno / Nullsoft / MSIX package kind:** silent-switch profiles, detection from Apps & features (ARP), exit-code map | L | The largest gap in a tender |
| 6 | **Import tracking and request channel:** stale flag, warning reason on the row, automatic channel | S–M | Makes "Import downloads automatically" true and visible |
| 7 | **Approval queue, delegation and notifications** | M | One approver must not block Patch Tuesday |
| 8 | **Compliance reporting:** SLA including never-deployed updates, unsupported OS, inventory CSV | M | The questions auditors ask first |
| 9 | **Reboot UX:** user notice with postpone, pending-reboot view | M–L | Patches pending reboot are not protecting anything yet |
| 10 | **IA cleanup:** §1 renames and moves, schedule calendar, no shell commands in banners | S–M | Clear separation at low cost |

**After these:** Windows feature upgrades, Microsoft 365 Apps and Defender definitions, branch distribution points.
