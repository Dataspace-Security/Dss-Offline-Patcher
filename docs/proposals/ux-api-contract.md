# API contract for the UX iteration (P1 + P2 + live progress)

The TypeScript shapes are the source of truth: `web/src/types.ts`, section "UX iteration" (Policy, PackageFleet, EndpointMissing, FleetStatus*, AcquisitionRequest*, TargetLive) plus `Endpoint.missing`, `FleetUpdates.updates[].requested` and `Target.live`. JSON field names below must match exactly. All endpoints keep existing auth (bearer / SSO cookie + CSRF header for writes) and roles.

## Server endpoints

| Method & path | Role | Response / behaviour |
|---|---|---|
| `GET /api/policy` | viewer | `Policy`: approvals_required by severity, separation_of_duties, deadlines by severity as Go duration strings (from `store.Policy`, defaults included). |
| `GET /api/packages-needs` | viewer | `Record<package_id, PackageFleet>` for approved **and quarantined** packages. Existing fields unchanged; new counts per the comments in types.ts. An endpoint is counted in exactly one of needed / up_to_date / not_installed (non-applicable endpoints are not counted); deploying / verified / failed / exception count targets (install operation) and active exceptions and may overlap with needed. Retired endpoints excluded. |
| `GET /api/endpoints` | viewer | Each `Endpoint` gains `missing: {os, apps, ready}`: os/apps from the cached update-intelligence fleet view (per endpoint), ready = approved catalog packages it needs (`Needs`). `null` when there is no usable intelligence (ready is still useful: if intel is missing, return `{os:0, apps:0, ready:N}`? No — return null for the whole object only when intel is missing AND ready is 0; otherwise fill what is known). Must stay O(fleet) and use the existing caches; do not parse inventory twice. Also on `GET /api/endpoints/{id}`. |
| `GET /api/fleet/status` | viewer | `FleetStatus`: one row per KB / app from the intel fleet view, **plus** rows for up-to-date apps/KBs the matcher considers current (so "up to date" is visible, not only missing). Per endpoint status precedence: exception > failed > being_patched > verified > outdated > up_to_date, using the row's catalog package's targets and exceptions. `requested` from tracked acquisition requests. Cache like `/api/updates` (60 s, invalidated with it). |
| `GET /api/updates` | viewer | rows gain `requested` (latest tracked request listing the KB / winget id, or null). |
| `POST /api/acquisition-requests` | operator | unchanged response; additionally **persists** the request (new table `acq_requests` with JSON items) so it can be tracked. |
| `GET /api/acquisition-requests` | viewer | `AcquisitionRequestRecord[]`, newest first, limit 100. `seen_at`: first acquisition status report (acqstatus) whose feeds include a `request` feed with this request id. Item `fulfilled` when a validated bundle contains a package with that KB/arch (`<KB>-<arch>`) or the winget package id prefix `<winget id>-<version>` (see cmd/pmctl/requests.go `wingetPackageID`); then `package_id` and `fulfilled_at` are set. Compute on read; no background job needed. |
| `POST /api/deployments/{id}/retry_failed` | operator | body `{reason}` (required). For targets in the deployment's **current ring** in state `failed` with attempts exhausted: reset attempts to 0 and state to `pending`, audit `deployment.retry_failed` with the target list; deployment must be `active` or `paused` (paused → stays paused; operator resumes). Returns the `Deployment`. Must re-check auto-pause thresholds normally afterwards. |
| `GET /api/deployments/{id}` | viewer | each target gains `live` (TargetLive or null) from the in-memory progress map (drop entries older than 10 min or when the target leaves downloading/downloaded/installing/pending_reboot). |

## Agent ↔ server (live progress and fast pickup)

- `CheckinResult` gains `next_checkin_seconds` (int). Server: 10 when the endpoint has at least one target in an active deployment whose ring is reached and whose state is non-terminal (pending, downloading, downloaded, installing, installed, pending_reboot), or when an active deployment was created/advanced/resumed in the last 2 minutes and includes the endpoint's groups; otherwise 0 (= use the configured interval). Agent: when > 0, wait `clamp(next, 5, configured)` before the next cycle. Old agents ignore the field (they decode leniently? — check: the agent must not use DisallowUnknownFields on server responses).
- `POST /api/agent/heartbeat` accepts an optional JSON body `{"progress": {"deployment_id", "package_id", "stage", "pct", "bytes_done", "bytes_total"}}` (empty body still valid, for old agents). Server stores it in memory keyed by endpoint+deployment (not in SQLite, not audited) for `Target.live`. Validate: stage in the TargetLive enum, pct -1..100, sizes ≥ 0, ids ≤ 128 chars; ignore progress for deployments the endpoint has no target in.
- Agent sends a heartbeat with progress about every 5 s while downloading (pct from bytes), once at verifying, every 30 s while installing (pct -1), and while waiting for reboot after an install that needs one. Existing `report` calls (state transitions, audited) are unchanged.
- Compatibility: server is always upgraded before agents. A new agent against an old server: the heartbeat body would be rejected if the old server decodes strictly — the old server's heartbeat handler ignores the body, so this is safe; verify.

## Not in scope

Auto-approve, auto-advance, templates, bulk approve (P3). No change to approval, separation of duties, signatures or audit semantics.
