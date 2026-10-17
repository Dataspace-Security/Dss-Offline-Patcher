# 05 — HTTP API contract (v1)

All bodies are JSON and all times are RFC 3339 UTC. Errors return `{"error": "message"}` with status 400/401/403/404/409/500.

## Admin API — `Authorization: Bearer <admin token>`

Roles are cumulative: `viewer` < `operator` < `approver` < `admin`.

| Method & path | Role | Body → Response |
|---|---|---|
| `GET /api/me` | viewer | → `{user, role}` |
| `GET /api/summary` | viewer | → `Summary` |
| `GET /api/bundles` | viewer | → `Bundle[]` (newest first) |
| `GET /api/bundles/{id}` | viewer | → `Bundle` (`id` = numeric intake id) |
| `GET /api/packages?state=` | viewer | → `Package[]` |
| `GET /api/packages/{package_id}` | viewer | → `Package` |
| `POST /api/packages/{package_id}/approve` | approver | `{reason}` → `Package` |
| `POST /api/packages/{package_id}/reject` | approver | `{reason}` → `Package` |
| `POST /api/packages/{package_id}/revoke` | approver | `{reason}` → `Package` |
| `GET /api/endpoints` | viewer | → `Endpoint[]` |
| `GET /api/endpoints/{endpoint_id}` | viewer | → `EndpointDetail` |
| `PATCH /api/endpoints/{endpoint_id}` | operator | `{groups?, site?, owner?, criticality?}` → `Endpoint` |
| `POST /api/enrollment-tokens` | operator | `{groups: string[], site, expires_in_hours, max_uses?}` → **201** `{token, expires_at, max_uses}` (the token is shown **once**). `max_uses` default 1, at most 10000. `expires_in_hours` default 24, at most 720; tokens with `max_uses` > 1 at most 336 (14 days). There is no API to revoke a token. |
| `GET /api/agent-setup` | viewer | → `AgentSetup` (signing keys agents should pin — from the latest verified trust document, else `trusted_keys` in the config — and staged agent binaries) |
| `GET /api/agent-setup/files/{name}` | viewer | → file from `<data_dir>/agent-dist/` (e.g. `pmagent.exe`) |
| `GET /api/deployments` | viewer | → `Deployment[]` |
| `POST /api/deployments` | operator | `NewDeployment` → `Deployment` |
| `GET /api/deployments/{deployment_id}` | viewer | → `DeploymentDetail` |
| `POST /api/deployments/{deployment_id}/pause` | operator | `{reason}` → `Deployment` |
| `POST /api/deployments/{deployment_id}/resume` | operator | `{reason}` → `Deployment` |
| `POST /api/deployments/{deployment_id}/cancel` | operator | `{reason}` → `Deployment` |
| `POST /api/deployments/{deployment_id}/advance` | operator | `{reason}` → `Deployment` |
| `GET /api/exceptions` | viewer | → `Exception[]` |
| `POST /api/exceptions` | approver | `NewException` → `Exception` |
| `POST /api/exceptions/{exception_id}/revoke` | approver | `{reason}` → `Exception` |
| `GET /api/audit?object_id=&action=&actor=&package_id=&limit=&before_seq=` | viewer | → `AuditEvent[]` (newest first, default limit 200) |
| `GET /api/audit/verify` | viewer | → `{ok, count, first_bad_seq, error}` |
| `GET /api/audit/export?package_id=` | viewer | → `LifecycleExport` (JSON attachment) |

## Agent API

| Method & path | Auth | Body → Response |
|---|---|---|
| `POST /api/agent/enroll` | enrollment token in body | `{token, hostname, os, os_version, build, arch, agent_version, csr?}` → **201**. **TLS mode** (server has `pki_dir`): `csr` (PEM) is required, response `{endpoint_id, certificate, ca_certificate}`. **Lab mode** (`insecure_http`): response `{endpoint_id, secret}`. Invalid, used or expired token → 401. Body at most 64 KB; `hostname` must be 1-253 characters of letters, digits, `.`, `-`, `_` (else 400). Per client IP: a burst of 20, then one attempt per 3 s (→ **429** with `Retry-After`; requests from the server host itself are exempt). Denied attempts are logged each time but audited (`endpoint.enroll_denied`) at most once per IP per minute, with the number suppressed since the last one. |
| `POST /api/agent/checkin` | device | `{hostname, os_version, build, arch, agent_version, reboot_pending, edition, inventory: InventoryItem[]}` → `{assignments: Assignment[], checkin_interval_seconds, reboot_now, download_rate_kbps, trust?}` |
| `GET /api/agent/manifest/{package_id}` | device | → `{manifest: base64, signature: base64, key_id}` (the original signed bytes) |
| `GET /api/agent/content/{sha256}` | device | → raw bytes, `Range` supported. Only for an approved package with an open target on this endpoint in an active deployment. |
| `POST /api/agent/report` | device | `{deployment_id, package_id, state, detail, exit_code, health?, health_detail?}` → `{ok}` (`health`: `ok` \| `failed`) |
| `POST /api/agent/renew` | device (mTLS) | `{csr}` → `{certificate, ca_certificate}`. Replaces the endpoint's certificate. The previous certificate keeps working until the new one is first used (so a lost response or a crash before the agent saves the new certificate does not lock it out); if a renewal is never used, a later renewal keeps that same previous certificate as the fallback. 409 in lab mode. |

**Device authentication.** TLS mode: the client certificate issued at enrollment (mTLS); its
serial must be the endpoint's current one and the endpoint must not be retired, otherwise 401
`client certificate not valid for an active endpoint`; no certificate → 401
`client certificate required`. Lab mode: `Authorization: Bearer <device secret>`.

Agent-reportable `state`: `downloading`, `downloaded`, `installing`, `installed`, `pending_reboot`, `failed`, `not_applicable`, `deferred` (v1.2). Only the server sets `verified`, `lost_after_install` and `rolled_back`.

## Types

```ts
type Summary = {
  endpoints: { total: number; by_status: Record<EndpointStatus, number> };
  packages: Record<PackageState, number>;
  bundles: Record<BundleState, number>;
  deployments: Record<DeploymentState, number>;
  active_exceptions: number;
  audit: { ok: boolean; count: number };
};

type BundleState = "received" | "validated" | "rejected";
type Check = { name: string; ok: boolean; detail: string };
type Bundle = {
  id: number; bundle_id: string; source: string; sequence: number; key_id: string;
  state: BundleState; filename: string; file_sha256: string; file_size: number;
  received_at: string; package_count: number; checks: Check[]; error: string;
};

type PackageState = "quarantined" | "approved" | "rejected" | "revoked";
type Package = {
  package_id: string; bundle_id: string; title: string; vendor: string;
  kind: "msu" | "msi"; version: string; kb: string; product_code: string;
  severity: "critical" | "important" | "moderate" | "low"; release_date: string;
  supersedes: string[];
  applicability: { os: string; arch: string; min_build: number; max_build: number };
  file_name: string; size: number; sha256: string; source_url: string;
  vendor_signature: { status: string; signer: string; checked_at: string };
  state: PackageState; state_reason: string; state_by: string; state_at: string; created_at: string;
};

type EndpointStatus = "compliant" | "noncompliant" | "pending_reboot" | "failed" | "exception" | "stale" | "offline";
type Endpoint = {
  endpoint_id: string; hostname: string; os: string; os_version: string; build: number; arch: string;
  groups: string[]; site: string; owner: string; criticality: string;
  last_seen: string; inventory_at: string; reboot_pending: boolean; agent_version: string;
  enrolled_at: string; status: EndpointStatus;
};
type InventoryItem = { kind: "kb" | "product"; id: string; name: string; version: string };
type EndpointDetail = Endpoint & { inventory: InventoryItem[]; targets: Target[] };

type DeploymentState = "active" | "paused" | "cancelled" | "completed";
type TargetState = "pending" | "downloading" | "downloaded" | "installing" | "installed"
  | "pending_reboot" | "verified" | "failed" | "not_applicable" | "exception";
type Ring = { name: string; groups: string[] };
type NewDeployment = {
  package_id: string; name: string; rings: Ring[]; max_failure_pct: number; max_retries: number;
  window_start: string; window_end: string; // "HH:MM" UTC, both empty = always
  emergency: boolean; justification: string;
};
type Deployment = NewDeployment & {
  deployment_id: string; state: DeploymentState; current_ring: number; state_reason: string;
  created_by: string; created_at: string; updated_at: string;
  counts: Partial<Record<TargetState, number>>;
};
type Target = {
  deployment_id: string; package_id: string; endpoint_id: string; hostname: string; ring: number;
  state: TargetState; attempts: number; detail: string; exit_code: number; updated_at: string;
};
type DeploymentDetail = Deployment & { targets: Target[] };

type NewException = {
  endpoint_id: string; package_id: string; // "" = all packages
  owner: string; reason: string; compensating_controls: string; expires_at: string;
};
type Exception = NewException & {
  exception_id: string; created_by: string; created_at: string; revoked: boolean; active: boolean;
};

type AuditEvent = {
  seq: number; ts: string; actor: string; action: string; object_type: string; object_id: string;
  outcome: "success" | "failure"; package_id: string; details: Record<string, unknown>;
  prev_hash: string; hash: string;
};

type Assignment = {
  deployment_id: string; package_id: string; kind: "msu" | "msi"; kb: string; product_code: string;
  file_name: string; size: number; sha256: string;
  url: string;          // path on the same server origin, e.g. /api/agent/content/<sha256>
  manifest_url: string; // /api/agent/manifest/<package_id>
};

type AgentSetup = {
  trusted_keys: { key_id: string; public_key: string; sources: string[] }[]; // public_key is PEM
  tls: boolean; checkin_interval_seconds: number;
  agent_files: { name: string; size: number; sha256: string }[]; agent_dist_dir: string;
};

type LifecycleExport = {
  generated_at: string; package: Package; bundle: Bundle; deployments: DeploymentDetail[];
  exceptions: Exception[]; events: AuditEvent[]; audit_chain: { ok: boolean; count: number };
};
```

## v1.1 additions (roadmap B2–B10, C1–C8, D3)

### Authentication (B2)
| Method & path | Auth | Notes |
|---|---|---|
| `GET /auth/config` | none | → `{sso: bool, static_tokens: bool, require_mfa: bool}` — the login page shows "Sign in with SSO" when `sso` |
| `GET /auth/login?return=/path` | none | redirects to the IdP (OIDC + PKCE); on return sets the `offpatch_session` cookie (HttpOnly, SameSite=Strict) and redirects to `return`. On failure redirects to `/?login_error=<message>` |
| `POST /auth/logout` | session | → `{end_session_url?}` |
| `GET /api/me` | any | → `{user, role, source: "sso"|"token", mfa: bool}` |

Cookie-authenticated (SSO) requests that change state MUST send header `X-Offpatch-CSRF: 1`. The console should send it on every request and use `credentials: "same-origin"`. Bearer-token requests do not need it.

| Method & path | Role | Body → Response |
|---|---|---|
| `GET /api/users` | admin | → `User[]` |
| `POST /api/users/{username}/disable` · `/enable` | admin | `{reason}` → `{ok}` (disable revokes sessions) |
| `POST /api/endpoints/{id}/retire` | operator | `{reason}` → `Endpoint` (status `retired`) |
| `GET /api/maintenance-windows` | viewer | → `MaintenanceWindow[]` |
| `POST /api/maintenance-windows` | operator | `MaintenanceWindow` (without id/created_*) → `MaintenanceWindow` |
| `POST /api/maintenance-windows/{id}/delete` | operator | `{reason}` → `{ok}` |
| `GET /api/transfer/reconcile` | viewer | → `Reconciliation` |
| `GET /api/reports/compliance` | viewer | → `ComplianceReport` |
| `GET /api/reports/compliance.csv` · `/api/reports/endpoints.csv` | viewer | CSV download |
| `GET /api/alerts?open=1` | viewer | → `Alert[]` |
| `POST /api/alerts/{id}/ack` | operator | `{reason}` → `{ok}` |
| `GET /metrics` | `Bearer <metrics_token>` | Prometheus text |

Agent API additions: `POST /api/agent/renew {csr}` → `{certificate, ca_certificate}` (mTLS). The check-in response adds `reboot_now`, `download_rate_kbps`, `trust` (signed trust document) and, per assignment, `reboot_allowed` and `health_checks`.

```ts
type Me = { user: string; role: Role; source: "sso" | "token"; mfa: boolean };
type User = { username: string; role: Role; source: string; email: string; mfa: boolean; first_login: string;
  last_login: string; disabled: boolean; disabled_reason: string; active_sessions: number };

// Endpoint gains:
//   edition: string; cert_not_after: string; retired_at: string; retired_reason: string; reboot_requested_at: string
//   hardware: Hardware   (reported by the agent on check-in; '{}' until the first report; kept when an older agent sends none)
// type Hardware = { manufacturer?, model?, serial_number?, cpu?: string; cpu_cores?, memory_bytes?: number;
//   disks?: {mount: string; total_bytes: number; free_bytes: number}[]; ip_addresses?: string[]; mac_address?, boot_time?, logged_in_user?, timezone?: string }
// InventoryItem gains source?: "appstore" (macOS apps from the Mac App Store; never offered .pkg updates).
// EndpointStatus gains "retired". Summary.endpoints gains `retired: number` (retired endpoints are excluded from total/by_status).

// Package gains:
//   approvals: {by: string; reason: string; at: string}[]; approvals_required: number;
//   package_name: string; prerequisites: string[]; superseded_by: string;
//   applicability.editions?: string[];  kind: "msu"|"msi"|"deb"|"rpm"|"pkg"|"agent"
// Approve on a package needing 2 approvals returns it still "quarantined" with approvals.length 1.
// The same approver approving twice → 409. With separation_of_duties, an approver of a package
// cannot create its deployment (409).

type HealthCheck = { type: "service_running" | "tcp_listening"; name: string };
// NewDeployment / Deployment gain:
//   deadline: string;            // RFC 3339 or "" — after it, maintenance windows no longer hold installs back
//   max_concurrent: number;      // 0 = unlimited
//   reboot_policy: "never" | "in_window" | "at_deadline";
//   ignore_windows: boolean;
//   health_checks: HealthCheck[];
// Target gains: health: "" | "ok" | "failed"; health_detail: string

type MaintenanceWindow = { window_id: string; name: string; groups: string[]; days: ("mon"|"tue"|"wed"|"thu"|"fri"|"sat"|"sun")[];
  start: string; end: string; /* HH:MM in timezone; may cross midnight */ timezone: string; /* IANA */ allow_reboot: boolean;
  created_by: string; created_at: string };

type TransferReceipt = { id: number; file: string; file_sha256: string; size: number; adapter: string; sent_at: string;
  received_at: string; key_id: string; signature_ok: boolean };
type Reconciliation = { matched: TransferReceipt[]; receipt_without_bundle: TransferReceipt[];
  bundle_without_receipt: Bundle[]; unsigned_or_invalid_receipts: number };

type SeverityStats = { targets: number; verified: number; outstanding: number; overdue: number; exceptions: number; pct_compliant: number };
type PackageReport = { package_id: string; title: string; severity: string; state: string; release_date: string; deadline: string;
  received_at: string; approved_at: string; first_verified_at: string; p90_verified_at: string;
  targets: number; verified: number; outstanding: number; overdue: number; exceptions: number; pct_compliant: number;
  days_release_to_received: number; days_received_to_approved: number; days_approved_to_first_verified: number;
  days_release_to_90pct_verified: number /* -1 = not reached */ };
type ComplianceReport = { generated_at: string; deadlines: Record<string, string>; by_severity: Record<string, SeverityStats>;
  packages: PackageReport[];
  fleet: { total: number; reporting: number; offline: number; stale: number; pending_reboot: number; pct_reporting: number };
  exceptions: { active: number; expiring_in_7d: number; oldest_age_days: number };
  intake: { validated: number; rejected: number } };

type Alert = { id: number; created_at: string; severity: "info" | "warning" | "critical"; kind: string; message: string;
  object_type: string; object_id: string; acknowledged_by: string; acknowledged_at: string };
// kind: deployment_auto_paused, signing_key_compromised, audit_export_failed (critical);
//       install_failed, health_check_failed, bundle_rejected, trust_rejected, intake_rate_limited,
//       endpoints_offline, inventory_stale, cert_expiring (warning; client certificate expires within 14 days);
//       exception_expiring (info; within 7 days).
// Alerts at or above notify.min_severity (default "warning") are also delivered, from inside the
// isolated zone only, to notify.smtp {addr, from, to[]} and/or notify.webhook_url (JSON POST of the
// Alert; header "Authorization: Bearer <notify.webhook_token>" when webhook_token is set).
// Failed deliveries are retried at the next sweep (alert_sweep_interval).

// AgentSetup gains: ca_certificate: string (PEM; "" in lab mode) — offer "Download ca.pem" and add `-ca` to commands when present.
```

## v1.2 additions — install safety (docs/03-state-model.md)

```ts
// Pre-install deferral. Agent-reportable states gain "deferred": a pre-install check (free disk
// space, battery) was not met; retried at every check-in, never counted as a failure.
// Check-in response gains:
//   preinstall: { min_free_disk_mb: number; min_battery_pct: number }   // for this endpoint's OS
// The agent needs max(2 × package size, min_free_disk_mb) free on the system volume and on its
// cache directory, and AC power or ≥ min_battery_pct (0 = no battery check). Agents talking to an
// older server use built-in defaults (windows 5120, macos 2048, linux 1024 MB; battery 40%).

// Lost endpoints. TargetState gains "lost_after_install" (server only): the endpoint reported
// installed / pending_reboot and has not checked in (nor reported on any target) for
// lost_after_install (default 2h) since that report or its reboot request. Counts towards the
// ring's max_failure_pct; raises a critical alert kind "lost_after_install" (object = deployment,
// message names every lost host; updated and re-sent while open). Check-in recovers it
// (verified, or back to pending_reboot / installed).
// EndpointStatus gains "lost_after_install" (highest precedence after "retired").

// Rollback. NewDeployment gains:
//   operation?: "install" | "rollback";     // default "install"; "rollback" requires justification
// Rollback is accepted for approved or revoked packages of kind msu (needs kb), msi (needs
// product_code), deb/rpm (needs package_name); otherwise 409 "rollback not supported for …".
// 409 while an active/paused deployment of the same package with the other operation exists.
// Deployment, Target gain operation: "install" | "rollback".
// Package gains rollback_unsupported: string ("" = supported; else why, e.g. macOS .pkg).
// Assignment gains operation?: "rollback" (url is "": nothing is downloaded; the agent verifies
// the signed manifest and runs wusa /uninstall /kb:N, msiexec /x {ProductCode}, dpkg -r or rpm -e).
// Rollback targets reuse the install states; "installed" = uninstaller succeeded, "verified" =
// fresh inventory no longer shows the package. Endpoints whose inventory does not show it (deb/rpm:
// at exactly this version) are not_applicable.
// TargetState gains "rolled_back" (server only): set on install targets of the same package and
// endpoint when a rollback is verified there; reports no longer count them as patched.
// Revoking a package cancels its install deployments only; rollback deployments keep running.
// Audit actions: deployment.created_rollback, target.deferred, target.lost_after_install, target.rolled_back.
```

## v1.3 additions — acquisition requests (docs/08-acquisition.md)

| Method & path | Role | Body → Response |
|---|---|---|
| `POST /api/acquisition-requests` | operator | `{apps: string[] (winget ids), kbs: string[]}` → `AcquisitionRequest` as a JSON attachment. 400 if nothing is selected, more than 500 items are selected, or an item is not currently needed by any endpoint; 409 without usable update intelligence. Audited as `acquisition.request_exported` (`details`: `apps` as `id@version`, `kbs` as `KB/arch`, `intel_generated_at`). |

Behaviour:
- The server builds the file only from its own fleet view (`GET /api/updates`), never from text supplied by the client.
- `AcquisitionRequest` is the `internal/acqrequest` format.
- `GET /api/updates` and `GET /api/endpoints/{id}/updates` now also link an app to a catalog MSI by normalised `package_name` when that package is newer than the installed version (product code first).

## v1.4 additions — UX iteration (docs/proposals/ux-api-contract.md)

TypeScript shapes: `web/src/types.ts`, section "UX iteration" (`Policy`, `PackageFleet`,
`EndpointMissing`, `FleetStatus*`, `AcquisitionRequest*`, `TargetLive`).

| Method & path | Role | Body → Response |
|---|---|---|
| `GET /api/policy` | viewer | → `Policy`: `approvals_required` and `deadlines` (Go duration strings, e.g. `"168h0m0s"`) for `critical`, `important`, `moderate`, `low` with defaults filled in, and `separation_of_duties`. |
| `GET /api/packages-needs` | viewer | → `Record<package_id, PackageFleet>` for the newest approved **and quarantined** version of each product (superseded KBs and older versions are left out, as before). Every applicable, non-retired endpoint with inventory is counted in exactly one of `needed` (unchanged: `endpoint_ids`, `hostnames`), `up_to_date` (present, superseded, newer, or otherwise not needed) and `not_installed` (third-party app not on it). Per endpoint, from install deployments: `verified` (verified in any deployment) else `deploying` (pending … pending_reboot or deferred in an active/paused deployment) else `failed` (failed / lost_after_install, deployment not cancelled); `exception` = active exceptions for the package or for all packages. These may overlap with `needed`. `active_deployment_id`: newest active or paused install deployment ("" if none). Cached for 60 s; rebuilt at once after a change that affects it (approve/reject/revoke, deployment create/action/retry, exceptions, bundle intake, enrolment/retirement, check-ins that change inventory); state changes from agent reports show within the 60 s. |
| `GET /api/endpoints`, `GET /api/endpoints/{id}` | viewer | Each endpoint gains `missing: {os, apps, ready}`: `os`/`apps` = Windows updates / newer app versions the update intelligence says it lacks (cached fleet view), `ready` = approved catalog packages it needs. `null` for retired endpoints, and when there is no usable intelligence and `ready` is 0; without intelligence but `ready` > 0: `{os: 0, apps: 0, ready}`. The list does not parse inventories per request: `missing` comes from the cached fleet view and package needs (same caching as `/api/packages-needs`). |
| `GET /api/fleet/status` | viewer | → `FleetStatus`: one row per KB / app of the intelligence fleet view, including KBs and apps every matched endpoint already has. Per endpoint `status` by precedence `exception` > `failed` > `being_patched` > `verified` > `outdated` > `up_to_date`, from the row's catalog package (the update's package; for rows without one, the package of the installed version) and its install targets and active exceptions. `requested`: latest tracked request listing it. By default every row has its counts and `endpoints: []`. **`?key=<KB or winget id>[&kind=os\|app]`** (key case-insensitive; kind optional): `rows` holds only that row, with its full `endpoints` list; 404 if there is no such row, 400 for another `kind` or `kind` without `key`. Cached like `/api/updates` (60 s, and rebuilt after the changes listed for `/api/packages-needs`; one rebuild at a time). `rows: []` without intelligence. |
| `GET /api/updates` | viewer | rows gain `requested: AcquisitionRequestRef \| null` (latest tracked request listing the KB / winget id). |
| `POST /api/acquisition-requests` | operator | Unchanged response; the request is also stored (table `acq_requests`) in the same transaction as its audit event. |
| `GET /api/acquisition-requests` | viewer | → `AcquisitionRequestRecord[]`, newest first, at most 100. Items: `{kind: "app", key: winget id, version}` per app and `{kind: "kb", key: KB, version: architecture}` per KB and architecture. `seen_at`: `received_at` of the first acquisition status report with a `request` feed naming the request id. An item is `fulfilled` when a validated bundle received at or after the request's `created_at` holds `<KB>-<arch>`, or pmctl's package id for the app version (`<winget id>-<version>[-<arch>]`, hash-suffixed form included); then `package_id` and `fulfilled_at` (`received_at` of the earliest such bundle; a later bundle that carries an already-imported package again counts) are set. A package that was already in the catalog before the request does not fulfil it. Otherwise `seen` once the request was seen, else `requested`. For a KB requested for several architectures, `requested` refs take the least advanced status. Computed on read. |
| `POST /api/deployments/{id}/retry_failed` | operator | `{reason}` (required) → `Deployment`. Targets in **every ring up to the current ring** in state `failed` with retries exhausted (`attempts > max_retries`) go back to `pending` with `attempts` 0. The deployment must be `active`, `paused` or `completed`: a paused one stays paused (an operator resumes it); a completed one becomes `active` again with `state_reason` `retry requested by <actor>: <reason>` (an install deployment only while its package is still approved). 409 for other states, an unapproved package, or when nothing is to retry ("no failed targets with exhausted retries in rings up to the current ring"). Audited as `deployment.retry_failed` (`details`: `reason`, `ring`, `state` before the retry, `targets` with their ring and last attempts / detail). The failure threshold is then re-checked as after a failure (remaining health-check failures or lost endpoints can auto-pause it again). |
| `GET /api/deployments/{id}` | viewer | each target gains `live: TargetLive \| null` (see heartbeat). |

Agent API:

| Method & path | Auth | Body → Response |
|---|---|---|
| `POST /api/agent/checkin` | device | Response gains `next_checkin_seconds`: `10` while the endpoint has work it can act on now (an assignment handed out in this check-in other than a deferred one, a target downloading … installing in an active deployment's reached ring, or `installed` for less than 10 minutes without a state change, or a reboot requested in this check-in — i.e. `reboot_now`, at most every 30 minutes), or when an active deployment that includes its groups was created, advanced, resumed or retried in the last 2 minutes; otherwise `0` (use `checkin_interval_seconds`). Agents wait `clamp(next ± 20 % jitter, 5, configured)`; older agents ignore the field. |
| `POST /api/agent/heartbeat` | device | Optional body `{"progress": {deployment_id, package_id, stage, pct, bytes_done, bytes_total}}` → **204**. No body or `{}` (older agents) is still valid; unknown fields are ignored. `stage`: `downloading` \| `verifying` \| `installing` \| `waiting_reboot`; `pct` -1..100; sizes ≥ 0; ids ≤ 128 characters (else 400). Progress for a deployment / package the endpoint has no target in is ignored. Kept in memory per endpoint and deployment (not stored, not audited); shown as `Target.live` while the target is downloading, downloaded, installing or pending_reboot, for at most 10 minutes after the last heartbeat. |
