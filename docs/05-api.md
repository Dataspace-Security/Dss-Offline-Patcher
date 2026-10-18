# 05 — HTTP API contract (v1)

All bodies are JSON and all times are RFC 3339 UTC. Errors return `{"error": "message"}` with status 400/401/403/404/409/500.

## Admin API — `Authorization: Bearer <admin token>`

Roles are cumulative: `viewer` < `user` < `admin` < `super_admin` (v1.8; `operator` and `approver` are accepted as `user`). The Role column below is the v1.8 minimum; see "v1.8 additions" for what changed.

| Method & path | Role | Body → Response |
|---|---|---|
| `GET /api/me` | viewer | → `{user, role}` |
| `GET /api/summary` | viewer | → `Summary` |
| `GET /api/bundles` | viewer | → `Bundle[]` (newest first) |
| `GET /api/bundles/{id}` | viewer | → `Bundle` (`id` = numeric intake id) |
| `GET /api/packages?state=` | viewer | → `Package[]` |
| `GET /api/packages/{package_id}` | viewer | → `Package` |
| `POST /api/packages/{package_id}/approve` | user | `{reason}` → `Package` |
| `POST /api/packages/{package_id}/reject` | user | `{reason}` → `Package` |
| `POST /api/packages/{package_id}/revoke` | admin | `{reason}` → `Package` |
| `GET /api/endpoints` | viewer | → `Endpoint[]` |
| `GET /api/endpoints/{endpoint_id}` | viewer | → `EndpointDetail` |
| `PATCH /api/endpoints/{endpoint_id}` | user | `{groups?, site?, owner?, criticality?}` → `Endpoint` |
| `POST /api/enrollment-tokens` | user | `{groups: string[], site, expires_in_hours, max_uses?}` → **201** `{token, expires_at, max_uses}` (the token is shown **once**). `max_uses` default 1, at most 10000. `expires_in_hours` default 24, at most 720; tokens with `max_uses` > 1 at most 336 (14 days). There is no API to revoke a token. |
| `GET /api/agent-setup` | viewer | → `AgentSetup` (signing keys agents should pin — from the latest verified trust document, else `trusted_keys` in the config — and staged agent binaries) |
| `GET /api/agent-setup/files/{name}` | viewer | → file from `<data_dir>/agent-dist/` (e.g. `pmagent.exe`) |
| `GET /api/deployments` | viewer | → `Deployment[]` |
| `POST /api/deployments` | user | `NewDeployment` → `Deployment` |
| `GET /api/deployments/{deployment_id}` | viewer | → `DeploymentDetail` |
| `POST /api/deployments/{deployment_id}/pause` | user | `{reason}` → `Deployment` |
| `POST /api/deployments/{deployment_id}/resume` | user | `{reason}` → `Deployment` |
| `POST /api/deployments/{deployment_id}/cancel` | user | `{reason}` → `Deployment` |
| `POST /api/deployments/{deployment_id}/advance` | user | `{reason}` → `Deployment` |
| `GET /api/exceptions` | viewer | → `Exception[]` |
| `POST /api/exceptions` | admin | `NewException` → `Exception` |
| `POST /api/exceptions/{exception_id}/revoke` | admin | `{reason}` → `Exception` |
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
| `POST /api/endpoints/{id}/retire` | user | `{reason}` → `Endpoint` (status `retired`) |
| `GET /api/maintenance-windows` | viewer | → `MaintenanceWindow[]` |
| `POST /api/maintenance-windows` | user | `MaintenanceWindow` (without id/created_*) → `MaintenanceWindow` |
| `POST /api/maintenance-windows/{id}/delete` | user | `{reason}` → `{ok}` |
| `GET /api/transfer/reconcile` | viewer | → `Reconciliation` |
| `GET /api/reports/compliance` | viewer | → `ComplianceReport` |
| `GET /api/reports/compliance.csv` · `/api/reports/endpoints.csv` | viewer | CSV download |
| `GET /api/alerts?open=1` | viewer | → `Alert[]` |
| `POST /api/alerts/{id}/ack` | user | `{reason}` → `{ok}` |
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
| `POST /api/acquisition-requests` | user | `{apps: string[] (winget ids), kbs: string[]}` → `AcquisitionRequest` as a JSON attachment. 400 if nothing is selected, more than 500 items are selected, or an item is not currently needed by any endpoint; 409 without usable update intelligence. Audited as `acquisition.request_exported` (`details`: `apps` as `id@version`, `kbs` as `KB/arch`, `intel_generated_at`). |

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
| `POST /api/acquisition-requests` | user | Unchanged response; the request is also stored (table `acq_requests`) in the same transaction as its audit event. |
| `GET /api/acquisition-requests` | viewer | → `AcquisitionRequestRecord[]`, newest first, at most 100. Items: `{kind: "app", key: winget id, version}` per app and `{kind: "kb", key: KB, version: architecture}` per KB and architecture. `seen_at`: `received_at` of the first acquisition status report with a `request` feed naming the request id. An item is `fulfilled` when a validated bundle received at or after the request's `created_at` holds `<KB>-<arch>`, or pmctl's package id for the app version (`<winget id>-<version>[-<arch>]`, hash-suffixed form included); then `package_id` and `fulfilled_at` (`received_at` of the earliest such bundle; a later bundle that carries an already-imported package again counts) are set. A package that was already in the catalog before the request does not fulfil it. Otherwise `seen` once the request was seen, else `requested`. For a KB requested for several architectures, `requested` refs take the least advanced status. Computed on read. |
| `POST /api/deployments/{id}/retry_failed` | user | `{reason}` (required) → `Deployment`. Targets in **every ring up to the current ring** in state `failed` with retries exhausted (`attempts > max_retries`) go back to `pending` with `attempts` 0. The deployment must be `active`, `paused` or `completed`: a paused one stays paused (an operator resumes it); a completed one becomes `active` again with `state_reason` `retry requested by <actor>: <reason>` (an install deployment only while its package is still approved). 409 for other states, an unapproved package, or when nothing is to retry ("no failed targets with exhausted retries in rings up to the current ring"). Audited as `deployment.retry_failed` (`details`: `reason`, `ring`, `state` before the retry, `targets` with their ring and last attempts / detail). The failure threshold is then re-checked as after a failure (remaining health-check failures or lost endpoints can auto-pause it again). |
| `GET /api/deployments/{id}` | viewer | each target gains `live: TargetLive \| null` (see heartbeat). |

Agent API:

| Method & path | Auth | Body → Response |
|---|---|---|
| `POST /api/agent/checkin` | device | Response gains `next_checkin_seconds`: `10` while the endpoint has work it can act on now (an assignment handed out in this check-in other than a deferred one, a target downloading … installing in an active deployment's reached ring, or `installed` for less than 10 minutes without a state change, or a reboot requested in this check-in — i.e. `reboot_now`, at most every 30 minutes), or when an active deployment that includes its groups was created, advanced, resumed or retried in the last 2 minutes; otherwise `0` (use `checkin_interval_seconds`). Agents wait `clamp(next ± 20 % jitter, 5, configured)`; older agents ignore the field. |
| `POST /api/agent/heartbeat` | device | Optional body `{"progress": {deployment_id, package_id, stage, pct, bytes_done, bytes_total}}` → **204**. No body or `{}` (older agents) is still valid; unknown fields are ignored. `stage`: `downloading` \| `verifying` \| `installing` \| `waiting_reboot`; `pct` -1..100; sizes ≥ 0; ids ≤ 128 characters (else 400). Progress for a deployment / package the endpoint has no target in is ignored. Kept in memory per endpoint and deployment (not stored, not audited); shown as `Target.live` while the target is downloading, downloaded, installing or pending_reboot, for at most 10 minutes after the last heartbeat. |

## v1.5 additions — direct hand-off of acquisition requests

| Method & path | Role | Body → Response |
|---|---|---|
| `POST /api/acquisition-requests` | user | Response gains `queued_to: string`. With `acquisition_requests_dir` set in `pmserver.json`, the request document is also written there as `<dir>/<request_id>.json` (temp file + fsync + rename, mode 0640) and `queued_to` is that directory. `""` when the key is unset, or when the write failed: the response is still 200 with the document (the operator carries the file), the error is logged and the audit event's `details` gain `queued_error`. `details.queued_to` is always recorded. |

Behaviour:
- The queued file is exactly the request document, i.e. the response **without** `queued_to` (`pmctl` parses strictly, so the console strips `queued_to` before saving the file).
- The file is written before the audit event; if the event cannot be recorded the file is removed again and the request fails (no audit record, no export).
- `acquisition_requests_dir` must be an absolute path (config load fails otherwise). If it is not writable at startup, pmserver logs a warning and keeps running; exports then fall back to the carried file.
- Production with separate server and acquisition hosts keeps it **unset** (strict one-way transfer). Set it only when acquisition runs on the same machine (`install-ubuntu.sh --role all` does) or the organisation approved an outbound folder. See [07-admin-guide.md](07-admin-guide.md) §3.9 and [08-acquisition.md](08-acquisition.md).

## v1.6 additions — P1 fixes (honest status, auto-advance, import results)

| Method & path | Role | Body → Response |
|---|---|---|
| `POST /api/deployments` | user | `NewDeployment` gains `auto_advance: boolean` (default `false`), echoed on `Deployment`. When the current ring is finished within `max_failure_pct` and is not the last ring, the deployment advances by itself (audited `deployment.advanced`, actor `system:scheduler`, `details.auto: true`); see [03-state-model.md](03-state-model.md). A second **active or paused** deployment of the same package and operation is refused with **409** ("already running; open it, wait for it to finish, or cancel it first"). |
| `GET /api/endpoints`, `GET /api/endpoints/{id}`, `GET /api/reports/endpoints.csv` | viewer | `status` may also be `updates_available` (would be `compliant`, but `missing.os + missing.apps > 0`), `out_of_support` (would be `compliant` or `updates_available`, but `missing.os_support` is `out_of_support`) and `awaiting_checkin` (enrolled < 24 h ago, no inventory yet; after 24 h `offline`). `missing` gains `os_support` (`supported` \| `out_of_support` \| omitted) and `os_last_update` (date of the build's newest cumulative update). |
| `GET /api/summary` | viewer | `endpoints.by_status` has a key for every status, including `updates_available`, `out_of_support` and `awaiting_checkin`; the same refined statuses as the endpoint list (so `compliant` no longer counts machines the intelligence says are behind). The `offpatch_endpoints` metric uses the same counts. |
| `GET /api/acquisition-requests` | viewer | Item `status` may also be `unsupported` (can never be fetched this way: no MSI installer for the architecture, no ProductCode, version no longer in winget, KB not in the catalog for the build/arch) or `failed` (transient: download, hash, network — the next run may work), with `reason`. Taken from the **newest** acquisition status report whose `items` list that request id + kind + key + version (key and version case-insensitive); `fetched` / `already_sent` there mean `seen`. `fulfilled` (the package arrived) wins over both. |
| `GET /api/updates`, `GET /api/fleet/status`, `GET /api/endpoints/{id}/updates` | viewer | `requested` (`AcquisitionRequestRef`) gains `reason` (for `unsupported` / `failed`); status rank for a KB requested for several architectures: `requested` 0, `seen` / `failed` / `unsupported` 1, `fulfilled` 2 (least advanced wins; on a tie the one with a reason). `GET /api/endpoints/{id}/updates` rows (`os[]`, `apps[]`) now carry `requested` too. |

```ts
type EndpointStatus = "compliant" | "updates_available" | "out_of_support" | "noncompliant" | "pending_reboot" | "failed"
  | "exception" | "stale" | "offline" | "lost_after_install" | "awaiting_checkin" | "retired";
type AcquisitionRequestRef = { request_id: string; at: string; status: "requested" | "seen" | "unsupported" | "failed" | "fulfilled"; reason?: string };
// Acquisition status report (signed, from pmctl auto): Report gains
type ItemResult = { request_id: string; kind: "app" | "kb"; key: string; version: string /* app version | KB arch */;
  result: "fetched" | "already_sent" | "unsupported" | "failed"; reason?: string; package_id?: string };
// Report.items?: ItemResult[]
```

Server behaviour without new endpoints (details in [03-state-model.md](03-state-model.md)):
- **Import again**: a `rejected` package delivered again in a validated bundle returns to `quarantined` (`package.reimported`); a `revoked` one stays revoked and is listed as a skipped duplicate.
- **Restart needed**: a `pending_reboot` target whose `reboot_policy` can never restart it (no maintenance window allows reboots; for `at_deadline`, before the deadline) has detail `installed; waiting for a restart: no maintenance window allows automatic restarts (restart the machine or add a window)`.
- **Installer busy**: `failed` reports with detail prefix `retry later: installer busy` are not counted as attempts for the first 10 in a row per target (detail `waiting: another installation is running on this machine (try N)`).
- **Static tokens**: `allow_static_tokens` defaults to `true` with or without `oidc`; pmserver logs one line at startup saying which sign-in methods work (a warning when `admin_tokens` are configured but disabled).

## v1.7 additions — P2 (Library, imports tracking, alerts that close themselves, evidence)

| Method & path | Role | Body → Response |
|---|---|---|
| `GET /api/library?q=&kind=app\|os&view=available\|installed\|catalog\|all&publisher=&sort=installed\|name\|date&page=1&per_page=50` | viewer | → `LibraryPage` (below). One searchable list of everything the update intelligence knows: winget apps (`kind: "app"`) and Windows cumulative updates (`kind: "os"`, one row per KB). `q`: words (case-insensitive, all must match) over name, id, publisher and MSI product codes. `publisher`: exact publisher, case-insensitive. `view`: `available` (default: `importable` = `yes` or installed in the fleet), `installed` (installed on at least one endpoint), `catalog` (has a catalog package), `all`. `sort`: `installed` (default: installed endpoints, then name), `name`, `date` (release date for KBs, `resolved_at` for apps; newest first). `per_page` is capped at 100. 400 for other `kind` / `view` / `sort` values or a page / per_page < 1. Without usable intelligence: `total: 0, items: []`. |
| `GET /api/library/{kind}/{id}` | viewer | → `LibraryItem` plus `endpoints: [{endpoint_id, hostname, installed_version, outdated}]` (sorted by hostname; for a KB: endpoints on its build, `installed_version` = their `os_version`). `id` is case-insensitive. 404 when not in the Library or without usable intelligence. |
| `POST /api/acquisition-requests` | user | Body gains `app_archs: {"<winget id>": "x64" \| "x86" \| "arm64"}`. Apps and KBs that no endpoint needs are now accepted when they are in the update intelligence (a Library import): an app is written with `architectures: [app_archs[id] or "x64"]`, `endpoints: 0` and no installed forms; a KB with every architecture the intelligence lists for it and `endpoints: 0`. `app_archs` is ignored for apps installed in the fleet (they keep the fleet's architectures). 400 for an architecture other than x64 / x86 / arm64, more than 500 `app_archs` entries, or an item that is not in the intelligence ("not in the update intelligence (reload the page): …"). |
| `GET /api/acquisition-requests` (and every `requested` ref) | viewer | Item `status` may also be `stale` with `reason` `the acquisition run at <finished_at> did not pick this request up`: the item is still `requested` / `seen`, and the **newest** acquisition status report (by `finished_at`), finished more than 10 min after the request's `created_at`, lists the request id neither in a `request` feed nor in `items`. An item with a `fetched` / `already_sent` result is on its way and never stale; `fulfilled` wins. Rank for `requested` refs: `stale` 0 (like `requested`). The console shows it as "Not picked up" with "Ask again". |
| `GET /api/summary` | viewer | Gains `intel: {generated_at, age_hours, stale} \| null` (null: no intelligence received). `stale`: older than 8 days. |
| `GET /api/endpoints`, `GET /api/endpoints/{id}` | viewer | `missing` gains `catalog`: approved **or quarantined** catalog packages the endpoint needs (`ready` counts the approved ones). `status` `updates_available` now also applies when `missing.catalog` > 0, so "fully up to date" means `os`, `apps` and `catalog` all 0. Without intelligence `missing` is set when `catalog` > 0. |
| `GET /api/alerts` | viewer | Each alert gains `details` (object, e.g. `{endpoint_ids: string[], hostnames: string[]}` for alerts about endpoints; omitted when empty), `resolved_at` and `resolved_by` (set when the condition cleared and the alert closed itself; `acknowledged_by` / `acknowledged_at` are then `system:scheduler` and that time). `?open=1` excludes resolved alerts. |
| `GET /api/reports/compliance`, `compliance.csv` | viewer | Per package: `needed` (endpoints whose inventory says they need it) and `not_targeted` (needed, no install target, no active exception). `targets` (the denominator) and `outstanding` now include `not_targeted` (and `overdue` past the deadline); needed endpoints with an active exception count in `exceptions`. A package is listed when it is approved, has targets, or is needed. The CSV gains the columns `needed`, `not_targeted` (last). |
| `GET /api/reports/targets.csv` | viewer | Evidence per endpoint: one row per target of every install deployment that is not cancelled, by hostname: `endpoint, hostname, package_id, title, state, verified_at, evidence, approved_by, deployment_id`. `evidence`: the inventory line that verified it (`product {GUID} "Name" 1.2.3 (user)`, `kb KB5044280`, …) or `os_version build 26300.9711` for a UBR verification; for targets verified before P2, the verification detail. `approved_by`: approvers, `; `-separated. Audited as `report.exported` (`targets.csv`); formula characters are neutralised as in the other CSVs. |

```ts
type LibraryPage = { source: string; generated_at: string; total: number; page: number; per_page: number; items: LibraryItem[] };
type LibraryItem = {
  kind: "app" | "os"; id: string /* winget id | KB */; name: string; publisher: string; latest_version: string /* KB: "<build>.<ubr>" */;
  description: string; links: { homepage: string; publisher_url: string; manifest: string } /* "" when unknown or unsafe */;
  installers: { arch: string; type: string; scope?: string; url: string; sha256?: string; product_code?: string }[] | null /* null: not resolved */;
  resolved_at: string; importable: "yes" | "no" | "unknown"; importable_reason: string;
  installed: { endpoints: number; outdated: number }; catalog: { package_id: string; state: string } | null;
  requested: AcquisitionRequestRef | null };
type AcquisitionRequestRef = { request_id: string; at: string; status: "requested" | "seen" | "stale" | "unsupported" | "failed" | "fulfilled"; reason?: string };
type Alert = { /* … */ details?: { endpoint_ids?: string[]; hostnames?: string[]; [k: string]: unknown }; resolved_at?: string; resolved_by?: string };
type IntelAge = { generated_at: string; age_hours: number; stale: boolean };
```

Library behaviour:
- Data: `intel.Doc.apps` and `windows`, plus the new signed `resolved` section (`[{id, version, publisher, homepage, publisher_url, license, description, installers: [{arch, type, scope, url, sha256, product_code}], resolved_at}]`, filled by pmctl). The entry for the app's latest version is used, else the newest version resolved.
- **Importable rule** (`intel.Importable`, the same rule pmctl uses): `yes` when a resolved installer for the fleet's architectures of the app (any architecture when it is installed nowhere; `neutral` always counts) has type `msi` or `wix` (the MSI ProductCode is known, or read from the MSI at import); `no` with a reason otherwise (`EXE installer only (nullsoft)`, `no MSI installer (msix)`, `no installer for x64 (only arm64)`, …); `unknown` when not resolved yet. Windows rows are always `yes`.
- `installed` comes from the cached fleet view: endpoints with the app (or on the KB's build) and, of those, how many are outdated. `catalog`: the fleet view's catalog link, else pmctl's package id for the latest version (`<winget id>-<version>[-<arch>]`), else (KBs) the catalog package for the KB.
- `links.manifest`: `https://github.com/microsoft/winget-pkgs/tree/master/manifests/<first letter of the id, lower case>/<id segments split on ".">/<version>`. KBs: `links.homepage` = `https://www.catalog.update.microsoft.com/Search.aspx?q=<KB>`.
- **Untrusted text**: links (and installer URLs) are returned only when they are absolute `https` URLs of at most 2048 bytes without whitespace, control or non-ASCII characters, quotes, angle brackets or credentials; anything else becomes `""`. Names and publishers (≤ 200 bytes) and descriptions (≤ 1000 bytes) have control and bidi-override characters removed and whitespace collapsed; `sha256` / `product_code` are dropped unless well-formed. Nothing in the Library is ever fetched or used by the server or agents.
- Search keys and static fields are built once per intelligence generation (one build at a time); a request scans the entries linearly (~16k apps).

Server behaviour without new endpoints (details in [03-state-model.md](03-state-model.md)):
- **Condition alerts close themselves.** `endpoints_offline`, `inventory_stale`, `out_of_support` (new, fleet), `install_unverified` (new, per deployment) and `lost_after_install` name up to 5 hostnames, then `+N more`, and carry `details.endpoint_ids`; while open, message and details follow the current hosts (not delivered again). They, and `install_failed` once the target verified, `health_check_failed` once health checks pass, `cert_expiring` once renewed, `acquisition_stale` once a report arrives and `intel_stale` (new) once fresh intelligence arrives, are resolved by the sweep (`system:scheduler`, audited `alert.resolved` with `alert_id`, `object_id`, `reason`).
- **`intel_stale`** (warning): the intelligence is older than 8 days. **`out_of_support`** (warning): endpoints on a Windows build Microsoft no longer updates.
- **`install_unverified`** (warning): a target `installed` for more than 6 h without inventory confirming it keeps its state with detail `installed but not confirmed by inventory after 6 h` (audited `target.install_unverified`), counts toward the ring's failure threshold, and one alert per deployment names the hosts.
- **LCU verification by UBR**: `manifest.Package` gains `expected_ubr` (msu only, optional, omitted when 0). A target verifies when the endpoint's build equals the package's `min_build` and the UBR parsed from `os_version` (`"(26300.9711)"`) is ≥ `expected_ubr`, even if the KB is not in inventory. Verified targets keep their evidence (`Target.evidence`, and `[<evidence>]` appended to the detail).
- **Per-user installs**: `InventoryItem.scope` (`"user"` for installs found in loaded user hives; omitted for machine-wide) is counted like a machine-wide install for needs, targeting and verification.
- **Health checks after the restart**: an agent report `{state: "installed", health: "ok" | "failed", health_detail}` for a target that is already `verified` records only the health result (no 409; the state stays `verified`; a failure raises `health_check_failed` and counts toward the threshold; a pass is audited `target.health_ok`). Any health `ok` closes an open `health_check_failed` alert of that target.

## v1.8 additions — roles, two-person deployment approval, local users

### Roles

Roles are cumulative: `viewer` (1) < `user` (2, bank) < `admin` (3, bank) < `super_admin` (4, vendor).
Older names stay accepted everywhere a role is configured (`admin_tokens`, `oidc.role_groups`, stored
sessions): `operator` and `approver` mean `user`. API responses always use the new names.

| Role | Can do (in addition to the roles below it) |
|---|---|
| `viewer` | Every `GET` above except `/api/users` (no secrets). |
| `user` | Acquisition requests; create deployments and rollbacks (they start `pending_approval`); approve / reject deployments and rollbacks (not their own); approve / reject packages; acknowledge alerts; maintenance windows; enrollment tokens; edit and retire endpoints; pause / resume / cancel / advance / retry deployments. |
| `admin` | Users: create, disable / enable, reset password, change role for `viewer`, `user` and `admin` (never `super_admin`); create and revoke exceptions; revoke packages. |
| `super_admin` | Everything, including managing `super_admin` accounts. **Not** a deployment approver (the vendor does not approve bank changes). |

The route table is the security boundary: the console hides what a role cannot do, the API refuses
it with **403** `requires role <role>` (audited `access.denied`). Role changes in the table above
compared with v1.7: package approve / reject `approver` → `user`; package revoke and exceptions
`approver` → `admin`.

### Deployment and rollback approval

| Method & path | Role | Body → Response |
|---|---|---|
| `POST /api/deployments` | user | Unchanged body. The deployment is created in state **`pending_approval`** (install, rollback and emergency alike) with **no targets**: nothing is dispatched until it is approved. A pending deployment counts as running for the one-running-per-package-and-operation rule (409). Raises an `info` alert `deployment_awaiting_approval`. |
| `POST /api/deployments/{id}/approve` | user | `{reason}` (required) → `Deployment`. 403 unless the caller's role is `user` or `admin`; 409 for the creator ("you created this deployment; N other people must approve it"), for a second approval by the same person, or when the deployment is not `pending_approval`. Audited `deployment.approved` (`details`: `reason`, `approvals`, `approvals_required`, `operation`, `role`). The approval that reaches `approvals_required` activates the deployment: state `active`, `activated_at` set, `state_reason` `approved by A and B`, targets created and evaluated, audited `deployment.activated` (`details.approved_by`: both names), the alert closes itself. |
| `POST /api/deployments/{id}/reject` | user | `{reason}` (required) → `Deployment`. Same eligibility rules as approve (not the creator: the creator cancels instead). State **`rejected`** (final), `rejected_by`, `rejected_at`, and `state_reason` = the reason. Audited `deployment.rejected`; the alert closes itself. |
| `POST /api/deployments/{id}/cancel` | user | Also from `pending_approval` (the creator may cancel their own). |
| `GET /api/policy` | viewer | Gains `deployment_approvals: number`. |

`pmserver.json` → `deployment_approvals` (default **2**, 1–5): different people who must approve each
deployment and rollback. The count is fixed on the deployment when it is created
(`approvals_required`). Deadlines are absolute times; windows and assignments only apply once the
deployment is `active`.

```ts
// Deployment gains:
//   approvals: {by: string; at: string; reason: string}[]   // by = "user:<name>"
//   approvals_required: number    // 0 = created before approvals existed
//   rejected_by: string; rejected_at: string; activated_at: string
// DeploymentState: "pending_approval" | "active" | "paused" | "completed" | "cancelled" | "rejected"
// Summary.deployments gains pending_approval and rejected counts.
```

### Local users (email + password)

| Method & path | Auth / role | Body → Response |
|---|---|---|
| `GET /auth/config` | none | Gains `password_login: bool` (false when `require_mfa` is set: a password alone is one factor). |
| `POST /api/auth/login` | none | `{email, password}` → `{user, email, role, auth: "password", must_change_password}` and the `offpatch_session` cookie (same session as SSO: `session_ttl`, `HttpOnly`, `SameSite=Strict`, `Secure` over TLS). Needs header `X-Offpatch-CSRF: 1`. **401** `wrong email or password` for an unknown email, a wrong password **and** a locked account (no enumeration; the same work is done in every case). 403 for a disabled account (only after the right password) or when `require_mfa` is set. **429** with `Retry-After` past 10 attempts per client IP (IPv6: per /64; then one per 6 s; loopback is not exempt; no proxy headers are trusted). 5 wrong passwords in a row lock the account for 15 minutes (audited `auth.locked`). Every failure is audited `auth.login_failed` with the reason; the attempted name only when it is a well-formed email, never the password. |
| `POST /api/auth/logout` | session or token | → `{end_session_url?}`. Ends the cookie session (needs `X-Offpatch-CSRF: 1`, also on `POST /auth/logout`, which still works); with a static token there is nothing to end (200). |
| `POST /api/auth/password` | local user session | `{current, new}` → `{ok}`. New password: at least 12 characters, not the email (or the part before the @), not the current one (400). A wrong `current` counts towards the lockout. Clears `must_change_password` and ends the user's other sessions. 409 for SSO and token callers. |
| `GET /api/me` | any | → `{user, email, display_name, role, auth: "password" \| "sso" \| "token", source (= auth), mfa, must_change_password, password_changed_at ("" until the user changed it), builtin (the installer-created super admin)}` |
| `GET /api/users` | admin | → `User[]`: SSO users (seen at sign-in) and local users. Never a password hash. |
| `POST /api/users` | admin | `{email, display_name?, role, password?}` → **201** `{email, username, display_name, role, must_change_password: true, source: "local", auth: "password", temp_password?}`. The password is temporary: the user must change it at first sign-in. Without `password` one is generated and returned **once** as `temp_password`. 400 invalid email / role / password; 403 for `role: super_admin` unless the caller is a super admin; 409 if the name exists (also as an SSO user or a static token name). Audited `user.created`. |
| `POST /api/users/{email}/disable` · `/enable` | admin | `{reason?}` → `{ok}`. Disable ends the user's sessions; enable also clears a lockout. Works for SSO and local users. |
| `POST /api/users/{email}/reset_password` | admin | `{password?, reason?}` → `{ok, temp_password?}`. Local users only (409 for SSO). New temporary password (generated and returned once when `password` is empty), `must_change_password`, lockout cleared, sessions ended. Audited `user.password_reset`. |
| `POST /api/users/{email}/set_role` | admin | `{role, reason?}` → `{ok}`. Local users only (SSO roles come from `oidc.role_groups`). Ends the user's sessions. Audited `user.role_changed` (`from`, `to`). |

Limits (403 / 409, refusals by role audited `access.denied`): only a `super_admin` creates, changes or
disables a `super_admin` or grants that role; nobody disables, demotes or resets themselves (409); the
last enabled super admin cannot be disabled or demoted (409; enabled `super_admin` static tokens count).
A user with `must_change_password` gets **403** `password_change_required` from every call except
`GET /api/me`, `POST /api/auth/password` and `POST /api/auth/logout`. An SSO sign-in whose name is a local
user or a static token name is refused. Audit events never contain passwords or hashes.

Passwords are stored as `pbkdf2-sha256$<iterations>$<salt>$<hash>` (PBKDF2-SHA256 from the Go standard
library, 600 000 iterations, 16-byte random salt) in table `local_users` (email, display_name, role,
password_hash, must_change_password, failed_attempts, locked_until, created_by, created_at,
password_changed_at, builtin). The disable switch is `users.disabled`, shared with SSO users.

```ts
// User gains: auth: "sso" | "password"; display_name; must_change_password; locked; locked_until?;
//   created_by?; created_at?; password_changed_at?.  Local users: source "local", username = email = the email.
```

Static admin tokens keep working for the API and automation (`Authorization: Bearer`), and in the
console only as a hidden break-glass at `/login?token=1`. `pmserver create-admin -config … -email …
[-name …] [-if-none]` creates the built-in super admin and prints a generated password once;
`pmserver reset-admin -config … -email …` (root on the server) prints a new one (recovery).
