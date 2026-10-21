# 05 — HTTP API contract (v1)

All bodies are JSON and all times are RFC 3339 UTC. Errors return `{"error": "message"}` with status 400/401/403/404/409/500.

## Admin API — session cookie (`offpatch_session`)

Admins authenticate with the `offpatch_session` cookie: from `POST /api/auth/login` (email + password, then `POST /api/auth/mfa` with an authenticator code when the account has one) or from SSO (`GET /auth/login`). Cookie-authenticated requests that change state must send header `X-Offpatch-CSRF: 1`. There are no static admin tokens (removed in v1.9): a request to `/api/*` with `Authorization: Bearer …` gets **401** `static admin tokens were removed; sign in with email and password`. See "v1.8 additions" and "v1.9 additions".

Roles are cumulative: `viewer` < `user` < `admin` < `super_admin` (v1.8; the old names `operator` and `approver` were removed in v1.9). The Role column below is the v1.8 minimum; see "v1.8 additions" for what changed and "v1.9 additions" for agent versions.

| Method & path | Role | Body → Response |
|---|---|---|
| `GET /api/me` | viewer | → `{user, role}` |
| `GET /api/summary` | viewer | → `Summary` |
| `GET /api/bundles` | user | → `Bundle[]` (newest first) |
| `GET /api/bundles/{id}` | user | → `Bundle` (`id` = numeric intake id) |
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
type InventoryItem = { kind: "kb" | "product" | "appx"; id: string; name: string; version: string;
  scope?: "user"; hidden?: boolean; source?: string;
  view?: "64" | "32" };  // registry view of a machine-wide Apps & features entry (agents 0.10.0+)
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
| `GET /auth/config` | none | → `{sso: bool, require_mfa: bool, password_login: true}` — the login page shows "Sign in with SSO" when `sso` (`static_tokens` was removed in v1.9) |
| `GET /auth/login?return=/path` | none | redirects to the IdP (OIDC + PKCE); on return sets the `offpatch_session` cookie (HttpOnly, SameSite=Strict) and redirects to `return`. On failure redirects to `/?login_error=<message>` |
| `POST /auth/logout` | session | → `{end_session_url?}` |
| `GET /api/me` | any | → `{user, role, source, mfa: bool}` (full v1.9 shape below) |

Cookie-authenticated requests (SSO and email + password) that change state MUST send header `X-Offpatch-CSRF: 1`. The console should send it on every request and use `credentials: "same-origin"`.

| Method & path | Role | Body → Response |
|---|---|---|
| `GET /api/users` | admin | → `User[]` |
| `POST /api/users/{username}/disable` · `/enable` | admin | `{reason}` → `{ok}` (disable revokes sessions) |
| `POST /api/endpoints/{id}/retire` | user | `{reason}` → `Endpoint` (status `retired`) |
| `GET /api/maintenance-windows` | viewer | → `MaintenanceWindow[]` |
| `POST /api/maintenance-windows` | user | `MaintenanceWindow` (without id/created_*) → `MaintenanceWindow` |
| `POST /api/maintenance-windows/{id}/delete` | user | `{reason}` → `{ok}` |
| `GET /api/transfer/reconcile` | user | → `Reconciliation` |
| `GET /api/reports/compliance` | viewer | → `ComplianceReport` |
| `GET /api/reports/compliance.csv` · `/api/reports/endpoints.csv` | viewer | CSV download |
| `GET /api/alerts?open=1` | viewer | → `Alert[]` |
| `POST /api/alerts/{id}/ack` | user | `{reason}` → `{ok}` |
| `GET /metrics` | `Bearer <metrics_token>` | Prometheus text |

Agent API additions: `POST /api/agent/renew {csr}` → `{certificate, ca_certificate}` (mTLS). The check-in response adds `reboot_now`, `download_rate_kbps`, `trust` (signed trust document) and, per assignment, `reboot_allowed` and `health_checks`.

```ts
type Me = { user: string; role: Role; source: "sso" | "password"; mfa: boolean };  // v1.8 and v1.9 fields below
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
| `GET /api/acquisition-requests` | user | → `AcquisitionRequestRecord[]`, newest first, at most 100. Items: `{kind: "app", key: winget id, version}` per app and `{kind: "kb", key: KB, version: architecture}` per KB and architecture. `seen_at`: `received_at` of the first acquisition status report with a `request` feed naming the request id. An item is `fulfilled` when a validated bundle received at or after the request's `created_at` holds `<KB>-<arch>`, or pmctl's package id for the app version (`<winget id>-<version>[-<arch>]`, hash-suffixed form included); then `package_id` and `fulfilled_at` (`received_at` of the earliest such bundle; a later bundle that carries an already-imported package again counts) are set. A package that was already in the catalog before the request does not fulfil it. Otherwise `seen` once the request was seen, else `requested`. For a KB requested for several architectures, `requested` refs take the least advanced status. Computed on read. |
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
- The two-machine layout (separate server and acquisition hosts) keeps it **unset** (strict one-way transfer). Set it only when acquisition runs on the same machine (the single-server `install-ubuntu.sh`, `--role all`, does) or the organisation approved an outbound folder. See [07-admin-guide.md](07-admin-guide.md) §3.9 and [08-acquisition.md](08-acquisition.md).

## v1.6 additions — P1 fixes (honest status, auto-advance, import results)

| Method & path | Role | Body → Response |
|---|---|---|
| `POST /api/deployments` | user | `NewDeployment` gains `auto_advance: boolean` (default `false`), echoed on `Deployment`. When the current ring is finished within `max_failure_pct` and is not the last ring, the deployment advances by itself (audited `deployment.advanced`, actor `system:scheduler`, `details.auto: true`); see [03-state-model.md](03-state-model.md). A second **active or paused** deployment of the same package and operation is refused with **409** ("already running; open it, wait for it to finish, or cancel it first"). |
| `GET /api/endpoints`, `GET /api/endpoints/{id}`, `GET /api/reports/endpoints.csv` | viewer | `status` may also be `updates_available` (would be `compliant`, but `missing.os + missing.apps > 0`), `out_of_support` (would be `compliant` or `updates_available`, but `missing.os_support` is `out_of_support`) and `awaiting_checkin` (enrolled < 24 h ago, no inventory yet; after 24 h `offline`). `missing` gains `os_support` (`supported` \| `out_of_support` \| omitted) and `os_last_update` (date of the build's newest cumulative update). |
| `GET /api/summary` | viewer | `endpoints.by_status` has a key for every status, including `updates_available`, `out_of_support` and `awaiting_checkin`; the same refined statuses as the endpoint list (so `compliant` no longer counts machines the intelligence says are behind). The `offpatch_endpoints` metric uses the same counts. |
| `GET /api/acquisition-requests` | user | Item `status` may also be `unsupported` (can never be fetched this way: no MSI installer for the architecture, no ProductCode, version no longer in winget, KB not in the catalog for the build/arch) or `failed` (transient: download, hash, network — the next run may work), with `reason`. Taken from the **newest** acquisition status report whose `items` list that request id + kind + key + version (key and version case-insensitive); `fetched` / `already_sent` there mean `seen`. `fulfilled` (the package arrived) wins over both. |
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
- **Static tokens** (v1.6 behaviour, removed in v1.9): `allow_static_tokens` and `admin_tokens` are no longer accepted; see "v1.9 additions".

## v1.7 additions — P2 (Library, imports tracking, alerts that close themselves, evidence)

| Method & path | Role | Body → Response |
|---|---|---|
| `GET /api/library?q=&kind=app\|os&view=available\|installed\|catalog\|all&publisher=&sort=installed\|name\|date&page=1&per_page=50` | super_admin | → `LibraryPage` (below). One searchable list of everything the update intelligence knows: winget apps (`kind: "app"`) and Windows cumulative updates (`kind: "os"`, one row per KB). `q`: words (case-insensitive, all must match) over name, id, publisher and MSI product codes. `publisher`: exact publisher, case-insensitive. `view`: `available` (default: `importable` = `yes` or installed in the fleet), `installed` (installed on at least one endpoint), `catalog` (has a catalog package), `all`. `sort`: `installed` (default: installed endpoints, then name), `name`, `date` (release date for KBs, `resolved_at` for apps; newest first). `per_page` is capped at 100. 400 for other `kind` / `view` / `sort` values or a page / per_page < 1. Without usable intelligence: `total: 0, items: []`. |
| `GET /api/library/{kind}/{id}` | super_admin | → `LibraryItem` plus `endpoints: [{endpoint_id, hostname, installed_version, outdated}]` (sorted by hostname; for a KB: endpoints on its build, `installed_version` = their `os_version`). `id` is case-insensitive. 404 when not in the Library or without usable intelligence. |
| `POST /api/acquisition-requests` | user (Library items and `app_archs`: super_admin) | Body gains `app_archs: {"<winget id>": "x64" \| "x86" \| "arm64"}`. Apps and KBs that no endpoint needs are now accepted when they are in the update intelligence (a Library import): an app is written with `architectures: [app_archs[id] or "x64"]`, `endpoints: 0` and no installed forms; a KB with every architecture the intelligence lists for it and `endpoints: 0`. `app_archs` is ignored for apps installed in the fleet (they keep the fleet's architectures). 400 for an architecture other than x64 / x86 / arm64, more than 500 `app_archs` entries, or an item that is not in the intelligence ("not in the update intelligence (reload the page): …"). |
| `GET /api/acquisition-requests` (and every `requested` ref) | user | Item `status` may also be `stale` with `reason` `the acquisition run at <finished_at> did not pick this request up`: the item is still `requested` / `seen`, and the **newest** acquisition status report (by `finished_at`), finished more than 10 min after the request's `created_at`, lists the request id neither in a `request` feed nor in `items`. An item with a `fetched` / `already_sent` result is on its way and never stale; `fulfilled` wins. Rank for `requested` refs: `stale` 0 (like `requested`). The console shows it as "Not picked up" with "Ask again". |
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
In v1.8 the older names `operator` and `approver` were still accepted as `user`; v1.9 removed them
(pmserver refuses to start when `oidc.role_groups` uses one; stored users and sessions were moved to
`user`). API responses always use the new names.

| Role | Can do (in addition to the roles below it) |
|---|---|
| `viewer` | Every `GET` above except `/api/users` (no secrets). |
| `user` | Acquisition requests; create deployments and rollbacks (they start `pending_approval`); approve / reject deployments and rollbacks (not their own); approve / reject packages; acknowledge alerts; maintenance windows; enrollment tokens; edit and retire endpoints; pause / resume / cancel / advance / retry deployments. |
| `admin` | Users: create, disable / enable, reset password, change role for `viewer`, `user` and `admin` (never `super_admin`); create and revoke exceptions; revoke packages. |
| `super_admin` | Everything, including managing `super_admin` accounts and (v1.9) agent versions. **Not** a deployment approver (the vendor does not approve bank changes). |

The route table is the security boundary: the console hides what a role cannot do, the API refuses
it with **403** `requires role <role>` (audited `access.denied`). Role changes in the table above
compared with v1.7: package approve / reject moved from the old approver role to `user`; package
revoke and exceptions to `admin`.

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
| `GET /auth/config` | none | Gains `password_login: bool` (v1.9: always `true`; `require_mfa` now makes the authenticator step required instead). |
| `POST /api/auth/login` | none | `{email, password, setup_code}` (`setup_code` only for the built-in super admin while it still has the default password; ignored otherwise) → `{user, email, role, auth: "password", must_change_password}` and the `offpatch_session` cookie (same session as SSO: `session_ttl`, `HttpOnly`, `SameSite=Strict`, `Secure` over TLS). Needs header `X-Offpatch-CSRF: 1`. **401** `wrong email or password` for an unknown email, a wrong password, a missing or wrong setup code (default password; counted like a wrong password) **and** a locked account (no enumeration; the same work is done in every case). 403 for a disabled account (only after the right password). v1.9: the 200 answer may ask for the authenticator step (see "v1.9 additions"). **429** with `Retry-After` past 10 attempts per client IP (IPv6: per /64; then one per 6 s; loopback is not exempt; no proxy headers are trusted). 5 wrong passwords in a row from one client address lock the account for that address for 15 minutes; 50 within 15 minutes from any addresses lock it everywhere (audited `auth.locked`, `details.scope`). **503** with `Retry-After` `the server is busy checking other sign-ins; …` when 4 password checks are already running and none frees up within 2 s. Failures are audited `auth.login_failed` with the reason and `details.client`, at most once a minute per account and address (`details.suppressed` = folded ones); the attempted name only when it is a well-formed email, never the password. Through `console_proxy` the per-client limit is checked first, then **429** when all clients together exceed 30 sign-in steps (then 1/s; addresses with a successful sign-in in the last 24 h keep a reserved 10, then 1 per 3 s), and **400** when the proxy sends no client address. |
| `POST /api/auth/logout` | session | → `{end_session_url?}`. Ends the cookie session (needs `X-Offpatch-CSRF: 1`, also on `POST /auth/logout`, which still works). |
| `POST /api/auth/password` | local user session | `{current, new}` → `{ok}`. New password: at least 12 characters, not the email (or the part before the @), not the current one (400). A wrong `current` counts towards the lockout. Clears `must_change_password` and ends the user's other sessions. 409 for SSO callers. |
| `GET /api/me` | any | → `{user, email, display_name, role, auth: "password" \| "sso", source (= auth), mfa, must_change_password, password_changed_at ("" until the user changed it), builtin (the installer-created super admin)}`; v1.9 adds `mfa_enrolled`, `mfa_required` |
| `GET /api/users` | admin | → `User[]`: SSO users (seen at sign-in) and local users. Never a password hash. |
| `POST /api/users` | admin | `{email, display_name?, role, password?}` → **201** `{email, username, display_name, role, must_change_password: true, source: "local", auth: "password", temp_password?}`. The password is temporary: the user must change it at first sign-in. Without `password` one is generated and returned **once** as `temp_password`. 400 invalid email / role / password; 403 for `role: super_admin` unless the caller is a super admin; 409 if the name exists (also as an SSO user). Audited `user.created`. |
| `POST /api/users/{email}/disable` · `/enable` | admin | `{reason?}` → `{ok}`. Disable ends the user's sessions; enable also clears a lockout. Works for SSO and local users. |
| `POST /api/users/{email}/reset_password` | admin | `{password?, reason?}` → `{ok, temp_password?}`. Local users only (409 for SSO). New temporary password (generated and returned once when `password` is empty), `must_change_password`, lockout cleared, sessions ended. Audited `user.password_reset`. |
| `POST /api/users/{email}/set_role` | admin | `{role, reason?}` → `{ok}`. Local users only (SSO roles come from `oidc.role_groups`). Ends the user's sessions. Audited `user.role_changed` (`from`, `to`). |

Limits (403 / 409, refusals by role audited `access.denied`): only a `super_admin` creates, changes or
disables a `super_admin` or grants that role; nobody disables, demotes or resets themselves (409); the
last enabled super admin cannot be disabled or demoted (409).
A user with `must_change_password` gets **403** `password_change_required` from every call except
`GET /api/me`, `POST /api/auth/password` and `POST /api/auth/logout`. An SSO sign-in whose name is a local
user is refused. Audit events never contain passwords or hashes.

Passwords are stored as `pbkdf2-sha256$<iterations>$<salt>$<hash>` (PBKDF2-SHA256 from the Go standard
library, 600 000 iterations, 16-byte random salt) in table `local_users` (email, display_name, role,
password_hash, must_change_password, failed_attempts, locked_until, created_by, created_at,
password_changed_at, builtin). The disable switch is `users.disabled`, shared with SSO users.

```ts
// User gains: auth: "sso" | "password"; display_name; must_change_password; locked; locked_until?;
//   created_by?; created_at?; password_changed_at?.  Local users: source "local", username = email = the email.
```

In v1.8 static admin tokens still worked for the API and as a hidden console break-glass; v1.9
removed them (see "v1.9 additions"). `pmserver create-admin -config … [-email …] [-name …]
[-if-none] [-password-random]` creates the built-in super admin; `pmserver reset-admin -config …
[-email …]` (root on the server) prints a new password once (recovery).

## v1.9 additions — sign-in and MFA, static tokens removed, agent versions

### Removed

| What | Now |
|---|---|
| Static admin tokens (`admin_tokens`, `allow_static_tokens` in `pmserver.json`) | pmserver **refuses to start** while either key is present; the message says to delete both and sign in with email + password. The installer removes them on upgrade and shreds `admin-token.txt` / `admin-token.sha256`. |
| `Authorization: Bearer <admin token>` on `/api/*` | **401** `static admin tokens were removed; sign in with email and password`. Agent bearer device secrets (lab mode) and `metrics_token` on `GET /metrics` are unchanged. |
| `pmserver new-token` | Removed. Enrollment tokens from scripts: `pmserver enroll-token` (below). |
| Console token sign-in (`/login?token=1`) | Removed. |
| `GET /auth/config` → `static_tokens` | Removed; `password_login` is always `true`. |
| Role names `operator`, `approver` | Removed everywhere. `oidc.role_groups` (and any configured role) must use `viewer`, `user`, `admin` or `super_admin`; pmserver refuses to start naming the old value. Stored users and sessions with an old name are migrated to `user`. |
| `require_mfa` switching email + password sign-in off | `require_mfa` now makes the authenticator step required for **every** local user (super admins too) and still refuses SSO sessions without IdP MFA. |

Admins authenticate only with email + password sessions (local users) and SSO (when `oidc` is
configured). Scripts sign in with `POST /api/auth/login` (+ `POST /api/auth/mfa`), keep the
`offpatch_session` cookie and send `X-Offpatch-CSRF: 1` on writes.

### MFA (authenticator app)

TOTP (RFC 6238), 6 digits, 30 s. **Required** for every local user, `super_admin` included (by
default; only `"require_mfa": false` makes it optional for super admins). SSO users: the IdP's MFA
(`require_mfa: true` checks `amr` / `acr`); the endpoints below answer 409 for SSO users. Each code
works once. Wrong codes have their **own** counter (a correct password does not reset it): 5 in a
row lock the code step for 15 min, doubling per further lockout up to 24 h (audited
`auth.mfa_locked`, critical alert `auth.mfa_locked`); a correct code or an admin **Enable** /
**Reset MFA** clears it. 10 recovery codes are shown once at enrolment, stored hashed, each single-use.
Secrets are encrypted at rest (AES-256-GCM) with the key in `mfa_key_file` (default
`<data_dir>/mfa.key`, 64 hex characters, mode 0600; created by the installer and at first start if
missing; included in `pmserver backup` at the default path only). The secret is never returned after enrolment.

`POST /api/auth/login` `{email, password}` has three 200 answers (errors unchanged: 401 `wrong email
or password`, 403 disabled, 429 rate limit):

- Authenticator enrolled → `{"mfa_required": true, "email"}`. **No** session cookie; a short-lived
  (5 min) HttpOnly cookie `offpatch_mfa` (Path `/api/auth/mfa`) is set. Continue with `POST /api/auth/mfa`.
- MFA required but not enrolled → `{user, email, role, auth: "password", must_change_password,
  mfa_required: false, mfa_enrollment_required: true}` and the session cookie. This session is
  **limited**: every call except `GET /api/me`, `POST /api/auth/mfa/enroll/start`,
  `POST /api/auth/mfa/enroll/confirm`, `POST /api/auth/password` and `POST /api/auth/logout` answers
  **403** `mfa_enrollment_required`. With `must_change_password` the password change comes first
  (403 `password_change_required`, the enrolment endpoints included), then enrolment.
- No MFA needed (super admin not enrolled, only with `"require_mfa": false`) → as in v1.8 plus
  `mfa_required: false, mfa_enrollment_required: false`. A password session without MFA stops
  working (401 `multi-factor authentication required; sign in again`) once MFA is required.

| Method & path | Auth / role | Body → Response |
|---|---|---|
| `POST /api/auth/mfa` | `offpatch_mfa` cookie from login | `{code: "123456"}` or `{recovery_code: "abcde-fghij"}` → 200 `{user, email, role, auth: "password", must_change_password, mfa: true}` + session cookie; the pre-auth cookie is cleared. The pre-auth cookie is **single use** (its nonce is kept server-side) and allows at most **3** codes. **401** `wrong or expired code` (wrong code, code already used, used recovery code, or the account is locked); **401** `sign-in expired; enter your email and password again` (no / invalid / expired / already used pre-auth cookie: restart at login), or `sign-in expired after 3 wrong codes; …`; **429** `too many wrong codes: two-step sign-in is locked …` (the code step is locked; no `Retry-After`); 403 disabled; 429 rate limit (same per-IP limit as login). |
| `POST /api/auth/mfa/enroll/start` | local user session (also the limited one) | `{}` → `{secret_base32, otpauth_uri}`; `otpauth_uri` = `otpauth://totp/DSS%20Patcher:<email>?secret=<secret_base32>&issuer=DSS%20Patcher&digits=6&period=30` (render as QR code, show the secret for manual entry). Calling again replaces the unconfirmed secret; the pending secret expires after 15 minutes. 409 if already enrolled ("ask an administrator to reset MFA"); 409 for SSO users. |
| `POST /api/auth/mfa/enroll/confirm` | local user session (also the limited one) | `{code}` → `{ok: true, recovery_codes: [10 × "abcde-fghij"]}` (shown **once**). The current session becomes a full, MFA-verified session at once (no new sign-in). 400 `wrong or expired code`; 409 `no enrolment in progress: start it first` / `the enrolment expired: start it again`. |
| `POST /api/auth/mfa/disable` | super_admin (own account only) | `{code}` → `{ok: true}`. 403 for other roles; 400 wrong code (counts towards the code lockout); 429 code step locked; 409 not enrolled or MFA is required (the default; allowed only with `"require_mfa": false`). |

Audit actions: `user.mfa_enrollment_started`, `user.mfa_enrolled`, `auth.password_verified` (password
right, MFA step next), `auth.mfa_failed` (`details.reason` / `stage`), `auth.mfa_recovery_used`,
`auth.locked` (`details.scope` `source` or `account`), `auth.mfa_locked`, `user.mfa_reset`,
`user.mfa_disabled`, `user.deleted`, `auth.login` (`details.mfa`, `details.mfa_enrollment_required`),
`user.password_change_forced` (the default password was still in use at startup).

### `/api/me` and `/api/users`

- `GET /api/me` gains `mfa_enrolled: bool` (local users) and `mfa_required: bool` (local users: true
  for bank roles and, unless `"require_mfa": false`, super admins; SSO: the `require_mfa` setting). `mfa` is
  still "this session was MFA-verified". `auth` / `source` are `"password"` or `"sso"`.
- `builtin: true` with `password_changed_at: ""` means the built-in super admin still has the
  vendor's default password: the console shows a change-password banner.
- `GET /api/users` items gain `mfa_enrolled: bool`.

### User actions

`POST /api/users/{email}/{action}`, body `{reason?}`:

| Action | Role | Response and rules |
|---|---|---|
| `reset_mfa` | admin for bank roles, super_admin for super admins (403 otherwise) | `{ok: true}`. Removes the user's authenticator and recovery codes and ends their sessions; they enrol again at the next sign-in. 409 for SSO users. Audited `user.mfa_reset`. |
| `delete` | admin for bank roles, super_admin for any | `{ok: true}`. Deletes a **local** user: account, sessions and MFA. The audit history is kept (`user.deleted`) and the email can be reused. 409 for yourself, the last super admin and SSO users (disable them instead); 404 unknown user. |

### Built-in super admin

`pmserver create-admin` (and the installer, `--admin-email`) defaults to
`superadmin@dataspacesecurity.com` and sets the vendor's **default password** (only its PBKDF2 hash is
embedded in `pmserver`; the password is in the vendor handbook). The installer summary prints
"super admin: superadmin@dataspacesecurity.com — default password (see vendor handbook); change it
after first sign-in". While the default password is in use, `/api/me` returns `builtin: true` and
`password_changed_at: ""`, and pmserver logs a WARN at every start. `-password-random` creates it
with a random password printed once instead.

### Agent versions

Packages of kind `agent` (`offpatch-agent-*`) are managed by the vendor:

| Action | Who | Refused with |
|---|---|---|
| `POST /api/packages/{id}/approve` · `/reject` · `/revoke` | super_admin only | 403 `agent versions are managed by the vendor (super admin)` |
| `POST /api/deployments` (install or rollback of an agent version) | super_admin only | 403 `agent versions are managed by the vendor (super admin)` |
| `POST /api/deployments/{id}/approve` · `/reject` for an agent-version deployment | role `admin` only (bank admins), not the creator; `deployment_approvals` of them | 403 `agent version deployments are approved by bank admins` (role `user`); the super admin cannot approve either |

### CLI changes

| Command | Change |
|---|---|
| `pmserver enroll-token -config pmserver.json -groups g1,g2 -site s -hours 1` | New. Prints `token: enr_…` and `expires_at` (one use; audited as created by `system:cli`). Run on the server as the service user. |
| `pmserver create-admin -config … [-email …] [-name …] [-if-none] [-if-fresh] [-password-random]` | Default `-email` `superadmin@dataspacesecurity.com`; without `-password-random` it sets the vendor's default password. An existing account with that email (also disabled) is reported and left unchanged (exit 0). `-if-fresh` (installer) creates only in a database with no users. |
| `pmserver reset-admin -config … [-email …]` | New random password printed once, account re-enabled, lockout cleared, and the super admin's MFA cleared. Run as root (as the service user). |
| `pmserver verify-report -zip compliance-….zip -pub audit-signing.pub` | New. Verifies a compliance evidence package offline (manifest signature and every file's SHA-256). |
| `pmserver new-token` | Removed. |
| `pmserver backup` | Also includes `<data_dir>/mfa.key` (a `mfa_key_file` elsewhere is not copied); writes the audit event `backup.created` (a restore writes `backup.restored` into the restored database). |

## v1.9 additions — auditor compliance report

The owner's "Patch Management Compliance Report" template, generated from product data and a
versioned report profile (docs/10-compliance-report.md explains what is computed and how). Exact
JSON shapes: `internal/compliance/types.go` (`Pack`) and `internal/store/report_profile.go`
(`ReportProfile`).

| Method & path | Role | Body → Response |
|---|---|---|
| `GET /api/reports/profile` | viewer | → `ReportProfileRecord` `{version, edited_by, edited_at, sha256, is_default, profile}`: the latest saved version, or version 0 with `is_default: true` (deadlines from `patch_deadlines`, the template's seven §4 rows with `applicable: "unknown"`, the four sign-off roles). `?version=N` → that version (404 if never saved). |
| `PUT /api/reports/profile` | admin | `ReportProfile` (strict JSON) → `ReportProfileRecord` of the new version. `?base_version=N`: 409 when another version was saved since N. 400 lists every problem: `regulators` ∈ RBI, SEBI, IRDAI, PFRDA, MeitY, CERT-In, other; `deadlines[].priority` ∈ emergency, critical, high, moderate, low (once each; missing ones are filled from the policy), `max_days` 1–3650, `clock_start` ∈ release, acquired, approved; `regulatory_mappings[].applicable` ∈ yes, no, unknown, `result` and `manual_controls.*.status` ∈ the status values; `manual_controls` keys PM-01…PM-17; dates `YYYY-MM-DD` (or RFC 3339); strings ≤ 8000 characters, lists ≤ 200. Audited `report.profile_updated` (`version`, `sha256`, `previous_version`, `changed`: top-level field names). |
| `GET /api/reports/profile/history` | viewer | → `[{version, edited_by, edited_at, sha256}]`, newest first. |
| `GET /api/reports/compliance-pack?from=YYYY-MM-DD&to=YYYY-MM-DD[&redact=1][&tz=Asia/Kolkata]` | viewer | → `Pack` (below). `to` is inclusive; defaults: this month so far, the server's time zone. 400 for bad dates, `from` after `to`, more than 3660 days, a period starting in the future, an unknown `tz`. Audited `report.compliance_generated` (`report_id`, `period_from`, `period_to`, `format: "json"`, `redacted`, `profile_version`, `overall_suggested`, `generated_at`). |
| `GET /api/reports/compliance-pack.zip?…` | viewer | Same parameters → `application/zip` (`compliance-<report_id>[-redacted].zip`), streamed: `report.pdf`, `report.md`, `summary.json` (= `Pack`), `evidence/E-001…E-010-*.csv`, `manifest.json`, `manifest.sig`, `signing-key.pub`. Audited like the JSON with `format: "zip"` and `manifest_sha256`, before the ZIP is finished (an audit failure leaves the download incomplete). |

Status values (controls, mappings, overall): `Compliant`, `Partially compliant`, `Non-compliant`,
`Not applicable`, `Not assessed`.

```ts
Pack = {
  meta: {report_id: "CR-…", title, product: "DSS Patcher", product_version, generated_at /* RFC 3339 with offset */,
         generated_by: {user, role}, period: {from, to /* inclusive */, as_of, timezone}, filters, redacted,
         report_type, control_domain, coverage_model, document_status, regulatory_review_date, prepared_for},
  disclaimer,                                  // the template's "Important" note, verbatim
  profile: ReportProfile, profile_version: {version, edited_by, edited_at, sha256, is_default},
  executive_summary: {in_scope_endpoints, current_inventory: {count, pct}, compliant_with_policy: {count, pct},
                      overdue: {count, pct}, stale_inventory: {count, pct}, pending_restart, active_exceptions,
                      emergency_open_past_target, findings_by_severity: {critical, high, medium, low}, evidence_completeness_pct},
  overall_assessment: {status, rationale, source: "computed" | "profile", suggested, suggested_rationale},
  key_findings: Finding[],                     // the three most severe
  scope: {endpoints_total, retired_excluded, os_families, application_vendors, sites, groups},
  controls: {id, objective, auditor_evidence, suggested_test, evidence, evidence_ids, test_performed,
             status, source: "automatic" | "manual" | "none", rationale, manual?: {status, evidence_ref, note}}[],  // PM-01…PM-17
  regulatory_mappings: (RegulatoryMapping & {conclusion, needs_review})[],   // "Not assessed — needs compliance review" until reviewed
  timeliness: {as_of, by_priority: {priority, max_days, source, clock_start, exception_process, pairs, compliant, verified_late,
               overdue, pending, failed, offline, exception, not_applicable, past_deadline_open, pct_on_time}[],
               outcome_counts, pairs_total, pairs: Pair[] /* worst first, ≤ pairs_limit (1000) */, pairs_limit, pairs_truncated},
  evidence_register: {id, item, source_system, period, scope, sha256, records, confidentiality, included, complete, note}[],  // E-001…E-010
  findings: {id: "F-001", title, control, source, observation, evidence_ids, risk, severity: "Critical" | "High" | "Medium" | "Low",
             root_cause, corrective_action, owner, due_date, status: "Open", affected_count, affected}[],
  exceptions: {exception_id, endpoint_id, scope, package_id, patch, reason, compensating_controls, owner, approver, opened, expires,
               status: "Active" | "Expired" | "Revoked"}[],
  signoff: {role, name, comments, date}[], scope_limitations: {auto: string[], profile}, management_response,
  references: {n, label, title, url, note?}[], audit_chain: {ok, events, first_bad_seq, error, head_seq}
}
Pair = {endpoint_id, hostname, package_id, title, kb, severity, priority /* emergency|critical|high|moderate|low */, release_date,
        acquired_at, approved_at, clock_start, deadline, deadline_source, installed_at, verified_at,
        outcome: "compliant" | "verified_late" | "overdue" | "pending" | "failed" | "offline" | "exception" | "not_applicable",
        past_deadline, deployment_id, evidence, exception_id, basis: "targeted" | "needed" | "exception"}
```

`manifest.json` = `{format: 1, product, product_version, report_id, generated_at, generated_by, period, filters, redacted,
files: [{path, sha256, size}], key_id, public_key (base64), public_key_fingerprint (SHA-256 hex), signature_algorithm: "ed25519"}`;
`manifest.sig` is the base64 Ed25519 signature of the `manifest.json` bytes with the server's audit-signing key
(`<data_dir>/audit-signing.key`, created on first use). Verify offline: `pmserver verify-report -zip … -pub audit-signing.pub`.
`redact=1` replaces hostnames, endpoint IDs, IP addresses and user IDs with stable pseudonyms (HMAC-SHA-256 with a per-server salt).

## Reports and exceptions

Every signed-in role (`viewer` and up) reads the whole Reports area: every
`/api/reports/*` GET (`compliance`, `compliance.csv`, `endpoints.csv`,
`targets.csv`, `compliance-pack`, `compliance-pack.zip`, `compliance-pack.pdf`,
`compliance.pdf`, `profile`, `profile/history`) and `GET /api/audit`,
`/api/audit/verify`, `/api/audit/export`, `/api/audit.pdf`.
`PUT /api/reports/profile` needs `admin`. The exceptions API is unchanged
(`GET /api/exceptions` viewer; `POST /api/exceptions`, `/{id}/revoke` admin);
the console shows it under Deployments → Exceptions.

### Server-made PDF files (viewer and up)

The server writes real PDF files (internal/pdf: PDF 1.4, A4, standard Helvetica / Courier fonts
with WinAnsi encoding, compressed content streams, footer "DSS Patcher · <report id> · page N of
M"); the console downloads them (no browser print dialog). Every generation is audited.

| Method & path | Role | Response |
|---|---|---|
| `GET /api/reports/compliance-pack.pdf?from=&to=[&redact=1][&tz=]` | viewer | `application/pdf`, `DSS-Patcher-compliance-report-<from>_<to>-<report id>[-redacted].pdf`: the auditor report (cover with logo, title block, Important note, sections 1–9 as `report.md`). Audited `report.compliance_generated` (`format: "pdf"`). The same PDF is `report.pdf` in the signed ZIP (listed in `manifest.json`). |
| `GET /api/reports/compliance.pdf` | viewer | `application/pdf`, `DSS-Patcher-patch-compliance-<date>-PC-<…>.pdf`: the patch compliance report (Reports page: by severity, fleet, exceptions, intake, packages). Audited `report.exported` (`object_id: "compliance.pdf"`, `report_id`, `sha256`). |
| `GET /api/audit.pdf?from=&to=[&tz=]` | viewer | `application/pdf`, `DSS-Patcher-audit-log-<from>_<to>-AL-<…>.pdf`: every audit event of the period (oldest first, at most 20 000; the signed off-box export has all) with the chain status. 400 for bad dates (as the compliance pack). Audited `report.exported` (`object_id: "audit.pdf"`, period, `events`, `truncated`, `sha256`). |

## Patches by role: the Library is the vendor's, Imports user and up

Owner decision. `GET /api/library` and `GET /api/library/{kind}/{id}` require
`super_admin` (403 `requires role super_admin` for bank roles). The Imports
reads, `GET /api/acquisition`, `GET /api/acquisition-requests`,
`GET /api/bundles`, `GET /api/bundles/{id}` and `GET /api/transfer/reconcile`,
require `user` (viewer: 403 `requires role user`). `POST /api/acquisition-requests`
stays `user`, but a bank role (user, admin) may only request keys that the
fleet view lists (what its machines have or need, i.e. Patches → Needed): a key
that only the Library index has, or any `app_archs`, is refused with **403**
`the Library is the vendor's (super admin): import what your machines need from Patches → Needed`,
audited `access.denied` (`details.reason: "library import"`, `items`). Keys in
neither are still **400** "not in the update intelligence".

## v1.10 additions — auto-download policy (docs/08-acquisition.md "Auto-download policy")

Every route is **super_admin** only (bank roles: 403 `requires role super_admin`, audited
`access.denied`).

| Route | Role | Contract |
|---|---|---|
| `GET /api/acquisition/policy` | super_admin | → `AcqPolicyView`: `{version, edited_by, edited_at, sha256, summary: string[], policy: AcqPolicy, is_default, default_source: "acquire.json" \| "downloader" \| "none", banner?, default_feeds: string[], downloader: DownloaderView \| null, delivery: {direct: bool}, windows_choices: [{product, build, arch, server?, catalog_product}], last_run_request: {run_id, requested_by, requested_at, queued_to} \| null, pending: {base_version, proposed_by, proposed_at, sha256, source_changes, summary, policy} \| null, can_approve: bool, signing: {key_id, public_key, error?}}` (`downloader.policy_signature`: the key id that verified the applied policy, or `"not verified: …"`). `version: 0, is_default: true` until the first save; `policy` is then the starting point (see `default_source`). `?version=N` → that stored version `{version, edited_by, edited_at, sha256, summary, policy}` (404 if none). |
| `PUT /api/acquisition/policy?base_version=N` | super_admin | Body `AcqPolicy` (unknown fields refused). Normalized and validated (400 listing every problem). `base_version` must be the latest version (0 before the first save), else **409** "changed by someone else … reload"; omitted = unconditional. Each source's `added_by` is set by the server (kept for existing ids). A change that adds a source or changes a source's address or verification data (S-4) is **not** saved: → **202** `{needs_approval: true, pending}` (audited `acquisition.policy_change_proposed`; replaces an earlier proposal). Otherwise → the stored version plus `queued_to` (the folder, or `""`) and `queued_error?`. Audited `acquisition.policy_updated` (`details`: version, sha256, previous_version, changes) and, with `acquisition_requests_dir`, `acquisition.policy_queued`. |
| `GET /api/acquisition/policy/history` | super_admin | → `[{version, edited_by, edited_at, sha256, summary}]`, newest first. |
| `GET /api/acquisition/policy/file[?version=N]` | super_admin | → the delivered document (`AcqPolicyFile`) as the attachment `policy-<NNNNNN>.json` (latest by default; 404 before the first save). Audited `acquisition.policy_downloaded`. |
| `POST /api/acquisition/policy/queue` | super_admin | Writes the latest version to `acquisition_requests_dir` again → `{version, queued_to}`. 409 without the folder, 404 before the first save, 500 if the write fails. |
| `POST /api/acquisition/policy/pending/approve` | super_admin, not the proposer | Body `{sha256}` (of the pending change the approver reviewed). Saves it as the next version (edited by the proposer) and queues it like a save → same answer as `PUT`. 403 for the proposer, 404 when nothing is pending, 409 when the proposal was replaced or the policy changed since. Audited `acquisition.policy_change_approved` and `acquisition.policy_updated` (`approved_by`). |
| `POST /api/acquisition/policy/pending/reject` | super_admin | Body `{reason}` (optional, ≤ 500 characters). Discards the pending change (the proposer withdraws, anyone else rejects) → `{rejected: true}`. Audited `acquisition.policy_change_rejected` (`how`: withdrawn \| rejected). |
| `POST /api/acquisition/run` | super_admin | Queues a run request `run-<UTC time>-<6 hex>.json` (`{format: "offpatch.acquisition-run", version: 1, run_id, requested_by, requested_at}`) → `{run_id, requested_by, requested_at, queued_to}`. 409 without `acquisition_requests_dir` (two machines). Audited `acquisition.run_requested`. |

Types:

- `AcqPolicy`: `{windows: [{product, build, arch: x64|x86|arm64, classification: security|all, enabled}], apps: [{source: "winget", id, arch: [...], channel: "latest", enabled, note}], sources: [{id, type: winget|microsoft-catalog|msrc|vendor-url|internal-mirror, enabled, added_by, note, url?, manifests_url?, name?, vendor?, expected_sha256?, signer?, kind?: msi|msu, version?, product_code?, kb?, arch?, replaces?: winget-index|winget-manifests|microsoft-catalog|msrc}], limits: {max_download_gb_per_run, keep_last_n_versions}}`.
- `AcqPolicyFile`: `{format: "offpatch.acquisition-policy", version: 1, policy_version, edited_by, edited_at, sha256 (hex SHA-256 of the compact JSON of policy), policy: AcqPolicy}`.
- `DownloaderView` (from the newest acquisition status report): `{source, host, finished_at, outcome, schedule, policy_version, policy_sha256, policy_applied_at, policy_error?, run_request?, sources: [{kind: source|app|windows, id, type?, result, detail?, packages?}], reports_policy}` (`reports_policy: false`: the downloader's pmctl predates the policy).
- The acquisition status report (`acqstatus.Report`) gains `policy_version`, `policy_sha256`, `policy_edited_by`, `policy_applied_at`, `policy_error`, `sources`, `defaults: {policy: AcqPolicy, feeds: string[]}` and `run_request`; older servers ignore them.

## v1.11 additions — EXE packages (kind `exe`)

| Route | Role | Contract |
|---|---|---|
| `GET /api/packages`, `GET /api/packages/{id}` | viewer | `Package` gains `exe` (kind `exe` only; omitted otherwise): the manifest's `exe` block (`installer_type`, `silent_args`, `success_codes`, `busy_codes`, `signer`, `detect {display_name, display_version, product_code, publisher}`, `uninstall {quiet_uninstall}`, `scope`), see [04-bundle-format.md](04-bundle-format.md). `kind` may be `exe`. `rollback_unsupported` is `rollback not supported for this installer (no silent uninstall)` unless `exe.uninstall.quiet_uninstall`. |
| `POST /api/deployments` | user | A rollback of an `exe` package without `quiet_uninstall` is refused (409, the reason above). Targets of an `exe` deployment on endpoints whose `agent_version` is below 0.9.0 (or unknown) are `not_applicable` with detail `agent too old for EXE packages: upgrade the agent to 0.9.0 or later` and are never assigned; they return to `pending` at the first check-in reporting 0.9.0 or later. |
| `GET /api/updates`, `GET /api/fleet/status` | viewer | Every row gains `importable: "yes" \| "no" \| "unknown"` and `importable_reason`: the Library's rule (`intel.Importable` with the architectures of the endpoints that have the app; KB rows: `yes`, "Windows cumulative update (Microsoft Update Catalog)"). |
| `GET /api/endpoints/{id}/updates` | viewer | Each `apps[]` entry gains `importable` and `importable_reason` (rule applied with the endpoint's architecture). |
| `GET /api/library`, `GET /api/library/{kind}/{id}` | super_admin | `installers[]` entries gain `silent: bool` (omitted when false): the winget manifest documents a silent switch (matters for plain `exe`). `importable_reason` may be `EXE installer (inno)` etc. |
| `POST /api/acquisition-requests` | user | **400** `can't import: <winget id>: <reason>[; …]` when any requested app is `importable: "no"` (fleet rows: as on `/api/updates`; Library items: with the chosen architecture). No request is created or audited. `unknown` is accepted (pmctl decides). |

The catalog column of `/api/updates` and `/api/fleet/status` also links app rows to `exe` packages, by `exe.detect.product_code` (the ARP key inventory reports as the item id) or normalised `package_name`.

## v1.12 additions — console behind a reverse proxy (`console_proxy`)

Optional second listener (`console_proxy.listen`, plain HTTP on loopback or a private address) for
a reverse proxy that terminates TLS (Temps, nginx); see
[07-admin-guide.md §5.6](07-admin-guide.md#56-console-behind-a-reverse-proxy-temps-nginx-load-balancer).

| Route / behaviour | Contract |
|---|---|
| any request from outside `console_proxy.trusted_proxies` | **403** |
| `/api/agent/*`, `/api/agent-setup/bootstrap/*` | **421** (agents use the main listener, mTLS) |
| `/metrics` | **404** |
| `X-Forwarded-Proto` not `https` | `GET`/`HEAD`: **308** to `https://<X-Forwarded-Host or Host><path>?<query>`; other methods **403** |
| everything else (console, `/api/*` admin routes, `/auth/*`, `/api/auth/*`) | as on the main listener, plus `Strict-Transport-Security: max-age=31536000`; cookies `Secure` |
| `GET /api/system` (viewer) | gains `console_proxy: {listen, trusted_proxies}` when configured |

Client address on that listener (trusted proxy only): right-most `X-Forwarded-For` entry that is
not a trusted proxy, else `X-Real-IP`, else the proxy. It keys the sign-in rate limit and appears
in logs. The main listener never reads `X-Forwarded-*` / `X-Real-IP`.
