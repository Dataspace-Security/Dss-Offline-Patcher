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
| `POST /api/agent/enroll` | enrollment token in body | `{token, hostname, os, os_version, build, arch, agent_version, csr?}` → **201**. **TLS mode** (server has `pki_dir`): `csr` (PEM) is required, response `{endpoint_id, certificate, ca_certificate}`. **Lab mode** (`insecure_http`): response `{endpoint_id, secret}`. Invalid, used or expired token → 401. |
| `POST /api/agent/checkin` | device | `{hostname, os_version, build, arch, agent_version, reboot_pending, edition, inventory: InventoryItem[]}` → `{assignments: Assignment[], checkin_interval_seconds, reboot_now, download_rate_kbps, trust?}` |
| `GET /api/agent/manifest/{package_id}` | device | → `{manifest: base64, signature: base64, key_id}` (the original signed bytes) |
| `GET /api/agent/content/{sha256}` | device | → raw bytes, `Range` supported. Only for an approved package with an open target on this endpoint in an active deployment. |
| `POST /api/agent/report` | device | `{deployment_id, package_id, state, detail, exit_code, health?, health_detail?}` → `{ok}` (`health`: `ok` \| `failed`) |
| `POST /api/agent/renew` | device (mTLS) | `{csr}` → `{certificate, ca_certificate}`. Replaces the endpoint's certificate; the previous one stops working. 409 in lab mode. |

**Device authentication.** TLS mode: the client certificate issued at enrollment (mTLS); its
serial must be the endpoint's current one and the endpoint must not be retired, otherwise 401
`client certificate not valid for an active endpoint`; no certificate → 401
`client certificate required`. Lab mode: `Authorization: Bearer <device secret>`.

Agent-reportable `state`: `downloading`, `downloaded`, `installing`, `installed`, `pending_reboot`, `failed`, `not_applicable`. Only the server sets `verified`.

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
