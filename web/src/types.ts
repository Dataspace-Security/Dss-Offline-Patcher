// Types copied verbatim from docs/05-api.md (only `export` added), including
// the "v1.1 additions" section.

export type Summary = {
  endpoints: { total: number; by_status: Record<EndpointStatus, number>; retired?: number };
  packages: Record<PackageState, number>;
  bundles: Record<BundleState, number>;
  deployments: Record<DeploymentState, number>;
  active_exceptions: number;
  audit: { ok: boolean; count: number };
};

export type BundleState = "received" | "validated" | "rejected";
// v1.1: `name` may be "key_status" (signing key active vs. retired).
export type Check = { name: string; ok: boolean; detail: string };
export type Bundle = {
  id: number; bundle_id: string; source: string; sequence: number; key_id: string;
  state: BundleState; filename: string; file_sha256: string; file_size: number;
  received_at: string; package_count: number; checks: Check[]; error: string;
};

export type PackageState = "quarantined" | "approved" | "rejected" | "revoked";
export type PackageKind = "msu" | "msi" | "deb" | "rpm" | "pkg" | "agent";
export type Approval = { by: string; reason: string; at: string };
export type Package = {
  package_id: string; bundle_id: string; title: string; vendor: string;
  kind: PackageKind; version: string; kb: string; product_code: string;
  severity: "critical" | "important" | "moderate" | "low"; release_date: string;
  supersedes: string[];
  applicability: { os: string; arch: string; min_build: number; max_build: number; editions?: string[] };
  file_name: string; size: number; sha256: string; source_url: string;
  vendor_signature: { status: string; signer: string; checked_at: string };
  state: PackageState; state_reason: string; state_by: string; state_at: string; created_at: string;
  // v1.1
  approvals: Approval[]; approvals_required: number;
  package_name: string; prerequisites: string[]; superseded_by: string;
};

export type EndpointStatus = "compliant" | "noncompliant" | "pending_reboot" | "failed" | "exception" | "stale" | "offline" | "retired";
export type Endpoint = {
  endpoint_id: string; hostname: string; os: string; os_version: string; build: number; arch: string;
  groups: string[]; site: string; owner: string; criticality: string;
  last_seen: string; inventory_at: string; reboot_pending: boolean; agent_version: string;
  enrolled_at: string; status: EndpointStatus;
  // v1.1
  edition: string; cert_not_after: string; retired_at: string; retired_reason: string; reboot_requested_at: string;
};
export type InventoryItem = { kind: "kb" | "product"; id: string; name: string; version: string };
export type EndpointDetail = Endpoint & { inventory: InventoryItem[]; targets: Target[] };

export type DeploymentState = "active" | "paused" | "cancelled" | "completed";
export type TargetState = "pending" | "downloading" | "downloaded" | "installing" | "installed"
  | "pending_reboot" | "verified" | "failed" | "not_applicable" | "exception";
export type Ring = { name: string; groups: string[] };
export type HealthCheck = { type: "service_running" | "tcp_listening"; name: string };
export type RebootPolicy = "never" | "in_window" | "at_deadline";
export type NewDeployment = {
  package_id: string; name: string; rings: Ring[]; max_failure_pct: number; max_retries: number;
  window_start: string; window_end: string; // "HH:MM" UTC, both empty = always
  emergency: boolean; justification: string;
  // v1.1
  deadline: string;            // RFC 3339 or "" — after it, maintenance windows no longer hold installs back
  max_concurrent: number;      // 0 = unlimited
  reboot_policy: RebootPolicy;
  ignore_windows: boolean;
  health_checks: HealthCheck[];
};
export type Deployment = NewDeployment & {
  deployment_id: string; state: DeploymentState; current_ring: number; state_reason: string;
  created_by: string; created_at: string; updated_at: string;
  counts: Partial<Record<TargetState, number>>;
};
export type Target = {
  deployment_id: string; package_id: string; endpoint_id: string; hostname: string; ring: number;
  state: TargetState; attempts: number; detail: string; exit_code: number; updated_at: string;
  // v1.1
  health: "" | "ok" | "failed"; health_detail: string;
};
export type DeploymentDetail = Deployment & { targets: Target[] };

export type NewException = {
  endpoint_id: string; package_id: string; // "" = all packages
  owner: string; reason: string; compensating_controls: string; expires_at: string;
};
export type Exception = NewException & {
  exception_id: string; created_by: string; created_at: string; revoked: boolean; active: boolean;
};

export type AuditEvent = {
  seq: number; ts: string; actor: string; action: string; object_type: string; object_id: string;
  outcome: "success" | "failure"; package_id: string; details: Record<string, unknown>;
  prev_hash: string; hash: string;
};

export type Assignment = {
  deployment_id: string; package_id: string; kind: PackageKind; kb: string; product_code: string;
  file_name: string; size: number; sha256: string;
  url: string;          // path on the same server origin, e.g. /api/agent/content/<sha256>
  manifest_url: string; // /api/agent/manifest/<package_id>
  // v1.1
  reboot_allowed?: boolean; health_checks?: HealthCheck[];
};

export type LifecycleExport = {
  generated_at: string; package: Package; bundle: Bundle; deployments: DeploymentDetail[];
  exceptions: Exception[]; events: AuditEvent[]; audit_chain: { ok: boolean; count: number };
};

export type AgentSetup = {
  trusted_keys: { key_id: string; public_key: string; sources: string[] }[]; // public_key is PEM
  tls: boolean;
  checkin_interval_seconds: number;
  agent_files: { name: string; size: number; sha256: string }[];
  agent_dist_dir: string;
  // v1.1
  ca_certificate: string; // PEM; "" in lab mode
};

// ---- v1.1: auth & users (B2, C8) ----
export type Role = "viewer" | "operator" | "approver" | "admin";
export type Me = { user: string; role: Role; source: "sso" | "token"; mfa: boolean };
export type AuthConfig = { sso: boolean; static_tokens: boolean; require_mfa: boolean };
export type LogoutResponse = { end_session_url?: string };
export type User = {
  username: string; role: Role; source: string; email: string; mfa: boolean; first_login: string;
  last_login: string; disabled: boolean; disabled_reason: string; active_sessions: number;
};

// ---- v1.1: maintenance windows (C1) ----
export type Weekday = "mon" | "tue" | "wed" | "thu" | "fri" | "sat" | "sun";
export type MaintenanceWindow = {
  window_id: string; name: string; groups: string[]; days: Weekday[];
  start: string; end: string; /* HH:MM in timezone; may cross midnight */ timezone: string; /* IANA */ allow_reboot: boolean;
  created_by: string; created_at: string;
};
export type NewMaintenanceWindow = Omit<MaintenanceWindow, "window_id" | "created_by" | "created_at">;

// ---- v1.1: transfer reconciliation (B7) ----
export type TransferReceipt = {
  id: number; file: string; file_sha256: string; size: number; adapter: string; sent_at: string;
  received_at: string; key_id: string; signature_ok: boolean;
};
export type Reconciliation = {
  matched: TransferReceipt[]; receipt_without_bundle: TransferReceipt[];
  bundle_without_receipt: Bundle[]; unsigned_or_invalid_receipts: number;
};

// ---- v1.1: reporting (C5) ----
export type SeverityStats = { targets: number; verified: number; outstanding: number; overdue: number; exceptions: number; pct_compliant: number };
export type PackageReport = {
  package_id: string; title: string; severity: string; state: string; release_date: string; deadline: string;
  received_at: string; approved_at: string; first_verified_at: string; p90_verified_at: string;
  targets: number; verified: number; outstanding: number; overdue: number; exceptions: number; pct_compliant: number;
  days_release_to_received: number; days_received_to_approved: number; days_approved_to_first_verified: number;
  days_release_to_90pct_verified: number; /* -1 = not reached */
};
export type ComplianceReport = {
  generated_at: string; deadlines: Record<string, string>; by_severity: Record<string, SeverityStats>;
  packages: PackageReport[];
  fleet: { total: number; reporting: number; offline: number; stale: number; pending_reboot: number; pct_reporting: number };
  exceptions: { active: number; expiring_in_7d: number; oldest_age_days: number };
  intake: { validated: number; rejected: number };
};

// ---- v1.1: alerts (C6) ----
export type Alert = {
  id: number; created_at: string; severity: "info" | "warning" | "critical"; kind: string; message: string;
  object_type: string; object_id: string; acknowledged_by: string; acknowledged_at: string;
};

// ---- Console-only helper types (not part of the API contract) ----
export type AuditVerify = { ok: boolean; count: number; first_bad_seq: number; error: string };
export type EnrollmentToken = { token: string; expires_at: string; max_uses: number };
