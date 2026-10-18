// Types copied verbatim from docs/05-api.md (only `export` added), including
// the "v1.1 additions" section.

export type Summary = {
  endpoints: { total: number; by_status: Record<EndpointStatus, number>; retired?: number };
  packages: Record<PackageState, number>;
  bundles: Record<BundleState, number>;
  deployments: Record<DeploymentState, number>;
  active_exceptions: number;
  audit: { ok: boolean; count: number };
  /** P2: age of the update intelligence (absent on older servers / without intelligence). stale = older than 8 days. */
  intel?: { generated_at: string; age_hours: number; stale: boolean } | null;
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
export type PackageKind = "msu" | "msi" | "deb" | "rpm" | "pkg" | "agent"
  | "exe"; // EXE contract: signed vendor EXE installer (Inno Setup / Nullsoft / WiX Burn / plain EXE)
/** EXE contract: installer technology of an exe-kind package (winget InstallerType). */
export type ExeInstallerType = "exe" | "inno" | "nullsoft" | "burn";
/** EXE contract: manifest.ExeInstall (present only on kind "exe"). */
export type ExeInstall = {
  installer_type: ExeInstallerType;
  silent_args: string[]; // argv, no shell
  success_codes: number[]; // always includes 0; 3010 / 1641 = installed, restart needed
  busy_codes?: number[]; // "installer busy / package in use": retried later
  signer: string; // Authenticode subject CN that pmctl verified
  detect: { display_name: string; display_version?: string; product_code?: string; publisher?: string };
  uninstall: { quiet_uninstall: boolean }; // false = rollback not supported
  scope: "machine";
};
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
  // v1.2: why a rollback deployment is impossible ("" = supported: msu, msi, deb, rpm)
  rollback_unsupported: string;
  // EXE contract (assumed server field: store.Package gains `exe` from the manifest, omitted for other kinds)
  exe?: ExeInstall | null;
};

export type EndpointStatus = "compliant" | "noncompliant" | "pending_reboot" | "failed" | "exception" | "stale" | "offline" | "retired"
  | "lost_after_install" // v1.2
  | "updates_available" | "out_of_support" | "awaiting_checkin"; // P1: honest status (was "compliant" / never checked in)
export type Endpoint = {
  endpoint_id: string; hostname: string; os: string; os_version: string; build: number; arch: string;
  groups: string[]; site: string; owner: string; criticality: string;
  last_seen: string; inventory_at: string; reboot_pending: boolean; agent_version: string;
  enrolled_at: string; status: EndpointStatus;
  // v1.1
  edition: string; cert_not_after: string; retired_at: string; retired_reason: string; reboot_requested_at: string;
  hardware?: Hardware;
  // UX iteration: counts from update intelligence + catalog (null without intelligence)
  missing?: EndpointMissing | null;
};
export type Hardware = {
  manufacturer?: string; model?: string; serial_number?: string; cpu?: string; cpu_cores?: number; memory_bytes?: number;
  disks?: { mount: string; total_bytes: number; free_bytes: number }[];
  ip_addresses?: string[]; mac_address?: string; boot_time?: string; logged_in_user?: string; timezone?: string;
};
export type InventoryItem = { kind: "kb" | "product" | "pkg" | "app" | "agent"; id: string; name: string; version: string; source?: "appstore";
  /** P2: "user" = per-user install (one user's profile); empty = whole machine. */
  scope?: "user" | "";
};
export type EndpointDetail = Endpoint & { inventory: InventoryItem[]; targets: Target[] };

// Roles contract: every deployment / rollback starts in pending_approval; rejected is final.
export type DeploymentState = "pending_approval" | "active" | "paused" | "cancelled" | "completed" | "rejected";
export type TargetState = "pending" | "downloading" | "downloaded" | "installing" | "installed"
  | "pending_reboot" | "verified" | "failed" | "not_applicable" | "exception"
  | "deferred" | "lost_after_install" | "rolled_back"; // v1.2
export type DeploymentOperation = "install" | "rollback"; // v1.2
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
  // v1.2 (default "install"; "rollback" requires a justification)
  operation?: DeploymentOperation;
  // P1: when true the next stage starts by itself once the current one finished without too many failures
  auto_advance?: boolean;
};
export type Deployment = NewDeployment & {
  deployment_id: string; state: DeploymentState; current_ring: number; state_reason: string;
  created_by: string; created_at: string; updated_at: string;
  counts: Partial<Record<TargetState, number>>;
  // Roles contract: 2-person approval of deployments and rollbacks (absent on older servers).
  approvals?: DeploymentApproval[] | null; approvals_required?: number;
  rejected_by?: string; rejected_at?: string;
};
export type DeploymentApproval = { by: string; at: string; reason: string };
export type Target = {
  deployment_id: string; package_id: string; endpoint_id: string; hostname: string; ring: number;
  state: TargetState; attempts: number; detail: string; exit_code: number; updated_at: string;
  // v1.1
  health: "" | "ok" | "failed"; health_detail: string;
  // v1.2: the deployment's operation
  operation: DeploymentOperation;
  live?: TargetLive | null; // UX iteration: live progress from heartbeats
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
  // v1.2: "rollback" = uninstall (url is empty: nothing to download)
  operation?: "rollback";
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
  ca_sha256?: string; // upper-case hex SHA-256 of the CA certificate (DER)
  root_public_key?: string; // PEM; "" when no root key is configured
  windows_bootstrap?: boolean; // pmagent.exe staged and CA served in the TLS chain
  server_cert_hosts?: string[]; // DNS names / IPs in the server certificate
};

// ---- auth & users (v1.1 B2/C8, roles contract) ----
/** The four roles, lowest to highest. */
export type Role = "viewer" | "user" | "admin" | "super_admin";
export type AuthKind = "password" | "sso";
/** GET /api/me. `auth` / `must_change_password` come with the roles contract; `source` / `mfa` from older servers. */
export type Me = {
  user: string; role: Role; auth: AuthKind; must_change_password: boolean;
  /** Sign-in e-mail of password users (owner change 2026-10-18). */
  email?: string;
  display_name?: string; source?: string; mfa?: boolean;
  /** Authenticator-app MFA: set up for this account / required for its role (bank roles yes, super admin optional). */
  mfa_enrolled?: boolean; mfa_required?: boolean;
  /** Assumed: "" / absent while the built-in super admin still has the installer's password; `builtin` marks that account. */
  password_changed_at?: string; builtin?: boolean;
};
export type AuthConfig = { sso: boolean; require_mfa: boolean; /** Server version, when the server reports it. */ version?: string };
export type LogoutResponse = { end_session_url?: string };
/** GET /api/users: local (e-mail + password) users and SSO users; never password hashes. */
export type User = {
  /** Local users are identified by `email`; SSO users by `username` (older servers: username only). */
  username?: string; role: Role; display_name?: string;
  /** "local" / "password" = username + password; anything else (e.g. "sso", an issuer) = single sign-on. */
  source: string; email?: string; mfa?: boolean; mfa_enrolled?: boolean;
  first_login?: string; last_login: string; disabled: boolean; disabled_reason?: string; active_sessions?: number;
  must_change_password?: boolean; locked_until?: string; created_by?: string; created_at?: string;
};
/** POST /api/users and /reset_password may echo the temporary password; otherwise the one the console sent is shown. */
export type UserWriteResponse = Partial<User> & { temp_password?: string; password?: string };

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
// P2: the denominator is the machines that NEED a package (targeted or not); outstanding includes needed machines without a target.
// `needed` (when the server sends it) is that denominator; older servers only send `targets`.
export type SeverityStats = { targets: number; verified: number; outstanding: number; overdue: number; exceptions: number; pct_compliant: number; needed?: number };
export type PackageReport = {
  package_id: string; title: string; severity: string; state: string; release_date: string; deadline: string;
  received_at: string; approved_at: string; first_verified_at: string; p90_verified_at: string;
  targets: number; verified: number; outstanding: number; overdue: number; exceptions: number; pct_compliant: number;
  needed?: number; // P2: machines that need it (denominator), targeted or not
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
  // P2: alerts about endpoints carry their ids; condition-based alerts close themselves.
  details?: { endpoint_ids?: string[]; hostnames?: string[] } & Record<string, unknown>;
  resolved_at?: string; resolved_by?: string;
};

// ---- Console-only helper types (not part of the API contract) ----
export type AuditVerify = { ok: boolean; count: number; first_bad_seq: number; error: string };
export type EnrollmentToken = { token: string; expires_at: string; max_uses: number };

// ---- update intelligence (GET /api/endpoints/{id}/updates, /api/updates) ----
export type IntelSummary = {
  source: string; key_id: string; generated_at: string; received_at: string;
  windows: number; apps: number; apps_source?: string; warnings?: string[];
  error?: string; // set when the stored document cannot be used (e.g. its key was revoked)
};
export type CatalogLink = { package_id: string; state: string };
export type OSUpdate = {
  product: string; build: number; server?: boolean; arch: string; kb: string; ubr?: number;
  release_date?: string; title: string; size_mb?: number; installed_ubr: number; catalog: CatalogLink | null;
  basis: "build_revision" | "kb_inventory";
};
export type AppUpdate = {
  app_id: string; name: string; installed_name: string; installed_version: string; latest_version: string;
  matched_by: "product_code" | "name"; product_code?: string; catalog: CatalogLink | null;
  /** EXE contract (assumed server fields, same values as the Library): "no" = Import is not offered. */
  importable?: Importable; importable_reason?: string;
};
export type EndpointUpdates = { intel: IntelSummary | null; os: OSUpdate[]; apps: AppUpdate[]; current: number; unmatched: number };
export type AcquisitionRequest = {
  format: string; version: number; request_id: string; created_at: string; created_by: string; intel_generated_at?: string;
  apps: { winget_id: string; name?: string; version: string; architectures: string[];
    installed?: { product_code?: string; name: string; version: string }[]; endpoints: number }[];
  kbs: { kb: string; product?: string; title?: string; build: number; arch: string; server?: boolean; endpoints: number }[];
  /** POST response only: where the server queued the request directly ("" = strict one-way, carry the file). */
  queued_to?: string;
};
export type FleetUpdates = {
  intel: IntelSummary | null;
  updates: { kind: "os" | "app"; key: string; name: string; latest: string; catalog: CatalogLink | null;
    requested?: AcquisitionRequestRef | null; // latest export listing it
    /** EXE contract (assumed server fields, same values as the Library): "no" = Import is not offered. */
    importable?: Importable; importable_reason?: string;
    endpoints: { endpoint_id: string; hostname: string; installed: string }[] }[];
};

// ---- UX iteration (docs/proposals/ux-simplification.md, contract: docs/proposals/ux-api-contract.md) ----

/** GET /api/policy (viewer). Durations are Go strings, e.g. "168h0m0s". */
export type Policy = {
  approvals_required: Record<string, number>; // by severity; missing = 1
  separation_of_duties: boolean;
  deadlines: Record<string, string>; // by severity: release date + this = install deadline
  /** Roles contract: approvals every deployment / rollback needs before it starts (default 2). */
  deployment_approvals?: number;
};

/** GET /api/packages-needs → Record<package_id, PackageFleet> (extended; old fields kept). */
export type PackageFleet = {
  package_id: string;
  needed: number; endpoint_ids: string[]; hostnames: string[]; // endpoints that still need it (unchanged meaning)
  up_to_date: number;    // inventory shows it (or a superseding KB / newer version)
  not_installed: number; // third-party app not on the endpoint (never targeted)
  up_to_date_ids: string[]; not_installed_ids: string[]; // which endpoints those are
  deploying: number;     // targets pending..installed / pending_reboot in an active or paused deployment
  verified: number;      // targets verified (any deployment, operation install)
  failed: number;        // targets failed / lost_after_install
  exception: number;     // active exceptions
  active_deployment_id: string; // "" if none (active or paused, operation install)
};

/** Endpoint gains `missing` (null/absent when there is no update intelligence). */
export type EndpointMissing = { os: number; apps: number; ready: number; catalog?: number; // catalog = approved + awaiting-approval packages it needs
  os_support?: "supported" | "out_of_support" | ""; os_last_update?: string; // Windows build still receives updates? (date of its newest cumulative update)
}; // ready = approved catalog packages it needs

/** GET /api/fleet/status (viewer): one row per KB or app across the fleet. */
export type FleetStatusEndpoint = {
  endpoint_id: string; hostname: string;
  status: "up_to_date" | "outdated" | "being_patched" | "verified" | "failed" | "exception";
  installed: string; // installed version or OS version
};
export type FleetStatusRow = {
  kind: "os" | "app"; key: string; name: string; latest: string;
  catalog: CatalogLink | null;
  requested: AcquisitionRequestRef | null;
  /** EXE contract (assumed server fields, same values as the Library): "no" = Import is not offered. */
  importable?: Importable; importable_reason?: string;
  up_to_date: number; outdated: number; being_patched: number; verified: number; failed: number; exception: number;
  endpoints: FleetStatusEndpoint[];
};
export type FleetStatus = { intel: IntelSummary | null; rows: FleetStatusRow[] };

/** Acquisition request tracking (P2.3). */
export type AcquisitionStatus = "requested" | "seen" | "fulfilled" | "unsupported" | "failed"
  | "stale"; // P2: a later acquisition run did not pick the request up (reason says which run)
/** unsupported = can never be fetched this way; failed = transient, may succeed next run. `reason` explains both. */
export type AcquisitionRequestRef = { request_id: string; at: string; status: AcquisitionStatus; reason?: string };
export type AcquisitionRequestItem = { kind: "app" | "kb"; key: string; version: string; status: AcquisitionStatus; fulfilled_at: string; package_id: string; reason?: string };
export type AcquisitionRequestRecord = {
  request_id: string; created_at: string; created_by: string; intel_generated_at: string;
  seen_at: string; // first acquisition status report that lists it ("" if none)
  items: AcquisitionRequestItem[];
};

/** Live progress of a target (in memory on the server, from agent heartbeats; not audited). */
export type TargetLive = {
  stage: "downloading" | "verifying" | "installing" | "waiting_reboot";
  pct: number;            // 0..100 for downloading, -1 when unknown
  bytes_done: number; bytes_total: number;
  at: string;             // last heartbeat time
};

// ---- P2: Library (GET /api/library, GET /api/library/{kind}/{id}) ----

export type LibraryKind = "app" | "os";
export type LibraryView = "available" | "installed" | "catalog" | "all";
export type LibrarySort = "installed" | "name" | "date";
export type Importable = "yes" | "no" | "unknown";
export type LibraryInstaller = {
  arch: string; type: string; scope?: string; url: string; sha256?: string; product_code?: string;
};
export type LibraryItem = {
  kind: LibraryKind; id: string; name: string; publisher: string; latest_version: string; description: string;
  /** Untrusted community links (https only, ≤ 2 KB; empty when absent). */
  links: { homepage?: string; publisher_url?: string; manifest?: string };
  installers: LibraryInstaller[] | null; resolved_at: string;
  importable: Importable; importable_reason: string;
  installed: { endpoints: number; outdated: number };
  catalog: CatalogLink | null;
  requested: AcquisitionRequestRef | null;
};
export type LibraryPage = {
  source: string; generated_at: string; total: number; page: number; per_page: number; items: LibraryItem[];
};
export type LibraryItemDetail = LibraryItem & {
  endpoints: { endpoint_id: string; hostname: string; installed_version: string; outdated: boolean }[];
};
