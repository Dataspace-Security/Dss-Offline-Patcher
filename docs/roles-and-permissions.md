# Roles and permissions (DSS Patcher console)

Who can see and do what in the console. The server is the security boundary:
every API route names the lowest role allowed (`internal/server/server.go`,
`Handler()`), and the console only shows a control to a role the server
accepts it from. Hiding a button is a convenience, not the protection.

## The four roles

| Role | Who | In one line |
|---|---|---|
| **Viewer** | Bank staff who only need to look | Sees everything except the Library and Imports (no secrets). Has no action buttons at all. |
| **User** | Bank operators | Imports patches, approves packages, plans deployments and rollbacks, approves other people's deployments. |
| **Admin** | Bank administrators | Everything a User can do, plus the bank's users, exceptions and revoking packages. |
| **Super admin** | The vendor (setup and support) | Everything, including server settings, agent versions, the Library and all users. **Does not approve deployments**, agent-version deployments included (that is the bank's two-person rule). |

These four are the only roles (the old names `operator` and `approver` were removed; the server refuses to start if the config or SSO `role_groups` still use them, and stored users are moved to User). Sign-in is e-mail + password with an authenticator-app code (required for Viewer, User and Admin; optional for the Super admin unless the server sets `require_mfa`) or single sign-on. There is no token sign-in: static admin tokens were removed.

## Two rules that are not just "higher role can do more"

1. **Deployment and rollback approval (two-person rule).** A new deployment or
   rollback waits for approval (default: 2 approvals). Only a **User or Admin**
   can approve or reject it, and only if they **did not create it** and **have
   not approved it already**. The Super admin and Viewers cannot approve.
   **Agent versions** (packages of kind `agent`, `offpatch-agent-*`) are the
   vendor's: only the Super admin approves, rejects, revokes and deploys or
   rolls them back, and only bank **Admins** (not Users, not the Super admin,
   not the creator) approve or reject such a deployment.
   The creator sees "You created this — 2 other people must approve".
   An approval must come from someone the creator does not control: it is
   refused from an account whose password, MFA or role was last set (or
   which was created) by the deployment's creator, and from a second account
   set up by the same person as an earlier approver when both were set up in
   the last 7 days. Accounts one admin created months ago approve normally.
   An approval from an account set up in the last 7 days raises a critical
   alert. Approval fixes the endpoints: machines added to the deployment's
   groups afterwards are left out (shown on the deployment) and need a new
   deployment.
2. **Admins manage bank roles only.** An Admin can create users and give them
   Viewer, User or Admin. Only the Super admin can see, create, change or
   disable a Super admin account, or give someone that role. Only the Super
   admin resets another Admin's password or MFA or changes an Admin's role
   (an Admin who could sign in as a colleague could approve twice). Nobody can disable
   or demote themselves. Delete works only for e-mail + password users (SSO
   users: disable), never on yourself and never on the last Super admin; the
   audit history of a deleted user is kept.
3. **Reports are for everyone.** Every signed-in role (Viewer and up) sees
   and downloads the whole Reports area: patch compliance and its CSVs and
   PDF, the auditor compliance report (PDF and signed evidence ZIP), the
   report profile (read; Admins and the Super admin edit it), the audit
   trail (browse, verify, lifecycle export, PDF of a period). Exceptions live
   under Deployments → Exceptions for every role.
4. **The Library is the vendor's.** The Library (everything that could be
   imported, including software no machine has yet) is a **Super admin**
   tool: tab, drawer and Import-from-Library. Bank Users and Admins import
   only what their machines need (Patches → Needed, endpoint Updates);
   the server refuses a bank import of a Library-only item or with
   `app_archs` (403, audited). Imports (what was asked for, downloaded and
   received) is for User and up.

## Pages and navigation

| Page / tab | Viewer | User | Admin | Super admin |
|---|:-:|:-:|:-:|:-:|
| Overview → Summary, Your work, Alerts | ✓ | ✓ | ✓ | ✓ |
| Patches → "How patches flow" guide (what this role can do at each step; Hide / "How patches flow" to show again) | ✓ | ✓ | ✓ | ✓ |
| Patches → Needed, Catalog | ✓ (read only) | ✓ | ✓ | ✓ |
| Patches → Imports | — (opens Needed) | ✓ | ✓ | ✓ |
| Patches → Library (and Library links on Needed, Imports, Overview) | — (opens Needed) | — (opens Needed) | — (opens Needed) | ✓ |
| Overview → Supply chain: last download run, imports waiting, "Imports →" | — (update information and bundles only) | ✓ | ✓ | ✓ |
| Deployments → list, detail, Maintenance windows, Exceptions | ✓ | ✓ | ✓ | ✓ |
| Deployments → New deployment form | — | ✓ | ✓ | ✓ |
| Endpoints → list, endpoint detail | ✓ | ✓ | ✓ | ✓ |
| Endpoints → Add endpoints (agent setup guide) | — | ✓ | ✓ | ✓ |
| Reports → Patch compliance, Compliance report, Report profile (read), Audit | ✓ | ✓ | ✓ | ✓ |
| Overview → Recent activity (audit feed), "overdue endpoint-patches" in Your work; compliance gauge opens Reports | ✓ | ✓ | ✓ | ✓ |
| Catalog → package Lifecycle, "Audit trail for this package →"; deployment "Audit trail →" | ✓ | ✓ | ✓ | ✓ |
| Settings (sidebar item) | — | — | ✓ (opens Users) | ✓ (opens Server) |
| Settings → Users | — | — | ✓ (bank roles only) | ✓ (all users) |
| Settings → Server | — | — | — | ✓ |
| Settings → Agent versions | — | — | — | ✓ |
| Settings → Auto-download (what the downloader fetches every run; server: 403 for bank roles) | — | — | — | ✓ |

## Actions

✓ = shown and allowed; — = not shown. "(own)" and similar notes are extra conditions.

### Overview

| Action | Viewer | User | Admin | Super admin |
|---|:-:|:-:|:-:|:-:|
| Acknowledge an alert | — | ✓ | ✓ | ✓ |
| "Your work": deployments waiting for my approval | — | ✓ | ✓ | — |
| "Your work": packages awaiting approval, approved & not deployed, stages / pauses / failed retries | — | ✓ (no agent versions) | ✓ (no agent versions) | ✓ |
| "Your work": first-run links (create enrollment token, Import) | — (plain text instead) | ✓ | ✓ | ✓ |

### Patches

| Action | Viewer | User | Admin | Super admin |
|---|:-:|:-:|:-:|:-:|
| Import an update / app your machines have or need (Needed, endpoint Updates, Imports "Ask again"), incl. bulk Import on Needed | — | ✓ | ✓ | ✓ |
| Import from the Library (software no machine has, architecture picker) | — | — (server: 403) | — (server: 403) | ✓ |
| Approve / reject a package (Catalog, "Review & approve", Patch this) | — | ✓ | ✓ | ✓ |
| Revoke an approved package | — | — | ✓ | ✓ |
| Patch this… (guided deployment) | — | ✓ | ✓ | ✓ |
| Roll back… a package | — | ✓ | ✓ | ✓ |
| Agent versions: approve, reject, deploy, roll back, revoke | — | — | — | ✓ |

### Deployments

| Action | Viewer | User | Admin | Super admin |
|---|:-:|:-:|:-:|:-:|
| New deployment / rollback (starts "waiting for approval") | — | ✓ | ✓ | ✓ |
| Approve / reject a waiting deployment or rollback | — | ✓ not the creator, not already approved | ✓ not the creator, not already approved | — |
| New deployment / rollback of an **agent version** (`kind` agent, `offpatch-agent-*`) | — | — | — | ✓ (server: 403 "agent versions are managed by the vendor (super admin)" for bank roles) |
| Approve / reject a waiting **agent-version** deployment or rollback | — | — (403 "agent version deployments are approved by bank admins") | ✓ not the creator, not already approved; `deployment_approvals` bank admins needed | — |
| Pause, resume, start next stage, retry failed, cancel (incl. a waiting one) | — | ✓ (not agent versions) | ✓ (not agent versions) | ✓ |
| Raise an exception for a failed target | — | "Ask an Admin…" (copyable text, no change) | ✓ | ✓ |
| Deployments → Exceptions: create / revoke an exception | — (read only) | — (read only) | ✓ | ✓ |
| Create / delete a maintenance window | — | ✓ | ✓ | ✓ |

### Endpoints

| Action | Viewer | User | Admin | Super admin |
|---|:-:|:-:|:-:|:-:|
| Create an enrollment token | — | ✓ | ✓ | ✓ |
| Edit groups / site / owner / criticality (one or bulk "Edit groups…") | — (fields read-only) | ✓ | ✓ | ✓ |
| Retire an endpoint | — | ✓ | ✓ | ✓ |

### Reports

| Action | Viewer | User | Admin | Super admin |
|---|:-:|:-:|:-:|:-:|
| Patch compliance, download CSVs (compliance, endpoints, evidence), Download PDF (server-made file) | ✓ | ✓ | ✓ | ✓ |
| Audit trail: browse, verify chain, export lifecycle JSON, Download PDF of a period | ✓ | ✓ | ✓ | ✓ |

### Settings → Users

| Action | Viewer | User | Admin | Super admin |
|---|:-:|:-:|:-:|:-:|
| See the user list | — | — | ✓ (Super admins hidden) | ✓ |
| Add a user | — | — | ✓ Viewer / User / Admin | ✓ any role |
| Change role, reset password (e-mail + password users) | — | — | ✓ Viewers and Users, not self (not other Admins) | ✓ any, not self |
| Disable / enable a user (incl. SSO users) | — | — | ✓ bank roles, not self | ✓ any, not self |
| Delete an e-mail + password user (confirm, reason optional; Disable is the gentler option; SSO users: disable) | — | — | ✓ bank roles, not self | ✓ any, not self |
| See MFA status (On / Not set up); Reset MFA (e-mail + password users) | — | — | ✓ see all bank roles; reset Viewers and Users, not self (not other Admins) | ✓ any, not self |

### Settings → Auto-download

| Action | Viewer | User | Admin | Super admin |
|---|:-:|:-:|:-:|:-:|
| See the auto-download policy, its history and whether the downloader applied it | — | — | — | ✓ |
| Change and save it (Windows releases, apps, download sources, limits) | — | — | — | ✓ |
| Download the policy file (two machines), hand it over again, Run now | — | — | — | ✓ |

### Everyone

| Action | Viewer | User | Admin | Super admin |
|---|:-:|:-:|:-:|:-:|
| Change own password (e-mail + password sign-in) | ✓ | ✓ | ✓ | ✓ |
| Theme, sign out | ✓ | ✓ | ✓ | ✓ |
| Two-step sign-in (authenticator app) for e-mail + password users | required | required | required | optional (turn on / off own; required if the server sets `require_mfa`) |

### Reports → Compliance report / Report profile

| Action | Viewer | User | Admin | Super admin |
|---|:-:|:-:|:-:|:-:|
| Generate the auditor report, Download PDF, Download evidence package (ZIP) | ✓ | ✓ | ✓ | ✓ |
| Read the report profile and its version history | ✓ | ✓ | ✓ | ✓ |
| Edit and save the report profile | — | — | ✓ | ✓ |

## Server routes behind the actions

| Route | Lowest role |
|---|---|
| All other `GET /api/...` reads, `POST /api/auth/password` | Viewer |
| `POST /api/alerts/{id}/ack`, `POST /api/acquisition-requests` | User (a Library-only item or `app_archs`: Super admin only, 403 "the Library is the vendor's …", audited) |
| `GET /api/acquisition`, `GET /api/acquisition-requests`, `GET /api/bundles`, `GET /api/bundles/{id}`, `GET /api/transfer/reconcile` (Imports) | User |
| `GET /api/library`, `GET /api/library/{kind}/{id}` | Super admin only |
| `POST /api/packages/{id}/approve`, `/reject` | User |
| `POST /api/packages/{id}/revoke` | Admin |
| `POST /api/deployments`, `/{id}/pause\|resume\|cancel\|advance`, `/{id}/retry_failed` | User (agent-version deployments: Super admin only, 403) |
| `POST /api/deployments/{id}/approve`, `/reject` | User or Admin only (`CanApproveDeployments`), never the creator; for an agent-version deployment Admin only; approve: 409 from an account whose credentials the creator set, or a second account freshly set up by the same person |
| `POST /api/packages/{id}/approve\|reject\|revoke`, `POST /api/deployments` (install or rollback) for an agent version | Super admin only |
| `PATCH /api/endpoints/{id}`, `POST /api/endpoints/{id}/retire`, `POST /api/enrollment-tokens` | User |
| `POST /api/maintenance-windows`, `/{id}/delete` | User |
| `POST /api/exceptions`, `/{id}/revoke` | Admin |
| `GET/POST /api/users`, `POST /api/users/{name}/disable\|enable\|reset_password\|set_role\|delete\|reset_mfa` | Admin (Super admin accounts and role: Super admin only; `reset_password`, `reset_mfa`, `set_role` on an Admin: Super admin only; never yourself) |
| `POST /api/auth/login`, `POST /api/auth/mfa` | none (sign-in) |
| `POST /api/auth/mfa/enroll/start`, `/enroll/confirm` | any signed-in e-mail + password user (also the limited first sign-in session) |
| `POST /api/auth/mfa/disable` | Super admin (own authenticator only) |
| `GET /api/exceptions` | Viewer |
| `GET /api/reports/compliance`, `/compliance.csv`, `/endpoints.csv`, `/targets.csv`, `/compliance-pack`, `/compliance-pack.zip`, `GET /api/reports/profile`, `GET /api/reports/profile/history` | Viewer |
| `GET /api/reports/compliance-pack.pdf`, `GET /api/reports/compliance.pdf`, `GET /api/audit.pdf` (server-made PDF files) | Viewer |
| `GET /api/audit`, `/api/audit/verify`, `/api/audit/export` (lifecycle JSON) | Viewer |
| `PUT /api/reports/profile` | Admin |

### Known gaps between console and server

- None for agent versions any more: the server enforces the Super admin and
  bank-Admin rules above (403 "agent versions are managed by the vendor
  (super admin)" / "agent version deployments are approved by bank admins").
- **Settings → Server** reads `GET /api/system`, which any Viewer may call; the
  page is hidden from everyone but the Super admin, but the data is not secret.
