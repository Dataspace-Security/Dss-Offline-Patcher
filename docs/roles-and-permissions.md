# Roles and permissions (DSS Patcher console)

Who can see and do what in the console. The server is the security boundary:
every API route names the lowest role allowed (`internal/server/server.go`,
`Handler()`), and the console only shows a control to a role the server
accepts it from. Hiding a button is a convenience, not the protection.

## The four roles

| Role | Who | In one line |
|---|---|---|
| **Viewer** | Bank staff who only need to look | Sees everything (no secrets). Has no action buttons at all. |
| **User** | Bank operators | Imports patches, approves packages, plans deployments and rollbacks, approves other people's deployments. |
| **Admin** | Bank administrators | Everything a User can do, plus the bank's users, exceptions and revoking packages. |
| **Super admin** | The vendor (setup and support) | Everything, including server settings, agent versions and all users. **Does not approve deployments** (that is the bank's two-person rule). |

Old role names still work: `operator` and `approver` mean User.

## Two rules that are not just "higher role can do more"

1. **Deployment and rollback approval (two-person rule).** A new deployment or
   rollback waits for approval (default: 2 approvals). Only a **User or Admin**
   can approve or reject it, and only if they **did not create it** and **have
   not approved it already**. The Super admin and Viewers cannot approve.
   The creator sees "You created this — 2 other people must approve".
2. **Admins manage bank roles only.** An Admin can create users and give them
   Viewer, User or Admin. Only the Super admin can see, create, change or
   disable a Super admin account, or give someone that role. Nobody can disable
   or demote themselves.

## Pages and navigation

| Page / tab | Viewer | User | Admin | Super admin |
|---|:-:|:-:|:-:|:-:|
| Overview → Summary, Your work, Alerts | ✓ | ✓ | ✓ | ✓ |
| Patches → Needed, Library, Catalog, Imports | ✓ | ✓ | ✓ | ✓ |
| Deployments → list, detail, Maintenance windows | ✓ | ✓ | ✓ | ✓ |
| Deployments → New deployment form | — | ✓ | ✓ | ✓ |
| Endpoints → list, endpoint detail | ✓ | ✓ | ✓ | ✓ |
| Endpoints → Add endpoints (agent setup guide) | — | ✓ | ✓ | ✓ |
| Reports → Compliance, Exceptions, Audit | ✓ | ✓ | ✓ | ✓ |
| Settings (sidebar item) | — | — | ✓ (opens Users) | ✓ (opens Server) |
| Settings → Users | — | — | ✓ (bank roles only) | ✓ (all users) |
| Settings → Server | — | — | — | ✓ |
| Settings → Agent versions | — | — | — | ✓ |

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
| Import an update / app (Needed, Library drawer, endpoint Updates, Imports "Ask again"), incl. bulk Import on Needed | — | ✓ | ✓ | ✓ |
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
| Pause, resume, start next stage, retry failed, cancel (incl. a waiting one) | — | ✓ | ✓ | ✓ |
| Raise an exception for a failed target | — | "Ask an Admin…" (copyable text, no change) | ✓ | ✓ |
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
| Download CSVs, print / PDF, verify audit chain, export lifecycle JSON | ✓ | ✓ | ✓ | ✓ |
| Create / revoke an exception | — | — | ✓ | ✓ |

### Settings → Users

| Action | Viewer | User | Admin | Super admin |
|---|:-:|:-:|:-:|:-:|
| See the user list | — | — | ✓ (Super admins hidden) | ✓ |
| Add a user | — | — | ✓ Viewer / User / Admin | ✓ any role |
| Change role, reset password (e-mail + password users) | — | — | ✓ bank roles, not self | ✓ any, not self |
| Disable / enable a user (incl. SSO users) | — | — | ✓ bank roles, not self | ✓ any, not self |

### Everyone

| Action | Viewer | User | Admin | Super admin |
|---|:-:|:-:|:-:|:-:|
| Change own password (e-mail + password sign-in) | ✓ | ✓ | ✓ | ✓ |
| Theme, sign out | ✓ | ✓ | ✓ | ✓ |

## Server routes behind the actions

| Route | Lowest role |
|---|---|
| All `GET /api/...` reads, `POST /api/auth/password` | Viewer |
| `POST /api/alerts/{id}/ack`, `POST /api/acquisition-requests` | User |
| `POST /api/packages/{id}/approve`, `/reject` | User |
| `POST /api/packages/{id}/revoke` | Admin |
| `POST /api/deployments`, `/{id}/pause\|resume\|cancel\|advance`, `/{id}/retry_failed` | User |
| `POST /api/deployments/{id}/approve`, `/reject` | User or Admin only (`CanApproveDeployments`), never the creator |
| `PATCH /api/endpoints/{id}`, `POST /api/endpoints/{id}/retire`, `POST /api/enrollment-tokens` | User |
| `POST /api/maintenance-windows`, `/{id}/delete` | User |
| `POST /api/exceptions`, `/{id}/revoke` | Admin |
| `GET/POST /api/users`, `POST /api/users/{name}/disable\|enable\|reset_password\|set_role` | Admin (Super admin accounts and role: Super admin only) |

### Known gaps between console and server

- **Agent versions** are a Super admin task in the console, but the server
  checks only the generic package and deployment routes (User for
  approve/reject/deploy, Admin for revoke). A User calling the API directly
  could approve or deploy an agent package.
- **Settings → Server** reads `GET /api/system`, which any Viewer may call; the
  page is hidden from everyone but the Super admin, but the data is not secret.
