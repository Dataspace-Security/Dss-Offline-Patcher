# Contabo Dataspace / Temps deployment requirements

Assessment date: 19 October 2026. Target: `169.58.36.46`.
Status: Temps project `dss-offline-patcher` (ID 12) and its production
environment (ID 18) exist. The app is not live. SQLite was selected and the
project's temporary PostgreSQL link was removed. The existing release archive
and checksum file are staged under `/home/deploy/offpatch/releases/`.

## 1. Verified environment

| Item | Observed state |
|---|---|
| Host | Ubuntu 24.04.4 LTS, x86_64 |
| Capacity | 6 vCPUs, about 11 GiB RAM; 7.9 GiB available at inspection |
| Disk | 193 GB filesystem; about 96 GB free; shared with existing applications |
| Platform | Temps systemd service; Docker Compose v5.3.1 available |
| Temps binary | v0.1.0-nightly.20261018.d438f7b09 |
| Existing listeners | Temps uses 80/443; console uses 8081 |
| App port | No listener observed on 8443; external firewall reachability untested |
| Time | Host reports NTP synchronized |
| Deployment access | SSH and Docker access work as `deploy`; passwordless sudo unavailable |
| Temps integration | Authenticated CLI context `dataspace-ai-harness`; browser shows Harness connected |
| Existing project | `dss-offline-patcher`, ID 12; production environment ID 18 |

Measurements are a snapshot, not a capacity guarantee. Leave headroom for
existing services, image builds, downloaded patches and backups.

## 2. Application and release

- Source repository: `https://github.com/Dataspace-Security/Dss-Offline-Patcher`.
- Inspected checkout commit: `927542f`. Choose and record the deployment commit
  or release; an existing archive is not proof that it matches every source file.
- Available release: `offpatch-0.9.0-linux-amd64.tar.gz` (~37 MB).
- SHA-256 verified locally and after upload:
  `fbe1a70524ae98c015add3b96a93e3cda7d2db8a23b5603fa3240734fe6f81f7`.
- Extracted `pmserver` and `pmctl` contain `go1.27.2` metadata. This addresses the
  older toolchain requirement recorded in the repository; a fresh vulnerability
  scan is still part of release verification.
- `pmserver` includes the built React console. No separate Node runtime,
  frontend hosting, PostgreSQL or Redis is required at runtime.
- Build from source: Go 1.27.2 or later and the locked Node/npm frontend build.
  Existing Dockerfile: `packaging/server/Dockerfile`, context repository root.
  Already pins `golang:1.27.2-alpine` (no longer the floating `1.27-alpine` tag);
  that pin is still a mutable tag, not a digest — pin to an approved digest for
  stronger build reproducibility if required. Keep secrets and local release/data
  directories out of the build context.
- The existing server image does not include `pmctl`, an acquisition scheduler,
  or endpoint distribution binaries. Package these separately; stage the
  release's Windows/Linux/macOS agents in the persistent `agent-dist` directory.

## 3. Temps project requirements

### Selected database: SQLite

The deployment uses the existing SQLite implementation. PostgreSQL migration
changes were reverted at the user's request. The dedicated Temps project was
unlinked from PostgreSQL; the existing PostgreSQL and Dragonfly services remain
in use by their other applications.

A new `pm.db` is created in the management server's persistent data volume.
Only one management instance runs. Use `pmserver backup` and `verify-backup`
for consistent snapshots; never store the live database in the container layer.

### Deployment configuration

Recommended implementation to validate: a Temps Docker Compose project with
management server, acquisition worker and scheduled backup job. This is a
proposal, not a tested configuration on the installed nightly.

- Confirm authenticated Temps access that can create projects, set secrets,
  configure Compose and deploy. Verify the Git provider can access this repo,
  or use the documented uploaded/pasted Compose workflow.
- Use one production environment, one server replica and no idle/sleep mode.
  SQLite requires a single active management instance; disable automatic
  previews initially so they cannot share production keys or volumes.
- Persist named volumes across replacement and redeploy. Explicitly test the
  installed nightly's Compose behavior before relying on it.
- Temps' Compose policy restricts host bind mounts to the checkout and rejects
  host namespace/privileged settings. Design with named volumes and ordinary
  containers; do not assume `/srv` host mounts or host networking are allowed.
- The app reads JSON configuration, not generic `PORT`/database variables.
  Provide a protected config file and explicitly configure `0.0.0.0:8443`.
- Set measured CPU/memory limits for server, downloader and backups. A suggested
  small-pilot starting budget is 2 vCPUs / 2 GiB RAM total, subject to load and
  download tests; this is not a benchmarked minimum.
- Temps Compose replacements have a brief outage. Schedule deployments and
  take an application backup before upgrades; preserve previous image digests.

## 4. Network and TLS — unresolved deployment dependency

The existing production agent middleware reads verified TLS client certificates
from `r.TLS.VerifiedChains`. It does not accept forwarded client-certificate
headers as device identity. Plain HTTP is explicitly a lab mode.

Temps' documented normal proxy terminates TLS and performs HTTP readiness checks.
Consequently, a standard domain pointing at this app does not establish the
required end-to-end agent mTLS. Backend HTTPS alone also does not preserve the
original client's certificate. TCP passthrough has not been verified.

Before deployment, select and test an access architecture:

1. Preferred candidate: Temps manages the containers; agents and administrators
   reach the app's native TLS listener through a private/VPN route or restricted
   direct port. Verify whether Temps preserves the required port mapping rather
   than rewriting it to its web proxy's dynamic localhost port.
2. Alternatively, prove a supported TCP passthrough route on the installed
   platform/edge. Do not infer this from normal automatic HTTPS support.
3. If only the standard HTTP proxy is available, application/network changes
   are necessary before production agent enrollment. Do not use lab bearer
   mode merely to make the web deployment pass health checks.

Required inputs: final domain/IP, DNS control, admin and endpoint network CIDRs,
VPN/private connectivity, and whether this is a demo/pilot or isolated production.
Use certificate SANs for the selected names and IPs. Distribute/pin the internal
CA on clients. Configure an HTTPS `/auth/config` readiness probe and verify that
Temps accepts its scheme and internal CA, or implement an appropriate probe.
The distroless image has no shell/curl or built-in Docker health check.

Only the acquisition worker needs vendor HTTPS and DNS. Enforce management
egress restrictions while preserving any explicitly required IdP, SMTP, SIEM
and backup connectivity. Existing host services must retain their connectivity.
The installer's UID-based nftables rules are not automatically supplied by a
Temps deployment. Container networks must be tested for equivalent isolation.

Truly disconnected endpoints require the management server within their
reachable isolated network. Public Contabo hosting alone does not create an
air gap. A strict two-machine installation additionally needs a selected
one-way transfer mechanism and an internal management host.

## 5. Persistence, secrets and ownership

| Storage | Container location / contents | Requirement |
|---|---|---|
| Server configuration/PKI | `/etc/offpatch-server`: JSON config, public trust keys, CA and server certificates/keys | Persistent; protected; initialize before first service start |
| Server state | `/var/lib/offpatch-server`: SQLite, repository, quarantine/inbox, MFA/audit keys, agent-dist | Persistent; writable only as required |
| Acquisition | Separate config, bundle signing key, sequence state, downloads, runs, receipts/status | Persistent; signing key unavailable to management container |
| Transfer | Server inbox and acquisition request directory | Shared only between required components, with tested ownership |
| Audit export | Configured `audit_export_dir` | Persistent; replicate to independent/WORM storage |
| Backups | Separate backup destination | Persistent; encrypted off-host copy |

The packaged server runs as UID/GID 65532. Initialize volume ownership so that
PKI initialization, SQLite writes and shared inbox/request access succeed.
The downloader should run separately without access to the server database or
CA private key. Keep all private keys out of Git, images and build arguments.
Named Docker volumes on this VPS remain on the same underlying disk.

Required secrets: bundle signing key, offline root signing key (kept offline),
CA/server private keys, generated admin credential, MFA encryption key,
audit signing key and optional metrics token. Optional integrations add OIDC,
SMTP, SIEM and off-host backup credentials. Use the application's actual config
fields or mounted files; environment variables alone do not configure them.

## 6. Acquisition and disk budget

- Run `pmctl auto` hourly, prevent overlapping runs, and process queued console
  requests promptly. Persist source ID, sequence state and receipts.
- Configure `acquisition_requests_dir` and shared request paths. Mount the
  base acquisition config read-only for the server and set
  `OFFPATCH_ACQUIRE_CONFIG` if it is not `/etc/offpatch/acquire.json`.
- Declare `deployment_mode: single-server` when both roles share this VPS;
  do not label separate containers as a two-machine isolated installation.
- Select actual Windows versions/builds, architectures, Linux/macOS needs and
  third-party apps. Avoid downloading an assumed fleet's entire patch set.
- Set download/run retention, version retention, bundle size limits and intake
  quotas; choose concurrency and bandwidth limits for the target sites.
- Size disk for retained repository content + quarantine/inbox + acquisition
  downloads/bundles + local backup copies + build/image overhead. The roughly
  96 GB free disk cannot all be allocated to this app. Agree the patch catalogue
  and retention before choosing a safe maximum; configure low-disk alerts.

## 7. Access and operational policy

- Create the initial super admin with a generated credential, require a password
  change, and require MFA. Decide whether local authentication or OIDC is used.
- Identify administrators and approvers. Configure separation of duties and
  deployment approvals (default two people distinct from the creator).
- Choose pilot endpoints, maintenance windows/time zones, reboot rules,
  deadlines, rate limits and support/recovery owners.
- Select an intake scanner if required. The current distroless image cannot run
  an arbitrary host scanner; package the selected integration explicitly.
- Set audit retention (configured pruning requires at least 30 days), independent
  audit export destination, notification routing and certificate renewal owner.
- Confirm fleet size/site count, expected download volume, acceptable outage,
  recovery point objective and recovery time objective.

## 8. Backup and acceptance criteria

- Schedule `pmserver backup` daily followed by `verify-backup`; retain an agreed
  number (installer default 14), alert on failure, and copy encrypted backups
  off the VPS. Temps does not automatically back up Compose named volumes.
- Include DB, content, config, matching MFA key and PKI. Separately preserve
  acquisition config/signing key/sequence state and offline root custody.
- Perform a restore exercise in an isolated test environment. A Temps image
  rollback is not a database/content restore or an endpoint patch rollback.
- Verify login/MFA, roles/approval rules, staged agent binary downloads, real
  mTLS enrollment, check-in and certificate renewal.
- Verify signed bundle acquisition, quarantine, approval and a pilot install
  with post-install verification; reject invalid signatures and missing client
  certificates. Exercise acquisition requests and stale-source alerts.
- Redeploy/restart and prove volumes, identity, policies and records survive.
  Test resource use and large patch downloads on this VPS.
- Repository roadmap still records real Windows installer/service validation,
  operational exercises and security review as pilot prerequisites. Check their
  current evidence before promoting the deployment to production.

## 9. Inputs still needed

1. Intended environment: demonstration, pilot or production; truly isolated or VPN-connected endpoints.
2. Final domain, DNS access, administrator/endpoint CIDRs and network/VPN path.
3. Fleet size, supported OS/builds/architectures and required app patch catalogue.
4. Admin/approver identities, local versus OIDC login, maintenance/reboot policy.
5. Patch/backup/audit retention, off-host destinations, RPO/RTO and alert recipients.
6. Authenticated Temps deployment access and a verified mTLS-compatible ingress path.

## References

Repository: `README.md`, `packaging/server/Dockerfile`, `internal/server/config.go`,
`internal/server/server.go`, `docs/06-roadmap.md`, `docs/09-capacity.md`,
and runbooks 01, 02, 03, 05, 07 and 09.

- [Temps Docker Compose](https://temps.sh/docs/deploy-docker-compose)
- [Temps Docker containers and readiness checks](https://temps.sh/docs/docker-containers)
- [Temps request flow and TLS termination](https://temps.sh/docs/request-flow)

Public documentation describes current upstream behavior; installed-nightly
compatibility and actual ingress behavior still require deployment-time tests.
