# Runbook 01 — Install the management server (pmserver)

## Purpose

Install `pmserver` in the isolated management zone with TLS, the internal CA for agent mTLS,
an admin login (SSO and/or a break-glass token), staged agent binaries, off-box audit export and
metrics.

## When to use

- First installation (pilot or production).
- Rebuilding a server before a restore (then continue with [runbook 05](05-backup-and-restore.md)).

## Prerequisites and roles

| Item | Notes |
|---|---|
| Linux host in the isolated zone | systemd. A container image is also being prepared (`packaging/server/Dockerfile`). Windows (`pmserver.exe`) builds, but there is no service wrapper for it. |
| OS administrator | Root on the host. Nothing here is done in the console. |
| `pmserver` binary | Built in the build environment with **Go 1.27.2 or later** (`docs/security/README.md` §2.2), e.g. `make release VERSION=x.y.z`. Carry `dist/release/` and its `SHA256SUMS` across the boundary and verify the hashes. |
| `bundle.pub` | Public bundle signing key from the acquisition zone ([runbook 02](02-acquisition-zone-setup-and-monthly-run.md)). Public keys only — never copy a `.key` file into this zone. |
| `root.pub` | Public **root** key for signed key rotation (runbook 02/03). Strongly recommended. |
| DNS name / IP | The name(s) endpoints and admins use, e.g. `pm.corp.internal`. |
| Transfer receiver | The diode/gateway must deliver files into `<data_dir>/inbox/`. |
| For SSO | An OIDC client registered at your IdP, IdP reachable from the server, IdP groups per role. |
| Audit export storage | A mount for `audit_export_dir` (see step 9). |

Paths below follow `packaging/server/` (files are being written; check that folder for the current
versions): config `/etc/offpatch-server/pmserver.json`, PKI `/etc/offpatch-server/pki`, data
`/var/lib/offpatch-server`.

## Steps

### 1. Create the service user and directories

```bash
useradd --system --home /var/lib/offpatch-server --shell /usr/sbin/nologin offpatch
install -m 0755 pmserver /usr/local/bin/pmserver
install -d -o offpatch -g offpatch -m 0700 /var/lib/offpatch-server /etc/offpatch-server
```

### 2. Create the internal CA and the server certificate

```bash
sudo -u offpatch /usr/local/bin/pmserver init-pki \
  -dir /etc/offpatch-server/pki -hosts pm.corp.internal,10.20.0.5
```

- `-hosts` is required: every DNS name and IP endpoints use to reach the server.
- Creates `ca.pem`, `ca.key` (10-year CA, ECDSA P-256), `server.pem`, `server.key` (valid **2 years**).
- It refuses to run on a directory that already has a CA.
- `ca.key` signs every endpoint certificate. Keep it readable only by `offpatch` and back it up
  encrypted (runbook 05).
- Renew the server certificate before its 2-year expiry, or when host names change, with the
  existing CA (agents keep trusting it because they pin `ca.pem`):

  ```bash
  sudo -u offpatch /usr/local/bin/pmserver reissue-server-cert \
    -dir /etc/offpatch-server/pki -hosts pm.corp.internal,10.20.0.5
  # new server certificate written to …/server.pem (previous kept as *.old); restart pmserver to use it
  systemctl restart pmserver
  ```

  It needs `ca.pem` and `ca.key` in `-dir`, renames the current `server.pem`/`server.key` to
  `server.pem.old`/`server.key.old`, and issues a new 2-year certificate for `-hosts` (required).
  Put a reminder in your calendar. Check expiry with
  `openssl x509 -enddate -noout -in /etc/offpatch-server/pki/server.pem`.

### 3. Install the public keys

```bash
install -o offpatch -m 0644 bundle.pub root.pub /etc/offpatch-server/
```

### 4. Create the break-glass admin token

```bash
/usr/local/bin/pmserver new-token
# token:        adm_…            → store in the safe, never in the config
# token_sha256: 3b1f…            → goes into admin_tokens
```

Repeat for any automation accounts (one token per user/role).

### 5. Write the configuration

Start from `packaging/server/pmserver.example.json`. Minimal production config:

```json
{
  "listen": "0.0.0.0:8443",
  "data_dir": "/var/lib/offpatch-server",
  "pki_dir": "/etc/offpatch-server/pki",
  "trusted_keys": [{"public_key_file": "/etc/offpatch-server/bundle.pub", "sources": ["acq-zone-1"]}],
  "root_public_key_file": "/etc/offpatch-server/root.pub",
  "admin_tokens": [{"user": "breakglass", "role": "admin", "token_sha256": "<from step 4>"}],
  "audit_export_dir": "/mnt/audit-worm/offpatch",
  "metrics_token": "<random secret>"
}
```

```bash
chown offpatch:offpatch /etc/offpatch-server/pmserver.json
chmod 0600 /etc/offpatch-server/pmserver.json
```

Rules enforced at startup (the server refuses to start otherwise):

- Unknown keys are rejected (a typo is a startup error, not silently ignored).
- At least one `trusted_keys` entry, each with `sources`.
- `oidc`, or at least one `admin_tokens` entry with `allow_static_tokens` not `false`.
- **TLS is required**: set `pki_dir` (uses `pki/server.pem` and `server.key`) or `tls_cert` + `tls_key`.
  `pki_dir` is required whenever TLS is on, because it issues the endpoint client certificates.
  `insecure_http: true` is for an isolated lab only and cannot be combined with TLS settings.
- `audit_retention` needs `audit_export_dir` and must be at least `720h`.
- `approval_policy` keys must be severities, values 1–5.
- Durations are Go duration strings: `"30m"`, `"24h"`, `"720h"`. There is no `d` unit.
- Relative paths are resolved from the config file's directory.

All keys (`internal/server/config.go`, `internal/oidc/oidc.go`, `internal/server/ops.go`):

| Key | Default | Meaning |
|---|---|---|
| `listen` | `127.0.0.1:8080` | Address:port. Set e.g. `0.0.0.0:8443`. |
| `data_dir` | `data` | inbox, received, quarantine, repository, agent-dist, `pm.db`, `audit-signing.key`. |
| `pki_dir` | — | Internal CA and server certificate from `init-pki`. |
| `tls_cert`, `tls_key` | from `pki_dir` | Override the server certificate. Both or neither. |
| `insecure_http` | `false` | Lab only: plain HTTP, agents use bearer secrets. |
| `trusted_keys[]` | required | `public_key_file` or `public_key` (PEM), `sources[]`. Once a signed trust document has been accepted, it replaces this list for intake (runbook 03). |
| `root_public_key_file` | — | Enables signed trust documents (key rotation / revocation). |
| `admin_tokens[]` | — | `user`, `role` (`viewer`/`operator`/`approver`/`admin`), `token_sha256`. |
| `allow_static_tokens` | `true` | `false` disables all bearer admin tokens. |
| `oidc` | — | See step 6. |
| `session_ttl` | `8h` | SSO session lifetime. |
| `require_mfa` | `false` | Refuse SSO logins and sessions without MFA. By design it does not apply to static (break-glass) tokens. |
| `approval_policy` | 1 per severity | e.g. `{"critical": 2, "important": 2}`. |
| `separation_of_duties` | `false` | An approver of a package cannot deploy it. |
| `patch_deadlines` | critical `168h`, important `720h`, moderate `1440h`, low `2160h` | Release-to-install deadlines used in reports and the `overdue` metric. |
| `offline_after` | `30m` | Endpoint becomes `offline`. |
| `stale_inventory_after` | `24h` | Endpoint becomes `stale`. |
| `checkin_interval_seconds` | `60` | Sent to agents. |
| `download_rate_kbps` | `0` (unlimited) | Per-agent download throttle, kilobits/s. |
| `site_download_kbps` | — | Per-site override, e.g. `{"branch-office-1": 20000}`. |
| `max_bundle_bytes` | 32 GiB | Intake `size` check and total extracted size. |
| `max_files` | `500` | Files per bundle. |
| `max_file_bytes` | 16 GiB | Per payload file. |
| `scan_command` | — | e.g. `["/usr/bin/clamscan", "--no-summary"]`; the file path is appended; exit 0 = clean. |
| `intake_interval` | `5s` | Inbox polling. |
| `intake_max_bundles_per_hour` | `0` (off) | Rolling-hour limit; excess waits in the inbox. |
| `intake_max_bytes_per_hour` | `0` (off) | Same, in bytes. |
| `audit_export_dir` | — | Off-box audit export and signed checkpoints. |
| `audit_checkpoint_interval` | `1h` | Export frequency. |
| `audit_retention` | `0` (keep) | Prune DB events older than this, only after export (min `720h`). |
| `notify.smtp` | — | `addr` (internal relay `host:port`), `from`, `to[]`. No SMTP auth or TLS options. |
| `notify.webhook_url`, `notify.webhook_token` | — | Internal SIEM/chat bridge; JSON POST, optional bearer token. |
| `notify.min_severity` | `warning` | `info`, `warning` or `critical`. |
| `metrics_token` | — | Enables `GET /metrics` (bearer). |
| `alert_sweep_interval` | `5m` | Sweep for offline/stale endpoints, exceptions expiring within 7 days and client certificates expiring within 14 days (`cert_expiring`); then alert delivery. |

### 6. (Recommended) Configure SSO

Register an OIDC confidential or public client at the IdP with redirect URI
`https://pm.corp.internal:8443/auth/callback`, scopes `openid profile email`, and a groups claim.
Add to the config:

```json
"oidc": {
  "issuer": "https://adfs.corp.internal/adfs",
  "client_id": "offpatch-console",
  "client_secret": "",
  "redirect_url": "https://pm.corp.internal:8443/auth/callback",
  "groups_claim": "groups",
  "role_groups": {"admin": ["PM-Admins"], "approver": ["PM-Approvers"], "operator": ["PM-Operators"], "viewer": ["PM-Viewers"]},
  "ca_cert_file": "/etc/offpatch-server/corp-ca.pem"
},
"require_mfa": true,
"session_ttl": "8h"
```

| `oidc` key | Default | Notes |
|---|---|---|
| `issuer` | required | Must equal the issuer in `<issuer>/.well-known/openid-configuration`. |
| `client_id`, `redirect_url` | required | |
| `client_secret` | — | Sent to the token endpoint if set. |
| `scopes` | `openid profile email` | |
| `username_claim` | `preferred_username` | Falls back to `email`, then `sub`. |
| `groups_claim` | `groups` | |
| `role_groups` | — | role → list of IdP group names. Highest role wins. No match = login refused. |
| `require_mfa` | — | Also set by top-level `require_mfa`. |
| `mfa_amr_values` | `mfa otp hwk swk fpt face sms pop fido` | An `amr` value from this list counts as MFA. |
| `mfa_acr_values` | — | `acr` values that count as MFA. |
| `ca_cert_file` | system roots | CA for the IdP's TLS certificate. |

Discovery happens at the first login, not at startup. If the IdP is unreachable, the login page
shows "Single sign-on is unavailable" and the break-glass token still works. Once SSO works, decide
whether to keep `admin_tokens` (break-glass) or set `allow_static_tokens: false`.

### 7. Install the systemd unit and start

```bash
install -m 0644 packaging/server/pmserver.service /etc/systemd/system/pmserver.service
# if audit_export_dir is set, uncomment/add its mount in ReadWritePaths= in the unit
systemctl daemon-reload
systemctl enable --now pmserver
journalctl -u pmserver -n 50
```

Expect `pmserver listening … tls=true mtls_agents=true` and, with export configured,
`audit export enabled … verify_with=/var/lib/offpatch-server/audit-signing.pub`. The warning
`audit_export_dir not set` means audit evidence lives only in the database.

Configuration is read only at startup. **Every config change needs `systemctl restart pmserver`.**

### 8. Stage agent binaries for the console

```bash
install -d -o offpatch -m 0750 /var/lib/offpatch-server/agent-dist
install -o offpatch -m 0644 pmagent-x.y.z-windows-amd64.exe /var/lib/offpatch-server/agent-dist/pmagent.exe
install -o offpatch -m 0644 offpatch-agent-x.y.z.msi offpatch-agent_x.y.z_amd64.deb /var/lib/offpatch-server/agent-dist/
```

File names must match `^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$`, otherwise they are not listed. The
console's **Agent setup** page lists them with size and SHA-256, plus the trusted keys and `ca.pem`.

### 9. Audit export storage

`audit_export_dir` receives `audit-<from>-<to>.jsonl` files (written as `.part`, then renamed) and
**appends** a signed line to `checkpoints.jsonl` every `audit_checkpoint_interval`. The storage must
therefore allow creating, renaming and appending files by the `offpatch` user, while preventing
modification and deletion by everyone else (WORM share with append semantics, or a local directory
replicated to WORM storage). Export failures raise a critical `audit_export_failed` alert.
The checkpoint verification key `audit-signing.pub` is created in `data_dir`; copy it to the
auditors' verification workstation (runbook 07).

### 10. Metrics and monitoring

```yaml
# Prometheus scrape job (inside the isolated zone)
- job_name: offpatch
  scheme: https
  tls_config: {ca_file: /etc/prometheus/offpatch-ca.pem}
  authorization: {credentials: "<metrics_token>"}
  static_configs: [{targets: ["pm.corp.internal:8443"]}]
```

Gauges: `offpatch_endpoints{status}`, `offpatch_packages{state}`, `offpatch_bundles{state}`,
`offpatch_deployments{state}`, `offpatch_alerts_open{severity}`, `offpatch_targets_overdue{severity}`,
`offpatch_compliance_percent{severity}`, `offpatch_fleet_reporting_percent`,
`offpatch_exceptions_active`, `offpatch_audit_chain_ok`; counter `offpatch_audit_events`.
Suggested alerts: `offpatch_audit_chain_ok == 0`, `offpatch_fleet_reporting_percent` below your
target, `offpatch_targets_overdue{severity="critical"} > 0`. Also monitor disk space of `data_dir`
(repository and received evidence grow with every bundle; nothing is deleted automatically).

### 11. Network

| Flow | Allow |
|---|---|
| Endpoints → server | TCP `listen` port only |
| Admin workstations → server | TCP `listen` port |
| Server → IdP, SMTP relay, webhook | Internal only, if configured |
| Server → anything outside the isolated zone | **Deny** |
| Transfer receiver → `<data_dir>/inbox` | File writes only |

## Verification

```bash
curl --cacert /etc/offpatch-server/pki/ca.pem https://pm.corp.internal:8443/auth/config
# {"require_mfa":true,"sso":true,"static_tokens":true}
TOK=adm_…   # break-glass token
curl --cacert /etc/offpatch-server/pki/ca.pem -H "Authorization: Bearer $TOK" https://pm.corp.internal:8443/api/me
curl --cacert /etc/offpatch-server/pki/ca.pem -H "Authorization: Bearer $TOK" https://pm.corp.internal:8443/api/audit/verify
curl --cacert /etc/offpatch-server/pki/ca.pem -H "Authorization: Bearer <metrics_token>" https://pm.corp.internal:8443/metrics | head
```

- Sign in to the console with SSO as a member of each role group; `GET /api/me` shows
  `source: "sso"` and `mfa: true`. A user in no role group is refused (`auth.login_denied`).
- Agent setup page lists the trusted key, `ca.pem` and the staged files.
- After the first `audit_checkpoint_interval`, `checkpoints.jsonl` exists in `audit_export_dir`.
- Send a test bundle (runbook 02) and see it `validated`.
- Take the first backup and verify it (runbook 05).

## Rollback / escape hatch

- Server does not start: `journalctl -u pmserver` shows the `config:` error. Fix and restart.
- SSO broken: sign in with the break-glass token (Bearer) and fix `oidc`.
- Abandon an install: `systemctl disable --now pmserver`; the data and PKI directories hold all
  state. Do not reuse a CA you have discarded: endpoints pin it.

## Evidence to keep

- Release `SHA256SUMS` and the verified hashes of the installed binaries.
- Final `pmserver.json` (without secrets) and its hash, in the change record.
- CA fingerprint printed by `init-pki`.
- Who holds the break-glass token and where it is stored.
- First successful `GET /api/audit/verify` and first backup `verify-backup` output.
