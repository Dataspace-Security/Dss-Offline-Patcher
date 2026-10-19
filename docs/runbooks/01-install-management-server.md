# Runbook 01 — Install the management server (pmserver)

## Purpose

Install `pmserver` with TLS, the internal CA for agent mTLS,
admin sign-in (email + password with an authenticator app, and/or SSO), staged agent binaries, off-box audit export and
metrics.

## When to use

- First installation (pilot or production).
- Rebuilding a server before a restore (then continue with [runbook 05](05-backup-and-restore.md)).

## Prerequisites and roles

| Item | Notes |
|---|---|
| Linux host | Single server (default): one Ubuntu server whose downloader account may reach the internet (TCP 80/443, DNS). Two-machine layout: a host in the isolated zone. Ubuntu 22.04 / 24.04 / 26.04 with systemd for the installer (method A). Other systemd Linux: method B. Container image: `packaging/server/Dockerfile` (see the comments in it). Windows (`pmserver.exe`) builds, but there is no service wrapper for it. |
| OS administrator | Root on the host. Nothing here is done in the console. |
| Release | Built in the build environment with **Go 1.27.2 or later** (`docs/security/README.md` §2.2): `make dist` (installer tarball, method A) or `make release VERSION=x.y.z` (method B). Carry it and its `SHA256SUMS` across the boundary and verify the hashes. |
| `bundle.pub` | Two-machine layout only: public bundle signing key from the acquisition zone ([runbook 02](02-acquisition-zone-setup-and-monthly-run.md)). Public keys only — never copy a `.key` file into this zone. |
| `root.pub` | Public **root** key for signed key rotation (runbook 02/03). Strongly recommended. |
| DNS name / IP | The name(s) endpoints and admins use, e.g. `pm.corp.internal`. |
| Transfer receiver | Two-machine layout only: the diode/gateway must deliver files into `<data_dir>/inbox/`. |
| For SSO | An OIDC client registered at your IdP, IdP reachable from the server, IdP groups per role. |
| Audit export storage | A mount for `audit_export_dir` on separate / WORM storage (see step 9). |
| Time source | An internal NTP server. The installer warns if the clock is not synchronized. |

Two install methods. Their paths differ; see [Paths by install method](README.md#paths-by-install-method).

| | Method A: `install-ubuntu.sh` (recommended; A1 single server or A2 `--role server`) | Method B: manual (`packaging/server/`) |
|---|---|---|
| Config | `/etc/offpatch/pmserver.json` | `/etc/offpatch-server/pmserver.json` |
| PKI | `/etc/offpatch/pki` | `/etc/offpatch-server/pki` |
| Public keys | `/etc/offpatch/keys/bundle.pub`, `root.pub` | `/etc/offpatch-server/bundle.pub`, `root.pub` |
| Data | `/var/lib/offpatch-server` | `/var/lib/offpatch-server` |
| Unit | `offpatch-server.service` (+ `offpatch-backup.timer`; A1 also `offpatch-acquire.timer`, `offpatch-egress.service`) | `pmserver.service` |

## Method A1: single server, one command (production default)

On the server, from the verified release tarball:

```bash
tar xzf offpatch-<version>-linux-amd64.tar.gz && cd offpatch-<version>-linux-amd64
sudo ./install-ubuntu.sh
```

No `--role` = `--role all`. Everything in method A2 below applies (CA and certificate, super admin,
MFA key, hardened `offpatch-server.service`, daily backup, ufw), plus:

- **Downloader** `pmctl auto` as user `offpatch-acq`, every hour (`offpatch-acquire.timer`,
  `RandomizedDelaySec=5min`, `Persistent=true`). A run still downloading when the next one starts
  holds the run lock; the new run exits 3 ("skipped"), which the unit treats as success. Console
  acquisition requests are queued to `/var/lib/offpatch-acq/requests` and fetched at once by
  `offpatch-acquire-requests.path`. It creates the bundle signing key (readable only by `offpatch-acq`).
- **Egress lock**: nftables table `inet offpatch_egress` (`/etc/nftables.d/offpatch.nft`, loaded at
  boot by `offpatch-egress.service`; nftables is installed if missing). Only `offpatch-acq` may open
  new outbound connections, to TCP 80/443 and DNS 53; `offpatch` (pmserver) may open new connections
  to loopback only. Replies to agents and browsers, other users, root and SSH are not affected.
  Refusals are logged as `offpatch-egress denied:` (`journalctl -k`). It also blocks outbound SSO,
  SMTP and webhooks from pmserver (steps 6 and 10): add a rule for those, or `--no-egress-lock`
  (not recommended; `--egress-lock` restores it). Check: `sudo nft list table inet offpatch_egress`.
- **Root key**: created as `/etc/offpatch/keys/root.key` unless you pass `--root-pubkey root.pub`
  (root key made offline, runbook 02 A2). Move it off the server at once:

  ```bash
  sudo ./install-ubuntu.sh --export-root-key /media/usb   # mount point of offline media
  ```

  It refuses a folder on the server's own filesystem, copies `root.key`, `root.pub` and `root.sha256`,
  verifies the copy by SHA-256, asks you to type `DELETE` (`--yes` skips the question) and shreds the
  server copy. `root.pub` stays on the server. `--status` reminds you while `root.key` is present.
- **Firewall**: with ufw active, the port is opened only from `--allow-from` CIDRs or, without
  them, from the local subnet of the server's address (both printed). PCs on other subnets need
  `--allow-from`. ufw is never enabled by the installer; when it is inactive the summary prints
  `ufw allow OpenSSH`, the port rules and `ufw enable` for you to run.
- **Disclosure**: `pmserver.json` gets `"deployment_mode": "single-server"` (added on upgrades when
  missing). The compliance report states in the scope limitations and in PM-04 that the downloader
  runs on the management server and that egress is limited to the downloader account by host
  firewall rules. `acquisition_stale_after` defaults to 3h (hourly runs).

The summary ends with the next steps: the console URL with the server name (`--domain`, for
browsers), the URL agents connect to (`https://<server IP>:8443`), the hosts-file line for the
admins' PCs when there is no internal DNS (never needed on endpoints), the super admin
email (default password), then 1. sign in and change the password, 2. Settings → Users: create the
bank's Admin, 3. Endpoints → Create enrollment token → run the PowerShell line on each PC (as
Administrator), 4. Patches → Needed → Import, Catalog → Approve, Patch this (2 approvals). Each PC
needs TCP 8443 (or `--port`) to the server's IP.

A two-machine layout (A2 with a separate acquisition host) is stricter: the internet-facing
downloader then shares no machine with the server's data.

## Server name and console certificate (methods A1/A2)

Details and configuration keys: [admin guide section 5.5](../07-admin-guide.md#55-server-name-and-certificates).

1. **Name.** `--domain patcher.bank.example` (default `dsspatcher.internal`, or the
   name of the earlier install). The installer writes `server_name` and `agent_ip` into
   `pmserver.json`, makes sure the internal server certificate names it and the server's IP
   (reissuing it on upgrades when not; agents keep working, they pin the CA) and prints the URL
   `https://<name>:8443` for the console. Create an internal DNS A record, or give admins the
   printed hosts-file line (`<IP> <name> # DSS Patcher`) for their own PCs. Agents do not use the
   name: they connect to `https://<IP>:8443` (`agent_url`, printed as "Agents connect to"), so
   endpoints need no DNS or hosts-file entry. The Windows enrollment command uses that URL;
   Ubuntu agents: `--role agent --server https://<IP>:8443` (`--server-ip` is accepted and
   ignored). Agents enrolled by the name under an earlier release keep that URL until
   re-enrolled with a new token.
2. **Browser certificate**, one of:
   - Group Policy: distribute `/etc/offpatch/pki/ca.pem` as a Trusted Root Certification Authority (no change on the server).
   - The bank's own certificate (recommended for isolated networks; no internet):

     ```bash
     sudo ./install-ubuntu.sh --public-cert /root/patcher-fullchain.pem --public-key /root/patcher.key [--public-domain patcher.bank.example]
     ```

     Checked (key matches, not expired, chain order) and copied to `/etc/offpatch/pki/public/`
     (offpatch, 0600). Replace it later the same way; no restart needed.
   - Let's Encrypt (public DNS name, internet access):

     ```bash
     sudo ./install-ubuntu.sh --public-domain patcher.example.com [--acme-challenge auto|http|cloudflare] [--acme-email EMAIL]
     ```

     `auto`: HTTP-01 (`certbot --standalone`) when TCP 80 is free, else Cloudflare DNS-01 when
     `/etc/offpatch/acme/cloudflare.ini` exists (root, 0600, `dns_cloudflare_api_token = <token>`;
     or `--cloudflare-credentials FILE`), else it stops and lists the options. Renewal: certbot's
     timer and the deploy hook `/etc/letsencrypt/renewal-hooks/deploy/offpatch.sh`; no restart.

   With only these options on an existing install, nothing else changes (pmserver is restarted
   once; the previous `pmserver.json` is restored if it does not come up). Agents always keep the
   internal CA and mTLS (TLS ALPN `dss-agent/1`, or no SNI for older agents).
3. Allow TCP 8443 from the admins' and PCs' networks (`--allow-from`, network firewall).

Verify (replace the names):

```bash
curl -sS -o /dev/null -w '%{http_code}\n' https://patcher.bank.example:8443/auth/config   # 200; public/bank certificate verifies
curl -sS -X POST https://patcher.bank.example:8443/api/agent/checkin                      # 421 for a browser-like client
openssl s_client -connect 127.0.0.1:8443 -servername patcher.bank.example -alpn dss-agent/1,http/1.1 </dev/null 2>/dev/null | grep -E 'issuer|Acceptable client'   # internal CA, client certificate requested
sudo ./install-ubuntu.sh --status                                                       # server name, public certificate expiry
sudo certbot renew --dry-run                                                            # Let's Encrypt only
```

## Method A2: two-machine layout (`--role server`, stricter)

On the server, from the verified release tarball, with `bundle.pub` from the acquisition host and
`root.pub` from the offline root key ceremony (runbook 02 A1/A2):

```bash
tar xzf offpatch-<version>-linux-amd64.tar.gz && cd offpatch-<version>-linux-amd64
sudo ./install-ubuntu.sh --role server --hosts pm.corp.internal,10.20.0.5 \
     --pubkey bundle.pub --root-pubkey root.pub \
     --audit-dir /mnt/audit-worm/offpatch --allow-from 10.20.0.0/16
```

What it does (covers steps 1-5, 7 and 8 below, plus the daily backup of runbook 05):

- Refuses to run if any `*.key` file is in `/etc/offpatch/keys`: the server holds public keys only.
  It never generates signing keys. `--pubkey` is required on the first install. Existing `.pub`
  files are never overwritten (rotate keys with runbook 03).
- Creates the internal CA and server certificate for `--hosts` (step 2).
- Creates the **built-in super admin** (the vendor's console account) with `--admin-email`
  (default `superadmin@dataspacesecurity.com`) and the vendor's **default password** (in the vendor
  handbook; only its PBKDF2 hash is embedded in `pmserver`, nothing is in the config). The summary
  prints `super admin: superadmin@dataspacesecurity.com — default password (see vendor handbook);
  change it after first sign-in`. Sign in, change the password at once (until then the console shows
  a banner and pmserver logs a warning at every start), then create the bank's first Admin
  (Settings → Users). Lost it: [recovery](#recovery-nobody-can-sign-in).
- Creates the MFA key `/var/lib/offpatch-server/mfa.key` (64 hex characters, owner `offpatch`, mode
  0600). It encrypts the users' authenticator secrets; it is included in the backups.
- There are no static admin tokens: the installer creates none and prints none.
- Writes `/etc/offpatch/pmserver.json` on the first install only and never changes it afterwards.
  Edit it for SSO, notifications, metrics and so on (steps 5, 6, 10), then
  `systemctl restart offpatch-server`.
- Runs `offpatch-server.service` as user `offpatch` with the hardening of
  `packaging/server/pmserver.service`. The unit gets no capabilities unless the port is below 1024.
- Creates group `offpatch-inbox`. Add the transfer receiver's account to it. Only that group can
  write `/var/lib/offpatch-server/inbox`.
- Installs `offpatch-backup.timer`: a daily verified backup into `/var/lib/offpatch-backup`
  (`--backup-dir`), keeping 14 (`--backup-keep`). See runbook 05.
- ufw (only if active; never enabled by the installer): opens the port only to each `--allow-from`
  CIDR (repeatable), else to the local subnet of the server's address.
- Writes `"deployment_mode": "two-machine"` into the new `pmserver.json`
  (`acquisition_stale_after` stays 26h: status reports cross the transfer when files are carried).
- Warns loudly if `--audit-dir` is on the same filesystem as the data, and if NTP is not synchronized.

Upgrade: run the same command from the new release (A1: `sudo ./install-ubuntu.sh`; the role is remembered). It takes a verified pre-upgrade backup, keeps
the previous binaries in `/opt/offpatch/bin.prev`, and keeps keys, PKI, config and data. If no
local super admin exists yet (an install from before local users), the upgrade creates the built-in
super admin with the default password. An upgrade from a release with static admin tokens removes
`admin_tokens` and `allow_static_tokens` from `pmserver.json` and shreds
`/etc/offpatch/admin-token.txt` and `admin-token.sha256`; it creates `mfa.key` if missing. Port,
TLS mode and audit directory come from the existing `pmserver.json`; a conflicting flag is refused.

Then continue with steps 6 (SSO), 9 (audit storage), 10 (metrics) and 11 (network) below, using the
method A paths, and with the verification section.

## Method B: manual install (`packaging/server/` layout)

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
  systemctl restart pmserver        # method A: systemctl restart offpatch-server
  ```

  It needs `ca.pem` and `ca.key` in `-dir`, renames the current `server.pem`/`server.key` to
  `server.pem.old`/`server.key.old`, and issues a new 2-year certificate for `-hosts` (required).
  Put a reminder in your calendar. Check expiry with
  `openssl x509 -enddate -noout -in /etc/offpatch-server/pki/server.pem`.

### 3. Install the public keys

```bash
install -o offpatch -m 0644 bundle.pub root.pub /etc/offpatch-server/
```

Public keys only. If a `.key` file was copied here by mistake, remove it (`shred -u`) and treat it
as exposed (runbook 04).

### 4. Create the built-in super admin (console sign-in)

After step 5 (the command reads the config to find the database):

```bash
sudo -u offpatch /usr/local/bin/pmserver create-admin -config /etc/offpatch-server/pmserver.json
# created the built-in super admin with the default password (see the vendor handbook); change it after the first sign-in
# email:    superadmin@dataspacesecurity.com
# default_password: yes
```

`-email` defaults to `superadmin@dataspacesecurity.com`. Without `-password-random` it sets the
vendor's default password (only its PBKDF2 hash is embedded in `pmserver`; the password is in the
vendor handbook). Change it at the first sign-in: until then `/api/me` shows `builtin: true` and
`password_changed_at: ""`, the console shows a change-password banner and pmserver logs a WARN at
every start. `-password-random` instead generates a password and prints it **once**. `-if-none`
makes it a no-op when an enabled local super admin exists. There are no static admin tokens
(`pmserver new-token` was removed in v1.9); scripts sign in with email + password
([runbooks/README.md](README.md#conventions-used-in-the-runbooks)).

#### Recovery: nobody can sign in

Lost password or authenticator, or the account is locked or disabled. As root on the server, run as
the service user so the database keeps its owner:

```bash
sudo -u offpatch /usr/local/bin/pmserver reset-admin -config /etc/offpatch-server/pmserver.json \
     -email <super admin email>
# method A: sudo runuser -u offpatch -- /opt/offpatch/bin/pmserver reset-admin -config /etc/offpatch/pmserver.json -email <email>
```

It prints a new random password **once**, re-enables the account, clears the lockout and **clears
the super admin's MFA** (it may enrol again), and ends the account's other sessions (audited
`user.password_reset` by `system:cli`). `-email` defaults to `superadmin@dataspacesecurity.com`. If
no local super admin exists at all, create one with `pmserver create-admin` (step 4). Bank users who
lost their authenticator are reset by an Admin in the console (**Reset MFA**).

### 5. Write the configuration

Start from `packaging/server/pmserver.example.json`. Minimal production config:

```json
{
  "listen": "0.0.0.0:8443",
  "data_dir": "/var/lib/offpatch-server",
  "pki_dir": "/etc/offpatch-server/pki",
  "trusted_keys": [{"public_key_file": "/etc/offpatch-server/bundle.pub", "sources": ["acq-zone-1"]}],
  "root_public_key_file": "/etc/offpatch-server/root.pub",
  "audit_export_dir": "/mnt/audit-worm/offpatch",
  "metrics_token": "<random secret>"
}
```

Replace every placeholder: `<random secret>` with the output of `openssl rand -hex 32`. If you
started from `pmserver.example.json`, also replace `REPLACE_with_random_secret` and the example host
names. The server does
not reject these placeholders at startup, so check:

```bash
grep -nE 'REPLACE|0{64}|<[a-z_ ]+>' /etc/offpatch-server/pmserver.json   # must print nothing
```

```bash
chown offpatch:offpatch /etc/offpatch-server/pmserver.json
chmod 0600 /etc/offpatch-server/pmserver.json
```

Rules enforced at startup (the server refuses to start otherwise):

- Unknown keys are rejected (a typo is a startup error, not silently ignored).
- At least one `trusted_keys` entry, each with `sources`.
- `admin_tokens` and `allow_static_tokens` are refused (static admin tokens were removed in v1.9):
  delete them and sign in with email + password.
- Roles in `oidc.role_groups` must be `viewer`, `user`, `admin` or `super_admin`; the old names
  `operator` and `approver` are refused with an error naming the value (rename them to `user`).
- Without `oidc`, console sign-in is email + password only (local users); create the super admin
  (step 4).
- `deployment_approvals` is 1–5.
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
| `data_dir` | `data` | inbox, received, quarantine, repository, agent-dist, `pm.db`, `audit-signing.key`, `mfa.key`. |
| `mfa_key_file` | `<data_dir>/mfa.key` | 32-byte key (64 hex characters, mode 0600) that encrypts authenticator (TOTP) secrets at rest (AES-256-GCM). Created by the installer, and by pmserver at first start if missing. Back it up with the database (`pmserver backup` includes it): without it every MFA enrolment is lost. |
| `pki_dir` | — | Internal CA and server certificate from `init-pki`. |
| `tls_cert`, `tls_key` | from `pki_dir` | Override the server certificate. Both or neither. |
| `insecure_http` | `false` | Lab only: plain HTTP, agents use bearer secrets. |
| `trusted_keys[]` | required | `public_key_file` or `public_key` (PEM), `sources[]`. Once a signed trust document has been accepted, it replaces this list for intake (runbook 03). |
| `root_public_key_file` | — | Enables signed trust documents (key rotation / revocation). |
| `deployment_approvals` | `2` | Different bank users/admins (not the creator) who approve each deployment and rollback before it starts (1–5; an isolated single-person lab may use 1). |
| `oidc` | — | See step 6. |
| `session_ttl` | `8h` | Console session lifetime (SSO and email + password). |
| `require_mfa` | `false` | Make the authenticator step required for **every** local user (also super admins; bank roles always need it), and refuse SSO logins and sessions without MFA from the IdP. Email + password sign-in stays on. |
| `approval_policy` | 1 per severity | e.g. `{"critical": 2, "important": 2}`. |
| `separation_of_duties` | `false` | Whoever approved a package cannot deploy it. |
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
  "role_groups": {"admin": ["PM-Admins"], "user": ["PM-Operators", "PM-Approvers"], "viewer": ["PM-Viewers"]},
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
| `role_groups` | — | role (`viewer`, `user`, `admin`, `super_admin`) → list of IdP group names. Highest role wins. No match = login refused. `operator` / `approver` are refused at startup. |
| `require_mfa` | — | Also set by top-level `require_mfa`. |
| `mfa_amr_values` | `mfa otp hwk swk fpt face sms pop fido` | An `amr` value from this list counts as MFA. |
| `mfa_acr_values` | — | `acr` values that count as MFA. |
| `ca_cert_file` | system roots | CA for the IdP's TLS certificate. |

Discovery happens at the first login, not at startup. If the IdP is unreachable, the login page
shows "Single sign-on is unavailable"; local users (email + password + authenticator) can still
sign in.

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

Configuration is read only at startup. **Every config change needs `systemctl restart pmserver`**
(method A: `systemctl restart offpatch-server`).

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
replicated to WORM storage). Do not put it on the same filesystem as `data_dir`: a compromise or
disk loss would take the evidence with it. Method A: pass `--audit-dir` on the first install (the
unit gets it in `ReadWritePaths=`). To move it later, change `audit_export_dir` in `pmserver.json` and
re-run the installer, which rewrites the unit from the config. Export failures raise a critical `audit_export_failed` alert.
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

Commands use method B paths; with method A, the CA is `/etc/offpatch/pki/ca.pem`.

```bash
curl --cacert /etc/offpatch-server/pki/ca.pem https://pm.corp.internal:8443/auth/config
# {"password_login":true,"require_mfa":true,"sso":true}
# sign in once as the super admin into the cookie jar `jar` (runbooks/README.md conventions), then:
curl --cacert /etc/offpatch-server/pki/ca.pem -b jar https://pm.corp.internal:8443/api/me
curl --cacert /etc/offpatch-server/pki/ca.pem -b jar https://pm.corp.internal:8443/api/audit/verify
curl --cacert /etc/offpatch-server/pki/ca.pem -H "Authorization: Bearer <metrics_token>" https://pm.corp.internal:8443/metrics | head
```

- Sign in to the console with the built-in super admin (email + password); `GET /api/me` shows
  `auth: "password"`, `role: "super_admin"`, `builtin: true`. Change the default password
  (`password_changed_at` is then set and the start-up warning stops). Create a bank Admin and two bank
  Users; each must enrol an authenticator at the first sign-in (QR code, 10 recovery codes). Check
  that a deployment needs two of them to approve.
- A request with `Authorization: Bearer x` to `/api/me` answers 401 `static admin tokens were
  removed; sign in with email and password`.
- Sign in to the console with SSO as a member of each role group; `GET /api/me` shows
  `source: "sso"` and `mfa: true`. A user in no role group is refused (`auth.login_denied`).
- Agent setup page lists the trusted key, `ca.pem` and the staged files.
- After the first `audit_checkpoint_interval`, `checkpoints.jsonl` exists in `audit_export_dir`.
- Send a test bundle (runbook 02) and see it `validated`.
- After the first update intelligence arrives: `GET /api/summary` shows `intel.stale: false`, and
  **Patches → Library** lists apps (`GET /api/library?view=all` returns a non-zero `total`).
- Take the first backup and verify it (runbook 05).

### Upgrading to the roles release (email + password users, two-person deployment approval)

- The database migrates by itself on start (table `local_users`, `deployment_approvals`; new
  columns on `deployments` and `sessions`). Deployments that are already `active` or `paused` keep
  running (`approvals_required` 0); **every new deployment and rollback waits for two approvals** from
  bank Users/Admins other than its creator. In a single-person lab set `"deployment_approvals": 1` in
  `pmserver.json` and restart; there you still need one bank User or Admin who did not create it (the
  super admin does not approve).
- Roles: users gain package approval; package revoke and exceptions now need `admin`. Check
  `oidc.role_groups` against docs/07-admin-guide.md §2.
- The installer upgrade creates the built-in super admin when no local super admin exists. Without
  the installer: step 4.

### Upgrading to v1.9 (MFA, static admin tokens removed)

- **Static admin tokens are gone.** pmserver refuses to start while `pmserver.json` has
  `admin_tokens` or `allow_static_tokens`. The installer removes both keys and shreds
  `/etc/offpatch/admin-token.txt` / `admin-token.sha256`; with method B delete them by hand. Scripts
  that used `Authorization: Bearer` must sign in with email + password instead
  ([conventions](README.md#conventions-used-in-the-runbooks)); enrollment tokens from the server
  shell: `pmserver enroll-token`.
- **Old role names are refused**: rename `operator` / `approver` in `oidc.role_groups` to `user`
  (e.g. `"user": ["PM-Operators", "PM-Approvers"]`). Stored users and sessions are migrated to
  `user` automatically.
- **MFA**: every bank user (viewer, user, admin) must enrol an authenticator app at the next sign-in.
  Tell them before the upgrade. `mfa.key` is created by the installer (or at the first start); include
  it in the backup copies.
- The default email of a newly created built-in super admin is now `superadmin@dataspacesecurity.com`
  with the vendor's default password; an existing super admin is kept unchanged.
- Agent versions are now approved and deployed by the super admin only; their deployments are
  approved by bank admins only.

### Upgrading to the P2 release (Library, evidence, alerts that close themselves)

- Upgrade **pmserver before pmctl**: the new pmctl adds a signed `resolved` section to the update
  intelligence and `expected_ubr` to cumulative-update packages; an older server rejects both
  (strict parsing). The database migrates by itself on start (new columns on `alerts`, `packages`
  and `targets`).
- **Upgrade the agents before** bundles carrying `expected_ubr` are deployed: older agents parse
  the signed manifest strictly and refuse it ("manifest verification failed", a critical alert).
  Until the fleet runs the new agent, keep pmctl from filling `expected_ubr` (ask the acquisition
  team) or deploy the agent upgrade first (runbook 08).
- After the upgrade, open alerts that describe a condition that has already cleared close
  themselves at the next alert sweep (resolved by `system:scheduler`).

## Rollback / escape hatch

- Server does not start: `journalctl -u pmserver` (method A: `journalctl -u offpatch-server`) shows
  the `config:` error. Fix and restart.
- Method A upgrade went wrong: `systemctl stop offpatch-server`,
  `cp -a /opt/offpatch/bin.prev/. /opt/offpatch/bin/`, start again. If the new version has already
  changed the database, restore the `pre-upgrade-*` backup as well (runbook 05).
- SSO broken: sign in as a local user (email + password + authenticator) and fix `oidc`.
- Nobody can sign in: `pmserver reset-admin` on the server ([recovery](#recovery-nobody-can-sign-in)).
- Abandon an install: `systemctl disable --now pmserver` (method A: `sudo ./install-ubuntu.sh
  --uninstall`, which lists the secrets left on disk). The data and PKI directories hold all
  state. Do not reuse a CA you have discarded: endpoints pin it.

## Evidence to keep

- Release `SHA256SUMS` and the verified hashes of the installed binaries.
- Final `pmserver.json` (without secrets) and its hash, in the change record.
- CA fingerprint printed by `init-pki`.
- Who holds the built-in super admin password (vendor) and when it was last changed or reset.
- First successful `GET /api/audit/verify` and first backup `verify-backup` output.
