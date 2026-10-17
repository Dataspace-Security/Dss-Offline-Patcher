# offpatch runbooks

Operational procedures for offpatch (roadmap D1). Each runbook has: purpose, when to use,
prerequisites and roles, numbered steps with exact commands, verification, rollback / escape hatch,
and the evidence to keep. Day-to-day console work and troubleshooting are in the
[administrator training guide](../07-admin-guide.md).

| # | Runbook | Zone | Roles | Frequency |
|---|---|---|---|---|
| 01 | [Install the management server](01-install-management-server.md) | Isolated | Server OS admin | Once / rebuild |
| 02 | [Acquisition zone setup and monthly run](02-acquisition-zone-setup-and-monthly-run.md) | Connected → boundary → isolated | Acquisition operator, root key custodian, viewer | Setup once; monthly |
| 03 | [Planned signing key rotation](03-key-rotation.md) | Connected + isolated | Root key custodian, acquisition operator, server OS admin | Per key policy |
| 04 | [Signing key compromise](04-signing-key-compromise.md) | All | Incident lead, root key custodian, approver, operator | Incident |
| 05 | [Backup and restore](05-backup-and-restore.md) | Isolated | Server OS admin | Daily backup; restore test per DR schedule (Phase 7 exit gate) |
| 06 | [Failed update recovery](06-failed-update-recovery.md) | Isolated + endpoints | Operator, approver, endpoint support | Incident |
| 07 | [Audit verification and evidence](07-audit-verification-and-evidence.md) | Isolated + auditor workstation | Viewer, auditor | Monthly; before audits |
| 08 | [Agent upgrade](08-agent-upgrade.md) | All | Acquisition operator, approver, operator | Per agent release |
| 09 | [Endpoint onboarding and offboarding](09-endpoint-onboarding-and-offboarding.md) | Isolated + endpoints | Operator, endpoint support | Ongoing |

## Command reference (as implemented)

| Binary | Subcommands |
|---|---|
| `pmserver` | `-config <file>` (run), `new-token`, `init-pki -dir -hosts`, `reissue-server-cert -dir -hosts`, `backup -config -dir [-no-pki]`, `verify-backup -dir`, `restore -config -dir [-force]`, `verify-audit -export -pub [-db]` |
| `pmctl` | `keygen -out`, `build -key [-pub] -spec -out [-source] [-seq] [-state] [-ttl]`, `inspect -bundle [-pub]`, `send -bundle [-via dropdir\|command] [-to] [-command] [-key] [-pub] [-log]`, `trust -root [-root-pub] -seq -key file.pub=src [-retire file.pub] [-revoke key_id:reason] -out`, `catalog-search -q`, `msrc -month [-product] [-arch]`, `fetch …`, `fetch-url … [-kind msu\|msi\|deb\|rpm\|pkg\|agent] [-package-name] [-os]` |
| `pmagent` | `enroll -server -token -pubkey [-root-pubkey] [-ca] [-state-dir] [-platform windows\|linux\|macos\|sim]`, `run [-state-dir] [-once]`, `service install\|uninstall [-state-dir]` (Windows SCM, systemd, launchd), `version` |

## Paths by install method

The runbooks use the **installer layout** (`install-ubuntu.sh`, the supported method). If you installed
by hand from `packaging/server/` or run the container image, substitute the paths from this table.

| Item | `install-ubuntu.sh` (default) | Manual (`packaging/server/pmserver.service`) | Container (`packaging/server/Dockerfile`) |
|---|---|---|---|
| Server config | `/etc/offpatch/pmserver.json` | `/etc/offpatch-server/pmserver.json` | `/etc/offpatch-server/pmserver.json` (volume) |
| PKI (CA, server cert) | `/etc/offpatch/pki` | `/etc/offpatch-server/pki` | `/etc/offpatch-server/pki` |
| Trusted public keys | `/etc/offpatch/keys/bundle.pub`, `root.pub` | `/etc/offpatch-server/bundle.pub`, `root.pub` | `/etc/offpatch-server/*.pub` |
| Server data (`data_dir`) | `/var/lib/offpatch-server` | `/var/lib/offpatch-server` | `/var/lib/offpatch-server` (volume) |
| Audit export (default) | `--audit-dir`, else `/var/lib/offpatch-server/audit-export` | as configured | as configured |
| Server unit | `offpatch-server.service` | `pmserver.service` | container `pmserver` |
| Server binary | `/opt/offpatch/bin/pmserver` (`/usr/local/bin/pmserver` symlink) | `/usr/local/bin/pmserver` | `/usr/local/bin/pmserver` |
| Service users | `offpatch` (server), `offpatch-acq` (acquisition), group `offpatch-inbox` (may write the inbox) | `offpatch` | UID 65532 |
| Backups | `offpatch-backup.timer` → `/var/lib/offpatch-backup` | your own timer (runbook 05) | host timer + `docker exec` |
| Acquisition config / keys | `/etc/offpatch/acquire.json`, `/etc/offpatch/keys/bundle.key` | `/etc/offpatch-acq/acquire.json` (`packaging/acquisition/`) | n/a |
| Acquisition data / timer | `/var/lib/offpatch-acq`, `offpatch-acquire.timer` (user `offpatch-acq`) | same (`packaging/acquisition/`) | n/a |
| Previous binaries after upgrade | `/opt/offpatch/bin.prev` | keep your own copy | previous image tag |

Restart after a config change: `systemctl restart offpatch-server` (installer), `systemctl restart
pmserver` (manual), `docker restart pmserver` (container). Logs: `journalctl -u offpatch-server`
(installer) or `journalctl -u pmserver` (manual).

## Conventions used in the runbooks

- Server URL `https://pm.corp.internal:8443`; paths from the installer column above.
- Placeholders in angle brackets (`<metrics_token>`, `<from step 4>`, `adm_…`) and in
  `packaging/server/pmserver.example.json` (`REPLACE_…`, all-zero `token_sha256`) **must be replaced**
  before use. Generate secrets with `openssl rand -hex 32`. Check a finished config with
  `grep -nE 'REPLACE|0{64}|<[a-z_ ]+>' /etc/offpatch/pmserver.json` (must print nothing).
- `$TOK` is a static admin token with the role the step needs (API calls). The same actions are
  available in the console for SSO users.
- Every state-changing API call that takes `{"reason": …}` records the reason in the hash-chained
  audit log. Use change or incident references.

## Gaps an operator should know about

- No automated rollback of installed updates (D12); recovery is per package class (runbook 06).
- The server TLS certificate is valid 2 years; renew it with `pmserver reissue-server-cert`
  (runbook 01). Nothing alerts on its expiry.
- No server-side view of which agents applied a trust document (key rotation); check samples.
- No API to revoke an unused enrollment token; it lapses at expiry (multi-use tokens: 14 days max).
- No group-wide exceptions; exceptions are per endpoint.
- `require_mfa` does not apply to static break-glass tokens (by design).
- A deployment `deadline` overrides endpoint maintenance windows, not the deployment's own UTC window.
- Windows agent integration (`wusa`/`msiexec`, service restart after self-upgrade) is not yet
  validated on real Windows (roadmap B1).
