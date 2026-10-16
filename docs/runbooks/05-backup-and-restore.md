# Runbook 05 — Backup and restore of the management server

## Purpose

Take consistent, verifiable backups of `pmserver`, restore them, and prove the restore works. A
tested restore in a non-production environment is part of the **Phase 7 exit gate**
([00-product-workflow.md](../00-product-workflow.md) Phase 7).

## When to use

- Scheduled backups (daily, and before every upgrade or config change).
- Server loss or corruption.
- The periodic restore test (at least before the pilot and then on your DR test schedule).

## What a backup contains (`internal/backup/backup.go`)

| Included | Path in backup |
|---|---|
| Database snapshot (`VACUUM INTO`, consistent while the server runs) | `data/pm.db` |
| Approved content repository | `data/repository/…` |
| Quarantine | `data/quarantine/…` |
| Received bundle evidence, receipts, trust documents | `data/received/…` |
| Staged agent binaries | `data/agent-dist/…` |
| Audit checkpoint signing key pair | `data/audit-signing.key`, `data/audit-signing.pub` |
| All files in `pki_dir` (incl. **`ca.key`**) unless `-no-pki` | `pki/…` |
| The config file given with `-config` | `config/<name>` |
| SHA-256 of every file, audit head (seq + hash) | `backup.json` |

**Not included** — back these up separately:

- Files the config points to outside `data_dir`/`pki_dir`: `trusted_keys[].public_key_file`,
  `root_public_key_file`, `tls_cert`/`tls_key` when not in `pki_dir`, `oidc.ca_cert_file`.
- `audit_export_dir` (it is your off-box evidence store; it has its own retention).
- `<data_dir>/inbox/` (unprocessed transfers) and `*.part`/`*.tmp` files.
- The systemd unit, OS configuration, logs.
- Anything in the acquisition zone (keys, `state.json`, `sent.jsonl`) and agent state on endpoints.

`restore` does **not** restore the config file. You put it in place yourself (step R2).

## Prerequisites and roles

| Item | Notes |
|---|---|
| Server OS admin | Runs `pmserver backup` as the `offpatch` user (needs read access to data, PKI and config). |
| Backup target | Separate disk/host, encrypted. A backup with PKI contains the CA private key. |
| Restore host | Same or newer `pmserver` version, same paths as in the config. |

## Backup procedure

1. Run (safe while the server is running):

   ```bash
   DIR=/srv/backup/offpatch/$(date -u +%Y%m%dT%H%M%SZ)
   sudo -u offpatch /usr/local/bin/pmserver backup -config /etc/offpatch-server/pmserver.json -dir "$DIR"
   # WARNING: backup contains the CA private key — store it encrypted and access-controlled
   # backup written to …: N files, audit seq 12345
   ```

   - `-dir` must not already contain a backup (`backup.json`). Use a new directory each time.
   - `-no-pki` leaves out the whole `pki_dir` (CA key, CA certificate, server certificate and key).
     Only use it if the PKI is backed up separately under stricter control.
2. Verify:

   ```bash
   /usr/local/bin/pmserver verify-backup -dir "$DIR"
   # backup OK: N files, created …, audit seq 12345
   ```

   It re-hashes every file and fails on any modified, missing or unexpected file.
3. Copy the directory to the backup target and encrypt it. Back up the files listed under "Not
   included" with it.

**Schedule.** Daily, plus before upgrades and config changes. Example systemd timer service:

```ini
# /etc/systemd/system/pmserver-backup.service
[Service]
Type=oneshot
User=offpatch
ExecStart=/bin/sh -c 'd=/srv/backup/offpatch/$(date -u +%%Y%%m%%dT%%H%%M%%SZ); /usr/local/bin/pmserver backup -config /etc/offpatch-server/pmserver.json -dir "$d" && /usr/local/bin/pmserver verify-backup -dir "$d"'
# /etc/systemd/system/pmserver-backup.timer
[Timer]
OnCalendar=*-*-* 02:30:00
Persistent=true
[Install]
WantedBy=timers.target
```

(`/srv/backup` must be writable by `offpatch`.) Alert if the job fails. Retention of backup copies is
your policy; nothing is pruned by `pmserver`.

Container deployments (`packaging/server/Dockerfile`, being written): the image's entrypoint already
passes `-config`, so run subcommands with `docker exec <container> /usr/local/bin/pmserver backup
-config /etc/offpatch-server/pmserver.json -dir <dir inside a mounted volume>`.

## Restore procedure

R1. **Stop the server** (if it is running): `systemctl stop pmserver`.

R2. **Put the config in place.** Copy `config/pmserver.json` from the backup (or your current
reviewed version) to `/etc/offpatch-server/pmserver.json`, plus the external files listed under
"Not included" (`bundle.pub`, `root.pub`, IdP CA, …). `restore` reads `data_dir` and `pki_dir`
from this config.

R3. **Verify the backup** you are about to restore:

```bash
/usr/local/bin/pmserver verify-backup -dir /srv/backup/offpatch/20261116T023000Z
```

R4. **Restore:**

```bash
sudo -u offpatch /usr/local/bin/pmserver restore -config /etc/offpatch-server/pmserver.json \
  -dir /srv/backup/offpatch/20261116T023000Z
# restored N files into /var/lib/offpatch-server; audit chain verified to seq 12345; approved content verified
```

- If `data_dir` already has `pm.db`, restore refuses. Add `-force` to overwrite (server must be
  stopped). `-force` overwrites files from the backup but does not delete other files already in
  `data_dir`; for a clean restore, move the old `data_dir` aside first.
- PKI files are restored into `pki_dir` when the backup contains them.
- After copying, restore checks: the audit chain verifies, the audit head matches `backup.json`, and
  every approved package's file is in the repository with the right size and SHA-256. Any failure
  stops with an error.

R5. **Audit export directory.** The database records how far it exported. After a restore that
point is older than the newest checkpoint already in `audit_export_dir` (events written after the
backup are lost from the database, and new events would reuse their sequence numbers). The server
detects this and **refuses to export**: every `audit_checkpoint_interval` it logs "export directory
… already has checkpoints up to seq N but the database has exported only to M (restored from
backup?)" and raises the critical alert `audit_export_failed`. No new evidence leaves the server and
retention pruning stops until you act.

Before starting the server, set `audit_export_dir` to a **new empty directory** (e.g.
`/mnt/audit-worm/offpatch/after-restore-20261116`; add it to `ReadWritePaths=` in the systemd unit)
and keep the old one unchanged as evidence. If you started without doing this, change the config,
restart, and acknowledge the alert.

R6. **Start:** `systemctl start pmserver`; check `journalctl -u pmserver`.

## After a restore: what changed since the backup is lost

| Lost | Consequence | Action |
|---|---|---|
| Endpoints enrolled after the backup | Agents get `401 client certificate not valid for an active endpoint` | Re-enroll them (runbook 09). |
| Certificates renewed after the backup | Same 401 (serial no longer matches) | Re-enroll. |
| Endpoints retired after the backup | They are active again | Retire again. |
| Bundles received after the backup | Not in the catalog; the source's last sequence is older | Re-send them from the acquisition zone (their sequence is still higher, so they are accepted). |
| Approvals, deployments, exceptions after the backup | Gone | Redo them; reference the incident in reasons. |
| Audit events after the backup | Gone from the database | They exist in the old `audit_export_dir` if export was on. Record the gap in the incident report. |

## Restore test (Phase 7 exit gate)

Run on a separate, non-production host at least before the pilot, then on your DR schedule.

1. Take a fresh backup on production and `verify-backup` it. Note the audit seq.
2. On the test host: install the same `pmserver` version (runbook 01 steps 1 and 7, **not**
   `init-pki`), put the config in place with `listen` on the test host and `audit_export_dir`
   pointing to a scratch directory.
3. Restore (R3–R4). Record the duration.
4. Before starting the server, cross-check against a copy of production's audit export:
   `pmserver verify-audit -export <copy of production audit_export_dir> -pub /var/lib/offpatch-server/audit-signing.pub
   -db /var/lib/offpatch-server/pm.db` must report `"ok": true`. (Run it before the start: once the
   test server writes new events, their sequence numbers collide with checkpoints production wrote
   after the backup, and those checkpoints are then reported as differing.)
5. Start the server, then check:
   - `GET /api/audit/verify` → `ok: true`, count ≥ the backup's audit seq.
   - Catalog: approved packages present; open one and download its lifecycle export.
   - Endpoints and deployments match production at backup time.
   - Sign in with SSO and with the break-glass token.
6. Do **not** let production agents reach the test server. Their certificates are valid there
   (same CA, same database), so a production agent pointed at it would check in and could be
   given work. Keep the test host on an isolated network. Optionally enroll one test agent to
   prove the restored CA issues certificates.
7. Record the result.

## Verification

- `verify-backup` output for every scheduled backup.
- Restore command prints "audit chain verified … approved content verified".
- Post-restore checks in the restore test all pass.

## Rollback / escape hatch

- Restore failed half-way: stop, move the partially restored `data_dir` aside, restore again into an
  empty directory (or another, older backup).
- `verify-backup` fails: do not use that backup; take the previous one and investigate the storage.

## Evidence to keep

- Backup job logs and `verify-backup` output (date, file count, audit seq).
- Restore test record: date, backup used, duration, each check's result, tester, sign-off.
- For a real restore: incident record, backup used, data lost window, endpoints re-enrolled, old
  and new `audit_export_dir` paths.
