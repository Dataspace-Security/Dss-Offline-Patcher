# Runbook 05 — Backup and restore of the management server

## Purpose

Take consistent, verifiable backups of `pmserver`, restore them, and prove the restore works. A
tested restore in a non-production environment is part of the **Phase 7 exit gate**
([00-product-workflow.md](../00-product-workflow.md) Phase 7).

## When to use

- Scheduled backups (daily, and before every upgrade or config change).
- Server loss or corruption.
- The periodic restore test (at least before the pilot and then on your DR test schedule).

## What a backup contains (`internal/backup`)

A backup is a directory with three files (format 2, finding S-6):

| File | Content |
|---|---|
| `data.tar.age` | Encrypted: database snapshot (`VACUUM INTO`, consistent while the server runs) `data/pm.db`; approved content repository `data/repository/…`; quarantine `data/quarantine/…`; received bundle evidence, receipts, trust documents `data/received/…`; staged agent binaries `data/agent-dist/…` |
| `keys.tar.age` | Encrypted **separately** (own file key; optionally other recipients, `-keys-recipients` or `backup-keys-recipients.txt` next to the config): audit checkpoint signing key pair `data/audit-signing.key/.pub`; auto-download policy signing key pair `data/policy-signing.key/.pub`; MFA key `data/mfa.key` (decrypts the users' authenticator secrets; `mfa_key_file`, default `<data_dir>/mfa.key`); all files in `pki_dir` (incl. **`ca.key`**) unless `-no-pki` `pki/…`; the config file given with `-config` `config/<name>` |
| `backup.json` | Plaintext manifest, **signed** with the audit-signing key: path, size and SHA-256 of every file (before encryption) and which part holds it, SHA-256 and size of both encrypted parts, the recipients, the audit head (seq + hash) |

**Encryption.** [age](https://age-encryption.org) (`filippo.io/age`), hybrid post-quantum keys
(ML-KEM-768 + X25519), to the bank's **backup recipient** (public key) in
`/etc/offpatch/backup-recipients.txt` (`-recipients FILE`; default: `backup-recipients.txt`
next to `-config`). The matching **identity** (private key) is not on the server: the backup
service cannot decrypt its own backups. Plaintext never reaches the backup directory (the
database snapshot is taken next to the live database and deleted after). `pmserver backup`
refuses to run without a recipient.

**Keys (installer).** On the first install with this version (and upgrades from an earlier one)
the installer runs `pmserver backup-keygen`: the recipient goes to
`/etc/offpatch/backup-recipients.txt` (root:offpatch 0640), the identity to
`/root/offpatch-backup-identity.txt` (root only, 0400) with a loud warning. **Copy the identity
offline** (bank safe, HSM or password manager, two copies), then delete it on the server
(`sudo shred -u /root/offpatch-backup-identity.txt`); every installer run warns while it is still
there. A bank with its own age key writes its public key (`age1…` or `age1pq1…`) to
`backup-recipients.txt` before installing; no key pair is generated then. Manual install:
`pmserver backup-keygen -out <identity file> -recipient-out /etc/offpatch-server/backup-recipients.txt`.

**Signature.** `backup.json` is signed with `<data_dir>/audit-signing.key`. Keep the server's
`audit-signing.pub` off the server with the identity (you already need it for
`verify-audit`, runbook 07): `verify-backup`, `restore` and `decrypt-backup` check the signature
against `-pub FILE`, or against `<data_dir>/audit-signing.pub` of `-config` when it is readable.

**Earlier backups** (format 1, a plain folder copy) are still verified and restored, with a
warning; the installer counts them and warns. Delete them once a new encrypted backup is
verified: they hold `ca.key` and `mfa.key` in plaintext. A pre-upgrade backup taken by a version
from before encrypted backups is plaintext too (the installer says so).

**Not included** — back these up separately:

- Files the config points to outside `data_dir`/`pki_dir`: `trusted_keys[].public_key_file`,
  `root_public_key_file`, `tls_cert`/`tls_key` when not in `pki_dir`, `oidc.ca_cert_file`, and
  `mfa_key_file` when it is not `<data_dir>/mfa.key` (only that path is copied).
- `audit_export_dir` (it is your off-box evidence store; it has its own retention).
- `<data_dir>/inbox/` (unprocessed transfers) and `*.part`/`*.tmp` files.
- The systemd unit, OS configuration, logs.
- Anything in the acquisition zone (keys, `state.json`, `sent.jsonl`) and agent state on endpoints.

`restore` does **not** restore the config file. You put it in place yourself (step R3; it is in `keys.tar.age`).

**The MFA key belongs with the database.** A restore without the matching `mfa.key` loses every
MFA enrolment: authenticator codes no longer verify, and every bank user must be reset (**Reset
MFA** by an Admin; the super admin with `pmserver reset-admin`) and enrol again. Both are in the
backup, encrypted: with the database, the key decrypts the authenticator secrets.

**Audit evidence.** Every `pmserver backup` writes the audit event `backup.created` (actor
`system:backup`; files, audit seq, whether the PKI was included) and every `pmserver restore` writes
`backup.restored` into the restored database. The compliance report uses them as backup and
restore-test evidence.

## Prerequisites and roles

| Item | Notes |
|---|---|
| Server OS admin | Runs `pmserver backup` as the `offpatch` user (needs read access to data, PKI, config and the recipients file). |
| Backup target | Separate disk/host. The backup is encrypted; it still holds every key, so restrict access. |
| Backup identity + `audit-signing.pub` | Kept offline by the bank (key custodian). Needed to restore, decrypt or deep-verify. |
| Restore host | Same or newer `pmserver` version, same paths as in the config. |

Commands below use the installer layout (config `/etc/offpatch/pmserver.json`, unit
`offpatch-server`). Manual install: `/etc/offpatch-server/pmserver.json` and unit `pmserver`; see
[Paths by install method](README.md#paths-by-install-method).

## Scheduled backups (installer)

`install-ubuntu.sh --role server` (and `--role all`) installs:

| Unit / file | What it does |
|---|---|
| `offpatch-backup.timer` | Daily at 02:30 (random delay up to 15 min, catches up after downtime). |
| `offpatch-backup.service` | Runs `/opt/offpatch/bin/offpatch-backup` as `offpatch`: checks free space, then `pmserver backup -config /etc/offpatch/pmserver.json -recipients /etc/offpatch/backup-recipients.txt -dir <backup-dir>/<UTC timestamp>` and `pmserver verify-backup -config … -dir …` (signature and encrypted parts; the server has no identity to decrypt). An incomplete or unverified backup is deleted and the run fails. |
| Retention | Keeps the newest **14** verified scheduled backups (`--backup-keep N`), deletes older ones. |
| `offpatch-backup-failed.service` | `OnFailure=`: logs `offpatch-backup.service FAILED` at `daemon.err` (syslog / journal, tag `offpatch-backup`) and writes `<backup-dir>/last-failure`. |
| `<backup-dir>/last-success` | Time and path of the last verified backup. `install-ubuntu.sh --status` shows it. |
| `<backup-dir>/pre-upgrade-*` | Taken by the installer before every server upgrade (newest 3 kept; `--skip-backup` skips it). |

Default `<backup-dir>` is `/var/lib/offpatch-backup` (`--backup-dir`, mode 0700, owner `offpatch`).
Each backup is a **full copy** of the repository, so size the disk for about 15 times `data_dir`, or
lower `--backup-keep`. The installer warns when the backup directory is on the same filesystem as
the data. Either way, **copy each backup off the machine** (it is encrypted; a disk failure would
otherwise lose both).

Watch for failures: alert on `offpatch-backup` errors in syslog/journal, on a `last-failure` newer
than `last-success`, or on `last-success` older than 26 hours. The server does not alert on a missing
backup itself.

```bash
systemctl list-timers offpatch-backup.timer
journalctl -u offpatch-backup -n 20
sudo systemctl start offpatch-backup.service    # take one now (e.g. before a config change)
```

## Backup procedure (manual / on demand)

1. Run (safe while the server is running):

   ```bash
   DIR=/srv/backup/offpatch/$(date -u +%Y%m%dT%H%M%SZ)
   sudo -u offpatch /usr/local/bin/pmserver backup -config /etc/offpatch/pmserver.json \
     -recipients /etc/offpatch/backup-recipients.txt -dir "$DIR"
   # encrypted backup written to …: N files, audit seq 12345, signed by ed25519:…
   ```

   - `-dir` must not already contain a backup (`backup.json`). Use a new directory each time.
   - `-no-pki` leaves out the whole `pki_dir` (CA key, CA certificate, server certificate and key).
     Only use it if the PKI is backed up separately under stricter control.
   - `-keys-recipients FILE` encrypts `keys.tar.age` to other recipients (e.g. the key
     custodian's key only), so whoever restores data cannot read the keys without them.
2. Verify:

   ```bash
   /usr/local/bin/pmserver verify-backup -config /etc/offpatch/pmserver.json -dir "$DIR"
   # backup OK: N files, created …, audit seq 12345 (signature and encrypted parts verified)
   ```

   It checks the manifest signature and both encrypted parts, and fails on any modified, missing
   or unexpected file. Add `-identity <identity file>` (off the server, e.g. on the restore test
   host) to also decrypt and check every file inside.
3. Copy the directory to the backup target. Back up the files listed under "Not included" with
   it.

**Schedule (manual install only; the installer already set this up).** Daily, plus before upgrades
and config changes. Example systemd timer service:

```ini
# /etc/systemd/system/pmserver-backup.service
[Service]
Type=oneshot
User=offpatch
ExecStart=/bin/sh -c 'd=/srv/backup/offpatch/$(date -u +%%Y%%m%%dT%%H%%M%%SZ); /usr/local/bin/pmserver backup -config /etc/offpatch-server/pmserver.json -dir "$d" && /usr/local/bin/pmserver verify-backup -config /etc/offpatch-server/pmserver.json -dir "$d"'
# /etc/systemd/system/pmserver-backup.timer
[Timer]
OnCalendar=*-*-* 02:30:00
Persistent=true
[Install]
WantedBy=timers.target
```

(`/srv/backup` must be writable by `offpatch`.) Alert if the job fails. `pmserver` itself prunes
nothing; the installer's `offpatch-backup` script does the retention described above.

Container deployments (`packaging/server/Dockerfile`): the image's entrypoint already
passes `-config`, so run subcommands with `docker exec <container> /usr/local/bin/pmserver backup
-config /etc/offpatch-server/pmserver.json -dir <dir inside a mounted volume>`.

## Restore procedure

R1. **Stop the server and the backup timer** (if running):
`systemctl stop offpatch-backup.timer offpatch-server` (manual install: `systemctl stop pmserver`).

R2. **Bring the keys.** The key custodian brings the backup identity file and the server's
`audit-signing.pub` (both kept offline). Put them in a root-owned 0700 directory readable by the
restore account only for the duration (e.g. `install -d -m 0700 -o offpatch /run/offpatch-restore`),
and remove them after R4.

R3. **Put the config in place.** Copy `config/pmserver.json` from the backup (or your current
reviewed version) to `/etc/offpatch/pmserver.json`, plus the external files listed under
"Not included" (`/etc/offpatch/keys/bundle.pub`, `root.pub`, IdP CA, …). `restore` reads `data_dir`
and `pki_dir` from this config. The config is inside `keys.tar.age`: take it out with

```bash
sudo -u offpatch /usr/local/bin/pmserver decrypt-backup -dir /var/lib/offpatch-backup/20261116T023000Z \
  -identity /run/offpatch-restore/identity.txt -pub /run/offpatch-restore/audit-signing.pub -out /run/offpatch-restore/plain
# then copy /run/offpatch-restore/plain/config/pmserver.json; delete /run/offpatch-restore/plain afterwards (plaintext keys)
```

(`age -d -i identity.txt keys.tar.age | tar -x` works too, with `age` 1.3 or later.)

R4. **Verify and restore** (verification runs first; with the identity every file is checked):

```bash
sudo -u offpatch /usr/local/bin/pmserver verify-backup -dir /var/lib/offpatch-backup/20261116T023000Z \
  -pub /run/offpatch-restore/audit-signing.pub -identity /run/offpatch-restore/identity.txt
sudo -u offpatch /usr/local/bin/pmserver restore -config /etc/offpatch/pmserver.json \
  -dir /var/lib/offpatch-backup/20261116T023000Z \
  -pub /run/offpatch-restore/audit-signing.pub -identity /run/offpatch-restore/identity.txt
# restored N files into /var/lib/offpatch-server; audit chain verified to seq 12345; approved content verified
```

- An encrypted backup is not restored without `-identity`; a backup whose `backup.json` is not
  signed by the given `audit-signing.pub` is refused. `-pub` may be left out when the config's
  `data_dir` still holds the right `audit-signing.pub` (restore over the same server).
- Earlier unencrypted backups (format 1) restore without `-identity`, with a warning.
- Then delete the identity and the decrypted copy from the server again.

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
`/mnt/audit-worm/offpatch/after-restore-20261116`). Installer: change `audit_export_dir` in
`pmserver.json` and re-run the installer with the same `--role` (it rewrites `ReadWritePaths=` from
the config; use `--skip-backup` if the database is the restored one you just verified). Manual
install: add it to `ReadWritePaths=` in the unit)
and keep the old one unchanged as evidence. If you started without doing this, change the config,
restart, and acknowledge the alert.

R6. **Start:** `systemctl start offpatch-server offpatch-backup.timer`; check
`journalctl -u offpatch-server` (manual install: unit `pmserver`).

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
2. On the test host: install the same `pmserver` version, **without** creating a new CA: copy the
   binaries to `/opt/offpatch/bin` (or runbook 01 method B steps 1 and 7, not `init-pki`), put the
   config in place with `listen` on the test host and `audit_export_dir` pointing to a scratch
   directory. (Running the installer would create a new CA and a new MFA key; restore overwrites the PKI,
   but use a clean host so nothing is mixed.)
3. Restore (R2–R4, the identity brought by the key custodian). Record the duration.
4. Before starting the server, cross-check against a copy of production's audit export:
   `pmserver verify-audit -export <copy of production audit_export_dir> -pub /var/lib/offpatch-server/audit-signing.pub
   -db /var/lib/offpatch-server/pm.db` must report `"ok": true`. (Run it before the start: once the
   test server writes new events, their sequence numbers collide with checkpoints production wrote
   after the backup, and those checkpoints are then reported as differing.)
5. Start the server, then check:
   - `GET /api/audit/verify` → `ok: true`, count ≥ the backup's audit seq.
   - Catalog: approved packages present; open one and download its lifecycle export.
   - Endpoints and deployments match production at backup time.
   - Sign in with SSO and as a local user with an authenticator code enrolled before the backup
     (proves `mfa.key` was restored). Audit shows `backup.restored`.
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
