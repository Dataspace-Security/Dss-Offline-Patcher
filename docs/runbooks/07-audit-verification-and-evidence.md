# Runbook 07 — Audit verification and evidence export

## Purpose

Prove the audit trail is intact, produce evidence for one patch lifecycle, and verify the off-box
audit export independently of the server.

## When to use

- Monthly, and before any external audit.
- After a restore or a suspected intrusion on the management server.
- When an auditor asks for the history of a specific patch.

## How the audit trail works (from the code)

| Layer | What it is | What detects tampering |
|---|---|---|
| Database chain | Every event has `seq`, `prev_hash` and `hash = SHA-256(prev_hash, seq, ts, actor, action, object_type, object_id, outcome, package_id, details)`. The table is append-only through the application. | `GET /api/audit/verify` walks the chain and reports the **first** broken event: `sequence gap`, `prev_hash mismatch`, or `hash mismatch (event modified)`. |
| Off-box export (`audit_export_dir`) | Every `audit_checkpoint_interval` (default 1 h): new events to `audit-<from>-<to>.jsonl`, plus one line in `checkpoints.jsonl` with the last `seq`, its `hash`, the file's SHA-256, signed with Ed25519 by `<data_dir>/audit-signing.key`. Audited as `audit.checkpoint`. | `pmserver verify-audit`: checks signatures, file hashes, chain continuity across files, that each checkpoint matches its last event, and (with `-db`) that the live database still has the checkpointed hashes. Detects a **fully rewritten** database chain, which the database check alone cannot. |
| Retention (`audit_retention`, optional, min 720h) | Events older than the retention **and** already covered by a signed checkpoint are deleted from the database. The chain then starts from a stored anchor (last pruned seq + hash). Audited as `audit.pruned`. | Pruned events remain in the export files; `verify-audit` covers them. |

## Prerequisites and roles

| Item | Notes |
|---|---|
| Viewer role | For the console/API checks and lifecycle export. |
| Read-only copy of `audit_export_dir` | For the off-box check, ideally on an auditor's workstation. |
| `audit-signing.pub` | From `<data_dir>/audit-signing.pub`. Obtain it once at install time and store it with the auditors, so a compromised server cannot swap it. |
| `pmserver` binary | `verify-audit` is a subcommand; it does not start a server. |

## Steps

### 1. Chain check (console or API)

Audit page → **Verify**, or:

```bash
curl --cacert ca.pem -H "Authorization: Bearer $TOK" https://pm.corp.internal:8443/api/audit/verify
# {"ok":true,"count":48211,"first_bad_seq":0,"error":""}
```

The Overview page and the metric `offpatch_audit_chain_ok` show the same result continuously.

### 2. Off-box verification

On the auditor's workstation, with a read-only copy of the export directory:

```bash
pmserver verify-audit -export /mnt/audit-copy/offpatch -pub audit-signing.pub
```

With a copy of the live database (taken with `pmserver backup`, or the file copied while the server
is stopped), add the cross-check:

```bash
pmserver verify-audit -export /mnt/audit-copy/offpatch -pub audit-signing.pub -db /tmp/restore/data/pm.db
```

Output (exit code 0 only when OK):

```json
{ "ok": true, "checkpoints": 712, "events": 48190, "last_seq": 48190, "problems": null }
```

`-export` and `-pub` are required; `-db` is optional. `ok` is false if there are no checkpoints at
all.

### 3. What tamper evidence looks like

| Message | Meaning |
|---|---|
| API: `sequence gap` at seq N | Events were deleted from the database. |
| API: `prev_hash mismatch` at seq N | An event was inserted, removed or re-ordered. |
| API: `hash mismatch (event modified)` at seq N | Event N's content was changed. |
| `checkpoint N: bad signature` | Checkpoint line altered, or signed by a different key (wrong `-pub`, or the server key was replaced). |
| `checkpoint N: export file … missing or modified` | An export file was deleted or edited. |
| `checkpoint N: gap after M` | A checkpoint (and its events) is missing between M and N. |
| `event N: chain break` / `event N: hash mismatch` | Export file contents do not chain or were edited. |
| `checkpoint N: does not match last exported event` | Checkpoint and file disagree. |
| `checkpoint N: database event hash differs — database chain was rewritten` | The database was rewritten after export (even if the database chain itself verifies). Also seen when you check a database restored from backup (which has since written new events) against the export directory that existed before the restore; see runbook 05 R5. |
| Server log / alert `audit_export_failed`: `export directory … already has checkpoints up to seq N but the database has exported only to M (restored from backup?)` | The export directory is ahead of the database. The server refuses to write overlapping evidence and stops exporting. | After a legitimate restore: point `audit_export_dir` at a new empty directory and restart (runbook 05 R5). Without a restore: someone replaced or rolled back the database; treat as an incident. |
| `database chain: <error> at N` | Same as the API check, run against `-db`. |

Any of these: treat as a security incident. Do not modify the database or export files; take
copies (hash them) and escalate.

### 4. Lifecycle evidence for one patch

Audit page → **Export lifecycle** → enter the `package_id`, or:

```bash
curl --cacert ca.pem -H "Authorization: Bearer $TOK" -o lifecycle-KB5046613-x64.json \
  "https://pm.corp.internal:8443/api/audit/export?package_id=KB5046613-x64"
sha256sum lifecycle-KB5046613-x64.json
```

Contents: `generated_at`; `package` (metadata, SHA-256, vendor signature, state, approvals); `bundle`
(intake record with file hash, size, source, sequence, key and every check); `deployments` (each with
every target: endpoint, ring, state, attempts, exit code, detail, health, timestamps); `exceptions`
(for the package and endpoint-wide ones); `events` (the bundle's events and every event with this
`package_id`, oldest first, up to 5,000); `audit_chain` (`ok`, `count` at export time). The export is
itself audited (`audit.exported`).

Limits: events pruned by retention are not in the export (use the off-box export files for them);
transfer receipts are separate (`GET /api/transfer/reconcile`, `transfer.receipt` events).

### 5. Searching

`GET /api/audit?object_id=&action=&actor=&package_id=&limit=&before_seq=` (newest first, default 200,
max 5,000; `action` is a prefix match). Examples:

```bash
# all approvals and revocations in the last page of events
curl … "https://pm.corp.internal:8443/api/audit?action=package.&limit=500"
# everything one user did
curl … "https://pm.corp.internal:8443/api/audit?actor=user:alice&limit=500"
# denied access attempts and failed logins
curl … "https://pm.corp.internal:8443/api/audit?action=access.denied"
curl … "https://pm.corp.internal:8443/api/audit?action=auth.login_denied"
```

### 6. Retention behaviour

- `audit_retention` unset or `0`: nothing is ever deleted from the database.
- Set (≥ `720h`, needs `audit_export_dir`): after each successful export, events that are older than
  the retention and at or below the newest checkpoint are deleted. `GET /api/audit/verify` still
  verifies (from the anchor), and its `count` keeps counting from the original sequence numbers.
- The export directory is never pruned by `pmserver`. Its retention is set on the storage.
- Choose the retention period with your auditors (roadmap A6). The example config uses `26280h`
  (3 years).

## Verification

- API verify `ok: true`; off-box `verify-audit` exit 0 with `"ok": true`.
- `last_seq` from `verify-audit` is close to the current count (within one checkpoint interval).
- No `audit_export_failed` alerts open.

## Rollback / escape hatch

Read-only procedure. If verification fails, do not "repair" anything: preserve and escalate.
If the export key `audit-signing.key` is lost, the server creates a new key pair at the next start.
`verify-audit` checks all checkpoints in a directory against one `.pub`, so a directory with
checkpoints from two keys always reports bad signatures. Point `audit_export_dir` at a new empty
directory when the key changes, give the auditors the new `.pub`, and keep the old directory and
old `.pub` together. Record the change.

## Evidence to keep

- Dated `verify-audit` reports (JSON) and the API verify result.
- Lifecycle exports with their SHA-256.
- The `audit-signing.pub` fingerprint held by the auditors.
