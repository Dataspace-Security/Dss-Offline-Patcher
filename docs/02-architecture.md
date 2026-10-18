# 02 — Architecture, trust boundaries and threat model (MVP)

## Zones and binaries

```text
 CONNECTED ACQUISITION ZONE            TRANSFER BOUNDARY             ISOLATED MANAGEMENT ZONE                 ENDPOINT ZONE
 ┌────────────────────────┐   .pmb    ┌──────────────────┐  files   ┌────────────────────────────┐  HTTPS   ┌──────────────┐
 │ pmctl                  │ ────────► │ drop directory   │ ───────► │ pmserver                    │ ◄──────► │ pmagent      │
 │  keygen                │  one-way  │ (diode stand-in) │  appear  │  intake → quarantine →      │ private  │  inventory   │
 │  bundle build/inspect  │           └──────────────────┘          │  validate → catalog →       │ network  │  download    │
 │  transfer (adapter)    │                                         │  approve → repository →     │  only    │  verify      │
 │ holds bundle SIGNING   │                                         │  deploy → verify → audit    │          │  install     │
 │ key (private)          │                                         │  + React console (/)        │          │  report      │
 └────────────────────────┘                                         │ holds signing PUBLIC keys   │          │ pinned pubkey│
                                                                    └────────────────────────────┘          └──────────────┘
```

| Binary | Zone | Responsibility |
|---|---|---|
| `pmctl` | Connected acquisition | Generates signing keys, builds signed bundles from downloaded vendor files, hands bundles to the transfer adapter. Never holds endpoint credentials. |
| `pmserver` | Isolated management | Intake watcher, quarantine, validation, catalog, approval, immutable repository, deployment orchestration, endpoint API, admin API, hash-chained audit, embedded console. |
| `pmagent` | Endpoint | Enrolls (mTLS client certificate), reports inventory and heartbeat, receives assignments, downloads only from `pmserver`, re-verifies signature and hash, installs (Windows `wusa`/`msiexec`, Linux `dpkg`/`rpm`, macOS `installer`), reports each stage, applies root-signed trust updates, and upgrades itself from approved `agent` packages (staged, version-checked, rolled back automatically if the new binary does not stay up). On Windows it runs as SYSTEM, refuses a state directory (`%ProgramData%\offpatch`) that is a junction or not owned by SYSTEM/Administrators, and locks it to SYSTEM + Administrators. State and certificates are replaced atomically; inventory is cached (15 min, refreshed after installs) and check-ins back off up to 15 min while the server is unreachable. |

## Data on disk (`data_dir` in `pmserver.json`)

```
<data_dir>/inbox/        transfer adapter writes here (*.pmb, *.receipt.json, *.trust.json; *.part while in flight)
<data_dir>/received/     evidence copy of every bundle file as received (by sha256), plus receipts/ and trust/
<data_dir>/quarantine/   extracted bundle contents — NEVER served
<data_dir>/repository/   approved content, addressed by sha256, read-only files — the only thing served
<data_dir>/agent-dist/   agent binaries/packages staged for download from the console
<data_dir>/pm.db         SQLite: catalog, endpoints, deployments, results, exceptions, audit
<data_dir>/audit-signing.key|.pub   signs audit export checkpoints (when audit_export_dir is set)
<data_dir>/mfa.key       encrypts authenticator (TOTP) secrets at rest (AES-256-GCM; mfa_key_file)
```

The internal CA and server certificate live in `pki_dir` (`pmserver init-pki`).

## Trust model

- **Bundle signing key** (Ed25519 private) lives only in the acquisition zone (HSM in production). The server and every agent pin the public key(s) by `key_id`. A key is only trusted for the `sources` listed against it.
- **Server** trusts nothing from the inbox until validation passes, and nothing from validation is deployable until a signed-in bank user (role `user` or higher) approves it.
- **Agent** trusts the server for *what* to install and *when*. It does not trust it for *content*: it re-verifies the original manifest signature with its pinned key and checks the payload SHA-256 before installing. A compromised repository therefore cannot push modified binaries.
- **Agent commands are scoped.** The only command is "install package X from deployment Y". There is no arbitrary remote execution.

## Abuse cases → controls

| Abuse case | Control in MVP |
|---|---|
| Modified payload in transit or in quarantine | Per-file SHA-256 in signed manifest; checked at intake **and** on the endpoint. |
| Forged manifest | Ed25519 signature check against a pinned key that is allowed for that `source`. |
| Replayed old bundle | `sequence` must be greater than the last accepted sequence for the source; `bundle_id` must be unique; `expires_at` is enforced. |
| Malformed or oversized bundle / tar bomb / path traversal | Max bundle size, max file count, max total extracted size, rejection of absolute paths, `..`, links and device entries, and of files not in the manifest. |
| Auto-deploy on receipt | Intake only creates packages in `quarantined`. Only `approve` (role `user` or higher, mandatory reason) copies into the repository. |
| Unauthorised approval | Role check plus mandatory reason, and the approval is audited. Sign-in is email + password with a mandatory authenticator app (TOTP) for bank roles, or OIDC with optional `require_mfa`; there are no static admin tokens. Agent versions are managed by the vendor (super admin) and their deployments are approved by bank admins only; per-severity multi-person approval (`approval_policy`) and `separation_of_duties`. |
| Compromised agent | A per-device mTLS client certificate (bearer secret in lab mode) limits it to its own identity. It can only report about itself and download approved content. |
| Repository tampering | Content-addressed storage. The agent hash check catches modification. Audit records approval and the hash. |
| Audit tampering | Hash chain. `GET /api/audit/verify` reports the first broken link. Optional off-box export with signed checkpoints (`audit_export_dir`, `pmserver verify-audit`) detects a fully rewritten chain. |
| Endpoint silence treated as compliant | Silent endpoints show as `offline` or `stale`, never as `installed`/`verified`. |
| Endpoint reaching the internet | Agent refuses foreign origins and has no fallback. **Network egress denial is still required.** |
| DoS via inbox flooding | Size limits, one-at-a-time intake, rejected bundles moved aside, optional per-hour rate limits (`intake_max_bundles_per_hour`, `intake_max_bytes_per_hour`; excess waits in the inbox). |
| Compromised bundle signing key | Root-signed trust documents rotate or revoke bundle keys; revoking as `compromised` revokes/rejects its packages and cancels their deployments (runbooks 03, 04). |

## Known limitations

The current list of open items is kept in [06-roadmap.md](06-roadmap.md). Architectural ones to keep
in mind: single node with SQLite and no replication to sites; vendor Authenticode is **recorded** in
the manifest by `pmctl` (Windows build hosts, `msu`/`msi` only) and not re-executed inside the
isolated zone; no automated rollback (D12). Operational gaps are listed in
[runbooks/README.md](runbooks/README.md).
