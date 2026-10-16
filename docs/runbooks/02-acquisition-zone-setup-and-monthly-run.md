# Runbook 02 — Acquisition zone setup and the monthly run

## Purpose

Set up the connected acquisition zone (signing keys, optional HSM) and run the monthly cycle:
find updates, download and verify them, build a signed bundle, send it across the boundary with a
signed receipt, and confirm on the server that what was sent is what arrived.

## When to use

- Once, when setting up the acquisition host (Part A).
- Every Patch Tuesday and for out-of-band releases (Part B).

## Prerequisites and roles

| Item | Notes |
|---|---|
| Acquisition host | Connected zone. Windows recommended: only there does `pmctl build` check Authenticode for `msu`/`msi` and record `vendor_signature: valid`. On other OSs, and always for `deb`/`rpm`/`pkg`/`agent`, it records `not_checked`. |
| `pmctl` | Same release as `pmserver`. |
| Offline machine for the root key | Never networked; or an HSM. |
| Acquisition operator | Runs `pmctl`. A second person reviews `spec.json` before signing (four-eyes, recommended). |
| Server viewer account | To check intake and reconciliation afterwards. |
| Transfer path | Drop directory (MVP) or a gateway CLI used via `-via command`. |

These commands run **only in the connected zone**. Nothing here runs in the isolated zone. Reference:
[08-acquisition.md](../08-acquisition.md).

---

## Part A — One-time setup

### A1. Bundle signing key

```bash
mkdir -p acq && cd acq
pmctl keygen -out bundle
# key_id: ed25519:9a1c0b7e4d2f6a13
# private: bundle.key (keep in the acquisition zone / HSM)
# public:  bundle.pub (install on pmserver and agents)
```

`keygen` writes `bundle.key` with mode 0600 and refuses to overwrite an existing key. Record the
`key_id`.

### A2. Root key (offline)

On the offline machine (not the acquisition host):

```bash
pmctl keygen -out root
```

- `root.key` signs trust documents only (key rotation and revocation, [runbook 03](03-key-rotation.md)).
  Store it encrypted on offline media in a safe, with a second copy in a separate location.
- `root.pub` goes to the server (`root_public_key_file`) and to every agent at enrollment
  (`-root-pubkey`).
- There is no mechanism to rotate the root key itself. Replacing it means changing the server
  config and re-enrolling every agent. Protect it accordingly.

### A3. HSM signing (optional, recommended for production)

Any `-key` (and `-root` for `pmctl trust`) accepts `exec:<command>`. `pmctl` runs the command, writes
the bytes to sign on its **stdin**, and expects the **base64 Ed25519 signature** on **stdout**. The
private key never touches `pmctl`. You must also give the public key (`-pub`, or `-root-pub` for
trust), and `pmctl` verifies every signature against it before using it.

```bash
# your wrapper around the HSM vendor's tool / PKCS#11; must print base64(signature)
pmctl build -key "exec:/opt/offpatch/hsm-sign.sh offpatch-bundle-2026" -pub bundle.pub \
  -spec spec.json -out out/2026-11.pmb -state state.json
```

The command line is split on spaces (no shell quoting). Test the wrapper with a throwaway bundle
and `pmctl inspect -pub` before relying on it.

### A4. Install the public keys in the isolated zone

Carry `bundle.pub` and `root.pub` (public keys only) to the server ([runbook 01](01-install-management-server.md))
and to the agent packaging (MSI `ConfigDir`, Linux `/etc/offpatch/`).

### A5. (Recommended) First trust document

Prove the root-key path end to end before you need it:

```bash
pmctl trust -root root.key -seq 1 -key bundle.pub=acq-zone-1 -out keys-1.trust.json
pmctl send -bundle keys-1.trust.json -to /mnt/diode/out -key bundle.key
```

On the server, `GET /api/audit?action=trust.` shows `trust.updated` with object `1`. See runbook 03.

### A6. Sequence state

`pmctl build` takes the next `sequence` per `-source` from the state file (`-state`, default
`.pmctl-state.json`) and writes it back after a successful build. The server rejects any bundle
whose sequence is not greater than the last one it accepted for that source (`replay`).
Back up the state file. If it is lost, or you move to a new host, pass `-seq` with a number higher
than the last accepted one (Intake page shows each bundle's sequence).

---

## Part B — Monthly run

> **Unattended alternative:** `pmctl auto` performs B1–B6 on a daily schedule, including the send. Set it up once with `packaging/acquisition/` (Task Scheduler or systemd timer) and check `auto-log.jsonl` and the scheduler result each morning. See [docs/08-acquisition.md](../08-acquisition.md#unattended-acquisition-pmctl-auto). The manual steps below remain the procedure for out-of-band patches and troubleshooting.

Set a working directory per month, for example `acq/2026-11/`.

### B1. What shipped?

```bash
pmctl msrc -month 2026-Nov -product "Windows 10 Version 22H2" -arch x64
pmctl msrc -month 2026-Nov -product "Windows Server 2022"
```

Prints KB, severity, CVE count and products from the MSRC CVRF API. `-product`/`-arch` limit the
products and compute severity for them only. Decide what to fetch; there is no automatic selection.

### B2. Look up catalog rows (optional)

```bash
pmctl catalog-search -q KB5046613
```

First page only (up to 25 rows).

### B3. Fetch each Microsoft KB

```bash
pmctl fetch -kb KB5046613 -product "Windows 10 Version 22H2" -arch x64 \
  -min-build 19045 -max-build 19045 -msrc-month 2026-Nov \
  -out acq/2026-11/downloads -spec acq/2026-11/spec.json
```

| Flag | Notes |
|---|---|
| `-kb`, `-product`, `-arch` | Must select exactly one catalog row; otherwise it fails and lists candidates. Use `-match <title text>` to narrow, `-file <name text>` when an update has several files. |
| `-min-build`, `-max-build` | Applicability build range written into the spec. |
| `-severity` or `-msrc-month` | Severity source. Without both, the catalog's MSRC field is used, else `important` (with a warning). |
| `-package-id` | Default `<KB>-<arch>`. |
| `-product-code` | Only if the catalog file is an `.msi`. |

`fetch` refuses downloads with no catalog hash, checks SHA-1 (and SHA-256 when offered) and size,
resumes interrupted downloads, and replaces an existing spec entry with the same `package_id`.

### B4. Third-party and non-Windows packages (`fetch-url`)

```bash
# Windows MSI
pmctl fetch-url -url https://downloads.vendor.example/app-5.2.msi \
  -sha256 <hash from the vendor's release notes or signed checksum file> \
  -package-id VendorApp-5.2 -title "Vendor App 5.2" -vendor Vendor \
  -kind msi -product-code {11111111-2222-3333-4444-555555555555} -version 5.2.0 \
  -severity important -out acq/2026-11/downloads -spec acq/2026-11/spec.json

# Linux .deb (kind inferred from the extension; -package-name required for deb/rpm/pkg)
pmctl fetch-url -url https://mirror.vendor.example/openssl_3.0.13-1_amd64.deb -sha256 <hex> \
  -package-id openssl-3.0.13-1-deb12-amd64 -title "OpenSSL 3.0.13-1 (Debian 12)" -vendor Debian \
  -package-name openssl -version 3.0.13-1 -arch x64 -severity important \
  -out acq/2026-11/downloads -spec acq/2026-11/spec.json
```

| Flag | Notes |
|---|---|
| `-kind` | `msu`, `msi`, `deb`, `rpm`, `pkg` or `agent`. Default from the file extension (`.msu`, `.msi`, `.deb`, `.rpm`, `.pkg`); required for `agent`. |
| `-kb` / `-product-code` / `-package-name` | Required for `msu` / `msi` / `deb`,`rpm`,`pkg` respectively. |
| `-version` | Required for `deb`, `rpm`, `pkg`, `agent`. |
| `-os` | `windows`, `linux` or `macos`. Default from the kind (`deb`/`rpm` → linux, `pkg` → macos, otherwise windows). Set it for `agent` packages that are not for Windows. |
| `-arch` | Default `any`. |
| `-min-build`, `-max-build`, `-supersedes`, `-release-date`, `-file` | Optional. |

HTTPS only; `-sha256` is required and a mismatch deletes the download. The new entry is
schema-checked before `spec.json` is written.

### B5. Optional fields not covered by `fetch-url`

`fetch-url` has no flags for `prerequisites` or `applicability.editions`. Add them to the entry in
`spec.json` by hand, or write the whole entry by hand for files you obtained another way:

```json
{"package_id": "openssl-3.0.13-1-deb12-amd64", "title": "OpenSSL 3.0.13-1 (Debian 12)", "vendor": "Debian",
 "kind": "deb", "package_name": "openssl", "version": "3.0.13-1", "severity": "important",
 "release_date": "2026-11-12", "prerequisites": ["libssl3"],
 "applicability": {"os": "linux", "arch": "x64", "editions": ["debian"]},
 "path": "downloads/openssl_3.0.13-1_amd64.deb"}
```

- `deb`/`rpm` need `applicability.os: linux`, `pkg` needs `macos`, plus `package_name` and `version`.
  On Linux, `editions` matches the distribution `ID` from `/etc/os-release` (`debian`, `ubuntu`,
  `rhel`, `rocky`, …). Leave `min_build`/`max_build` at 0 for Linux and macOS (agents report build 0).
- `prerequisites` are package names (or KBs) that must already be in the endpoint's inventory.
  Dependencies are never resolved from network repositories.
- `vendor_signature`: `pmctl build` runs Authenticode only for `msu`/`msi` entries (on Windows).
  `deb`, `rpm`, `pkg` and `agent` entries are recorded as `not_checked` automatically; leave the
  field out.

### B6. Review, build, inspect

```bash
# second person reviews acq/2026-11/spec.json (package ids, severity, applicability, supersedes)
pmctl build -key acq/bundle.key -spec acq/2026-11/spec.json \
  -out acq/2026-11/out/2026-11.pmb -state acq/state.json
# -source acq-zone-1 (default) · -ttl 720h (default; max 90 days) · -seq to override
pmctl inspect -bundle acq/2026-11/out/2026-11.pmb -pub acq/bundle.pub
```

`inspect` must print `SCHEMA: ok`, `SIGNATURE: ok` and `ok` for every package. Note the bundle
SHA-256 printed by `build`.

The bundle must be received before it expires (`-ttl`). The server also rejects a `created_at`
more than 10 minutes in the future, so keep the acquisition host's clock in sync.

### B7. Send with a signed receipt

```bash
# drop directory (MVP / diode presenting a directory)
pmctl send -bundle acq/2026-11/out/2026-11.pmb -to /mnt/diode/out -key acq/bundle.key -log acq/sent.jsonl

# gateway / diode CLI: {file} is replaced by the path (appended if absent); must exit 0 only when accepted
pmctl send -bundle acq/2026-11/out/2026-11.pmb -via command -command "diodectl push {file}" \
  -key acq/bundle.key -log acq/sent.jsonl
```

- Only `.pmb` and `.trust.json` files can be sent.
- The drop-dir adapter writes `<name>.part` and renames, so the receiver never sees a partial file.
  It refuses if a file of that name is still pending in the drop directory.
- `-key` signs the transfer receipt (file or `exec:` with `-pub`). Without it the receipt is
  unsigned and the server counts it as unsigned.
- The receipt (`<name>.pmb.receipt.json`) is sent after the bundle and appended to `-log`
  (default `sent.jsonl`).

### B8. Confirm intake and reconcile (isolated zone, viewer)

1. **Intake** page: the bundle is `validated` and every check is green. If it is `rejected`, see
   the check table in the [admin guide §8.1](../07-admin-guide.md#81-bundle-rejected-at-intake).
2. **Intake → Transfer reconciliation**, or:

```bash
curl --cacert ca.pem -H "Authorization: Bearer $TOK" https://pm.corp.internal:8443/api/transfer/reconcile
```

| Field | Expected | If not |
|---|---|---|
| `matched` | Contains this month's receipt | — |
| `receipt_without_bundle` | Empty | Sent but never arrived, or arrived with different bytes (substitution). Investigate the transfer path. |
| `bundle_without_receipt` | Empty | A bundle arrived without a valid signed receipt: sent without `-key`, receipt lost, or a file that did not come from `pmctl send`. |
| `unsigned_or_invalid_receipts` | 0 | Receipts without `-key`, or with a signature that does not verify against a trusted key. |

Receipts for **trust documents** (`*.trust.json`) are left out of `matched` and
`receipt_without_bundle`; trust documents are tracked by the `trust.updated` / `trust.rejected`
audit events instead. They still count in `unsigned_or_invalid_receipts` if sent without `-key`,
so sign their receipts too.

3. Hand over to the approvers (admin guide §3.2 and §4).

## Verification

- `pmctl inspect` output clean; bundle SHA-256 from `build` equals `file_sha256` on the Intake page
  and `sha256` in `sent.jsonl`.
- Audit: `bundle.validated`, one `package.quarantined` per new package, `transfer.receipt` with
  `outcome: success`.

## Rollback / escape hatch

- Bad entry discovered before sending: fix `spec.json`, rebuild (a new sequence is used; gaps are fine).
- Bundle rejected: fix the cause and rebuild. A rejected bundle does not consume its sequence on the
  server.
- Wrong content already validated (still `quarantined`): an approver **rejects** the packages with a
  reason. Re-send corrected content under **new** `package_id`s.
- Wrong content already approved: revoke ([runbook 06](06-failed-update-recovery.md)).
- A signing key may be exposed: [runbook 04](04-signing-key-compromise.md).

## Evidence to keep

- `msrc` output and the reasons for the selection.
- Final `spec.json` (includes the `acquired` provenance block from `fetch`) and the reviewer's name.
- `pmctl build` and `inspect` output; bundle SHA-256.
- `sent.jsonl` and the state file (back it up).
- Reconciliation result for the month; the lifecycle export per package once deployed (runbook 07).
