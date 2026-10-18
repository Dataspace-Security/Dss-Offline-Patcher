# Runbook 03 — Planned bundle signing key rotation

## Purpose

Replace the bundle signing key on a schedule, without breaking content that is already approved
and deployed, using a root-signed **trust document** (`pmctl trust`).

## When to use

- Scheduled rotation (interval set by your key-management policy, roadmap A3).
- Moving signing into an HSM.
- Retiring an acquisition host.

If the old key may be **compromised**, use [runbook 04](04-signing-key-compromise.md) instead.

## How it works (from the code)

- A trust document lists bundle keys with status `active` (may sign new bundles) or `retired`
  (no new bundles; content already signed stays valid), plus `revoked` keys. It has a `sequence`
  that must increase every time, and is signed with the **root** key.
- It travels like a bundle (`pmctl send`). The server processes trust documents **before** bundles
  in the same inbox scan, verifies them against `root_public_key_file`, refuses a sequence that is
  not newer (`trust.rejected`, alert `trust_rejected`), stores it, and **replaces** its trusted key
  set with the document's keys (`trust.updated`). It re-applies the stored document at every start.
- The server passes the signed document to every agent in the check-in response. An agent that
  pinned the root key (`-root-pubkey` at enrollment) verifies it, and if its sequence is higher than
  the agent's `trust_seq`, replaces its pinned keys with **all** keys in the document (active and
  retired) and saves `trust_seq` in `agent.json`.
- A key that is in neither `-key` nor `-retire` is dropped. Agents then refuse packages signed by it
  ("untrusted key"), even already-approved ones. **Always list the old key with `-retire`.**

## Prerequisites and roles

| Item | Notes |
|---|---|
| `root.key` (offline) or root HSM signer | Custodians present per your key ceremony. |
| `root_public_key_file` set on the server | Without it, trust documents are refused ("no root_public_key_file configured"). |
| Agents enrolled with `-root-pubkey` | Agents without a root key **cannot** apply the rotation and must be re-enrolled. Check before you start (step 1). |
| Current trust sequence | `GET /api/audit?action=trust.updated&limit=1` → `object_id` is the current sequence (0 if none yet). |
| Roles | Acquisition operator + root key custodian(s); server OS admin (config update); viewer to verify. |

## Steps

1. **Check agent readiness.** On a sample of endpoints of each type, open `agent.json` in the state
   directory and confirm `root_key` is present. Endpoints without it: plan re-enrollment (runbook 09)
   with `-root-pubkey` before the old key is removed.
2. **Generate the new key** (acquisition host, or create it in the HSM):

   ```bash
   pmctl keygen -out bundle-2027
   # key_id: ed25519:<new>
   ```

3. **Issue the trust document** (offline root machine). `-seq` = current sequence + 1:

   ```bash
   pmctl trust -root root.key -seq 3 \
     -key bundle-2027.pub=acq-zone-1 \
     -retire bundle-2026.pub \
     -out keys-3.trust.json
   ```

   - `-key <file.pub>=<source>[,<source>…]` — active key(s), repeatable. At least one active key.
   - `-retire <file.pub>` — retired key(s), repeatable.
   - With an HSM root: `-root "exec:<command>" -root-pub root.pub`.
   - The output file name must end in `.trust.json`.
4. **Send it** across the boundary:

   ```bash
   pmctl send -bundle keys-3.trust.json -to /mnt/diode/out -key acq/bundle-2026.key   # signs the transfer receipt
   ```

5. **Verify on the server** (within one `intake_interval`):

   ```bash
   # signed in as a viewer (cookie jar from POST /api/auth/login, see runbooks/README.md)
   curl --cacert ca.pem -b jar \
     "https://pm.corp.internal:8443/api/audit?action=trust.&limit=5"
   ```

   Expect `trust.updated` with `object_id` `3` and the document in `details`. A `trust.rejected`
   event (and `trust_rejected` alert) gives the reason: bad signature, not newer than current,
   invalid document, or no root key configured. The server log shows
   `trust document applied sequence=3`.
6. **Check the console.** The **Agent setup** page and `GET /api/agent-setup` list the keys of the
   latest verified trust document (they fall back to `trusted_keys` from `pmserver.json` only when
   no trust document is stored). Confirm the new key is listed. The list contains every key in the
   document, active and retired.

   Recommended hygiene, not required: also update `trusted_keys` in `pmserver.json` to the new key
   at the next planned restart, so the config file matches reality:

   ```json
   "trusted_keys": [{"public_key_file": "/etc/offpatch/keys/bundle-2027.pub", "sources": ["acq-zone-1"]}]
   ```

   Installer layout shown; copy `bundle-2027.pub` (public only) to `/etc/offpatch/keys/` yourself,
   because the installer never replaces or adds trusted keys on re-runs, and restart
   `offpatch-server`. Manual install: `/etc/offpatch-server/bundle-2027.pub`, unit `pmserver`. On an
   installer-built acquisition host, put `bundle-2027.key` in `/etc/offpatch/keys/` and change `"key"`
   in `/etc/offpatch/acquire.json`; a re-run of the installer gives it the right owner
   (root:`offpatch-acq`, 0640).

   At start the server re-applies the stored trust document, so intake keeps using the document's
   key set (including the retired key for receipts and history) whatever the config says.
7. **Verify agents.** After one check-in interval, on sample endpoints:
   - `agent.json` shows `"trust_seq": 3` and the new key ID under `trusted_keys`.
   - Agent log shows `trust document applied sequence=3`.
   - `trust update not applied` in the agent log means it has no root key (re-enroll) or the
     document did not verify.

   The server does **not** record which agents applied a trust document. There is no fleet-wide
   view; check samples per site and platform, and rely on step 8.
8. **Switch signing.** From now on build with the new key; the per-source sequence continues as before:

   ```bash
   pmctl build -key acq/bundle-2027.key -spec spec.json -out out/2027-01.pmb -state acq/state.json
   ```

   Send a small test bundle, approve it, deploy to a pilot ring, and confirm targets reach `verified`
   on each platform. A rejected test bundle with `key_status` means you are still signing with the
   retired key.
9. **Update packaging.** Rebuild the Windows MSI (`ConfigDir\bundle.pub`) and Linux
   `/etc/offpatch/bundle.pub` for new endpoints. Old packages still work if they pin the root key,
   because the first check-in delivers the trust document before any assignment is processed.
10. **Destroy or archive** the old private key according to policy once no further bundles will be
    signed with it.

## Verification

- `trust.updated` event with the new sequence; no `trust_rejected` alert.
- Test bundle signed with the new key `validated`; a bundle signed with the old key is rejected
  with `key_status` (retired).
- Sample agents report `trust_seq` = new sequence; test deployment verified on each platform.
- Packages signed with the old (retired) key still install on endpoints.

## Rollback / escape hatch

- Trust documents only move forward (higher sequence). To undo, issue a **new** document with the
  next sequence that makes the old key `active` again (and the new one `retired` or absent).
- Wrong document accepted and agents refusing content ("untrusted key"): issue a corrected document
  with the next sequence that lists every key still needed.
- Endpoints that cannot apply trust documents (no root key): re-enroll them with `-root-pubkey`.

## Evidence to keep

- Key ceremony record: who was present, `key_id` of new and retired keys, date.
- The signed `keys-N.trust.json` and the `pmctl trust` output.
- `trust.updated` audit event (it is in the hash chain and the off-box export).
- Agent sample results (host, `trust_seq`, date).
- Test bundle lifecycle export.
