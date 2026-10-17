# Runbook 04 — Bundle signing key compromise (incident)

## Purpose

Contain a suspected or confirmed compromise of a **bundle signing key**: stop new content signed
with it, revoke what it delivered, cancel its deployments, re-issue legitimate content with a new
key, and keep the evidence.

## When to use

- The bundle private key (file or HSM access) may have been copied or misused.
- Bundles you did not build appear on the Intake page with a trusted `key_id`.
- The acquisition host is compromised.

For a compromise of the **root** key, see "Root key compromise" at the end.

## What the product does automatically (from the code)

When the server accepts a trust document that lists a key under `revoked` with reason `compromised`:

| Effect | Detail |
|---|---|
| Intake | The key is no longer in the trusted set. New bundles signed with it are rejected (`trusted_key`). |
| Quarantined packages from bundles signed by that key | → `rejected`, actor `system:trust`, reason `signing key <key_id> revoked as compromised`. |
| Approved packages from bundles signed by that key | → `revoked`, same actor and reason. |
| Their active and paused deployments | → `cancelled` (`deployment.cancelled`, reason `package revoked: …`). |
| Alert | `signing_key_compromised` (critical): "… N package(s) revoked and their deployments cancelled — start the incident procedure". |
| Agents (with a pinned root key) | After the next check-in: the key is removed from their pinned keys and recorded as revoked. They refuse any manifest signed by it ("manifest signed by revoked key"). |

What it does **not** do:

- It does not uninstall anything already installed on endpoints. There is no automated rollback.
- Until the trust document has crossed the boundary and been processed, the server still trusts the
  key. An attacker with the key still cannot get content installed without an **approval**, because
  everything arrives `quarantined`.
- Agents enrolled without `-root-pubkey` never learn of the revocation and keep trusting the key.
- A revocation with any reason other than `compromised` only removes the key; it does not touch
  packages.

## Prerequisites and roles

| Role | Tasks |
|---|---|
| Incident lead | Owns the timeline, communication, decisions. |
| Root key custodian(s) | Sign the trust document (offline). |
| Acquisition operator | New key, rebuild content. |
| Approver | Interim manual revocations, re-approval of re-issued content. |
| Operator | Pause/cancel deployments, exceptions. |
| Server OS admin | Config changes if no root key is configured. |

## Steps

### Contain (first hour)

1. **Freeze intake decisions.** Tell approvers not to approve anything until cleared. List what is
   waiting: Catalog → `quarantined`.
2. **Identify the key.** Note the `key_id` (`ed25519:…`). On the Intake page, list every bundle with
   that `key_id`, and every package from those bundles.
3. **Pause deployments** of packages from those bundles (operator, reason `INC-… key compromise`):
   `POST /api/deployments/{id}/pause`. If you already know content is malicious, an approver
   **revokes** the package (`POST /api/packages/{id}/revoke`), which cancels its deployments.
4. **Issue the revocation** (offline root machine). Generate a replacement key first
   (`pmctl keygen -out bundle-new`, on a clean host or in the HSM), then, with `-seq` = current
   sequence + 1 (`GET /api/audit?action=trust.updated&limit=1`):

   ```bash
   pmctl trust -root root.key -seq 4 \
     -key bundle-new.pub=acq-zone-1 \
     -revoke ed25519:9a1c0b7e4d2f6a13:compromised \
     -out keys-4.trust.json
   ```

   - Do not also list the compromised key under `-key` or `-retire` (the document is invalid if a
     key is both listed and revoked).
   - List any other legitimate keys still in use, as `-key` or `-retire`, or they are dropped too.
5. **Send it** through the boundary from a host you trust (if the acquisition host is compromised,
   use a clean one): `pmctl send -bundle keys-4.trust.json -to <drop dir> -key bundle-new.key` (sign the receipt with the new key, never the compromised one).
6. **Confirm** on the server:
   - Audit: `trust.updated` (object `4`), then `package.revoked` / `package.rejected` and
     `deployment.cancelled` by `system:trust`.
   - Alert `signing_key_compromised` with the package count.
   - Catalog: no `approved` package from the affected bundles remains.

### If no root key is configured

Trust documents cannot be used. Then:

1. Remove the key from `trusted_keys` in `pmserver.json` (add the new key) and restart the server
   (`systemctl restart offpatch-server`; manual install: `pmserver`). With the installer layout, the
   new public key goes into `/etc/offpatch/keys/` by hand; re-runs never replace trusted keys.
2. An approver revokes each approved package and rejects each quarantined package from the affected
   bundles, with the incident reference as reason. Revocation cancels their deployments.
3. Re-enroll **every agent** with the new `bundle.pub` and `-root-pubkey root.pub` (runbook 09), and
   retire the old endpoint records. Until then those agents still accept manifests signed by the
   compromised key.

### Assess impact

7. **Which endpoints installed affected content?** For each affected package:
   `GET /api/audit/export?package_id=<id>` (lifecycle export) lists every deployment and target with
   state, timestamps, exit codes. Targets `installed`, `pending_reboot` or `verified` received it.
8. **Was the content legitimate?** For each affected package, compare the payload SHA-256 in the
   catalog with the vendor's published file (Microsoft Update Catalog, vendor checksums) and the
   `acquired` provenance in that month's `spec.json`. For `msu`/`msi`, the recorded
   `vendor_signature` from a Windows build host is supporting evidence, not proof.
9. **Malicious or unknown content was installed:** treat those endpoints as compromised and follow
   your endpoint incident process. Recovery per package class is in
   [runbook 06](06-failed-update-recovery.md); reimaging is the safe default.
10. **Check agents applied the revocation:** on sample endpoints, `agent.json` shows the new
    `trust_seq` and the key ID under `revoked`. There is no server-side report of this.

### Recover

11. **Rebuild legitimate content** with the new key. Revoked package IDs cannot be reused (a
    different file under the same `package_id` is a `catalog_conflict`; the identical file is
    skipped as a duplicate and stays revoked). Give re-issued packages **new `package_id`s**, e.g.
    `KB5046613-x64-r2`. Sequence continues per source.
12. Send, validate, re-approve (approvers record the incident reference), and deploy again with
    rings. Endpoints that already have the update are marked `verified` immediately from inventory.
13. Update the server config `trusted_keys` and the agent packaging to the new key (as in
    [runbook 03](03-key-rotation.md) steps 6 and 9).

### Communicate

14. Inform: security operations, endpoint owners of affected endpoints, change board, auditors.
    Include the key ID, time window of exposure, affected packages and endpoints, actions taken.

## Verification

- No `approved` package remains from bundles signed by the revoked key.
- A test bundle signed with the compromised key is rejected (`trusted_key`).
- Sample agents list the key as revoked.
- Re-issued packages are `verified` on the fleet; compliance report shows no overdue gap caused by
  the incident (or the gap is explained).

## Rollback / escape hatch

- A key revoked as `compromised` cannot be re-activated in a way that restores its packages:
  `revoked` and `rejected` are final package states. If the revocation was a mistake, issue a new
  trust document that trusts the key again and re-issue the content under new `package_id`s.

## Root key compromise

Not handled by the product. The root public key is pinned in `root_public_key_file` and in every
agent's `agent.json`; a trust document cannot replace it. Recovery: generate a new root key
offline (`pmctl keygen -out root`, runbook 02 A2),
change `root_public_key_file` (restart the server), and re-enroll every agent with the new
`-root-pubkey`. Until then, an attacker with the root key can make agents and the server trust any
bundle key (content would still need approval).

## Evidence to keep

- Incident timeline and decisions.
- The signed revocation trust document and `pmctl trust` output.
- Audit events: `trust.updated`, the automatic `package.revoked`/`package.rejected`/`deployment.cancelled`
  by `system:trust`, all manual actions with the incident reference.
- Lifecycle exports of every affected package (before and after).
- `received/<sha256>.pmb` evidence copies of every bundle signed with the key (do not delete them),
  and any suspicious bundles.
- Agent samples showing the revocation applied; list of affected endpoints and their recovery outcome.
- `pmserver verify-audit` report covering the incident window (runbook 07).
