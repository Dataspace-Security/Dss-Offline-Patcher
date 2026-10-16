# 03 — State model

Every transition below is enforced in code (`internal/store`) and writes an audit event with actor and, where marked **R**, a mandatory reason.

## Bundle (transfer unit)

```
received ──validate ok──► validated
    └──────validate fail─► rejected     (terminal; file kept in received/ as evidence)
```

## Package (catalog entry)

```
quarantined ──approve (R, approver)──► approved ──revoke (R, approver)──► revoked
     └────────reject (R, approver)───► rejected
```
- `quarantined`: in the catalog and visible, but not in the repository and not deployable.
- `approved`: copied to the immutable repository and deployable.
- `revoked`: no new assignments are issued. Active deployments of it are cancelled automatically.

## Deployment

```
active ◄──resume (R)── paused
  │ ──pause (R)──────────► paused
  │ ──auto-pause (failure threshold exceeded in current ring)──► paused
  │ ──advance (operator; only when current ring has no in-flight targets)──► active (next ring)
  │ ──cancel (R)─────────► cancelled   (from active or paused)
  └──last ring done──────► completed
```
- A deployment has ordered **rings** (e.g. `pilot`, `broad`). Each ring targets endpoints by group; rings up to and including the current ring receive assignments.
- `advance` takes an optional reason (pause, resume and cancel require one). It is refused while any target in the current ring is `downloading`, `downloaded` or `installing`; failed targets do not block it.
- `emergency: true` requires a justification. It is flagged in the audit log and the UI.

## Deployment target (one endpoint × one deployment)

```
pending ─► downloading ─► downloaded ─► installing ─► installed ─► verified
   │            │              │             ├──────► pending_reboot ─► verified
   │            └──────────────┴─────────────┴──────► failed ──retry (agent, ≤ max_retries)──► pending
   ├──agent: already present / not applicable──► not_applicable | verified
   └──active exception──► exception
```
- `verified` is set **only by the server** when a fresh inventory shows the package's KB/product code (or, for `deb`/`rpm`/`pkg`/`agent`, the package name / agent at the same or a newer version), or a KB that supersedes it (transitively). This check runs at every check-in for targets of `active`, `paused` and `completed` deployments, so an endpoint fixed by hand after its deployment completed still verifies.
- `failed` counts toward the ring failure threshold only once retries are exhausted (`attempts > max_retries`). Until then the failed target is offered to the agent again.

## Derived endpoint status (fleet view)

Precedence, highest first:

| Status | Rule |
|---|---|
| `offline` | `last_seen` older than `offline_after` (default 30 min) |
| `stale` | inventory older than `stale_inventory_after` (default 24 h) |
| `failed` | any target in `failed` |
| `pending_reboot` | any target `pending_reboot`, or the OS reports a reboot pending |
| `exception` | active exception covering an outstanding package |
| `noncompliant` | an approved package with an active deployment covers it and is not yet verified |
| `compliant` | otherwise |

Silence is never compliance: `offline` and `stale` take precedence over everything else.
