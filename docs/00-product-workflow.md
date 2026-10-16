# Offline Endpoint Patch Management Product — Project Workflow

## 1. Product objective

Build a patch-management product that lets administrators inventory, approve, distribute, install, and verify endpoint patches while endpoints have **no direct internet access**.

Updates enter the protected environment through a controlled **network transfer boundary** (preferably a one-way gateway/data diode where the security model requires it). An internal repository then serves approved updates to endpoints over the private network. No endpoint needs to contact a vendor service.

> A completely isolated network with no transfer path cannot receive new updates. The product deployment therefore needs an explicitly approved inbound update path, such as a one-way gateway or a tightly controlled broker. The architecture must preserve the endpoint network's no-internet policy.

## 2. Product outcomes

The first release should enable an organization to:

- Maintain an inventory of endpoints, operating systems, software, ownership, and patch status.
- Acquire update packages and metadata in a connected staging zone.
- Transfer packages inward without giving endpoints internet access or providing a general-purpose route back out.
- Verify package origin and integrity, quarantine packages, and record every transfer.
- Review, test, approve, schedule, and stage deployments.
- Install updates from an internal service and verify results on endpoints.
- Identify failed, stale, offline, noncompliant, and exception endpoints.
- Produce an auditable history from vendor source through endpoint installation.

## 3. Assumptions and decisions to confirm early

Resolve these during discovery; they shape the design and delivery plan:

1. **Endpoint platforms:** Windows, Linux distributions, macOS, server OSs, OT/embedded systems, or a subset.
2. **Isolation model:** physically disconnected with a one-way gateway, separated networks with a controlled broker, or a restricted connected network with egress denial.
3. **Transfer mechanism:** which gateway/data diode or approved cross-domain transfer service is available, and what file sizes and protocols it supports.
4. **Scale:** endpoint count, sites, network zones, concurrent installs, and update bandwidth.
5. **Patch scope:** OS updates only, or also third-party applications, firmware, drivers, and configuration changes.
6. **Management requirements:** identity provider, role model, change-approval process, audit retention, and reporting obligations.
7. **Availability and recovery:** maintenance windows, reboot policy, backup/recovery practices, and service-level targets.

Do not begin implementation of a platform-specific installer or gateway integration until the initial platform and transfer-boundary choices are agreed.

## 4. Target architecture

```text
┌──────────────────────────────┐
│ Connected acquisition zone  │
│ Vendor feeds, package fetch  │
└──────────────┬───────────────┘
               │ signed bundle / approved transfer protocol
               ▼
┌──────────────────────────────┐
│ Transfer boundary            │
│ One-way gateway or approved  │
│ inbound transfer broker      │
└──────────────┬───────────────┘
               ▼
┌──────────────────────────────┐
│ Isolated management zone     │
│ Intake → quarantine → verify │
│ approve → internal repository│
│ API, scheduler, audit, UI    │
└──────────────┬───────────────┘
               │ private network only
               ▼
┌──────────────────────────────┐
│ Managed endpoints            │
│ Inventory, download, install │
│ report status to internal API│
└──────────────────────────────┘
```

### Component responsibilities

- **Acquisition service:** fetches vendor packages and update metadata in the connected zone. It does not manage endpoint credentials.
- **Bundle builder:** creates a manifest with package IDs, versions, target products, sizes, hashes, source, timestamps, prerequisites, and signature information.
- **Transfer adapter:** sends signed bundles over the approved boundary. It must not tunnel general network traffic or enable endpoint internet access.
- **Intake and quarantine service:** receives bundles into a non-deployable area, validates the organization signature and hashes, checks vendor signatures where available, scans content, and records transfer evidence.
- **Patch catalog:** stores update metadata, applicability rules, supersedence, dependencies, approvals, and lifecycle state.
- **Internal content repository:** stores approved package binaries and serves them only inside the managed network.
- **Management API and console:** manages inventory, policy, approvals, deployment waves, exceptions, and reporting.
- **Endpoint agent or native management integration:** inventories software, evaluates applicability, downloads from the internal repository, installs according to policy, and reports results. It must not have an internet-update fallback.
- **Audit service:** records administrator actions, imports, approvals, deployments, endpoint results, and exceptions in tamper-evident storage.

## 5. Product development workflow

### Phase 0 — Discovery and constraints

**Activities**

- Interview security, endpoint operations, application owners, network/OT teams, and auditors.
- Map the endpoint lifecycle and the current update acquisition and transfer process.
- Confirm endpoint OSs, packaging formats, network zones, scale, bandwidth, and maintenance constraints.
- Identify the transfer-boundary product and its supported interface, directionality, maximum package size, and operational owner.
- Define risk classes, approval roles, patch deadlines, emergency process, and exception policy.
- List required evidence for audit and incident investigation.

**Deliverables**

- Product requirements and user roles.
- Environment and data-flow diagram.
- Threat model and trust boundaries.
- Platform and transfer-boundary decision record.
- Initial acceptance criteria and MVP scope.

**Exit gate**

Security and operations agree on the supported endpoint platform(s), inbound transfer method, and prohibited flows (especially any endpoint-to-internet route).

### Phase 1 — UX and workflow design

Design screens and flows for:

- Fleet health and stale inventory.
- Patch catalog with applicability, severity, source, and lifecycle status.
- Transfer intake, validation results, and quarantine review.
- Approval and change records.
- Pilot and staged rollout setup.
- Endpoint results, failure handling, and exceptions.
- Audit search and export.

Define status names and transitions before implementation. Require a reason and actor for state changes that affect security or deployment.

**Deliverables:** clickable or low-fidelity prototype, workflow state model, permission matrix, event/audit schema.

**Exit gate:** endpoint administrators and security approvers can complete a representative update scenario in the prototype.

### Phase 2 — Architecture and security design

**Activities**

- Specify service boundaries and the allowed data flows for each network zone.
- Define bundle format, manifest schema, signing and key-rotation plan, hash algorithms, and package size limits.
- Design identity integration, least-privilege roles, administrator MFA, secrets handling, and service authentication.
- Define endpoint-agent trust, certificate issuance/renewal, command authorization, and safe update behavior.
- Define repository immutability/versioning, backup/restore, audit retention, and disaster recovery.
- Create abuse cases: malicious or corrupted package, compromised acquisition host, replayed bundle, unauthorized approval, compromised agent, repository tampering, and denial of service.
- Define software bill of materials and dependency update process for the product itself.

**Deliverables:** architecture specification, threat model, security requirements, API contracts, storage model, deployment topology, recovery design.

**Exit gate:** security review approves the transfer boundary, trust model, key handling, and endpoint egress controls.

### Phase 3 — Build the MVP foundation

Implement the smallest vertical slice for one endpoint platform and one transfer method:

1. Create organizations/sites/zones and administrator roles.
2. Register endpoints and collect a minimal software/patch inventory.
3. Ingest a signed test bundle into quarantine.
4. Verify manifest signature and package hashes; record validation results.
5. Approve a package and publish it to the internal repository.
6. Target a test endpoint, install the package, and receive an installation result.
7. Show compliance status and the full audit trail.

**MVP exclusions unless essential:** multi-OS breadth, advanced vulnerability analytics, automated patch acquisition for every vendor, complex ring optimization, OT support, and automatic rollback. Avoid implying rollback is universally available.

**Exit gate:** one package can be traced from acquisition record to verified endpoint state without an endpoint contacting the internet.

### Phase 4 — Endpoint and repository implementation

**Endpoint agent requirements**

- Enroll securely with a unique device identity.
- Send inventory and heartbeat to internal management endpoints only.
- Evaluate update applicability locally or from signed catalog rules.
- Download content only from approved internal repositories.
- Verify content before installation.
- Respect maintenance windows, bandwidth limits, reboot policy, and user/operations constraints.
- Report download, install, reboot, verification, and error states separately.
- Support safe retry and idempotent execution.
- Provide signed agent upgrades through the same controlled update lifecycle.

**Repository requirements**

- Separate quarantine from approved content.
- Serve only approved, immutable package versions.
- Apply authorization and zone restrictions.
- Support resumable downloads and integrity verification.
- Record package access and deployment references.
- Replicate to sites only through approved internal links.

**Exit gate:** test endpoints cannot obtain content outside policy, and package tampering is detected before install.

### Phase 5 — Transfer-boundary integration

**Activities**

- Implement the selected gateway or broker adapter using its supported interface.
- Transfer only the defined bundle format and required metadata.
- Use unidirectional transfer when mandated by the environment.
- Provide a transfer receipt that binds package ID, manifest hash, source, destination, time, and result.
- Handle interrupted transfers, duplicates, replay, oversized bundles, and malformed manifests safely.
- Ensure the receiver does not automatically publish received packages.
- Provide operational dashboards and alerts for transfer failures without opening a reverse network path.

**Exit gate:** boundary review confirms directionality and allowed protocols; negative tests show arbitrary traffic cannot be relayed.

### Phase 6 — Approval, pilot, and deployment orchestration

Implement policy-driven deployment:

- Define target groups by platform, version, site, criticality, and application dependencies.
- Require approval appropriate to patch risk and target scope.
- Support pilot groups and progressive production waves.
- Configure maintenance windows, deadlines, retries, concurrency, bandwidth throttles, and reboot behavior.
- Set pause conditions based on install failures or health signals.
- Allow emergency deployment with recorded justification and expedited approvals.
- Require owners, compensating controls, review date, and expiry for exceptions.

**Exit gate:** a deployment can be paused, resumed, or cancelled with a complete audit record, and offline endpoints remain visible as pending rather than falsely compliant.

### Phase 7 — Verification, recovery, and operational readiness

**Verification**

- Re-inventory endpoints after installation.
- Confirm installed version or superseding update, restart completion, and relevant service health.
- Distinguish installed, pending reboot, failed, not applicable, offline, stale, and exception states.
- Reconcile endpoint claims with independent inventory evidence where feasible.

**Recovery**

- Define vendor-supported uninstall/rollback, backup restore, or reimage procedures per package class.
- Stop rollout when failure thresholds or health alarms trigger.
- Preserve logs and affected endpoint lists for incident analysis.
- Record recovery outcome and whether the package returns to quarantine or is rejected.

**Operational readiness**

- Document service installation, key backup/rotation, repository restore, monitoring, capacity, and incident runbooks.
- Train administrators and endpoint support staff.
- Establish support ownership and escalation paths.

**Exit gate:** operations can restore the management service and repository from backup and execute the documented failed-update procedure in a non-production environment.

### Phase 8 — Pilot deployment and rollout

1. Deploy the management plane in a representative non-production isolated zone.
2. Validate firewall rules and confirm endpoints have no direct internet egress.
3. Run a full transfer, verify, approve, pilot, deploy, and audit exercise.
4. Pilot with a small production group and agreed support coverage.
5. Review failed, stale, offline, and exception cases with endpoint owners.
6. Expand by site or endpoint class, with explicit go/no-go checks between waves.
7. Establish recurring release and emergency patch operations.

**Exit gate:** pilot objectives are met, open high-risk issues have owners and dates, and service ownership is accepted by operations.

### Phase 9 — Continuous improvement

- Review patch latency and compliance trends.
- Refine prioritization, rollout thresholds, and maintenance windows.
- Add endpoint platforms and vendor sources only after validation.
- Review transfer-boundary and key-management controls regularly.
- Reassess threat model after major architecture or vendor changes.
- Review unsupported/end-of-life software and exception expiry.

## 6. Runtime workflow for each patch

1. **Discover:** inventory or advisory identifies affected software/endpoints.
2. **Acquire:** connected acquisition zone fetches the vendor package and metadata.
3. **Validate source:** confirm vendor signature/catalog where available and capture source details.
4. **Package:** create a signed manifest containing hashes, versions, applicability, prerequisites, and package ID.
5. **Transfer:** send bundle through the approved inward transfer boundary; record receipt.
6. **Quarantine:** store in a non-deployable area.
7. **Inspect:** verify organizational signature and hashes, scan, validate metadata, and check for duplicate/replay.
8. **Assess:** calculate priority and identify affected groups and operational constraints.
9. **Approve:** record security, service-owner, and change approvals as required.
10. **Pilot:** deploy to representative systems and record health and compatibility evidence.
11. **Deploy:** progress through configured rings/waves; pause on thresholds.
12. **Verify:** collect fresh inventory and health evidence from endpoints.
13. **Resolve remainder:** retry, investigate, schedule offline endpoints, or create time-bound exceptions.
14. **Close:** retain package, transfer, approval, deployment, verification, and exception records.

## 7. Core data entities

- **Endpoint:** identity, platform, version, site, owner, group, criticality, last seen.
- **Software inventory item:** product, version, architecture, install source, detection time.
- **Patch/update:** vendor ID, version, affected products, severity, prerequisites, supersedence, release date.
- **Bundle:** bundle ID, manifest, hashes, signature, source, transfer receipt, validation state.
- **Approval/change:** approver, scope, rationale, decision, timestamp, maintenance window.
- **Deployment:** patch, target group, wave, schedule, retry policy, pause state.
- **Endpoint result:** download/install/reboot/verification state, timestamps, error details.
- **Exception:** affected scope, owner, reason, compensating controls, expiry/review date.
- **Audit event:** actor/service, action, object, timestamp, outcome, correlation ID, evidence reference.

## 8. Security and reliability requirements

- Enforce endpoint internet egress denial at network controls; do not rely only on agent configuration.
- Separate connected acquisition, transfer boundary, isolated management, and endpoint zones.
- Make all inbound bundles non-deployable until validation and approval complete.
- Verify hashes and signatures at intake and again at the endpoint before installation.
- Protect signing keys in a controlled key-management system; define rotation and compromise response.
- Use least privilege, strong administrator authentication, and separation of duties for high-risk releases.
- Keep tamper-evident audit logs and alert on changes to packages, approvals, policies, and keys.
- Encrypt internal management and repository traffic where supported by the environment.
- Rate-limit and scope endpoint commands; do not allow arbitrary remote command execution through the patch agent.
- Back up catalog, configuration, audit evidence, and repository metadata; test restoration.
- Define behavior for stale inventory and endpoints that do not check in; never treat silence as compliance.
- Maintain a signed and versioned product update process for the patch-management software itself.

## 9. Initial acceptance criteria

The MVP is ready for a controlled pilot when all are true:

- An endpoint has no direct internet route and successfully receives a patch from the internal repository.
- The intake service rejects a bundle with a modified file, invalid manifest signature, or malformed metadata.
- A received but unapproved bundle cannot be deployed.
- Every bundle has a traceable source, hash, transfer receipt, validation result, and approval history.
- Administrators can target a test group, deploy in stages, pause rollout, and see per-endpoint outcomes.
- Endpoint status distinguishes success, failure, pending reboot, offline, stale inventory, and exception.
- A fresh endpoint inventory verifies the installed patch or applicable superseding update.
- Recovery and service restore procedures have been exercised in a non-production environment.
- Audit evidence can be exported for one complete patch lifecycle.

## 10. Suggested delivery milestones

| Milestone | Completion evidence |
|---|---|
| M1 — Scope agreed | Platform, transfer mechanism, scale, users, and MVP boundaries recorded. |
| M2 — Design approved | Architecture, threat model, data flows, roles, bundle format, and recovery plan reviewed. |
| M3 — Vertical slice | Test bundle moves through intake to one test endpoint with an audit trail. |
| M4 — Security controls | Signature/hash validation, quarantine, access controls, egress rules, and tamper-evident audit implemented. |
| M5 — Pilot operations | Wave deployment, pause/recovery, reporting, and runbooks exercised. |
| M6 — Controlled rollout | Pilot accepted; site-by-site production rollout and support ownership established. |

## 11. Primary operational metrics

- Inventory freshness and percentage of managed endpoints reporting.
- Percentage compliant by patch priority and target deadline.
- Time from vendor release to acquisition, internal availability, approval, and verified installation.
- Transfer success rate and time to import.
- Package validation rejection rate and reasons.
- Pilot and production installation success/failure rates.
- Endpoints pending reboot, offline, stale, or unsupported.
- Number and age of active exceptions.
- Recovery time after a problematic update.

## 12. Reference guidance

- NIST, [SP 800-40 Rev. 4: Guide to Enterprise Patch Management Planning](https://csrc.nist.gov/pubs/sp/800/40/r4/final), describes patch management as identifying, prioritizing, acquiring, installing, and verifying patches.
- CISA, [ICS Recommended Practices](https://www.cisa.gov/resources-tools/resources/ics-recommended-practices), provides guidance relevant to patching operational technology and control systems.
- Microsoft, [Set up a disconnected WSUS network](https://learn.microsoft.com/nl-nl/security-updates/windowsupdateservices/18126805), documents an example of exporting update metadata and content into a disconnected Windows environment.
