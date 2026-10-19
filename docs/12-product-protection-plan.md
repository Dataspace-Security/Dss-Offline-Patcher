# Dataspace Security Patcher — product protection plan

Date: 19 October 2026.
Status: planning document only. No security feature, licensing mechanism,
trademark registration or copyright registration is implemented by this document.

## Confirmed identity

| Item | Agreed name |
|---|---|
| Company / brand | Dataspace Security |
| Software product | Dataspace Security Patcher |
| Description | Offline Patch Management Tool |
| Intended installation | Bank-controlled offline / isolated environment |
| Current database | SQLite with persistent application storage |

Use the actual registered owner and entity type in agreements and filings.
No corporate suffix, registration number or existing trademark registration
has been verified. Display branding can use the confirmed names above.

## Protection objectives and limits

Protect the original source and vendor signing keys; restrict use to contracted
installations; provide verifiable releases; preserve bank-controlled security,
recoverability and evidence. Passwords protect access to the application, not
the secrecy of installed executables. A host administrator can copy binaries,
inspect running memory and attempt to modify licence checks. Obfuscation can
increase the effort but cannot guarantee prevention.

## Workstreams

| Area | Existing evidence | Remaining work |
|---|---|---|
| Login and roles | Local passwords, TOTP MFA, roles and approval controls in repository | Bank-specific identity policy, individual accounts, secure bootstrap and recovery exercise |
| Agent identity | Native TLS/mTLS and certificate renewal | Validate the bank network/PKI and real endpoint onboarding |
| Patch integrity | Signed bundles, hashes, trust rotation and audit records | Key custody, release process and bank acceptance testing |
| Source protection | Final image contains compiled binaries and built browser assets | Audit delivery contents, private registry/repository access and build-cache handling |
| Offline licensing | No signed commercial licensing feature was added in this work | Design and implement after agreeing commercial terms |
| IP registration | Company/product names confirmed by user | Clearance, ownership review, filing preparation and external registration |
| Production assurance | SQLite image smoke tests passed; source E2E/server/store tests passed | Resolve the existing Linux/Windows-path test discrepancy, real Windows validation, independent penetration test and bank pilot |

Existing evidence is not a compliance certification or proof of complete bank
acceptance. Verify the exact version and installation configuration during pilot.

## Proposed offline licensing specification

This is a proposed design, not functionality in the current image.

- Use a digitally signed licence file that can be imported without internet.
- Include a licence ID, bank/customer identifier, product ID, installation ID,
  permitted endpoint count, enabled features, issue date and applicable terms.
- Decide perpetual versus time-limited use, support entitlement and whether
  disaster-recovery/staging installations count toward the allowance.
- Ship the public verification key only. Keep the private licence-signing key
  under Dataspace Security control, separate from release signing, patch-bundle
  signing and the bank installation's agent CA keys.
- Define canonical serialization, signature verification, key identifiers and
  a versioned, signed verification-key rotation process.
- Document how migration, VM replacement, reinstall and disaster recovery are
  re-authorized offline. Hardware changes must have an agreed recovery path.
- Decide expiry and over-limit behavior with the bank before implementation.
  Prefer clear warnings and a documented grace process; do not silently halt
  active patch jobs, destroy data or prevent recovery/export.
- Local time checks and software-only device binding cannot defeat a hostile
  host administrator. State those limitations accurately in commercial claims.
- Audit licence import and lifecycle events without recording private keys or
  full sensitive licence material in ordinary logs.
- Define signed offline renewal/replacement procedures and how a bank receives
  revocation information. No claim of real-time revocation without connectivity.

Acceptance tests must cover valid licences, modified/invalid signatures, wrong
installation, limits, agreed expiry behavior, clock changes, key rotation,
restart persistence and disaster recovery.

## Bank access and recovery policy

Use individual accounts and MFA according to bank policy, least-privilege roles
and separated approvals. Provision a unique initial credential per installation
and require its replacement. Do not deliver a shared default password as the
operational credential, a hardcoded master password or an undocumented vendor
backdoor. Bank-approved recovery must be authenticated and audited.

Vendor support access is disabled by default and explicitly approved by the
bank when needed. Keep bank data, credentials and CA custody governed by the
bank agreement. Test backup/restore, certificate renewal, identity retirement,
key rotation and operational logging in the actual isolated environment.

## Delivery and release package

Provide the final runtime image/binaries, release identifier, signed integrity
manifest, SBOM, third-party licence notices, operator/install/recovery guides
and bank acceptance test evidence. Supply source code only where explicitly
required by the contract, applicable licences or an agreed escrow arrangement.

Exclude repositories, source archives, development credentials, build caches,
vendor private signing keys, test databases and test CA keys from normal bank
delivery. Browser-delivered frontend code remains inspectable; keep private
licensing/signing operations out of it. Never embed a universal secret in a
client or server binary and claim it cannot be extracted.

Build in a trusted environment with controlled source access. Review the final
image, every shipped archive and dependency notices. Scan each release and
define how security advisories and signed fixes reach offline customers.

## India: IP and contract preparation

India is a working assumption; confirm the filing jurisdictions and the exact
legal owner with an IP professional before submission.

For trademarks, perform similarity/availability clearance for the company brand
and product name/logo, then select appropriate goods/services and marks to file.
The official Indian process uses Form TM-A. An IP professional should advise
whether the descriptive product wording has sufficient distinctiveness and
whether separate word/logo applications are appropriate. No clearance or
registration is claimed here. See [IP India filing process](https://ipindia.gov.in/trade-marks-learn-filing-process-step-by-step).

For software copyright, document the authors, original contributions, version,
ownership/assignment evidence and third-party components. Have counsel assess
authorship and ownership, including AI-assisted development, before making
claims. Registration uses Form XIV. The official guidance requires first and
last ten source-code pages, or all source if under twenty pages, without
redactions; review disclosure implications before submitting anything. See
[IP India copyright guidance](https://ipindia.gov.in/pages/copyright/learn/basics-of-copyright).

Have counsel prepare/review a commercial licence/EULA, ownership and permitted
use terms, confidentiality, support/SLA and vulnerability-handling commitments,
deployment acceptance, data responsibilities and any negotiated source escrow.
Legal restrictions should respect applicable law and third-party licence rights.
Registration and contract enforcement do not technically prevent binary copying.

## Release gates and decisions

1. Confirm legal owner, entity type, address and target filing jurisdictions.
2. Complete ownership/dependency review and trademark clearance.
3. Agree bank licence metrics, term, recovery and expiry/grace behavior.
4. Review the security/licensing design before authorizing implementation.
5. Implement and test approved controls; complete independent security review.
6. Exercise real Windows installation, backup/restore and a bank-controlled pilot.
7. Release signed, versioned delivery artifacts with approved contracts and guides.

The [NIST Secure Software Development Framework](https://csrc.nist.gov/pubs/sp/800/218/final)
is a useful reference for the development/release and vulnerability-response
process. It is not, by itself, a certification of this product.
