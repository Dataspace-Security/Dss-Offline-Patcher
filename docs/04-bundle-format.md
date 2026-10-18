# 04 — Bundle format (`.pmb`, schema v1)

A bundle is an uncompressed POSIX tar file:

```
manifest.json        exact bytes that were signed
manifest.sig         base64(Ed25519(manifest.json bytes)), single line
payload/<file>...    one file per package; names must match manifest
```

Any other entry is rejected. That includes directories other than `payload/`, symlinks, hard links, devices, absolute paths, `..`, and files not listed in the manifest.

## manifest.json

```json
{
  "schema_version": 1,
  "bundle_id": "b-20261016-0001-3f9c",
  "source": "acq-zone-1",
  "sequence": 7,
  "key_id": "ed25519:9a1c0b7e4d2f6a13",
  "created_at": "2026-10-16T09:00:00Z",
  "expires_at": "2026-11-15T09:00:00Z",
  "packages": [
    {
      "package_id": "KB5044273-x64",
      "title": "2026-10 Cumulative Update for Windows 10 22H2 x64",
      "vendor": "Microsoft",
      "kind": "msu",
      "version": "19045.5011",
      "kb": "KB5044273",
      "product_code": "",
      "severity": "critical",
      "release_date": "2026-10-08",
      "supersedes": ["KB5043064"],
      "applicability": { "os": "windows", "arch": "x64", "min_build": 19045, "max_build": 19045 },
      "file": { "name": "payload/windows10.0-kb5044273-x64.msu", "size": 123456, "sha256": "…64 hex…" },
      "source_url": "https://catalog.s.download.windowsupdate.com/…",
      "vendor_signature": { "status": "valid", "signer": "Microsoft Corporation", "checked_at": "2026-10-16T08:55:00Z" }
    }
  ]
}
```

### Field rules

| Field | Rule |
|---|---|
| `schema_version` | must be `1` |
| `bundle_id` | 1–64 chars `[A-Za-z0-9._-]`, unique across all bundles ever received |
| `source` | must be one of the `sources` the signing key is trusted for |
| `sequence` | integer > last accepted sequence for `source` |
| `key_id` | `ed25519:` + first 16 hex chars of SHA-256(public key) |
| `expires_at` | must be in the future at intake; maximum 90 days after `created_at` |
| `packages` | 1–500 entries; `package_id` unique within the bundle and new to the catalog (a re-sent package with an identical hash is recorded as a duplicate, not an error) |
| `kind` | See the kind table below. |
| `applicability.os` | `windows` \| `linux` \| `macos`; must match the kind (see below) |
| `applicability.arch` | `x64` \| `x86` \| `arm64` \| `any` |
| `applicability.min_build`, `max_build` | optional build range (0 = no bound); `max_build` ≥ `min_build`. Linux and macOS agents report build 0. |
| `applicability.editions` | optional list of `[A-Za-z0-9]{2,40}`. Windows: `EditionID` (e.g. `Enterprise`, `ServerStandard`); Linux: distribution `ID` from `/etc/os-release` (e.g. `debian`, `rhel`). Empty = any. |
| `prerequisites` | optional list of KBs (`KB1234567`) or package names that must already be in the endpoint inventory before install |
| `supersedes` | optional list of KBs |
| `severity` | `critical` \| `important` \| `moderate` \| `low` |
| `file.name` | `payload/<basename>`, basename `[A-Za-z0-9._-]+`, not `.`/`..`, no trailing dot, not a Windows device name (`CON`, `NUL`, `COM1`, …) |
| `file.sha256` | lowercase hex; must match the payload |
| `vendor_signature.status` | `valid` \| `invalid` \| `not_checked`. `invalid` is rejected at intake. |

### Package kinds

| `kind` | Required fields | `applicability.os` | Installed on the endpoint by |
|---|---|---|---|
| `msu` | `kb` (`KB` + 4–10 digits) | `windows` | `wusa.exe /quiet /norestart` |
| `msi` | `product_code` (`{GUID}`) | `windows` | `msiexec.exe /i … /qn /norestart` |
| `deb` | `package_name`, `version` | `linux` | `dpkg -i` |
| `rpm` | `package_name`, `version` | `linux` | `rpm -U --replacepkgs` |
| `pkg` | `package_name` (receipt id), `version` | `macos` | `/usr/sbin/installer` |
| `agent` | `version` like `1.2.3` (1–4 numeric parts, optional `-`/`+` suffix) | any one of the three | agent self-upgrade |
| `exe` | `exe` block (below), `version`, `package_name` = `exe.detect.display_name`, file name ending `.exe`, no `product_code` | `windows` | the EXE installer with `exe.silent_args` (agents 0.9.0 and later) |

`package_name`: `[A-Za-z0-9][A-Za-z0-9.+_-]{0,127}`.

#### The `exe` block (kind `exe` only)

Optional field `exe` (`omitempty`): msu, msi, deb, rpm, pkg and agent manifests are byte-identical to the format before EXE support. A package of another kind with an `exe` block is rejected.

```json
"exe": {
  "installer_type": "burn",
  "silent_args": ["/quiet", "/norestart"],
  "success_codes": [0, 3010, 1641],
  "busy_codes": [1618],
  "signer": "Microsoft Corporation",
  "detect": {
    "display_name": "Microsoft Visual C++ 2015-2022 Redistributable (x64) - 14.40.33810",
    "display_version": "14.51.36247.0",
    "product_code": "{0E3BB569-69D6-4C34-BFF9-C2F81DB5E5F0}",
    "publisher": "Microsoft Corporation"
  },
  "uninstall": { "quiet_uninstall": true },
  "scope": "machine"
}
```

| Field | Rule |
|---|---|
| `installer_type` | `exe` \| `inno` \| `nullsoft` \| `burn` |
| `silent_args` | 1–32 arguments (argv, no shell), each 1–256 characters, no `"` or control characters. Required for every type: pmctl fills the type default for inno (`/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /SP-`), nullsoft (`/S`) and burn (`/quiet /norestart`); a plain `exe` needs the winget manifest's switch. |
| `success_codes` | must include 0; at most 64; int32 or DWORD range. 3010 and 1641 mean installed + restart needed. |
| `busy_codes` | optional; "another install in progress / package in use": retry later. Not 0, not a success code. |
| `signer` | required: the Authenticode signer CommonName pmctl verified (also in `vendor_signature.signer`). |
| `detect.display_name` | required, at most 200 characters, no `"` or control characters; equals `package_name`. |
| `detect.display_version` | optional: the Apps & features `DisplayVersion` after install (else `version` is expected). |
| `detect.product_code` | optional: the Apps & features key name (`[A-Za-z0-9{}][A-Za-z0-9{}._ +()-]{0,127}`, e.g. `Microsoft EdgeWebView` or a `{GUID}`). |
| `detect.publisher` | optional. |
| `uninstall.quiet_uninstall` | true only if the app registers a `QuietUninstallString` (burn, inno); otherwise rollback is not supported. |
| `scope` | must be `machine`. |

Agents before 0.9.0 parse manifests strictly and do not know the field: pmctl puts EXE packages in bundles of their own, and the server never offers them to those agents (target `not_applicable`, "agent too old for EXE packages: upgrade the agent to 0.9.0 or later").

### Limits (server config, defaults)

`max_bundle_bytes` 32 GiB · `max_files` 500 · `max_file_bytes` 16 GiB

`pmctl auto` stays below these: it splits pending packages over several bundles (default at most 28 GiB and 450 packages each, `max_bundle_bytes` / `max_bundle_packages` in `acquire.json`), each with its own sequence. See [08-acquisition.md](08-acquisition.md).

`prerequisites` is set by `pmctl fetch` / `pmctl auto` for Windows checkpoint cumulative updates, which are shipped as their own `msu` packages (`<KB>-<arch>`).

## Transfer receipt (recorded on every intake attempt)

`bundle_file_sha256`, `bundle_file_size`, `filename`, `received_at`, `adapter` (`dropdir`), `bundle_id` (if parseable), `source`, `result` (`validated`/`rejected`), and the list of `checks` with pass/fail and detail.
