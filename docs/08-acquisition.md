# 08 — Patch acquisition (connected zone)

Roadmap item **C4**. `pmctl` can now find vendor updates, download and verify them, and write the
`spec.json` entries that `pmctl build` turns into a signed bundle. Before this, an operator downloaded
`.msu`/`.msi` files by hand and wrote `spec.json` manually.

**These commands run only on the acquisition host in the connected zone.** Nothing here runs in the
isolated zone. The isolated zone still receives only signed `.pmb` bundles, and the server and agents
check them exactly as before (see 02 and 04).

Code: `internal/acquire/` (catalog client, MSRC client, downloader, spec writer) and `cmd/pmctl/fetch.go`.

## Commands

```text
pmctl msrc           -month 2026-Oct [-product "Windows 10"] [-arch x64]
pmctl catalog-search -q "<query>"
pmctl fetch          -kb KB5044273 -product "Windows 10 Version 22H2" -arch x64
                     -min-build 19045 -max-build 19045
                     [-severity critical | -msrc-month 2026-Oct]
                     [-match <title substring>] [-file <file name substring>]
                     [-package-id ID] [-product-code {GUID}]
                     -out downloads/ -spec spec.json
pmctl fetch-url      -url https://vendor/x.msi -sha256 <hex> -package-id X -title T -vendor V
                     [-kind msu|msi|deb|rpm|pkg|agent] [-kb KB… | -product-code {GUID} | -package-name N]
                     [-os windows|linux|macos] -severity important
                     [-version v] [-release-date YYYY-MM-DD] [-arch any] [-supersedes KB1,KB2]
                     [-min-build n] [-max-build n] [-file name] -out downloads/ -spec spec.json
```

`fetch-url` kinds and their required flags:

| `-kind` | Inferred from | Required | `applicability.os` (default; override with `-os`) |
|---|---|---|---|
| `msu` | `.msu` | `-kb` | `windows` |
| `msi` | `.msi` | `-product-code` | `windows` |
| `deb` | `.deb` | `-package-name`, `-version` | `linux` |
| `rpm` | `.rpm` | `-package-name`, `-version` | `linux` |
| `pkg` | `.pkg` | `-package-name` (receipt id), `-version` | `macos` |
| `agent` | — (pass `-kind agent`) | `-version` (e.g. `1.2.3`) | `windows`; set `-os` for Linux/macOS agent binaries |

`applicability.editions` has no flag; add it to the spec entry by hand. `fetch` fills `prerequisites` itself for
checkpoint cumulative updates (see below); add other prerequisites by hand.

| Command | What it does |
|---|---|
| `msrc` | Reads `https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/<YYYY-Mon>` and prints KB, severity, CVE count and products, so you know what to fetch. `-product`/`-arch` limit the list to matching products and work out severity for those products only. |
| `catalog-search` | Searches the Microsoft Update Catalog and prints update ID, date, classification, size, version, products and title. Only the first page is shown (up to 25 rows). |
| `fetch` | Searches the catalog for the KB and selects the **single** row that matches the KB, the `-product` text (in the title or products column) and `-arch` (in the title). If no row or more than one row matches, it fails and lists the candidates. Then it downloads the file, verifies it and adds or replaces the spec entry. |
| `fetch-url` | For third-party vendors and for Linux, macOS and agent packages. Downloads over HTTPS only. The download must match the SHA-256 you supply. Then it adds or replaces the spec entry. |

### What `fetch` writes into spec.json

| Field | Source |
|---|---|
| `package_id` | `<KB>-<arch>` (override with `-package-id`) |
| `title` | catalog title |
| `vendor` / `kind` | `Microsoft` / `msu` (`msi` if the file is an `.msi`; `-product-code` is then required) |
| `kb`, `version` | `-kb`; catalog version column (omitted when the catalog shows `n/a`) |
| `severity` | `-severity`. If not given: MSRC (`-msrc-month`), for the matching product and arch. If not given: the "MSRC severity" field on the catalog details page (with a warning). Otherwise `important` (with a warning). |
| `release_date` | catalog "Last Updated" date, as YYYY-MM-DD |
| `supersedes` | "This update replaces the following updates" on the catalog details page. If that is empty, the MSRC `Supercedence` field. Checkpoint KBs (below) are never listed here. |
| `prerequisites` | the checkpoint cumulative update KBs listed in the same download dialog (Windows 11 24H2 and later), see "Checkpoint cumulative updates" |
| `applicability` | `{os: windows, arch, min_build, max_build}` from the flags |
| `source_url` | the catalog download URL |
| `path` | the downloaded file, relative to the directory of spec.json |
| `acquired` | provenance: time, method, catalog update ID, SHA-1, SHA-256, size, and which checks passed. `pmctl build` ignores this field. |

`fetch` leaves out `file` and `vendor_signature`. `pmctl build` computes `file`. For `msu`/`msi`
entries it also fills in `vendor_signature` by running Authenticode (`Get-AuthenticodeSignature`)
on Windows, or records `not_checked` on other systems. `deb`, `rpm`, `pkg` and `agent` entries are
always recorded as `not_checked`.

Rules for writing spec.json:

- The new entry is checked with `manifest.ValidateSchema` before it is written, so a bad entry fails at
  fetch time and not later at build time.
- Other entries are kept exactly as they were, including fields `pmctl` does not know about.
- An existing entry with the same `package_id` is replaced.
- The file is written to a temp file and then renamed, so the update is atomic.
- A spec.json that is not a JSON array is never overwritten.

## Trust model

| Source | Integrity controls |
|---|---|
| Microsoft Update Catalog | All pages and downloads use HTTPS. Redirects to plain HTTP are refused, and `http://*.windowsupdate.com` links are upgraded to HTTPS. Catalog file names end in `_<sha1>.msu`, and the download dialog also gives a base64 SHA-1 `digest`. The two must agree, or `fetch` fails. The downloaded file must match that SHA-1, and the exact byte size from the search row when the update has a single file. The download dialog sometimes includes a SHA-256; when it does, that is checked too. If the catalog gives no hash at all, `fetch` refuses the download. |
| Authenticode | When `pmctl build` runs on a Windows acquisition host, it checks the Microsoft signature and records the result in the signed manifest. The server rejects packages recorded as `invalid`. |
| Third-party vendors (`fetch-url`) | HTTPS only. `-sha256` is required. The operator gets it from the vendor through a separate channel, such as the vendor's release notes or a signed checksum file. A mismatch deletes the download and leaves spec.json untouched. |
| Everything fetched | Treated as untrusted data. Pages are size-limited and only parsed. Downloads are only hashed and never executed. File names must be `[A-Za-z0-9._-]`. Each file is capped at 16 GiB (Windows 11 cumulative updates already exceed 4 GiB). |

SHA-1 alone is a weak hash. Here it binds the file to what the catalog page advertised over HTTPS.
Authenticode at build time is the vendor-level check. After build, the bundle's own SHA-256 and Ed25519
signature protect the file all the way to the endpoint.

## Downloads

- Files are written to `<out>/<name>.part`, flushed to disk, verified, and only then renamed into place.
- If a run is interrupted (for example with Ctrl-C) or stalls, the `.part` file is kept. The next run
  resumes it with an HTTP `Range` request.
  - If the server ignores `Range`, the download restarts from the beginning.
  - If a resumed file fails verification, it is deleted and downloaded once more from scratch.
- A stall watchdog aborts a download after 2 minutes with no data.
- A `.part` that does not fit what the server now serves (the reported size differs from the expected
  size) is deleted, so the next run starts over instead of failing on every run.
- If the target file already exists and matches the expected hash, it is reused. If it does not match
  (an unversioned vendor URL now serves a new build under the same file name, or the file is damaged),
  it is deleted and downloaded again; the new file must match the expected hash like any download.
- Catalog and MSRC page/API requests are retried up to 3 times (backoff 2 s, 8 s) on transport errors,
  timeouts, HTTP 429 and 5xx. A 404 is not retried.

### Checkpoint cumulative updates

From Windows 11 24H2, a cumulative update can require a **checkpoint** cumulative update to be installed
first, and the catalog download dialog lists both `.msu` files. `fetch` picks the file whose name
contains the KB (or `-file`) as the package, and packages **every other `.msu` that names its own KB**
as a separate package `<checkpoint KB>-<arch>` (same severity, release date and applicability, verified
by the catalog SHA-1 like the main file). The main package lists those KBs in `prerequisites`; the
isolated server holds it back on endpoints that do not have them yet. Checkpoint KBs are never put in
`supersedes`. Any other extra file (not `.msu`, or without its own KB) is skipped with a warning.
`pmctl auto` does not download or send a checkpoint package again once it was delivered (it stays a
prerequisite of later updates).

## Limits and known gaps

- **The catalog has no official API.** `fetch` and `catalog-search` scrape `Search.aspx`,
  `DownloadDialog.aspx` and `ScopedViewInline.aspx`. If Microsoft changes those pages, parsing fails with
  `unexpected Microsoft Update Catalog page format`. It fails clearly rather than picking a wrong file.
  To check the scraper, run the live smoke test (it reads pages and sends one HEAD request; it never
  downloads a payload):
  `go test -tags live -run Live -v ./internal/acquire/`. You can choose what it checks with
  `LIVE_KB`, `LIVE_PRODUCT` and `LIVE_MONTH`.
- `pmctl` sends `Accept-Language: en-US`. Without it, the catalog translates titles based on where the
  client is, and product/arch matching breaks.
- Only the first page of search results is read (25 rows). A KB search normally returns far fewer.
- One file per package. When an update lists several files, `fetch` picks the file whose name contains
  the KB, or the one you name with `-file`; checkpoint `.msu` files become their own packages (above).
- `fetch` (Microsoft Update Catalog) handles `.msu` and `.msi` files. `fetch-url` also handles
  `deb`, `rpm`, `pkg` and `agent` packages. There is no feed integration for Linux distributions
  or macOS vendors: you choose the URL and supply the SHA-256.
- Importing a WSUS export (WsusContent plus metadata) is **not implemented**.
- No automatic monthly selection. You decide what to fetch from the `msrc` output.
- Authenticode is checked only for `msu`/`msi` and only when `pmctl build` runs on Windows. Otherwise
  the manifest records `not_checked`.

## Example monthly workflow (Patch Tuesday)

```sh
# 1. What shipped this month for our fleet?
pmctl msrc -month 2026-Oct -product "Windows 10 Version 22H2" -arch x64

# 2. Optional: look at the catalog rows for a KB
pmctl catalog-search -q KB5126657

# 3. Fetch each needed KB (severity comes from MSRC for this product)
pmctl fetch -kb KB5126657 -product "Windows 10 Version 22H2" -arch x64 \
    -min-build 19045 -max-build 19045 -msrc-month 2026-Oct \
    -out acq/downloads -spec acq/spec.json
pmctl fetch -kb KB5127683 -product "Windows 10 Version 22H2" -arch x64 \
    -min-build 19045 -max-build 19045 -msrc-month 2026-Oct \
    -out acq/downloads -spec acq/spec.json

# 4. Third-party app (SHA-256 copied from the vendor's release notes)
pmctl fetch-url -url https://downloads.acme.example/agent/acme-agent-2.2.msi \
    -sha256 3f5c...e1 -package-id AcmeAgent-2.2 -title "Acme Endpoint Agent 2.2" -vendor Acme \
    -kind msi -product-code {11111111-2222-3333-4444-555555555555} -version 2.2.0 -severity important \
    -out acq/downloads -spec acq/spec.json

# 5. Review acq/spec.json, then sign (on Windows, Authenticode is recorded here)
pmctl build -key acq/bundle.key -spec acq/spec.json -out acq/out/2026-10.pmb -config acq/acquire.json
pmctl inspect -bundle acq/out/2026-10.pmb -pub acq/bundle.pub
pmctl send -bundle acq/out/2026-10.pmb -to <drop dir>
```

Running a `fetch` again is safe. A verified file is reused and its spec entry is replaced. To leave a
package out of the next bundle, remove its entry from spec.json.

### Bundle sequence numbers (`pmctl build` and `pmctl auto`)

The isolated server accepts a bundle only if its `sequence` is above the last one it accepted for that
`source`. The next sequence comes from a **sequence state file** (`{"sequences": {"<source>": N}}`):

- `pmctl auto` uses `sequence_state` from `acquire.json` (default `<work_dir>/sequence.json`).
- `pmctl build` uses `-state` (default **`./.pmctl-state.json` in the current directory**), or, with
  `-config acquire.json`, the same `sequence_state` and `source` as `pmctl auto`. **Use one state file per
  source for both**; otherwise a manual bundle reuses numbers the server has already seen and is
  rejected as a replay. `pmctl build` warns when its state file has no sequence for the source but
  another known state file does (`./.pmctl-state.json`, `./sequence.json`, `./work/sequence.json`, or
  the `sequence_state` of `./acquire.json`).

Rules: the number is reserved under a lock file (`<state>.lock`) and written (temp file, fsync, rename)
**before** the bundle is signed, so two builds never share a number; a build that fails afterwards
leaves a gap, which the server accepts. The stored value never decreases. `-seq N` must be above the
stored value. A state file that cannot be parsed stops the build (it never restarts at 1): repair it by
hand with a value above the last bundle sent.

## Unattended acquisition: `pmctl auto`

`pmctl auto -config acquire.json` does the whole monthly run on its own, and is meant to run from a schedule on the acquisition host:

1. **Microsoft:** for each product in `microsoft.products`, it reads the MSRC release for the current month and the `months − 1` before it. It keeps the KBs at or above `min_severity` and **drops a KB that another candidate supersedes**, so last month's cumulative update is not fetched once this month's is out, but only once the superseding KB is available (fetched in this run or sent earlier): if this month's update fails, last month's is fetched meanwhile, with a warning. A checkpoint prerequisite is never dropped. It then fetches each remaining KB from the Update Catalog, with the same verification as `pmctl fetch`, including its checkpoint packages.
   - The **newest** month returns 404 until Patch Tuesday; that is a warning, not an error.
   - Any other MSRC error (after retries), or no month readable at all, is a failure: the Microsoft feeds show `failed`, the run report lists it under `failures.msrc`, and the run is `partial` (exit 2), so an unread feed never looks like "nothing new".
2. **Third-party apps:** for each entry in `apps`, it reads the current version from the vendor feed (`version.url` with `json_path` or `regex`). If that version was not sent before, it downloads `download_url` (`{version}` is substituted) and verifies it. Two verification modes:
   - `sha256`: the vendor's checksum document (`url`, plus an optional `regex` or `json_path`; by default it finds the `<hash>  <file>` line). **Preferred.**
   - `authenticode_signer`: for vendors that publish no checksum. The file is accepted only if Windows reports a Valid Authenticode signature from that signer. Requires a Windows acquisition host.
   - `pkg_signer`: for macOS `.pkg` installers with no published checksum. The file is accepted only if `pkgutil --check-signature` reports a valid, notarized Developer ID signature whose certificate contains this text. Include the Team ID, e.g. `Developer ID Installer: Google LLC (EQHXZ8M8AV)`. Requires a macOS acquisition host.

   For `.pkg` files, pmctl reads the version **inside the installer** and labels the package with it, because vendor feeds can run ahead of a fixed download link. A mismatch is reported as a warning. Set `label_from_pkg: true` when the feed value is only a change trigger (a release tag or build number such as Office `16.114.26101123` or Brave `1.97.59`); the package then takes the app version from the installer without a warning.

   An app without any of these is refused at config load; unverified downloads are never accepted. For `.msi` installers whose product code changes per version, set `product_code_from_msi: true`, or give a fixed `product_code`. pmctl reads the product code from the MSI's Property table itself (pure Go, `internal/msi`), on Linux, macOS and Windows alike.

   An app with a winget package id can also set `"winget_id": "Vendor.App"`: the app is then listed in the console's Library (see [The Library](#the-library-update-intelligence)).
3. **Each package is checked on its own** before building: the payload must exist, the manifest schema must pass, and on a Windows acquisition host its Authenticode status must not be invalid (e.g. `NotSigned`). A package that fails is left out with the reason under `failures` (retried next run); the rest is still built and sent. Without this, one bad package would make the server refuse the whole bundle.
4. It builds signed bundles from everything new, named after their bundle IDs: **one bundle, or several** when the pending packages exceed `max_bundle_bytes` (default 28 GiB, below the server's 32 GiB) or `max_bundle_packages` (default 450, below the server's `max_files` 500). Packages keep their order (checkpoint prerequisites first). Each bundle gets its own sequence. A single package larger than `max_bundle_bytes` is a failure. Before building, the run directory's volume must hold twice the pending bytes plus a 2 GiB reserve.
5. Each bundle is **sent automatically** through the configured adapter (`send.via`: `dropdir` or `command`) with a signed receipt, and the receipt is appended to `send.log`. If a send fails, the remaining bundles are not sent; their packages are retried next run.
6. A bundle's packages are recorded as done in `work_dir/state.json` **right after that bundle was sent**, before anything else happens. If the bundle was delivered but the receipt or the sender log failed, that is a warning and the packages are still done (a resend would only be a duplicate). Anything that failed (download, verification, build, send) is retried on the next run. Each run appends a JSON report to `work_dir/auto-log.jsonl` (`bundles` lists every bundle ID sent).

Other behaviour:

- **Overlapping runs:** a lock file (`work_dir/.auto.lock`) prevents them. It records the owner's pid, and the owner refreshes its time stamp every minute. A lock is taken over only if it has not been refreshed for 15 minutes **and** its pid is not running (or it is older than `run_timeout` + 1 h, i.e. the pid was reused).
- **Timeouts:** the whole run stops after `run_timeout` (default `6h`): what was delivered stays recorded, the rest is reported as failed and retried. An `exec:` signer call is killed after 60 s; a `command` transfer after `send.timeout` (default `2h`). The shipped systemd unit and Task Scheduler task allow 7 h, so pmctl stops itself first.
- **Stopping:** SIGINT/SIGTERM (Ctrl-C, `systemctl stop`) stop fetching; delivered packages are saved to `state.json` and the status report is still sent.
- **Corrupt `state.json`:** the run stops with an error instead of treating every package as new (which would fetch and send everything again). Restore it from a backup or repair the JSON.
- **Retention:** at the end of each real run, `runs/<time>-*/` directories (spec and bundles as built) older than `keep_runs_days` (default 14) are deleted, as are the `downloads/` files of packages sent more than `keep_downloads_days` (default 14) ago (unless the current run uses them) and `.part` / unverified leftovers not touched for that long. A negative value keeps everything.
- **Drop directory:** a `<name>.part` left by an interrupted send is removed once it is older than 1 h; a younger one is treated as a send in progress and the send fails (retried next run).
- **Exit codes:** `0` means sent, or nothing new. `2` means some items failed, or a feed (MSRC, update intelligence) could not be read; they are retried. `1` means the run failed (e.g. build or send).
- **`-dry-run`:** checks the feeds and prints what would be fetched. It downloads, builds and sends nothing.
- **Approval is unchanged:** bundles still arrive in quarantine on the isolated side and still need approval there. Automation only removes the manual download work.

`acquire.json` keys for these limits (all optional):

| Key | Default | Meaning |
|---|---|---|
| `max_bundle_bytes` | `30064771072` (28 GiB) | maximum size of one bundle; keep it below the server's `max_bundle_bytes` (32 GiB) |
| `max_bundle_packages` | `450` | maximum packages per bundle (1–500; the server's `max_files` is 500) |
| `run_timeout` | `"6h"` | deadline for the whole run |
| `send.timeout` | `"2h"` | `command` adapter: kill the gateway command after this long |
| `keep_runs_days` | `14` | delete run directories older than this (negative: keep) |
| `keep_downloads_days` | `14` | delete downloads of packages sent longer ago than this (negative: keep) |
| `expected_ubr` | `false` | record `expected_ubr` in Windows cumulative update packages (server verifies by build revision). Enable only after every agent runs 0.6.5 or later: agents up to 0.6.2 refuse bundles with the field. `pmctl fetch -expected-ubr` is the manual equivalent. |

`send.command` and `exec:` signer commands are split on spaces; quote a path that contains spaces:
`"command": "\"C:\\Program Files\\Gateway\\push.exe\" --to outbound {file}"`.

Files: [packaging/acquisition/acquire.example.json](../packaging/acquisition/acquire.example.json) (Windows 10/11/Server 2022, Firefox with Mozilla's SHA256SUMS, Chrome with Authenticode), [register-task.ps1](../packaging/acquisition/register-task.ps1) (Windows Task Scheduler, daily 03:00), and [offpatch-acquire.service](../packaging/acquisition/offpatch-acquire.service) + [.timer](../packaging/acquisition/offpatch-acquire.timer) (systemd, daily 03:00).

**Verify the vendor URLs and regexes in the example before relying on them:** vendors change their download and checksum locations.

Tested:

- `cmd/pmctl/auto_test.go` against the recorded Microsoft fixtures and a fake vendor: dry run, first run (CU + app → one signed bundle + receipt), no-op second run, a new vendor version, checksum-mismatch refusal and retry, and the lock.
- `cmd/pmctl/robust_test.go`: sequence state (only grows, `-seq` checks, corrupt file refused, warnings, `build -config`), splitting into several bundles, checkpoint packages end to end, a package with an invalid signature left out, receipt/log failure after delivery, MSRC failure → partial, corrupt `state.json`, retention, lock takeover and refresh, quoted commands, signer timeout, supersedence only when the superseding KB is available.
- `internal/acquire/robust_test.go`: checkpoint packaging from a synthetic two-file download dialog (`testdata/downloaddialog-checkpoint.html`), stale same-name file replaced, mismatched `.part` dropped, retries on 503, 404 detection. `internal/transfer/robust_test.go`: stale `.part` in the drop directory, gateway command timeout.
- A live **dry run** (read-only) against the real MSRC feed and the Firefox/Chrome version feeds listed the expected KBs and versions, and skipped three superseded September CUs. No live payload was downloaded.

### The Library (update intelligence)

Besides the newest version of every winget package (`apps`), update intelligence carries `resolved`: installer and description details for a chosen set of packages, so the console's **Library** can show what can be imported, and how, before anyone requests it. For each package pmctl reads the newest version's winget installer manifest and its defaultLocale manifest (`<id>.locale.en-US.yaml`, else the `DefaultLocale` the version manifest names) and records:

- `publisher`, `homepage` (PackageUrl), `publisher_url`, `license`, `description` (ShortDescription). Community text: control characters dropped, length capped, https links only.
- `installers`: every installer pmctl could fetch (`arch`, `type` msi/wix/exe/inno/nullsoft/burn/msix/zip/portable, `scope`, `url`, `sha256`, `product_code` for MSIs when the manifest states it). Installers without an https URL, and MSIs without a SHA-256, are left out: pmctl could not fetch them.

**Which packages:** the configured ones (`intel.library` and the `winget_id` of `apps` entries), every app id an acquisition request ever asked for (kept in `state.json` `requested_apps`; on the first run also read from `<requests>/done/`), and a built-in list of 288 common enterprise packages (browsers, archivers, PDF readers, meeting clients, Java runtimes, Python, Git, PuTTY, WinSCP, KeePass, Wireshark, VS Code, Visual C++ runtimes, ...; `cmd/pmctl/library_common.go`). Ids missing from the winget index are skipped (a warning for configured and requested ones).

**Cost:** each package version is looked up once: entries are cached by `id@version` in `state.json` (`library`; only the newest version of each id is kept). At most 300 new lookups happen per run (configured first, then requested, newest first, then the built-in list); the rest follow on the next runs. A failed lookup is a warning (at most 10 listed, then "+N more") and is retried next run; it never marks the intelligence feed failed. The feed shows e.g. `..., 212 in the library` and `library: 212 packages (131 importable), 37 looked up`.

**Importable** (the rule the console shows; `acquire.LibraryImportable`): "yes" if there is an MSI-type installer (`msi`, `wix`) for the architecture needed (for an app nobody has installed yet: any architecture), matched as when fetching: a neutral MSI fits x64 and x86, a 32-bit MSI fits x64. The manifest need not state a product code; pmctl reads it from the MSI. Otherwise "no" with the reason, e.g. `EXE installer only (nullsoft)` or `no MSI installer (only msix)`. Not resolved yet: unknown.

`intel` keys in `acquire.json` (all optional):

| Key | Default | Meaning |
|---|---|---|
| `library` | `[]` | extra winget ids to describe |
| `no_library` | `false` | send no `resolved` section |
| `library_no_common` | `false` | only configured and requested ids, not the built-in list |
| `library_max_lookups` | `300` | new manifest lookups per run (at most 300) |

`pmctl intel` (manual) resolves the built-in list too, without a cache; `-no-library` skips it, `-library a.b,c.d` adds ids and `-winget-manifests-url` points at a mirror.

### Status reports and the console

After every real run (not `-dry-run`), `pmctl auto` signs a **status report** with the bundle key and sends it through the same transfer adapter (`acq-<source>-<time>.status.json`). The report covers the outcome (ok / partial / failed), each feed's latest version found, new packages, failures, warnings and the bundle ID.

On the isolated side:

- **Intake** verifies the signature against the trusted bundle keys and keeps a history.
- The console's **Acquisition** page shows the latest report per source and the run history.
- **Alerts:**
  - `acquisition_partial` and `acquisition_failed` when a run reports failures.
  - `acquisition_status_rejected` when a report's signature does not verify.
  - `acquisition_stale` when no report arrives for `acquisition_stale_after` in `pmserver.json` ("silence is not success"): default 3 h with `"deployment_mode": "single-server"` (hourly runs on the same machine), else 26 h.
- Set `"schedule": "every hour (systemd timer)"` (what the installer writes) in `acquire.json` to show the schedule on that page. The installer's `offpatch-acquire.timer` runs hourly; a run that finds the previous one still holding the run lock exits 3 ("skipped"), which the units treat as success.

The isolated server cannot start a run (there is no reverse path), so **Refresh** only re-reads the latest report. To run now, start `pmctl auto` on the acquisition host, or `launchctl kickstart gui/$(id -u)/com.offpatch.acquire` for the launchd job installed by `packaging/acquisition/install-launchd.sh`.

The console's **Server** page (`GET /api/system`) shows the management server's version, uptime, security mode, signing keys, intake state, storage, audit and agent settings. No secrets are included.

## Acquisition requests from the console

The console's **Updates** page lists everything the fleet is missing according to update intelligence: newer winget application versions and Windows cumulative updates. This includes updates that are not in the catalog yet ("not imported"). An acquisition request turns that list into work for `pmctl auto`, so nobody has to hand-write `fetch-url` specs or `apps` entries.

**The boundary stays one-way.** The isolated server never sends anything out. In production the request leaves only as a file the operator downloads in the browser and carries to the acquisition zone on approved media.

**Direct when co-located.** With `acquisition_requests_dir` set in `pmserver.json` (absolute path), the server also writes each exported request into that folder (`<request_id>.json`, temp file + fsync + rename, mode 0640) and the response says `queued_to`. Production with separate hosts keeps it **unset** (strict one-way: carry the file). Set it only when acquisition runs on the same machine — the single-server install (`--role all`) sets it to `/var/lib/offpatch-acq/requests` — or the organisation approves an outbound folder. See [07-admin-guide.md](07-admin-guide.md) §3.9.

### Workflow

1. **Select and export (isolated zone, role `user`).** On **Updates**, tick the outdated apps and missing KBs that are not imported yet. "Select all" ticks every visible row that is not in the catalog. Click **Export acquisition request**. The browser saves `acq-request-<time>-<id>.json` (`POST /api/acquisition-requests`, see [05-api.md](05-api.md)). Every export is written to the audit log as `acquisition.request_exported`, with the user, the request id, every `winget_id@version` and every `KB/arch`.
2. **Carry it across.** Move the file on approved media into the requests directory on the acquisition host: `"requests": "requests"` in `acquire.json`, or `pmctl auto -requests <dir>`. With `acquisition_requests_dir` (co-located only) the server has already put it there.
   - `pmctl auto -only-requests` handles just the requests directory: no Microsoft feeds, configured apps or update intelligence. Bundles, retention, the run lock and the status report work as usual; the report carries the warning "requests-only run" and only `request` feeds. The single-server install runs it from `offpatch-acquire-requests.path` as soon as a request appears; the hourly run still does everything.
3. **Fetch (acquisition zone).** The next `pmctl auto` run reads every `*.json` in that directory:
   - **Apps:** for each `winget_id` and each requested architecture (`x64`, `x86`, `arm64`, taken from the endpoints that have the app; for an app no endpoint has, the architecture the operator chose when importing it from the Library):
     - pmctl downloads the per-version installer manifest from the winget community repository (`manifests/<l>/<Publisher>/<Name>/<version>/<id>.installer.yaml`, falling back to the singleton `<id>.yaml`) over HTTPS.
     - It picks the **MSI** installer for that architecture (`InstallerType` `msi` or `wix`; machine scope and a neutral or en-US locale preferred).
     - x64 endpoints fall back to a 32-bit MSI, with a warning, when no x64 MSI exists.
     - It downloads the installer over HTTPS and accepts it only if it matches the manifest's `InstallerSha256`.
     - It adds a spec entry: `kind: msi`, `product_code` from the manifest or, when the manifest states none (Microsoft Edge, for example), read from the downloaded MSI on any OS, `version` (the Apps & features `DisplayVersion` if the manifest gives one, else the winget version), and `package_name`.
     - `package_name` is the Apps & features name: the manifest's `DisplayName` if present. Otherwise it is the name the endpoints report, when they agree and it contains no version. Otherwise it is the winget name.
     - The package id is `<winget id>-<version>` (`-<arch>` when not x64).
     - Ids with characters outside `[A-Za-z0-9._-]` (`Notepad++`) or longer than 64 characters get a short hash suffix, so two packages never share an id.
   - **KBs:** each KB goes through the Update Catalog exactly like `pmctl fetch`, as `<KB>-<arch>`.
     - The request lists a KB once per architecture that misses it (x64 and arm64 machines can need the same KB number).
     - The catalog title from the intelligence selects the row.
     - The build pins applicability, unless one KB serves several builds: then the build is left open (`build: 0`).
     - `expected_ubr` (**only with `"expected_ubr": true` in `acquire.json`, default off; enable only after every agent runs 0.6.5 or later**: agents up to 0.6.2 refuse a bundle whose manifest has the field, with a critical alert): the build revision the update brings that build to (the `6899` of `26100.6899`), from the catalog title or, when the title does not state it, from the last update intelligence (`state.json` `windows_ubr`). The server then also confirms the update by the endpoint's build revision when Windows does not list the KB. The Microsoft feed (`microsoft.products`) fills it the same way for `min_build`.
   - The packages join the same signed bundle as the rest of the run and are sent automatically.
4. **Approve (isolated zone).** The bundle arrives through intake. Its packages wait in the **Catalog** as quarantined, and the Updates page's **Catalog** column changes from "not imported" to "in catalog · awaiting approval". Approval and deployment work as for any other package.

### Warnings, failures and the requests directory

- **Warnings, not failures:** items offpatch cannot package are listed under `warnings` in the run report and status report, and are not retried. Examples:
  - EXE, Inno, Nullsoft, Burn, MSIX or zip installers. offpatch deploys MSI packages only; there is no `exe` package kind.
  - An MSI whose Property table has no valid `ProductCode` (`MSI has no ProductCode`). A manifest without one is fine: pmctl reads it from the downloaded MSI, on any OS.
  - A version that is no longer in the winget repository.
  - A KB the Update Catalog does not list for the requested product, build and architecture.
- **Failures (retried next run):**
  - Network errors.
  - Installers that do not match `InstallerSha256`.
  - Manifests pmctl cannot parse. These are kept for retry; report them.
- **Request files:**
  - A request is moved to `<requests>/done/` once all its items were sent (or were sent earlier, or are warnings).
  - A request with a failed item stays in place and is retried on the next run.
  - A file that is not a valid request is moved to `<requests>/rejected/` with a warning.
  - `-dry-run` lists the candidate packages and moves nothing.
- **Status report:** each request appears as a feed of type `request` on the console's **Acquisition** page.
- **Per-item results:** the status report also lists every requested item under `items` (one entry per app, all its architectures folded together, and one per KB/arch), so the console can show the outcome on the row the operator clicked:

  | `result` | Meaning | Example `reason` |
  |---|---|---|
  | `fetched` | Downloaded and carried by a bundle sent this run. | |
  | `already_sent` | Sent for this same request by an earlier run (the request was kept because another item failed). | `sent for this request in bundle b-20261017-0003` |
  | `unsupported` | Can never be fetched this way; not retried. Console: "Can't import: <reason>". | `no MSI installer for x86 in winget (only exe)`, `winget no longer lists version 1.2.3`, `MSI has no ProductCode`, `KB5044273 not in the Microsoft Update Catalog for build 22000 x64` |
  | `failed` | Transient; the request stays and the next run retries it. Console: "Import failed: <reason>". | `SHA-256 mismatch: the download does not match the published hash`, `GET https://...: HTTP 503`, `downloaded but not sent: ...`, `the run reached its time limit before this finished; retried next run` |

  A package fetched this run counts as `fetched` only if a sent bundle carried it; a failed send or a package left out at build time makes it `failed`. For an app with several architectures, any failed architecture makes the item `failed`, else any fetched one `fetched`; reasons are prefixed with the architecture (`x86: no MSI installer for x86 in winget`). The full error text stays under `failures` and `warnings`.
- **A request is explicit:** its items are fetched and sent again even if `state.json` says an earlier run, or the regular Microsoft/app feeds, already sent them. This is how a package that was rejected on the isolated side is imported again: export a new request for it. Only what was already sent for *this* request (while it is retried because of a failed item) is not sent twice; that is kept in `state.json` under `request_sent` and dropped once the request moves to `done/` or its file is gone.
- **Duplicates within a run are fetched once:** an item listed by more than one request, or also brought by the Microsoft feed in the same run, is downloaded once and travels in the same bundle.

### The request file

Unsigned JSON, at most 1 MB and 500 items. `pmctl` parses it strictly: unknown fields are refused, and winget ids, versions, KBs, architectures and product codes are checked against fixed patterns.

The file is **advisory**. pmctl only takes ids and versions from it. Every URL and hash comes from the vendor sources, and everything fetched still arrives in quarantine. A forged or edited request can at most make pmctl fetch genuine winget or Microsoft packages that someone then has to approve.

The file contains no host names or endpoint ids. It carries only the ids, versions, installed product codes, names and versions, architectures and endpoint counts.

```json
{
  "format": "offpatch.acquisition-request", "version": 1,
  "request_id": "acq-request-20261017T101500Z-1a2b3c",
  "created_at": "2026-10-17T10:15:00Z", "created_by": "user:otto",
  "intel_generated_at": "2026-10-17T03:05:12Z",
  "apps": [{"winget_id": "Google.Chrome", "name": "Google Chrome", "version": "155.0.8059.85",
            "architectures": ["x64"], "endpoints": 12,
            "installed": [{"product_code": "{0228B730-26AA-39E9-B2E1-0FC0E3EA58C8}", "name": "Google Chrome", "version": "155.0.8059.82"}]}],
  "kbs": [{"kb": "KB5044280", "product": "Windows 11 Version 21H2",
           "title": "2024-10 Cumulative Update for Windows 11 for x64-based Systems (KB5044280)",
           "build": 22000, "arch": "x64", "endpoints": 3}]
}
```

`acquire.json` keys:
- `"requests"`: the directory, relative to the config file.
- `"winget_manifests_url"`: optional. Defaults to `https://raw.githubusercontent.com/microsoft/winget-pkgs/master/manifests`; set it to point at an internal mirror.

### How the Catalog column finds imported packages

- **Windows updates** match by KB.
- **Applications** match by MSI product code, newest version first. This covers apps such as Chrome, whose enterprise MSI keeps its product code across versions.
- **Otherwise by name:** many MSIs (for example 7-Zip) get a new product code with every version, so an application also matches by `package_name`. The name is compared after normalising it the same way the intelligence does (`7-Zip` matches `7-Zip 26.03 (x64 edition)`), and the package must be newer than the installed version.

**Known gap:** an endpoint's own "available updates" list (catalog packages it needs) still compares `package_name` with the installed name **exactly**. An app whose Apps & features name contains its version (7-Zip) shows as "in catalog" on the Updates page, but is not offered automatically on the endpoint page; deploy it from the catalog.

Tested:
- `internal/acquire/winget_test.go`: recorded winget-pkgs manifests for Chrome, 7-Zip, VLC, Notepad++ and VS Code (MSI selection, root defaults, EXE/Inno-only warnings, manifest URLs, 404 fallback, https only).
- `internal/msi/msi_test.go`: the pure-Go MSI reader on synthetic compound files built in the test (512- and 4096-byte sectors, mini stream and regular sectors, 2- and 3-byte string references, a string over 64 KiB) and broken ones (not an MSI, truncated, looping sector chain, no or invalid ProductCode, no string pool). `OFFPATCH_MSI_DIR=<dir>` (optionally `OFFPATCH_MSI_EXPECT="file=CODE;..."`) reads real MSIs: checked against the Windows Installer API on 168 MSIs (24 version 3, 144 version 4) and the Microsoft Edge enterprise MSI 155.0.4283.62 from winget (`{6E669770-C655-388E-835E-C146C8EC6A2E}`).
- `internal/acquire/library_test.go` and `cmd/pmctl/library_test.go`: the Library from the recorded Edge manifests (no ProductCode, still importable), locale fallbacks and free text the YAML reader refuses, the import rule, the lookup order, the `id@version` cache, the per-run budget and warnings; a request for Edge with no endpoint having it becomes an MSI package whose product code is read from the (synthetic) MSI.
- `cmd/pmctl/onlyrequests_test.go`: `pmctl auto -only-requests` fetches only the request (no configured app, no Microsoft feed), sends the bundle and status report, archives the request, honours the run lock, and refuses to run without a requests directory.
- `internal/e2e/acq_queue_test.go`: with `acquisition_requests_dir`, the export is queued as exactly the parsed document (0640, no temp file left), audited with `queued_to`; a failed write still returns 200 and is audited with `queued_error`.
- `cmd/pmctl/requests_test.go`: a full `pmctl auto` run with a request. Chrome and 7-Zip MSIs and a KB go into one signed bundle. VS Code (Inno only) and an unknown id become warnings and `unsupported` items with short reasons. The request is archived and a garbage file is rejected. The same request carried again is fetched and sent again. A tampered installer fails (`failed`, "SHA-256 mismatch") and its request is kept. The tests use no live network.
- `cmd/pmctl/requestitems_test.go`: per-item results. A KB not in the catalog for the build/arch is `unsupported`; on the retry of a request with a failed item, the item already sent for it is `already_sent` and not sent again, and `request_sent` is cleared once the request is done. A KB the Microsoft feed sent earlier is sent again when a request names it, and fetched once when feed and request bring it in the same run. Unit tests cover error classification (hash, timeout, network, catalog), MSI reasons, folding architectures, and "downloaded but not sent".
- `internal/e2e/acq_request_test.go`: export permissions, an audit record with who and what, a file that pmctl parses with no host names, unknown selections refused, and the Catalog link for winget-sourced Chrome (by product code) and 7-Zip (by name).

## Auto-download policy

The installer writes `acquire.json` with sensible defaults (Windows 11 24H2 security updates,
update intelligence, acquisition requests). The **super admin** changes what the downloader
fetches from the console, **Settings → Auto-download**, without editing files on the
acquisition host. `acquire.json` stays the **base**; the policy is merged over it on every run.

What the policy holds (`internal/acqpolicy`):

| Part | Entries | Effect in `pmctl auto` |
|---|---|---|
| Windows updates | `{product, build, arch, classification: security\|all, enabled}`, chosen from the releases the downloader knows plus those in the update intelligence | Adds the release to the Microsoft feed (`catalog_product` from the known list; Windows Server entries get the package suffix `-server`), or re-classifies the matching `acquire.json` product (`all` = every severity, `security` = `acquire.json`'s `min_severity`, `important` if `acquire.json` has no Microsoft section). `enabled: false` removes the matching `acquire.json` product. |
| Apps | `{source: winget, id, arch[], channel: latest, enabled, note}` | Kept at the newest version the update intelligence's Library knows (the id is added to the Library list, so its newest version is looked up by the same run's intelligence and downloaded on the next run). One MSI per architecture, checked against the winget manifest's SHA-256, package id `<id>-<version>[-<arch>]`. An app that an `acquire.json` app feed covers (same `winget_id`) is left to that feed; `enabled: false` also skips that feed. |
| Sources | `winget` (index `url`, `manifests_url`), `microsoft-catalog` / `msrc` (`url`), `vendor-url`, `internal-mirror` | URL overrides replace `intel.winget_url`, `winget_manifests_url`, `catalog_url`, `msrc_url`. Switching off `microsoft-catalog` or `msrc` stops all Windows downloads; switching off `winget` stops policy apps. `internal-mirror {url, replaces: winget-index\|winget-manifests\|microsoft-catalog\|msrc}` wins over the source's own URL. `vendor-url {name, url, kind msi\|msu, version, expected_sha256 \| signer, product_code?, kb (msu), arch?, vendor?}` is fetched like `pmctl fetch-url`: the file must match `expected_sha256`, or (Windows downloader only) carry a valid Authenticode signature whose subject contains `signer`; package id `<source id>-<version>`; an MSI without `product_code` has it read from the file. EXE installers are refused. |
| Limits | `max_download_gb_per_run` (0 = none), `keep_last_n_versions` (0 = by age) | A run stops downloading once this much was read (the rest fails for this run and is retried next run). Downloaded files of policy apps and vendor downloads beyond the newest N sent versions are deleted (state `families`). |
| Schedule | read-only | Shown from the status report (`schedule` in `acquire.json`); the timer belongs to the installer. |

Validation (server and pmctl run the same code): https only, a host, no user name or password,
no `#fragment`, no query parameter that looks like a credential (`token`, `key`, `secret`,
`sig`, `auth`, …), SHA-256 as 64 hex characters, winget ids and versions as for requests, at
most 50 Windows entries, 500 apps and 100 sources, one enabled source per type (vendor
downloads excepted) and per mirrored upstream, limits 0–10000 GB and 0–100 versions.

### How the policy reaches the downloader

Every save is a new **version** (who, when, SHA-256 of the content, a plain summary of what
changed), audited `acquisition.policy_updated`. The delivered file is
`policy-<version, 6 digits>.json`:

```json
{ "format": "offpatch.acquisition-policy", "version": 1, "policy_version": 3,
  "edited_by": "user:sam@vendor", "edited_at": "2026-10-18T10:00:00Z",
  "sha256": "<hex SHA-256 of the compact policy JSON>", "policy": { "windows": [], "apps": [], "sources": [], "limits": {} } }
```

- **One server** (the usual layout: `pmctl` as `offpatch-acq`, `pmserver` as `offpatch`):
  with `acquisition_requests_dir` set, the server writes the file into that folder on every
  save, exactly like acquisition requests (temp file, fsync, rename, mode 0640, group
  `offpatch-inbox` through the folder's setgid bit), audited `acquisition.policy_queued`. The
  request watcher (`offpatch-acquire-requests.path`, `PathExistsGlob=*.json`) starts
  `pmctl auto -only-requests`, which applies the policy at once; downloads follow on the next
  timer run. **Run now** writes `run-<id>.json` (audited `acquisition.run_requested`): a
  requests-only run that finds one does a full run.
- **Two machines**: nothing is written; the super admin clicks **Download policy file** and
  carries it, like a request file, into the downloader's `requests` folder. It is applied on
  the next scheduled run. Run now is not offered (409).

`pmctl auto` on every run (also `-only-requests`):

1. reads every `policy-*.json` in the requests folder strictly (unknown fields refused,
   SHA-256 checked, the policy validated and required to be in normalized form). Invalid files
   go to `rejected/` and the reason is reported as `policy_error`; the previous version stays
   in force. Valid ones go to `done/`; the newest one newer than the active version becomes
   active in `work_dir/policy.json` (with `applied_at`); older ones are ignored with a warning;
2. merges the active policy over `acquire.json`, so later timer runs keep applying it without
   the file;
3. reports in the signed status report: `policy_version`, `policy_sha256`, `policy_edited_by`,
   `policy_applied_at`, `policy_error`, `sources` (per entry: `kind` source / app / windows,
   `id`, `result` new / up_to_date / failed / unsupported / waiting / disabled / applied,
   `detail`, `packages`), `run_request`, and `defaults` (what `acquire.json` configures, as
   policy entries, plus the names of its custom app feeds).

The console shows **Applied by the downloader at …** when the newest status report names the
saved version, and **waiting for version N** otherwise (with **Hand over again** on one
server).

**Starting point.** Until the first save the page offers the installer's settings:
`acquire.json` itself if pmserver can read it (`/etc/offpatch/acquire.json`, or the path in the
environment variable `OFFPATCH_ACQUIRE_CONFIG`; the file is normally readable only by the
acquisition user), else the `defaults` from the newest status report, else an empty policy with
a banner. Nothing is stored or sent until Save. `acquire.json` app feeds with their own version
URLs are listed as "Also from the installer's settings" and keep running.

**Trust.** Like a request, the policy file is only as trusted as the folder it is written to
(owner `offpatch`, group `offpatch-inbox`, 0640) or the person who carries it. Its SHA-256
detects damage, not forgery. It cannot make the downloader accept anything unverified: every
download is still checked (winget manifest SHA-256, catalog hashes, vendor SHA-256 or
Authenticode signer) and arrives on the isolated side as a signed bundle in **quarantine**.

Tested:
- `internal/acqpolicy/acqpolicy_test.go`: normalisation, every validation rule (https,
  credentials, SHA-256, EXE refused, duplicates, one enabled source per type), the file's
  hash and tamper check, run requests, the `acquire.json` import and the change summary.
- `internal/store/acqpolicy_test.go`: versions, conflict on a stale `base_version`, invalid
  content refused, history, audit.
- `cmd/pmctl/policy_test.go`: the merge (add / re-classify / switch off Windows releases, app
  feeds switched off, URL overrides, mirrors, catalog off stops Windows), a full run with a
  delivered policy (vendor download by SHA-256, Chrome through a winget-manifests mirror, a
  release switched off, policy archived and kept, status report signed with version, results
  and defaults), a damaged version refused with the previous one kept, Run now turning a
  requests-only run into a full run, the per-run download limit and keep-last-N, and the known
  Windows list matching `acquire.DefaultWindowsProducts`.
- `internal/e2e/acq_policy_test.go`: super admin only (403 for viewer, user, admin), the
  starting point from `acquire.json` / the downloader's report / empty, save → file in
  `acquisition_requests_dir` that pmctl parses → status report → "applied", conflict, history,
  audit, Run now, the carried file on two machines.
