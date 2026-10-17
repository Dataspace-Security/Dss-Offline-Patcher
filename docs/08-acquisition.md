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

   An app without any of these is refused at config load; unverified downloads are never accepted. For `.msi` installers whose product code changes per version, set `product_code_from_msi: true` (Windows host), or give a fixed `product_code`.
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

`send.command` and `exec:` signer commands are split on spaces; quote a path that contains spaces:
`"command": "\"C:\\Program Files\\Gateway\\push.exe\" --to outbound {file}"`.

Files: [packaging/acquisition/acquire.example.json](../packaging/acquisition/acquire.example.json) (Windows 10/11/Server 2022, Firefox with Mozilla's SHA256SUMS, Chrome with Authenticode), [register-task.ps1](../packaging/acquisition/register-task.ps1) (Windows Task Scheduler, daily 03:00), and [offpatch-acquire.service](../packaging/acquisition/offpatch-acquire.service) + [.timer](../packaging/acquisition/offpatch-acquire.timer) (systemd, daily 03:00).

**Verify the vendor URLs and regexes in the example before relying on them:** vendors change their download and checksum locations.

Tested:

- `cmd/pmctl/auto_test.go` against the recorded Microsoft fixtures and a fake vendor: dry run, first run (CU + app → one signed bundle + receipt), no-op second run, a new vendor version, checksum-mismatch refusal and retry, and the lock.
- `cmd/pmctl/robust_test.go`: sequence state (only grows, `-seq` checks, corrupt file refused, warnings, `build -config`), splitting into several bundles, checkpoint packages end to end, a package with an invalid signature left out, receipt/log failure after delivery, MSRC failure → partial, corrupt `state.json`, retention, lock takeover and refresh, quoted commands, signer timeout, supersedence only when the superseding KB is available.
- `internal/acquire/robust_test.go`: checkpoint packaging from a synthetic two-file download dialog (`testdata/downloaddialog-checkpoint.html`), stale same-name file replaced, mismatched `.part` dropped, retries on 503, 404 detection. `internal/transfer/robust_test.go`: stale `.part` in the drop directory, gateway command timeout.
- A live **dry run** (read-only) against the real MSRC feed and the Firefox/Chrome version feeds listed the expected KBs and versions, and skipped three superseded September CUs. No live payload was downloaded.

### Status reports and the console

After every real run (not `-dry-run`), `pmctl auto` signs a **status report** with the bundle key and sends it through the same transfer adapter (`acq-<source>-<time>.status.json`). The report covers the outcome (ok / partial / failed), each feed's latest version found, new packages, failures, warnings and the bundle ID.

On the isolated side:

- **Intake** verifies the signature against the trusted bundle keys and keeps a history.
- The console's **Acquisition** page shows the latest report per source and the run history.
- **Alerts:**
  - `acquisition_partial` and `acquisition_failed` when a run reports failures.
  - `acquisition_status_rejected` when a report's signature does not verify.
  - `acquisition_stale` when no report arrives for 26 h ("silence is not success").
- Set `"schedule": "daily at 07:00"` in `acquire.json` to show the schedule on that page.

The isolated server cannot start a run (there is no reverse path), so **Refresh** only re-reads the latest report. To run now, start `pmctl auto` on the acquisition host, or `launchctl kickstart gui/$(id -u)/com.offpatch.acquire` for the launchd job installed by `packaging/acquisition/install-launchd.sh`.

The console's **Server** page (`GET /api/system`) shows the management server's version, uptime, security mode, signing keys, intake state, storage, audit and agent settings. No secrets are included.

## Acquisition requests from the console

The console's **Updates** page lists everything the fleet is missing according to update intelligence: newer winget application versions and Windows cumulative updates. This includes updates that are not in the catalog yet ("not imported"). An acquisition request turns that list into work for `pmctl auto`, so nobody has to hand-write `fetch-url` specs or `apps` entries.

**The boundary stays one-way.** The isolated server never sends anything out. The request leaves only as a file the operator downloads in the browser and carries to the acquisition zone on approved media.

### Workflow

1. **Select and export (isolated zone, role `operator`).** On **Updates**, tick the outdated apps and missing KBs that are not imported yet. "Select all" ticks every visible row that is not in the catalog. Click **Export acquisition request**. The browser saves `acq-request-<time>-<id>.json` (`POST /api/acquisition-requests`, see [05-api.md](05-api.md)). Every export is written to the audit log as `acquisition.request_exported`, with the user, the request id, every `winget_id@version` and every `KB/arch`.
2. **Carry it across.** Move the file on approved media into the requests directory on the acquisition host: `"requests": "requests"` in `acquire.json`, or `pmctl auto -requests <dir>`.
3. **Fetch (acquisition zone).** The next `pmctl auto` run reads every `*.json` in that directory:
   - **Apps:** for each `winget_id` and each requested architecture (`x64`, `x86`, `arm64`, taken from the endpoints that have the app):
     - pmctl downloads the per-version installer manifest from the winget community repository (`manifests/<l>/<Publisher>/<Name>/<version>/<id>.installer.yaml`, falling back to the singleton `<id>.yaml`) over HTTPS.
     - It picks the **MSI** installer for that architecture (`InstallerType` `msi` or `wix`; machine scope and a neutral or en-US locale preferred).
     - x64 endpoints fall back to a 32-bit MSI, with a warning, when no x64 MSI exists.
     - It downloads the installer over HTTPS and accepts it only if it matches the manifest's `InstallerSha256`.
     - It adds a spec entry: `kind: msi`, `product_code` from the manifest, `version` (the Apps & features `DisplayVersion` if the manifest gives one, else the winget version), and `package_name`.
     - `package_name` is the Apps & features name: the manifest's `DisplayName` if present. Otherwise it is the name the endpoints report, when they agree and it contains no version. Otherwise it is the winget name.
     - The package id is `<winget id>-<version>` (`-<arch>` when not x64).
     - Ids with characters outside `[A-Za-z0-9._-]` (`Notepad++`) or longer than 64 characters get a short hash suffix, so two packages never share an id.
   - **KBs:** each KB goes through the Update Catalog exactly like `pmctl fetch`, as `<KB>-<arch>`.
     - The request lists a KB once per architecture that misses it (x64 and arm64 machines can need the same KB number).
     - The catalog title from the intelligence selects the row.
     - The build pins applicability, unless one KB serves several builds: then the build is left open (`build: 0`).
   - The packages join the same signed bundle as the rest of the run and are sent automatically.
4. **Approve (isolated zone).** The bundle arrives through intake. Its packages wait in the **Catalog** as quarantined, and the Updates page's **Catalog** column changes from "not imported" to "in catalog · awaiting approval". Approval and deployment work as for any other package.

### Warnings, failures and the requests directory

- **Warnings, not failures:** items offpatch cannot package are listed under `warnings` in the run report and status report, and are not retried. Examples:
  - EXE, Inno, Nullsoft, Burn, MSIX or zip installers. offpatch deploys MSI packages only; there is no `exe` package kind.
  - A manifest with no `ProductCode`. On a Windows acquisition host, pmctl reads it from the MSI instead.
  - A version that is no longer in the winget repository.
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
- **Duplicates are fetched once:** packages already in `state.json`, or listed by more than one request, are not fetched again.

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
- `cmd/pmctl/requests_test.go`: a full `pmctl auto` run with a request. Chrome and 7-Zip MSIs and a KB go into one signed bundle. VS Code (Inno only) and an unknown id become warnings. The request is archived and a garbage file is rejected. A repeat is a no-op. A tampered installer fails and its request is kept. The tests use no live network.
- `internal/e2e/acq_request_test.go`: export permissions, an audit record with who and what, a file that pmctl parses with no host names, unknown selections refused, and the Catalog link for winget-sourced Chrome (by product code) and 7-Zip (by name).
