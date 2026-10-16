#!/usr/bin/env bash
# Generate CycloneDX JSON SBOMs into dist/sbom/:
#   offpatch-module.cdx.json            whole Go module (every required module)
#   pmserver|pmagent|pmctl.cdx.json      per shipped binary (what is actually linked
#                                        in, incl. Go stdlib version), built for
#                                        SBOM_GOOS/SBOM_GOARCH (default windows/amd64)
#   web-console.cdx.json                React console (npm, production deps only;
#                                        this is what gets embedded in pmserver)
#
# Tool versions are pinned below. They are fetched by `go install` / `npx` on
# first use, so run this in the connected zone or with a warm module/npm cache.
#
# Env: SBOM_GOOS, SBOM_GOARCH, OFFPATCH_VERSION (main component version, default "dev").
set -euo pipefail

CYCLONEDX_GOMOD_VERSION="v1.12.0"
CYCLONEDX_NPM_VERSION="6.0.1"
SBOM_GOOS="${SBOM_GOOS:-windows}"
SBOM_GOARCH="${SBOM_GOARCH:-amd64}"
OFFPATCH_VERSION="${OFFPATCH_VERSION:-dev}"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$ROOT/dist/sbom"
mkdir -p "$OUT"
cd "$ROOT"

# Build the pinned tool natively (the GOOS/GOARCH above only apply to targets).
TOOLS="$(mktemp -d)"
trap 'rm -rf "$TOOLS"' EXIT
GOOS="" GOARCH="" GOBIN="$TOOLS" go install "github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod@${CYCLONEDX_GOMOD_VERSION}"
gomod() { "$TOOLS/cyclonedx-gomod" "$@"; }

echo "sbom: Go module"
# mod mode only warns if it cannot derive a version from git.
gomod mod -json -licenses -output "$OUT/offpatch-module.cdx.json" .

# Per-binary SBOMs use "bin" mode on freshly built binaries: it reads the
# embedded build info, so it reflects exactly what ships and does not depend on
# git metadata (app mode fails in a repo without commits/tags).
for bin in pmserver pmagent pmctl; do
  echo "sbom: $bin ($SBOM_GOOS/$SBOM_GOARCH)"
  exe="$TOOLS/$bin"
  [ "$SBOM_GOOS" = windows ] && exe="$exe.exe"
  GOOS="$SBOM_GOOS" GOARCH="$SBOM_GOARCH" go build -trimpath -o "$exe" "./cmd/$bin"
  gomod bin -json -licenses -std -version "$OFFPATCH_VERSION" -output "$OUT/$bin.cdx.json" "$exe"
done

echo "sbom: web console"
(
  cd "$ROOT/web"
  [ -d node_modules ] || npm ci --no-audit --no-fund
  npx --yes "@cyclonedx/cyclonedx-npm@${CYCLONEDX_NPM_VERSION}" \
    --omit dev --output-format JSON --output-file "$OUT/web-console.cdx.json"
)

echo "sbom: wrote $OUT"
ls -l "$OUT"
