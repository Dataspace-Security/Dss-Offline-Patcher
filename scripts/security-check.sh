#!/usr/bin/env bash
# One-shot security gate for offpatch. Runs every check, prints a summary and
# exits non-zero if any check failed.
#
#   go vet (native and GOOS=windows)
#   manifest unit tests + fuzz regression corpus, then each fuzzer for FUZZTIME
#   govulncheck (reachability-aware scan of the Go module + stdlib)
#   npm audit of the console's production dependencies (fails on high+)
#   SBOM generation (scripts/sbom.sh → dist/sbom/)
#
# Env:
#   FUZZTIME      per-fuzzer duration (default 20s)
#   FUZZ_PARALLEL fuzz workers (default 4)
#
# Needs network access (or warm caches) for govulncheck's database, the pinned
# tools and npm audit, so run it in the connected/build zone.
set -uo pipefail

FUZZTIME="${FUZZTIME:-20s}"
FUZZ_PARALLEL="${FUZZ_PARALLEL:-4}"
GOVULNCHECK_VERSION="v1.9.0"
FUZZERS=(FuzzParse FuzzExtractSafe FuzzVerify)

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

failed=()
passed=()
step() {
  local name="$1"
  shift
  echo
  echo "==> $name"
  if "$@"; then
    passed+=("$name")
  else
    echo "!! $name FAILED"
    failed+=("$name")
  fi
}

step "go vet (native)" go vet ./...
step "go vet (GOOS=windows)" env GOOS=windows go vet ./...
step "manifest tests + fuzz corpus" go test -count=1 ./internal/manifest/
for fz in "${FUZZERS[@]}"; do
  # Short minimisation: the default (60s) can swallow the whole budget.
  step "fuzz $fz ($FUZZTIME)" go test -run='^$' -fuzz="^${fz}\$" -fuzztime="$FUZZTIME" \
    -fuzzminimizetime=2s -parallel="$FUZZ_PARALLEL" ./internal/manifest/
done
step "govulncheck $GOVULNCHECK_VERSION" go run "golang.org/x/vuln/cmd/govulncheck@${GOVULNCHECK_VERSION}" ./...
step "npm audit (production deps, high+)" bash -c 'cd web && npm audit --omit=dev --audit-level=high'
step "SBOM" bash "$ROOT/scripts/sbom.sh"

echo
echo "==== security-check summary ===="
for s in "${passed[@]}"; do echo "PASS  $s"; done
for s in "${failed[@]+"${failed[@]}"}"; do echo "FAIL  $s"; done
if [ "${#failed[@]}" -gt 0 ]; then
  echo "${#failed[@]} check(s) failed."
  echo "If a fuzzer failed, the crashing input is in internal/manifest/testdata/fuzz/<FuzzName>/;"
  echo "fix the bug and keep that file as a regression seed."
  exit 1
fi
echo "All checks passed."
