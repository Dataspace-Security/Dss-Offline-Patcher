package main

// Delivery in pmctl auto: every pending package is checked on its own (one
// bad package must not sink the rest), the good ones are split into bundles
// that fit the isolated server's limits, and each bundle is built (with its
// own sequence), sent, and recorded in state.json before the next one.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"offpatch/internal/acquire"
	"offpatch/internal/manifest"
)

const (
	// Size allowance besides the payloads: tar headers and padding per file,
	// the manifest entry per package, and the manifest + signature.
	perPackageOverhead = 4 << 10
	perBundleOverhead  = 1 << 20
)

type deliveryRun struct {
	ctx       context.Context
	c         *autoConfig
	runDir    string
	spec      string
	st        autoState
	statePath string
	rep       *autoReport
	fail      func(id string, err error)
}

type pendingPkg struct {
	sp   specPackage
	size int64
}

func deliver(d *deliveryRun) error {
	pkgs, err := preparePackages(d.spec, d.fail)
	// Packages refused above are failures, not new.
	d.rep.New = slices.DeleteFunc(d.rep.New, func(id string) bool { return d.rep.Failures[id] != "" })
	if err != nil {
		return fmt.Errorf("build: %w", err)
	}
	if len(pkgs) == 0 {
		return nil
	}
	var total int64
	for _, p := range pkgs {
		total += p.size
	}
	if err := acquire.CheckDiskSpace(d.runDir, total); err != nil {
		return fmt.Errorf("build: %w", err)
	}
	// Agents parse manifests strictly: EXE packages (agents 0.9.0+) and the
	// app formats (archive, portable, MSIX, per-user; agents 0.10.0+)
	// travel in bundles of their own, so an older agent never meets a
	// bundle it would refuse.
	var gens [3][]pendingPkg
	for _, p := range pkgs {
		g := p.sp.FormatGeneration()
		gens[g] = append(gens[g], p)
	}
	var groups [][]pendingPkg
	for _, g := range gens {
		groups = append(groups, partition(g, d.c.MaxBundleBytes, d.c.MaxBundlePackages, d.fail)...)
	}
	d.rep.New = slices.DeleteFunc(d.rep.New, func(id string) bool { return d.rep.Failures[id] != "" })
	for i, g := range groups {
		if err := d.ctx.Err(); err != nil {
			return fmt.Errorf("stopped before bundle %d of %d (its packages are retried next run): %w", i+1, len(groups), err)
		}
		if err := d.one(g, i+1, len(groups)); err != nil {
			return err
		}
	}
	return nil
}

// one builds, sends and records a single bundle.
func (d *deliveryRun) one(g []pendingPkg, n, of int) error {
	spec := make([]specPackage, len(g))
	for i, p := range g {
		spec[i] = p.sp
	}
	tmpOut := filepath.Join(d.runDir, fmt.Sprintf("bundle-%d.pmb", n))
	br, err := buildFromSpec(buildOpts{Key: d.c.Key, Pub: d.c.Pub, Out: tmpOut, Source: d.c.Source, State: d.c.SequenceState, TTL: d.c.TTL.Duration}, spec, d.runDir)
	if err != nil {
		return fmt.Errorf("build (bundle %d of %d): %w", n, of, err)
	}
	// Name the file after the unique bundle ID (sequence-based) so it never
	// collides with an earlier bundle still waiting in the transfer path.
	out := filepath.Join(d.runDir, br.BundleID+".pmb")
	if err := os.Rename(tmpOut, out); err != nil {
		return err
	}
	so := d.c.Send
	so.Key, so.Pub = d.c.Key, d.c.Pub
	if _, err := sendBundle(so, out); err != nil {
		var pd *postDeliveryError
		if !errors.As(err, &pd) {
			return fmt.Errorf("send %s (its packages are retried next run): %w", br.BundleID, err)
		}
		// The bundle is across; only the receipt/log failed.
		d.rep.Warnings = append(d.rep.Warnings, br.BundleID+": "+err.Error())
	}
	d.rep.Sent = true
	d.rep.Bundle = out
	d.rep.Bundles = append(d.rep.Bundles, br.BundleID)
	d.rep.BundleID = strings.Join(d.rep.Bundles, ", ")
	now := autoNow().UTC().Format(time.RFC3339)
	for _, p := range g {
		id := p.sp.PackageID
		d.st.Done[id] = autoDone{SHA256: br.PackageSHA256[id], BundleID: br.BundleID, SentAt: now, File: br.PackageFile[id]}
		delete(d.st.Failed, id)
	}
	// Record it now: a crash or kill later in the run must not resend it.
	if err := saveJSON(d.statePath, d.st); err != nil {
		d.rep.Warnings = append(d.rep.Warnings, fmt.Sprintf("state not saved after %s: %v", br.BundleID, err))
	}
	return nil
}

// preparePackages reads the run's spec and checks every package on its own:
// payload present, Authenticode status (on Windows hosts) not invalid, and
// the manifest schema. Offenders are reported through fail and left out.
func preparePackages(specPath string, fail func(id string, err error)) ([]pendingPkg, error) {
	b, err := os.ReadFile(specPath)
	if err != nil {
		return nil, err
	}
	var spec []specPackage
	if err := json.Unmarshal(b, &spec); err != nil {
		return nil, fmt.Errorf("spec: %w", err)
	}
	dir := filepath.Dir(specPath)
	var out []pendingPkg
	for _, sp := range spec {
		id := sp.PackageID
		if !filepath.IsAbs(sp.Path) {
			sp.Path = filepath.Join(dir, filepath.FromSlash(sp.Path))
		}
		fi, err := os.Stat(sp.Path)
		if err != nil {
			fail(id, fmt.Errorf("payload: %w", err))
			continue
		}
		if vs, handled, err := checkPayload(sp.Package, sp.Path); handled {
			if err != nil {
				fail(id, fmt.Errorf("left out of the bundle: %w", err))
				continue
			}
			sp.VendorSignature = vs
		} else if sp.VendorSignature.Status == "" {
			sp.VendorSignature = signatureFor(sp.Kind, sp.Path)
		}
		if sp.VendorSignature.Status == "invalid" {
			fail(id, fmt.Errorf("vendor signature of %s is not valid (signer %q); the isolated server would refuse the whole bundle, so it is left out and retried next run",
				filepath.Base(sp.Path), sp.VendorSignature.Signer))
			continue
		}
		if err := validatePackage(sp, fi.Size()); err != nil {
			fail(id, err)
			continue
		}
		out = append(out, pendingPkg{sp: sp, size: fi.Size()})
	}
	return out, nil
}

// validatePackage runs the manifest schema on one package (the payload hash
// is computed at build time; a placeholder stands in for it here).
func validatePackage(sp specPackage, size int64) error {
	p := sp.Package
	p.File = manifest.FileRef{Name: "payload/" + filepath.Base(sp.Path), Size: size, SHA256: strings.Repeat("0", 64)}
	if p.Supersedes == nil {
		p.Supersedes = []string{}
	}
	now := time.Now().UTC()
	m := manifest.Manifest{SchemaVersion: manifest.SchemaVersion, BundleID: "check", Source: "check", Sequence: 1,
		KeyID: "ed25519:0000000000000000", CreatedAt: now, ExpiresAt: now.Add(time.Hour), Packages: []manifest.Package{p}}
	if err := m.ValidateSchema(now); err != nil {
		return fmt.Errorf("left out of the bundle: %w", err)
	}
	return nil
}

// manifestBudget keeps a bundle's manifest well below the 16 MiB intake
// limit: archive packages list every file (about perArchiveFile bytes each).
const (
	manifestBudget = 12 << 20
	perArchiveFile = 256
)

// manifestCost estimates a package's share of the manifest.
func manifestCost(p pendingPkg) int64 {
	n := int64(perPackageOverhead)
	if p.sp.Archive != nil {
		n += int64(len(p.sp.Archive.Files)) * perArchiveFile
	}
	return n
}

// partition splits pkgs, in spec order (checkpoint prerequisites precede
// the updates that need them), into bundles of at most maxPkgs packages,
// maxBytes bytes and manifestBudget bytes of manifest. A package that
// cannot fit any bundle is a failure.
func partition(pkgs []pendingPkg, maxBytes int64, maxPkgs int, fail func(id string, err error)) [][]pendingPkg {
	var out [][]pendingPkg
	var cur []pendingPkg
	var curBytes int64 = perBundleOverhead
	var curManifest int64
	for _, p := range pkgs {
		need := p.size + perPackageOverhead
		if perBundleOverhead+need > maxBytes {
			fail(p.sp.PackageID, fmt.Errorf("payload is %d bytes, more than one bundle may carry (max_bundle_bytes %d)", p.size, maxBytes))
			continue
		}
		mc := manifestCost(p)
		if len(cur) > 0 && (len(cur) >= maxPkgs || curBytes+need > maxBytes || curManifest+mc > manifestBudget) {
			out = append(out, cur)
			cur, curBytes, curManifest = nil, perBundleOverhead, 0
		}
		cur = append(cur, p)
		curBytes += need
		curManifest += mc
	}
	if len(cur) > 0 {
		out = append(out, cur)
	}
	return out
}

// specFiles returns the payload base names a spec refers to.
func specFiles(specPath string) map[string]bool {
	out := map[string]bool{}
	b, err := os.ReadFile(specPath)
	if err != nil {
		return out
	}
	var spec []specPackage
	if json.Unmarshal(b, &spec) != nil {
		return out
	}
	for _, sp := range spec {
		out[filepath.Base(filepath.FromSlash(sp.Path))] = true
	}
	return out
}
