package main

// Authenticode for EXE installers (kind exe): verified in pure Go on every
// acquisition host (internal/acquire/authenticode), at fetch time and again
// when the bundle is built. The verified signer's CommonName is recorded in
// the manifest (exe.signer and vendor_signature.signer); the agent checks
// the signature again before it runs the installer.

import (
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
	"time"

	peauth "offpatch/internal/acquire/authenticode"
	"offpatch/internal/manifest"
)

// exeTrust is configured from acquire.json (authenticode_roots,
// exe_signers); the zero value uses the system roots plus the shipped
// code-signing roots and accepts any verified signer.
var exeTrust struct {
	roots   *x509.CertPool
	signers []string
}

// setExeTrust applies acquire.json's EXE settings.
func setExeTrust(rootsPEM string, signers []string) error {
	exeTrust.roots, exeTrust.signers = nil, nil
	if rootsPEM != "" {
		p, err := peauth.RootsWithPEM(rootsPEM)
		if err != nil {
			return fmt.Errorf("authenticode_roots: %w", err)
		}
		exeTrust.roots = p
	}
	for _, s := range signers {
		if s = strings.TrimSpace(s); s != "" {
			exeTrust.signers = append(exeTrust.signers, s)
		}
	}
	return nil
}

// exeVerify verifies a PE file's Authenticode signature; a hook for tests
// with synthetic payloads.
var exeVerify = func(path string) (*peauth.Result, error) {
	return peauth.VerifyFile(path, peauth.Options{Roots: exeTrust.roots})
}

// errExeSignature marks a payload whose signature is missing, invalid or
// from a signer outside exe_signers: retrying will not help.
var errExeSignature = errors.New("Authenticode")

// verifyExeSigner returns the verified signer CommonName of an EXE installer.
func verifyExeSigner(path string) (string, error) {
	res, err := verifyExeResult(path)
	if err != nil {
		return "", err
	}
	return res.Signer, nil
}

// verifyExeResult verifies an EXE installer and applies exe_signers: each
// entry is an exact CN ("Google LLC") or a subject DN whose CN and O must
// both match ("CN=Google LLC, O=Google LLC"); never a substring.
func verifyExeResult(path string) (*peauth.Result, error) {
	res, err := exeVerify(path)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errExeSignature, err)
	}
	if len(exeTrust.signers) > 0 {
		got := signerName{CN: res.Signer, O: res.Organization}
		ok := false
		for _, s := range exeTrust.signers {
			ok = ok || parseSignerSpec(s).matches(got)
		}
		if !ok {
			return nil, fmt.Errorf("%w: signer %q is not one of exe_signers %q", errExeSignature, res.Signer, exeTrust.signers)
		}
	}
	return res, nil
}

// checkExeSignature: an EXE package goes into a bundle only with a valid
// signature from exactly the signer its manifest names.
func checkExeSignature(p manifest.Package, path string) (manifest.VendorSignature, error) {
	signer, err := verifyExeSigner(path)
	if err != nil {
		return manifest.VendorSignature{}, err
	}
	if p.Exe == nil || !strings.EqualFold(p.Exe.Signer, signer) {
		want := ""
		if p.Exe != nil {
			want = p.Exe.Signer
		}
		return manifest.VendorSignature{}, fmt.Errorf("%w: payload signed by %q, manifest names %q", errExeSignature, signer, want)
	}
	// Keep the details recorded at fetch time (O, winget publisher, pin,
	// revocation; signerpin.go) when they describe this signer.
	detail := signer
	if d := p.VendorSignature.Signer; strings.HasPrefix(d, signer+" (") {
		detail = d
	}
	return manifest.VendorSignature{Status: "valid", Signer: detail, CheckedAt: time.Now().UTC().Format(time.RFC3339)}, nil
}
