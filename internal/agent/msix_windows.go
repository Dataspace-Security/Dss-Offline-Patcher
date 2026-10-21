//go:build windows

package agent

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"offpatch/internal/manifest"
)

// installMsix provisions an MSIX/APPX package (or bundle) for every user
// of the machine (agents 0.10.0+): the payload (already SHA-256 verified)
// is copied into a private run folder and re-hashed, its signature must be
// Valid (Get-AuthenticodeSignature; Windows also refuses an untrusted
// package itself) and by msix.signer when the manifest names one, else by
// the manifest's msix.publisher (msixSignature), then
// Add-AppxProvisionedPackage -Online -SkipLicense provisions it. Users get
// the new version at their next sign-in; signed-in users keep running the
// old one until then (Add-AppxPackage per user is not used).
func (w *Windows) installMsix(ctx context.Context, p manifest.Package, file string) Result {
	if p.Msix == nil {
		return Result{State: "failed", ExitCode: -1, Detail: "msix package without an msix block"}
	}
	dir, err := w.exeRunDir(p.PackageID)
	if err != nil {
		return Result{State: "failed", ExitCode: -1, Detail: "could not prepare a private folder for the package: " + err.Error()}
	}
	defer os.RemoveAll(dir)
	pkg := filepath.Join(dir, "package"+strings.ToLower(filepath.Ext(p.File.Name)))
	if err := copyFile(file, pkg); err != nil {
		return Result{State: "failed", ExitCode: -1, Detail: "could not stage the package: " + err.Error()}
	}
	if n, h, err := manifest.HashFile(pkg); err != nil || n != p.File.Size || h != p.File.SHA256 {
		return Result{State: "failed", ExitCode: -1, Detail: "staged package does not match signed manifest (sha256)" + sigTampering}
	}
	sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), installTimeout)
	defer cancel()
	out, err := powershellEnv(sctx, msixSigScript, "PM_PKG="+pkg)
	if err == nil {
		err = msixSignature(out, p.Msix.Signer, p.Msix.Publisher)
	}
	if err != nil {
		return sigFailure(err)
	}
	out, err = powershellEnv(sctx, msixProvisionScript, "PM_PKG="+pkg)
	if errors.Is(sctx.Err(), context.DeadlineExceeded) {
		return Result{State: "failed", ExitCode: -1, Detail: fmt.Sprintf("timed out: Add-AppxProvisionedPackage still running after %s", installTimeout)}
	}
	return classifyMsix(out, err)
}

// powershellEnv is powershell with extra environment variables (values the
// script reads as $env:NAME, never interpolated into its text).
func powershellEnv(ctx context.Context, script string, env ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, filepath.Join(os.Getenv("SystemRoot"), `System32\WindowsPowerShell\v1.0\powershell.exe`),
		"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", psPrelude+script)
	cmd.Env = append(os.Environ(), env...)
	out, err := cmd.Output()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return out, fmt.Errorf("powershell: %v: %s", err, strings.TrimSpace(string(ee.Stderr)))
		}
		return out, err
	}
	return out, nil
}
