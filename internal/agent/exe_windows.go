//go:build windows

package agent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"offpatch/internal/manifest"
)

// exeTmpMaxAge: run folders left behind (agent killed mid-install) are
// removed at the next EXE install.
const exeTmpMaxAge = 24 * time.Hour

// installExe runs a signed vendor EXE installer: the payload (already
// SHA-256 verified by the agent) is copied into a private run folder,
// re-hashed, its Authenticode signature and signer checked, then run with
// the manifest's argv, no shell, %TEMP% pointing at the run folder.
func (w *Windows) installExe(ctx context.Context, p manifest.Package, file string) Result {
	args, err := exeArgs(p.Exe)
	if err != nil {
		return Result{State: "failed", ExitCode: -1, Detail: "exe package refused: " + err.Error()}
	}
	dir, err := w.exeRunDir(p.PackageID)
	if err != nil {
		return Result{State: "failed", ExitCode: -1, Detail: "could not prepare a private folder for the installer: " + err.Error()}
	}
	defer os.RemoveAll(dir)
	exe := filepath.Join(dir, winBase(strings.TrimPrefix(p.File.Name, "payload/")))
	if err := copyFile(file, exe); err != nil {
		return Result{State: "failed", ExitCode: -1, Detail: "could not stage the installer: " + err.Error()}
	}
	// The copy is what runs: hash it again so nothing can swap the file
	// between the agent's check and the installer start.
	if n, h, err := manifest.HashFile(exe); err != nil || n != p.File.Size || h != p.File.SHA256 {
		return Result{State: "failed", ExitCode: -1, Detail: "staged installer does not match signed manifest (sha256) — possible tampering"}
	}
	if err := signatureCheck(exe, p.Exe.Signer, winVerifyTrust); err != nil {
		return sigFailure(err)
	}
	code, res := runInstallerCmd(ctx, filepath.Base(exe), func(ctx context.Context) *exec.Cmd {
		return exeCommand(ctx, exe, buildCmdLine(exe, args), dir)
	})
	if res != nil {
		return withBurnLog(*res, p.Exe, dir)
	}
	return withBurnLog(classifyExe(p.Exe, code, false), p.Exe, dir)
}

// uninstallExe rolls an EXE package back with the app's own
// QuietUninstallString from Apps & features, only when the manifest says
// the app registers one.
func (w *Windows) uninstallExe(ctx context.Context, p manifest.Package) Result {
	if !p.RollbackSupported() {
		return Result{State: "failed", ExitCode: -1, Detail: exeRollbackUnsupported}
	}
	entries, err := machineARPEntries()
	if err != nil {
		return Result{State: "failed", ExitCode: -1, Detail: "read Apps & features: " + err.Error()}
	}
	e, ok := chooseARPEntry(p, entries)
	if !ok {
		return Result{State: "installed", Detail: "not installed; nothing to remove"}
	}
	if e.QuietUninstall == "" {
		return Result{State: "failed", ExitCode: -1, Detail: exeRollbackUnsupported + ": " + e.DisplayName + " registers no QuietUninstallString"}
	}
	sys := filepath.Join(os.Getenv("SystemRoot"), "System32")
	exe, _, err := quietUninstall(e.QuietUninstall, sys)
	if err != nil {
		return Result{State: "failed", ExitCode: -1, Detail: "rollback refused: " + err.Error()}
	}
	if fi, err := os.Stat(exe); err != nil || fi.IsDir() {
		return Result{State: "failed", ExitCode: -1, Detail: "rollback refused: uninstaller " + exe + " not found"}
	}
	dir, err := w.exeRunDir(p.PackageID + "-uninstall")
	if err != nil {
		return Result{State: "failed", ExitCode: -1, Detail: "could not prepare a private folder for the uninstaller: " + err.Error()}
	}
	defer os.RemoveAll(dir)
	// The registered command line is passed unchanged; the program is bound
	// as the application name, so CreateProcess never searches for it.
	code, res := runInstallerCmd(ctx, filepath.Base(exe), func(ctx context.Context) *exec.Cmd {
		return exeCommand(ctx, exe, strings.TrimSpace(e.QuietUninstall), dir)
	})
	if res != nil {
		return *res
	}
	if isMsiexec(exe) {
		return classifyUninstall("msi", code)
	}
	return withBurnLog(classifyExe(p.Exe, code, true), p.Exe, dir)
}

// exeCommand: exe as the application name, cmdline verbatim, working
// directory and %TEMP%/%TMP% in the private run folder, no console window.
func exeCommand(ctx context.Context, exe, cmdline, dir string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, exe)
	cmd.Dir = dir
	cmd.Env = withTempDir(os.Environ(), dir)
	cmd.SysProcAttr = &syscall.SysProcAttr{CmdLine: cmdline, HideWindow: true}
	return cmd
}

func withTempDir(env []string, dir string) []string {
	out := make([]string, 0, len(env)+2)
	for _, kv := range env {
		k, _, _ := strings.Cut(kv, "=")
		if strings.EqualFold(k, "TEMP") || strings.EqualFold(k, "TMP") {
			continue
		}
		out = append(out, kv)
	}
	return append(out, "TEMP="+dir, "TMP="+dir)
}

// exeRunDir creates a fresh folder only SYSTEM and Administrators can use,
// under the (already locked) agent state directory.
func (w *Windows) exeRunDir(id string) (string, error) {
	base := filepath.Join(os.Getenv("SystemRoot"), "Temp")
	if w.LogDir != "" {
		base = filepath.Join(filepath.Dir(w.LogDir), "exetmp")
	}
	if err := os.MkdirAll(base, 0o700); err != nil {
		return "", err
	}
	pruneRunDirs(base, time.Now())
	dir, err := os.MkdirTemp(base, sanitizeRunName(id)+"-")
	if err != nil {
		return "", err
	}
	self, err := processUserSID()
	if err == nil {
		err = lockDir(dir, self, false)
	}
	if err != nil {
		os.RemoveAll(dir)
		return "", err
	}
	return dir, nil
}

func sanitizeRunName(id string) string {
	b := []byte(id)
	for i, c := range b {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
			b[i] = '_'
		}
	}
	if len(b) > 40 {
		b = b[:40]
	}
	return string(b)
}

func pruneRunDirs(base string, now time.Time) {
	ents, err := os.ReadDir(base)
	if err != nil {
		return
	}
	for _, e := range ents {
		if fi, err := e.Info(); err == nil && e.IsDir() && now.Sub(fi.ModTime()) > exeTmpMaxAge {
			os.RemoveAll(filepath.Join(base, e.Name()))
		}
	}
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// winVerifyTrust checks the file's embedded Authenticode signature with the
// generic verify policy. Endpoints are offline: no revocation checks and no
// network retrieval (cached URLs only), so only locally trusted roots count.
func winVerifyTrust(path string) error {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	fi := &windows.WinTrustFileInfo{Size: uint32(unsafe.Sizeof(windows.WinTrustFileInfo{})), FilePath: p}
	data := &windows.WinTrustData{
		Size:                            uint32(unsafe.Sizeof(windows.WinTrustData{})),
		UIChoice:                        windows.WTD_UI_NONE,
		RevocationChecks:                windows.WTD_REVOKE_NONE,
		UnionChoice:                     windows.WTD_CHOICE_FILE,
		StateAction:                     windows.WTD_STATEACTION_VERIFY,
		FileOrCatalogOrBlobOrSgnrOrCert: unsafe.Pointer(fi),
		ProvFlags:                       windows.WTD_REVOCATION_CHECK_NONE | windows.WTD_CACHE_ONLY_URL_RETRIEVAL,
	}
	verr := windows.WinVerifyTrustEx(windows.InvalidHWND, &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, data)
	data.StateAction = windows.WTD_STATEACTION_CLOSE
	windows.WinVerifyTrustEx(windows.InvalidHWND, &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, data)
	return trustError(verr)
}

func trustError(err error) error {
	if err == nil {
		return nil
	}
	var en syscall.Errno
	if !errors.As(err, &en) {
		return fmt.Errorf("WinVerifyTrust: %w", err)
	}
	why := map[windows.Handle]string{
		windows.TRUST_E_NOSIGNATURE:         "the file has no embedded Authenticode signature",
		windows.TRUST_E_BAD_DIGEST:          "the file was modified after it was signed",
		windows.CERT_E_UNTRUSTEDROOT:        "the signing certificate chains to a root this computer does not trust",
		windows.CERT_E_CHAINING:             "the signing certificate chain could not be built",
		windows.CERT_E_EXPIRED:              "the signing certificate has expired (and the signature has no valid timestamp)",
		windows.CERT_E_REVOKED:              "the signing certificate is revoked",
		windows.TRUST_E_EXPLICIT_DISTRUST:   "the signing certificate is explicitly distrusted",
		windows.TRUST_E_SUBJECT_NOT_TRUSTED: "the signature is not trusted",
		windows.TRUST_E_MALFORMED_SIGNATURE: "the signature is malformed",
	}[windows.Handle(en)]
	if why == "" {
		return fmt.Errorf("WinVerifyTrust: %v (0x%08X)", err, uint32(en))
	}
	return fmt.Errorf("%s (0x%08X)", why, uint32(en))
}

// machineARPEntries lists the per-machine Apps & features entries (64- and
// 32-bit views) with what rollback needs.
func machineARPEntries() ([]arpEntry, error) {
	var out []arpEntry
	for _, path := range uninstallKeys {
		k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.ENUMERATE_SUB_KEYS|registry.WOW64_64KEY)
		if errors.Is(err, registry.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("open %s: %w", path, err)
		}
		names, err := k.ReadSubKeyNames(-1)
		k.Close()
		if err != nil {
			return nil, fmt.Errorf("enumerate %s: %w", path, err)
		}
		for _, n := range names {
			sk, err := registry.OpenKey(registry.LOCAL_MACHINE, path+`\`+n, registry.QUERY_VALUE|registry.WOW64_64KEY)
			if err != nil {
				continue
			}
			e := arpEntry{Key: n}
			e.DisplayName, _, _ = sk.GetStringValue("DisplayName")
			e.DisplayVersion, _, _ = sk.GetStringValue("DisplayVersion")
			if q, typ, err := sk.GetStringValue("QuietUninstallString"); err == nil {
				if typ == registry.EXPAND_SZ {
					if x, err := registry.ExpandString(q); err == nil {
						q = x
					}
				}
				e.QuietUninstall = q
			}
			sk.Close()
			out = append(out, e)
		}
	}
	return out, nil
}
