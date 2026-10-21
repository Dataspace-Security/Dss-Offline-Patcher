//go:build windows

package agent

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"offpatch/internal/manifest"
	"offpatch/internal/store"
)

// Per-user installers (kind exe, exe.scope user; agents 0.10.0+). Run as
// SYSTEM, such an installer would install into the SYSTEM profile; the
// agent instead runs it in each signed-in user's session, with that user's
// token (WTSQueryUserToken + CreateProcessAsUser), hidden, with the
// manifest's silent arguments. The installer is staged in a private run
// folder, re-hashed and its signature checked before the user is given read
// access to it (and nothing more), so the user cannot change what runs.
// After each run the user's own Apps & features entry (HKU\<SID>) must show
// the version. Users who are not signed in are not reached: the target
// stays deferred ("waiting for the user to sign in") while nobody is, and
// the server's verification sees each user's entry once they sign in.

// userSession is one signed-in user (the first session of each).
type userSession struct {
	sid   *windows.SID
	sidS  string
	name  string
	token windows.Token
}

// signedInSessions lists the users with an active or disconnected session
// (both have a user token), one session per user. The caller closes the
// tokens.
func signedInSessions() ([]userSession, error) {
	var info *windows.WTS_SESSION_INFO
	var n uint32
	if err := windows.WTSEnumerateSessions(0, 0, 1, &info, &n); err != nil {
		return nil, fmt.Errorf("WTSEnumerateSessions: %w", err)
	}
	defer windows.WTSFreeMemory(uintptr(unsafe.Pointer(info)))
	var out []userSession
	seen := map[string]bool{}
	for _, s := range unsafe.Slice(info, n) {
		if s.State != windows.WTSActive && s.State != windows.WTSDisconnected {
			continue
		}
		var tok windows.Token
		if err := windows.WTSQueryUserToken(s.SessionID, &tok); err != nil {
			continue // no user in this session (services, the login screen)
		}
		tu, err := tok.GetTokenUser()
		if err != nil {
			tok.Close()
			continue
		}
		sid, err := tu.User.Sid.Copy()
		if err != nil || seen[sid.String()] {
			tok.Close()
			continue
		}
		seen[sid.String()] = true
		name := sid.String()
		if acct, dom, _, err := sid.LookupAccount(""); err == nil {
			name = dom + `\` + acct
		}
		out = append(out, userSession{sid: sid, sidS: sid.String(), name: name, token: tok})
	}
	return out, nil
}

// SignedInUsers is the number of users a per-user installer can reach now.
func (w *Windows) SignedInUsers() (int, error) {
	ss, err := signedInSessions()
	for _, s := range ss {
		s.token.Close()
	}
	return len(ss), err
}

func (w *Windows) installPerUser(ctx context.Context, p manifest.Package, file string) Result {
	args, err := exeArgs(p.Exe)
	if err != nil {
		return Result{State: "failed", ExitCode: -1, Detail: "exe package refused: " + err.Error()}
	}
	sessions, err := signedInSessions()
	defer func() {
		for _, s := range sessions {
			s.token.Close()
		}
	}()
	if err != nil {
		return Result{State: "failed", ExitCode: -1, Detail: "could not list signed-in users: " + err.Error()}
	}
	if len(sessions) == 0 {
		return aggregateUserRuns(nil)
	}
	dir, err := w.exeRunDir(p.PackageID + "-user")
	if err != nil {
		return Result{State: "failed", ExitCode: -1, Detail: "could not prepare a private folder for the installer: " + err.Error()}
	}
	defer os.RemoveAll(dir)
	exe := filepath.Join(dir, winBase(strings.TrimPrefix(p.File.Name, "payload/")))
	if err := copyFile(file, exe); err != nil {
		return Result{State: "failed", ExitCode: -1, Detail: "could not stage the installer: " + err.Error()}
	}
	if n, h, err := manifest.HashFile(exe); err != nil || n != p.File.Size || h != p.File.SHA256 {
		return Result{State: "failed", ExitCode: -1, Detail: "staged installer does not match signed manifest (sha256)" + sigTampering}
	}
	if err := signatureCheck(exe, p.Exe.Signer, winVerifyTrust); err != nil {
		return sigFailure(err)
	}
	var runs []userRun
	for _, s := range sessions {
		if userHasVersion(p, userUninstallItems(s.sidS)) {
			runs = append(runs, userRun{User: s.name, Skipped: true})
			continue
		}
		// Only this user may read (and run) the staged installer.
		if err := lockDirReader(dir, s.sid); err != nil {
			runs = append(runs, userRun{User: s.name, Result: Result{State: "failed", ExitCode: -1, Detail: "could not give the user access to the installer: " + err.Error()}})
			continue
		}
		code, res := runAsUser(s.token, exe, buildCmdLine(exe, args), dir)
		r := classifyExe(p.Exe, code, false)
		if res != nil {
			r = *res
		}
		if (r.State == "installed" || r.State == "pending_reboot") && !userHasVersion(p, userUninstallItems(s.sidS)) {
			r = Result{State: "failed", ExitCode: code, Detail: fmt.Sprintf("the installer finished (exit code %d) but the user's Apps & features shows no %s %s", code, p.Exe.Detect.DisplayName, exeWantVersion(p))}
		}
		runs = append(runs, userRun{User: s.name, Result: r})
	}
	return aggregateUserRuns(runs)
}

// userUninstallItems is the user's own Apps & features (their loaded hive).
func userUninstallItems(sid string) []store.InventoryItem {
	items, _ := scanUninstall(registry.USERS, sid+`\`+userUninstallKey, 0)
	return items
}

// lockDirReader sets dir's permissions to SYSTEM and Administrators (full
// control) plus read and execute for user, inherited by the files in it.
func lockDirReader(dir string, user *windows.SID) error {
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return err
	}
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return err
	}
	ace := func(s *windows.SID, mask windows.ACCESS_MASK) windows.EXPLICIT_ACCESS {
		return windows.EXPLICIT_ACCESS{AccessPermissions: mask, AccessMode: windows.SET_ACCESS, Inheritance: windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT,
			Trustee: windows.TRUSTEE{TrusteeForm: windows.TRUSTEE_IS_SID, TrusteeType: windows.TRUSTEE_IS_UNKNOWN, TrusteeValue: windows.TrusteeValueFromSID(s)}}
	}
	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{ace(system, windows.GENERIC_ALL), ace(admins, windows.GENERIC_ALL),
		ace(user, windows.GENERIC_READ|windows.GENERIC_EXECUTE)}, nil)
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil)
}

// runAsUser runs exe with cmdline as the token's user on their desktop,
// hidden, with their environment, and waits up to installTimeout. Like the
// other installers it is not stopped when the agent stops.
func runAsUser(tok windows.Token, exe, cmdline, dir string) (int, *Result) {
	var env *uint16
	if err := windows.CreateEnvironmentBlock(&env, tok, false); err != nil {
		return -1, &Result{State: "failed", ExitCode: -1, Detail: "could not build the user's environment: " + err.Error()}
	}
	defer windows.DestroyEnvironmentBlock(env)
	app, err1 := windows.UTF16PtrFromString(exe)
	cl, err2 := windows.UTF16PtrFromString(cmdline)
	cwd, err3 := windows.UTF16PtrFromString(dir)
	desk, err4 := windows.UTF16PtrFromString(`winsta0\default`)
	if err := errors.Join(err1, err2, err3, err4); err != nil {
		return -1, &Result{State: "failed", ExitCode: -1, Detail: "invalid installer path: " + err.Error()}
	}
	si := windows.StartupInfo{Desktop: desk, Flags: windows.STARTF_USESHOWWINDOW, ShowWindow: windows.SW_HIDE}
	si.Cb = uint32(unsafe.Sizeof(si))
	var pi windows.ProcessInformation
	err := windows.CreateProcessAsUser(tok, app, cl, nil, nil, false, windows.CREATE_UNICODE_ENVIRONMENT|windows.CREATE_NO_WINDOW, env, cwd, &si, &pi)
	if errors.Is(err, windows.ERROR_ELEVATION_REQUIRED) {
		return -1, &Result{State: "failed", ExitCode: -1, Detail: "the installer asks for administrator rights: it is not a per-user installer"}
	}
	if err != nil {
		return -1, &Result{State: "failed", ExitCode: -1, Detail: "could not start " + filepath.Base(exe) + " for the user: " + err.Error()}
	}
	defer windows.CloseHandle(pi.Process)
	defer windows.CloseHandle(pi.Thread)
	ev, err := windows.WaitForSingleObject(pi.Process, uint32(installTimeout/time.Millisecond))
	if err != nil || ev == uint32(windows.WAIT_TIMEOUT) {
		windows.TerminateProcess(pi.Process, 1)
		return -1, &Result{State: "failed", ExitCode: -1, Detail: fmt.Sprintf("timed out: %s still running after %s; it was stopped", filepath.Base(exe), installTimeout)}
	}
	var code uint32
	if err := windows.GetExitCodeProcess(pi.Process, &code); err != nil {
		return -1, &Result{State: "failed", ExitCode: -1, Detail: "could not read the installer's exit code: " + err.Error()}
	}
	return int(code), nil
}
