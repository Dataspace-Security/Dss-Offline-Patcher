//go:build windows

package agent

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

// SecureStateDir prepares the state directory (device key, certificate,
// agent.json, downloaded installers). The agent runs as SYSTEM, so a folder
// that a standard user created first (anyone may create folders under
// %ProgramData%) or a junction pointing elsewhere must never be trusted:
// it is refused with a clear reason. A trusted folder gets a protected DACL
// (SYSTEM and Administrators full control, inherited by everything inside),
// the same result as Secure-Dir in the bootstrap script.
func SecureStateDir(dir string) error {
	created := false
	if _, err := os.Lstat(dir); errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
		created = true
	} else if err != nil {
		return err
	}
	p, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return err
	}
	attrs, err := windows.GetFileAttributes(p)
	if err != nil {
		return fmt.Errorf("state dir %s: %w", dir, err)
	}
	if attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return fmt.Errorf("refusing state dir %s: it is a junction or symbolic link; remove it and run the installer again", dir)
	}
	if attrs&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
		return fmt.Errorf("refusing state dir %s: not a directory", dir)
	}
	sd, err := windows.GetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("state dir %s: read owner: %w", dir, err)
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return fmt.Errorf("state dir %s: read owner: %w", dir, err)
	}
	self, err := processUserSID()
	if err != nil {
		return err
	}
	if !trustedOwner(owner, self) {
		return fmt.Errorf("refusing state dir %s: owned by %s, not SYSTEM or Administrators (someone else created it first); "+
			"move it aside and run the installer again", dir, sidName(owner))
	}
	return lockDir(dir, self, created || owner.Equals(self))
}

// trustedOwner: SYSTEM, Administrators, or the account the agent runs as
// (an administrator's elevated `pmagent enroll`, or a developer's own run).
func trustedOwner(owner, self *windows.SID) bool {
	return owner != nil && (owner.IsWellKnown(windows.WinLocalSystemSid) ||
		owner.IsWellKnown(windows.WinBuiltinAdministratorsSid) || (self != nil && owner.Equals(self)))
}

func processUserSID() (*windows.SID, error) {
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, fmt.Errorf("current process user: %w", err)
	}
	return u.User.Sid.Copy()
}

func sidName(s *windows.SID) string {
	if acct, dom, _, err := s.LookupAccount(""); err == nil {
		if dom != "" {
			return dom + `\` + acct + " (" + s.String() + ")"
		}
		return acct + " (" + s.String() + ")"
	}
	return s.String()
}

// lockDir applies a protected DACL: SYSTEM + Administrators full control,
// inherited by files and subfolders. When the agent is not SYSTEM (an
// administrator enrolling by hand, tests) its own account keeps access too;
// the service re-applies the DACL without it at start. With takeOwner, an
// elevated caller also hands ownership to Administrators so the SYSTEM
// service accepts a folder an administrator created; that is best effort
// (a standard user cannot assign that owner).
func lockDir(dir string, self *windows.SID, takeOwner bool) error {
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return err
	}
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return err
	}
	sids := []*windows.SID{system, admins}
	if !self.Equals(system) {
		sids = append(sids, self)
	}
	var ea []windows.EXPLICIT_ACCESS
	for _, s := range sids {
		ea = append(ea, windows.EXPLICIT_ACCESS{
			AccessPermissions: windows.GENERIC_ALL,
			AccessMode:        windows.SET_ACCESS,
			Inheritance:       windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeType:  windows.TRUSTEE_IS_UNKNOWN,
				TrusteeValue: windows.TrusteeValueFromSID(s),
			},
		})
	}
	acl, err := windows.ACLFromEntries(ea, nil)
	if err != nil {
		return fmt.Errorf("state dir %s: build ACL: %w", dir, err)
	}
	if err := windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
		return fmt.Errorf("state dir %s: apply ACL: %w", dir, err)
	}
	if takeOwner && !self.Equals(system) && !self.Equals(admins) {
		_ = windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION, admins, nil, nil, nil)
	}
	return nil
}
