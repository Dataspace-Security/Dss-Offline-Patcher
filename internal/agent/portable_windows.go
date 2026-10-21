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
)

// Portable apps (kind portable, agents 0.10.0+): the verified files are
// copied to %ProgramFiles%\DSS Patcher Apps\<folder> (Users may read and
// run them, only Administrators and SYSTEM change them: the Program Files
// permissions), and an Apps & features entry is written under
// HKLM\...\Uninstall\<portable.arp_key> so inventory, verification and the
// console see the version. The entry's UninstallString runs
// "pmagent.exe" portable-remove "<key>", which removes exactly what the
// agent wrote. A Start-menu shortcut (all users) points at the program
// when the manifest names one. Nothing from the package is ever run.

// portableMarker marks Uninstall keys written by the agent; only those are
// ever removed.
const (
	portableMarker      = "DSSPatcherPortable"
	portableFolderValue = "DSSPatcherFolder"
	portableLinkValue   = "DSSPatcherShortcut"
)

func portableParent() (string, error) {
	pf, err := windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, 0)
	if err != nil {
		return "", fmt.Errorf("Program Files folder: %w", err)
	}
	return filepath.Join(pf, manifest.PortableParent), nil
}

func (w *Windows) installPortable(ctx context.Context, p manifest.Package, file string) Result {
	parent, err := portableParent()
	if err != nil {
		return Result{State: "failed", ExitCode: -1, Detail: err.Error()}
	}
	env := portableEnv{parent: parent, running: processUnder,
		verify: func(path, signer string) error { return signatureCheck(path, signer, winVerifyTrust) }}
	dir, res := installPortableFiles(p, file, env)
	if res != nil {
		return *res
	}
	link := ""
	if p.Portable.Shortcut != "" {
		if l, err := portableShortcut(ctx, p, dir); err == nil {
			link = l
		}
	}
	if err := writePortableARP(registry.LOCAL_MACHINE, p, dir, link); err != nil {
		return Result{State: "failed", ExitCode: -1, Detail: "the app was copied to " + dir + " but its Apps & features entry could not be written: " + err.Error()}
	}
	return Result{State: "installed", Detail: "portable app copied to " + dir}
}

// writePortableARP writes the app's Apps & features entry (64-bit view)
// under root (HKLM; tests use HKCU). SystemComponent is not set: the entry
// is visible like any app. An existing entry the agent did not write (no
// portableMarker) belongs to some other installer and is never
// overwritten.
func writePortableARP(root registry.Key, p manifest.Package, dir, link string) error {
	po := p.Portable
	if !validARPKey(po.ARPKey) {
		return fmt.Errorf("invalid Apps & features key %q", po.ARPKey)
	}
	k, existed, err := registry.CreateKey(root, uninstallKeys[0]+`\`+po.ARPKey, registry.ALL_ACCESS|registry.WOW64_64KEY)
	if err != nil {
		return err
	}
	defer k.Close()
	if existed {
		if mark, _, err := k.GetIntegerValue(portableMarker); err != nil || mark != 1 {
			return fmt.Errorf("an Apps & features entry %s exists that the DSS Patcher agent did not write; not overwriting it", po.ARPKey)
		}
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	remove := portableRemoveCommand(self, po.ARPKey)
	for name, v := range map[string]string{"DisplayName": po.DisplayName, "DisplayVersion": formatWantVersion(p), "Publisher": po.Publisher,
		"InstallLocation": dir, "DisplayIcon": filepath.Join(dir, filepath.FromSlash(po.Command)), "UninstallString": remove,
		"QuietUninstallString": remove, portableFolderValue: po.Folder, portableLinkValue: link,
		"InstallDate": time.Now().Format("20060102"), "Comments": "Installed by DSS Patcher (portable app)"} {
		if v == "" {
			k.DeleteValue(name)
			continue
		}
		if err := k.SetStringValue(name, v); err != nil {
			return err
		}
	}
	for name, v := range map[string]uint32{"NoModify": 1, "NoRepair": 1, portableMarker: 1, "EstimatedSize": uint32(dirSize(dir) / 1024)} {
		if err := k.SetDWordValue(name, v); err != nil {
			return err
		}
	}
	return nil
}

// portableShortcut creates the all-users Start-menu shortcut to the main
// program (best effort). Paths travel in the environment, never in the
// script text.
func portableShortcut(ctx context.Context, p manifest.Package, dir string) (string, error) {
	progs, err := windows.KnownFolderPath(windows.FOLDERID_CommonPrograms, 0)
	if err != nil {
		return "", err
	}
	link := filepath.Join(progs, p.Portable.Shortcut+".lnk")
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	_, err = powershellEnv(ctx, `$s = (New-Object -ComObject WScript.Shell).CreateShortcut($env:PM_LNK); $s.TargetPath = $env:PM_TARGET; $s.WorkingDirectory = $env:PM_DIR; $s.Save()`,
		"PM_LNK="+link, "PM_TARGET="+filepath.Join(dir, filepath.FromSlash(p.Portable.Command)), "PM_DIR="+dir)
	return link, err
}

// uninstallPortable rolls a portable app back (its folder, shortcut and
// Apps & features entry).
func (w *Windows) uninstallPortable(p manifest.Package) Result {
	if p.Portable == nil {
		return Result{State: "failed", ExitCode: -1, Detail: "portable package without a portable block"}
	}
	removed, err := removePortable(p.Portable.ARPKey)
	switch {
	case errors.Is(err, errPortableRunning):
		return Result{State: "failed", ExitCode: -1, Detail: appRunning + ": " + err.Error() + ")"}
	case err != nil:
		return Result{State: "failed", ExitCode: -1, Detail: "rollback failed: " + err.Error()}
	case !removed:
		return Result{State: "installed", Detail: "not installed; nothing to remove"}
	}
	return Result{State: "installed", Detail: "portable app removed"}
}

var errPortableRunning = errors.New("a program of the app is running")

// RemovePortable removes a portable app the agent installed, by its Apps &
// features key (pmagent portable-remove, the entry's UninstallString).
func RemovePortable(key string) error {
	_, err := removePortable(key)
	return err
}

// removePortable removes the folder, shortcut and entry of a portable app
// the agent wrote (the marker value must be present; the folder must be
// %ProgramFiles%\DSS Patcher Apps\<its folder>). removed is false when there
// is no such entry.
func removePortable(key string) (removed bool, err error) {
	if !validARPKey(key) {
		return false, fmt.Errorf("invalid Apps & features key %q", key)
	}
	path := uninstallKeys[0] + `\` + key
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if errors.Is(err, registry.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	mark, _, merr := k.GetIntegerValue(portableMarker)
	folder, _, _ := k.GetStringValue(portableFolderValue)
	link, _, _ := k.GetStringValue(portableLinkValue)
	k.Close()
	if merr != nil || mark != 1 || !manifest.ValidFolderName(folder) {
		return false, fmt.Errorf("%s was not written by the DSS Patcher agent; not removing it", key)
	}
	parent, err := portableParent()
	if err != nil {
		return false, err
	}
	dir := filepath.Join(parent, folder)
	if prog := processUnder(dir); prog != "" {
		return false, fmt.Errorf("%w (%s)", errPortableRunning, prog)
	}
	if err := os.RemoveAll(dir); err != nil {
		return false, fmt.Errorf("remove %s: %w", dir, err)
	}
	if link != "" {
		if progs, err := windows.KnownFolderPath(windows.FOLDERID_CommonPrograms, 0); err == nil && underDir(link, progs) && strings.EqualFold(filepath.Ext(link), ".lnk") {
			os.Remove(link)
		}
	}
	if err := registry.DeleteKey(registry.LOCAL_MACHINE, path); err != nil && !errors.Is(err, registry.ErrNotExist) {
		return false, err
	}
	return true, nil
}

// processUnder returns the image path of a running process whose program
// is below dir ("" if none). Processes the agent cannot open are ignored.
func processUnder(dir string) string {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(snap)
	var pe windows.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))
	for err = windows.Process32First(snap, &pe); err == nil; err = windows.Process32Next(snap, &pe) {
		h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pe.ProcessID)
		if err != nil {
			continue
		}
		buf := make([]uint16, windows.MAX_LONG_PATH)
		n := uint32(len(buf))
		err = windows.QueryFullProcessImageName(h, 0, &buf[0], &n)
		windows.CloseHandle(h)
		if err == nil {
			if img := windows.UTF16ToString(buf[:n]); underDir(img, dir) {
				return img
			}
		}
	}
	return ""
}
