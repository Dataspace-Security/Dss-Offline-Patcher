//go:build windows

package agent

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"offpatch/internal/manifest"
	"offpatch/internal/store"
)

const (
	serviceStopWait = 90 * time.Second
	appCloseWait    = 10 * time.Second
)

// appInstallDirs: the folders Apps & features gives for p's app (MSI
// product code, or the display name the package installs), both registry
// views. Only folders that exist and are narrow enough to act on.
func appInstallDirs(p manifest.Package) []string {
	blockedTrees, blockedExact := blockedDirs()
	seen := map[string]bool{}
	var out []string
	for _, view := range []uint32{registry.WOW64_64KEY, registry.WOW64_32KEY} {
		k, err := registry.OpenKey(registry.LOCAL_MACHINE, uninstallRoot, registry.ENUMERATE_SUB_KEYS|view)
		if err != nil {
			continue
		}
		names, _ := k.ReadSubKeyNames(-1)
		k.Close()
		for _, n := range names {
			sk, err := registry.OpenKey(registry.LOCAL_MACHINE, uninstallRoot+`\`+n, registry.QUERY_VALUE|view)
			if err != nil {
				continue
			}
			name, _, _ := sk.GetStringValue("DisplayName")
			loc, _, _ := sk.GetStringValue("InstallLocation")
			icon, _, _ := sk.GetStringValue("DisplayIcon")
			un, _, _ := sk.GetStringValue("UninstallString")
			sk.Close()
			match := (p.Kind == "msi" && p.ProductCode != "" && strings.EqualFold(n, p.ProductCode)) ||
				(p.PackageName != "" && name != "" && store.SameAppName(name, p.PackageName))
			if !match {
				continue
			}
			d := installDirFrom(loc, icon, un)
			if d == "" || seen[strings.ToLower(d)] || !safeAppDir(d, blockedTrees, blockedExact) {
				continue
			}
			if fi, err := os.Stat(d); err != nil || !fi.IsDir() {
				continue
			}
			seen[strings.ToLower(d)] = true
			out = append(out, d)
		}
	}
	return out
}

const uninstallRoot = `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`

// blockedDirs: Windows and the agent's own folders (whole trees), and
// folders that hold many apps (only exactly).
func blockedDirs() (trees, exact []string) {
	trees = []string{os.Getenv("SystemRoot")}
	if exe, err := os.Executable(); err == nil {
		trees = append(trees, filepath.Dir(exe))
	}
	trees = append(trees, filepath.Join(os.Getenv("ProgramData"), "offpatch"))
	exact = []string{os.Getenv("ProgramFiles"), os.Getenv("ProgramFiles(x86)"), os.Getenv("ProgramW6432"),
		os.Getenv("ProgramData"), os.Getenv("CommonProgramFiles"), os.Getenv("CommonProgramFiles(x86)"),
		filepath.Join(os.Getenv("SystemDrive")+`\`, "Users"), os.Getenv("PUBLIC")}
	return trees, exact
}

// quiesceApp stops what runs from p's install folders before the update.
// done (call with the installer's result) starts the stopped services
// again and notes what happened; a non-nil *Result means "do not install
// now" (an app is open and may not be closed).
func (w *Windows) quiesceApp(ctx context.Context, p manifest.Package) (done func(Result) Result, wait *Result) {
	noop := func(r Result) Result { return r }
	dirs := appInstallDirs(p)
	if len(dirs) == 0 {
		return noop, nil
	}
	// Open apps first: if one may not be closed, nothing is stopped.
	procs := processesUnder(dirs)
	if len(procs) > 0 && !closeAppsAllowed(ctx) {
		return noop, &Result{State: "failed", ExitCode: -1, Detail: appRunning + ": " + filepath.Base(procs[0].image) +
			"; the deployment does not allow closing apps, so it is tried again later)"}
	}
	stopped := stopServicesUnder(dirs)
	var closed []string
	for _, pr := range processesUnder(dirs) { // services may have ended some
		if closeProcess(pr.pid) {
			closed = append(closed, filepath.Base(pr.image))
		}
	}
	return func(r Result) Result {
		var started, failed []string
		for _, name := range stopped {
			if err := startService(name); err != nil {
				failed = append(failed, name+": "+err.Error())
			} else {
				started = append(started, name)
			}
		}
		return appendDetail(r, quiesceNote(stopped, started, failed, closed))
	}, nil
}

type procInfo struct {
	pid   uint32
	image string
}

// processesUnder lists running processes whose program is in dirs.
func processesUnder(dirs []string) []procInfo {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil
	}
	defer windows.CloseHandle(snap)
	self := uint32(os.Getpid())
	var out []procInfo
	var pe windows.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))
	for err = windows.Process32First(snap, &pe); err == nil; err = windows.Process32Next(snap, &pe) {
		if pe.ProcessID == self || pe.ProcessID == 0 {
			continue
		}
		h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pe.ProcessID)
		if err != nil {
			continue
		}
		buf := make([]uint16, windows.MAX_LONG_PATH)
		n := uint32(len(buf))
		err = windows.QueryFullProcessImageName(h, 0, &buf[0], &n)
		windows.CloseHandle(h)
		if err == nil {
			if img := windows.UTF16ToString(buf[:n]); underAnyDir(img, dirs) {
				out = append(out, procInfo{pid: pe.ProcessID, image: img})
			}
		}
	}
	return out
}

// closeProcess ends one process and waits briefly for it to go.
func closeProcess(pid uint32) bool {
	h, err := windows.OpenProcess(windows.PROCESS_TERMINATE|windows.SYNCHRONIZE, false, pid)
	if err != nil {
		return false
	}
	defer windows.CloseHandle(h)
	if err := windows.TerminateProcess(h, 1); err != nil {
		return false
	}
	windows.WaitForSingleObject(h, uint32(appCloseWait/time.Millisecond))
	return true
}

// stopServicesUnder stops running services whose program is in dirs (never
// the agent's own) and returns their names, in the order stopped.
func stopServicesUnder(dirs []string) []string {
	m, err := mgr.Connect()
	if err != nil {
		return nil
	}
	defer m.Disconnect()
	names, err := m.ListServices()
	if err != nil {
		return nil
	}
	var stopped []string
	for _, n := range names {
		if strings.EqualFold(n, selfServiceName) {
			continue
		}
		s, err := m.OpenService(n)
		if err != nil {
			continue
		}
		cfg, err := s.Config()
		if err != nil || !underAnyDir(serviceExe(cfg.BinaryPathName), dirs) {
			s.Close()
			continue
		}
		if st, err := s.Query(); err == nil && st.State == svc.Running {
			if _, err := s.Control(svc.Stop); err == nil && waitState(s, svc.Stopped, serviceStopWait) {
				stopped = append(stopped, n)
			}
		}
		s.Close()
	}
	return stopped
}

func waitState(s *mgr.Service, want svc.State, d time.Duration) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if st, err := s.Query(); err == nil && st.State == want {
			return true
		}
		time.Sleep(500 * time.Millisecond)
	}
	return false
}

// startService starts a service the update stopped (it may have been
// replaced or removed by the installer: then it is reported).
func startService(name string) error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(name)
	if err != nil {
		return err
	}
	defer s.Close()
	if st, err := s.Query(); err == nil && st.State == svc.Running {
		return nil // the installer started it already
	}
	if err := s.Start(); err != nil {
		return err
	}
	waitState(s, svc.Running, serviceStopWait)
	return nil
}
