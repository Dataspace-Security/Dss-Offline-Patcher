//go:build windows

package agent

import (
	"context"
	"os"
	"syscall"
	"unsafe"
)

var (
	kernel32           = syscall.NewLazyDLL("kernel32.dll")
	procGetDiskFreeEx  = kernel32.NewProc("GetDiskFreeSpaceExW")
	procGetPowerStatus = kernel32.NewProc("GetSystemPowerStatus")
)

func freeDiskBytes(path string) (int64, error) {
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	var avail, total, free uint64
	r, _, e := procGetDiskFreeEx.Call(uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(&avail)), uintptr(unsafe.Pointer(&total)), uintptr(unsafe.Pointer(&free)))
	if r == 0 {
		return 0, e
	}
	return int64(avail), nil
}

// systemVolume is the Windows drive, where updates are staged and installed.
func systemVolume() string {
	d := os.Getenv("SystemDrive")
	if d == "" {
		d = "C:"
	}
	return d + `\`
}

// readPower uses GetSystemPowerStatus (the same source as the taskbar
// battery icon; Win32_Battery is the WMI view of it).
func readPower(ctx context.Context) (PowerStatus, error) {
	var s struct {
		ACLineStatus, BatteryFlag, BatteryLifePercent, SystemStatusFlag byte
		BatteryLifeTime, BatteryFullLifeTime                            uint32
	}
	r, _, e := procGetPowerStatus.Call(uintptr(unsafe.Pointer(&s)))
	if r == 0 {
		return PowerStatus{}, e
	}
	return winPower(s.ACLineStatus, s.BatteryFlag, s.BatteryLifePercent), nil
}
