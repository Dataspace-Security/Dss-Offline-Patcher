//go:build windows

package agent

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"offpatch/internal/store"
)

// One CIM query for everything; numbers come back as JSON numbers.
const hardwareScript = `$cs = Get-CimInstance Win32_ComputerSystem; $bios = Get-CimInstance Win32_BIOS; ` +
	`$cpu = @(Get-CimInstance Win32_Processor); $os = Get-CimInstance Win32_OperatingSystem; ` +
	`$disks = @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' | ForEach-Object { @{ m = $_.DeviceID; t = [int64]$_.Size; f = [int64]$_.FreeSpace } }); ` +
	`@{ mf = $cs.Manufacturer; model = $cs.Model; serial = $bios.SerialNumber; cpu = $cpu[0].Name; ` +
	`cores = ($cpu | Measure-Object -Property NumberOfLogicalProcessors -Sum).Sum; mem = [int64]$cs.TotalPhysicalMemory; ` +
	`user = $cs.UserName; boot = $os.LastBootUpTime.ToUniversalTime().ToString('o'); disks = $disks } | ConvertTo-Json -Compress -Depth 4`

func (w *Windows) Hardware(ctx context.Context) store.Hardware {
	var h store.Hardware
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if out, err := powershell(cctx, hardwareScript); err == nil {
		var r struct {
			MF, Model, Serial, CPU, User, Boot string
			Cores                              int
			Mem                                int64
			Disks                              []struct {
				M    string
				T, F int64
			}
		}
		if json.Unmarshal(out, &r) == nil {
			h = store.Hardware{Manufacturer: r.MF, Model: r.Model, SerialNumber: r.Serial, CPU: strings.TrimSpace(r.CPU), CPUCores: r.Cores, MemoryBytes: r.Mem, LoggedInUser: r.User}
			if t, err := time.Parse(time.RFC3339Nano, r.Boot); err == nil {
				h.BootTime = t.UTC().Format(time.RFC3339)
			}
			for _, d := range r.Disks {
				h.Disks = append(h.Disks, store.DiskInfo{Mount: d.M, TotalBytes: d.T, FreeBytes: d.F})
			}
		}
	}
	fillNetwork(&h)
	return h
}
