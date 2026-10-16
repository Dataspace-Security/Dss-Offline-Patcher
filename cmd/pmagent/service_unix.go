//go:build linux || darwin

package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

// On Linux/macOS the service manager (systemd/launchd) runs `pmagent run`
// directly; there is no in-process service mode.
func isService() bool { return false }

func runService(*slog.Logger) {}

const systemdUnit = `[Unit]
Description=offpatch Endpoint Agent (installs approved updates from the internal offpatch server)
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=%s run -state-dir %s
# Restart also applies a self-upgrade (the agent exits 3 after swapping its binary).
Restart=always
RestartSec=15
User=root
NoNewPrivileges=false
ProtectHome=read-only
PrivateTmp=true

[Install]
WantedBy=multi-user.target
`

const launchdPlist = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>com.offpatch.agent</string>
  <key>ProgramArguments</key><array><string>%s</string><string>run</string><string>-state-dir</string><string>%s</string></array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ThrottleInterval</key><integer>15</integer>
  <key>StandardErrorPath</key><string>%s/agent.log</string>
</dict></plist>
`

func serviceCmd(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: pmagent service install|uninstall [-state-dir dir]")
	}
	fs := flag.NewFlagSet("service", flag.ExitOnError)
	dir := fs.String("state-dir", defaultStateDir(), "agent state directory")
	fs.Parse(args[1:])
	if os.Geteuid() != 0 {
		return fmt.Errorf("must run as root")
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	abs, _ := filepath.Abs(*dir)
	run := func(name string, a ...string) error {
		out, err := exec.Command(name, a...).CombinedOutput()
		if err != nil {
			return fmt.Errorf("%s %v: %v %s", name, a, err, out)
		}
		return nil
	}
	if runtime.GOOS == "linux" {
		unit := "/etc/systemd/system/offpatch-agent.service"
		switch args[0] {
		case "install":
			if err := os.WriteFile(unit, []byte(fmt.Sprintf(systemdUnit, exe, abs)), 0o644); err != nil {
				return err
			}
			if err := run("systemctl", "daemon-reload"); err != nil {
				return err
			}
			if err := run("systemctl", "enable", "--now", "offpatch-agent"); err != nil {
				return err
			}
			fmt.Println("installed and started systemd unit offpatch-agent")
		case "uninstall":
			run("systemctl", "disable", "--now", "offpatch-agent")
			os.Remove(unit)
			run("systemctl", "daemon-reload")
			fmt.Println("removed systemd unit offpatch-agent")
		default:
			return fmt.Errorf("unknown service command %q", args[0])
		}
		return nil
	}
	plist := "/Library/LaunchDaemons/com.offpatch.agent.plist"
	switch args[0] {
	case "install":
		if err := os.WriteFile(plist, []byte(fmt.Sprintf(launchdPlist, exe, abs, abs)), 0o644); err != nil {
			return err
		}
		if err := run("launchctl", "bootstrap", "system", plist); err != nil {
			return err
		}
		fmt.Println("installed and started launchd daemon com.offpatch.agent")
	case "uninstall":
		run("launchctl", "bootout", "system/com.offpatch.agent")
		os.Remove(plist)
		fmt.Println("removed launchd daemon com.offpatch.agent")
	default:
		return fmt.Errorf("unknown service command %q", args[0])
	}
	return nil
}
