package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"runtime"
	"strings"

	"offpatch/internal/msi"
)

// authenticode asks PowerShell for the file's Authenticode status (Windows
// acquisition hosts only; elsewhere the caller records "not_checked").
// A variable so tests with synthetic payloads can stub it.
var authenticode = authenticodePS

func authenticodePS(path string) (status, signer string, err error) {
	script := `$s = Get-AuthenticodeSignature -LiteralPath $env:PM_FILE; ` +
		`[pscustomobject]@{Status=[string]$s.Status; Signer=[string]$s.SignerCertificate.Subject} | ConvertTo-Json -Compress`
	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script)
	cmd.Env = append(cmd.Environ(), "PM_FILE="+path)
	out, err := cmd.Output()
	if err != nil {
		return "", "", err
	}
	var r struct{ Status, Signer string }
	if err := json.Unmarshal([]byte(strings.TrimSpace(string(out))), &r); err != nil {
		return "", "", err
	}
	return r.Status, r.Signer, nil
}

// msiProductCode reads ProductCode from an .msi with the pure-Go reader
// (internal/msi), on any acquisition host. On Windows, a file that reader
// cannot parse is retried through the Windows Installer API.
func msiProductCode(path string) (string, error) {
	code, err := msi.ProductCode(path)
	if err == nil || runtime.GOOS != "windows" || errors.Is(err, msi.ErrNoProductCode) {
		return code, err
	}
	if c, cerr := msiProductCodeCOM(path); cerr == nil {
		return c, nil
	}
	return "", err
}

// msiProductCodeCOM reads ProductCode via the Windows Installer COM API
// (Windows only). The path is passed via the environment, never
// interpolated into the script.
func msiProductCodeCOM(path string) (string, error) {
	script := `$i = New-Object -ComObject WindowsInstaller.Installer; ` +
		`$db = $i.GetType().InvokeMember('OpenDatabase','InvokeMethod',$null,$i,@($env:PM_FILE,0)); ` +
		`$v = $db.GetType().InvokeMember('OpenView','InvokeMethod',$null,$db,("SELECT Value FROM Property WHERE Property='ProductCode'")); ` +
		`$v.GetType().InvokeMember('Execute','InvokeMethod',$null,$v,$null) | Out-Null; ` +
		`$r = $v.GetType().InvokeMember('Fetch','InvokeMethod',$null,$v,$null); ` +
		`$r.GetType().InvokeMember('StringData','GetProperty',$null,$r,1)`
	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script)
	cmd.Env = append(cmd.Environ(), "PM_FILE="+path)
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("Windows Installer API: %w", err)
	}
	code := strings.ToUpper(strings.TrimSpace(string(out)))
	if !strings.HasPrefix(code, "{") || len(code) != 38 {
		return "", fmt.Errorf("unexpected ProductCode %q", code)
	}
	return code, nil
}
