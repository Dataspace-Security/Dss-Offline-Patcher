package main

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"offpatch/internal/msi"
)

// authenticode asks PowerShell for the file's Authenticode status (Windows
// acquisition hosts only; elsewhere the caller records "not_checked").
// A variable so tests with synthetic payloads can stub it.
var authenticode = authenticodePS

// psSignature is what Windows reports for a file's Authenticode signature:
// Status ("Valid", "NotSigned", ...), the signer's subject DN and, when
// Windows found them, the signer certificate and its issuer (for the pin
// and the CRL check, signerpin.go).
type psSignature struct {
	Status, Subject string
	Leaf, Issuer    *x509.Certificate
}

func authenticodePS(path string) (psSignature, error) {
	// The chain is built offline (RevocationMode NoCheck) only to find the
	// issuer; pmctl checks the CRL itself.
	script := `$s = Get-AuthenticodeSignature -LiteralPath $env:PM_FILE; $c = $s.SignerCertificate; $l = ''; $i = ''; ` +
		`if ($c) { $l = [Convert]::ToBase64String($c.RawData); ` +
		`$ch = New-Object System.Security.Cryptography.X509Certificates.X509Chain; $ch.ChainPolicy.RevocationMode = 'NoCheck'; [void]$ch.Build($c); ` +
		`if ($ch.ChainElements.Count -gt 1) { $i = [Convert]::ToBase64String($ch.ChainElements[1].Certificate.RawData) } }; ` +
		`[pscustomobject]@{Status=[string]$s.Status; Signer=[string]$c.Subject; Leaf=$l; Issuer=$i} | ConvertTo-Json -Compress`
	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script)
	cmd.Env = append(cmd.Environ(), "PM_FILE="+path)
	out, err := cmd.Output()
	if err != nil {
		return psSignature{}, err
	}
	var r struct{ Status, Signer, Leaf, Issuer string }
	if err := json.Unmarshal([]byte(strings.TrimSpace(string(out))), &r); err != nil {
		return psSignature{}, err
	}
	sig := psSignature{Status: r.Status, Subject: r.Signer}
	sig.Leaf, sig.Issuer = parseB64Cert(r.Leaf), parseB64Cert(r.Issuer)
	return sig, nil
}

func parseB64Cert(s string) *x509.Certificate {
	if s == "" {
		return nil
	}
	der, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		return nil
	}
	return c
}

// signerOfFile verifies a downloaded installer's Authenticode signature and
// returns its signer: PE files (EXE) in pure Go on any host, other files
// (MSI, MSU) through Windows on a Windows acquisition host.
func signerOfFile(path string) (signerInfo, error) {
	if isPE(path) {
		res, err := verifyExeResult(path)
		if err != nil {
			return signerInfo{}, err
		}
		return infoFromResult(res), nil
	}
	if runtime.GOOS != "windows" && !authenticodeAnywhere {
		return signerInfo{}, errors.New("Authenticode verification of MSI/MSU files needs a Windows acquisition host; configure a sha256 checksum source instead")
	}
	sig, err := authenticode(path)
	if err != nil {
		return signerInfo{}, fmt.Errorf("%w: %w", errExeSignature, err)
	}
	if !strings.EqualFold(sig.Status, "Valid") {
		return signerInfo{}, fmt.Errorf("%w: status %q (signer %q)", errExeSignature, sig.Status, sig.Subject)
	}
	info := infoFromCert(sig.Leaf, sig.Issuer, sig.Subject)
	if info.CN == "" {
		return signerInfo{}, fmt.Errorf("%w: signer %q has no CommonName", errExeSignature, sig.Subject)
	}
	return info, nil
}

// authenticodeAnywhere lets tests run the Windows path (stubbed) on any OS.
var authenticodeAnywhere = false

func isPE(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	var b [2]byte
	_, err = io.ReadFull(f, b[:])
	return err == nil && b[0] == 'M' && b[1] == 'Z'
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
