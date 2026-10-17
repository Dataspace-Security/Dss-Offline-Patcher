// Package transfer abstracts the network transfer boundary. Adapters send
// only bundle files (and their receipts) — no general-purpose relay and no
// reverse channel. The drop-directory adapter stands in for a data diode or
// cross-domain gateway that presents received files to the isolated side.
package transfer

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"offpatch/internal/manifest"
)

// Receipt is the sender-side record of one transfer. It is written next to
// the bundle as <bundle>.receipt.json so the receiver can reconcile what was
// sent against what arrived (lost, duplicated or substituted files).
type Receipt struct {
	Adapter     string `json:"adapter"`
	File        string `json:"file"`
	Destination string `json:"destination"`
	Size        int64  `json:"size"`
	SHA256      string `json:"sha256"`
	SentAt      string `json:"sent_at"`
	Result      string `json:"result"`
	KeyID       string `json:"key_id,omitempty"`
	Signature   string `json:"signature,omitempty"` // Ed25519 over the receipt with Signature=""
}

func (r Receipt) payload() []byte {
	r.Signature = ""
	b, _ := json.Marshal(r)
	return b
}

// Sign signs the receipt with the acquisition-zone bundle key.
func (r *Receipt) Sign(k ed25519.PrivateKey) {
	r.SignWith(manifest.KeyID(k.Public().(ed25519.PublicKey)), func(b []byte) (string, error) { return manifest.Sign(k, b), nil })
}

// SignWith signs via any signer (file key or HSM) returning base64.
func (r *Receipt) SignWith(keyID string, sign func([]byte) (string, error)) error {
	r.KeyID = keyID
	sig, err := sign(r.payload())
	r.Signature = sig
	return err
}

// VerifyReceipt checks a receipt signature against a trusted key.
func VerifyReceipt(r Receipt, pub ed25519.PublicKey) bool {
	sig, err := base64.StdEncoding.DecodeString(r.Signature)
	return err == nil && len(sig) == ed25519.SignatureSize && ed25519.Verify(pub, r.payload(), sig)
}

// ReceiptSuffix marks receipt files in the drop directory.
const ReceiptSuffix = ".receipt.json"

// Adapter sends a bundle across the boundary. Implementations must transfer
// only the bundle file — no general-purpose relay, no reverse channel.
type Adapter interface {
	Send(bundlePath string) (Receipt, error)
	// SendReceipt delivers the (signed) receipt after the bundle.
	SendReceipt(r Receipt) error
}

// Transferable reports whether a file of this name may cross the boundary:
// signed bundles, trust documents, acquisition status reports and update
// intelligence. Everything else is refused.
func Transferable(name string) bool {
	return filepath.Ext(name) == ".pmb" || strings.HasSuffix(name, ".trust.json") ||
		strings.HasSuffix(name, ".status.json") || strings.HasSuffix(name, ".intel.gz")
}

func checkBundle(path string) (string, int64, string, error) {
	name := filepath.Base(path)
	if !Transferable(name) {
		return "", 0, "", errors.New("only .pmb bundles, .trust.json, .status.json and .intel.gz documents may be transferred")
	}
	size, sha, err := manifest.HashFile(path)
	return name, size, sha, err
}

// DropDir writes <name>.pmb.part then renames to <name>.pmb so the receiver
// never sees a partial file.
type DropDir struct{ Dir string }

func atomicCopy(src io.Reader, dst string) error {
	tmp := dst + ".part"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o640)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, src); err != nil {
		out.Close()
		os.Remove(tmp)
		return err
	}
	if err := out.Sync(); err != nil {
		out.Close()
		os.Remove(tmp)
		return err
	}
	out.Close()
	if err := os.Rename(tmp, dst); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

func (d DropDir) Send(bundlePath string) (Receipt, error) {
	name, size, sha, err := checkBundle(bundlePath)
	if err != nil {
		return Receipt{}, err
	}
	dst := filepath.Join(d.Dir, name)
	if _, err := os.Stat(dst); err == nil {
		return Receipt{}, fmt.Errorf("%s already pending in drop directory", name)
	}
	src, err := os.Open(bundlePath)
	if err != nil {
		return Receipt{}, err
	}
	defer src.Close()
	if err := atomicCopy(src, dst); err != nil {
		return Receipt{}, err
	}
	return Receipt{Adapter: "dropdir", File: name, Destination: d.Dir, Size: size, SHA256: sha, SentAt: time.Now().UTC().Format(time.RFC3339), Result: "delivered"}, nil
}

func (d DropDir) SendReceipt(r Receipt) error {
	b, _ := json.MarshalIndent(r, "", "  ")
	return atomicCopy(strings.NewReader(string(b)), filepath.Join(d.Dir, r.File+ReceiptSuffix))
}

// Command hands each file to an external program — typically the gateway
// or diode vendor's upload CLI. "{file}" in Argv is replaced with the path.
// The program must exit 0 only when the file was accepted for transfer.
type Command struct {
	Argv    []string
	TempDir string // where receipts are written before handing them over
}

func (c Command) run(path string) error {
	if len(c.Argv) == 0 {
		return errors.New("command adapter: no command configured")
	}
	argv := make([]string, len(c.Argv))
	found := false
	for i, a := range c.Argv {
		if strings.Contains(a, "{file}") {
			found = true
		}
		argv[i] = strings.ReplaceAll(a, "{file}", path)
	}
	if !found {
		argv = append(argv, path)
	}
	out, err := exec.Command(argv[0], argv[1:]...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("gateway command failed: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (c Command) Send(bundlePath string) (Receipt, error) {
	name, size, sha, err := checkBundle(bundlePath)
	if err != nil {
		return Receipt{}, err
	}
	if err := c.run(bundlePath); err != nil {
		return Receipt{}, err
	}
	return Receipt{Adapter: "command:" + filepath.Base(c.Argv[0]), File: name, Size: size, SHA256: sha, SentAt: time.Now().UTC().Format(time.RFC3339), Result: "accepted-by-gateway"}, nil
}

func (c Command) SendReceipt(r Receipt) error {
	dir := c.TempDir
	if dir == "" {
		dir = os.TempDir()
	}
	p := filepath.Join(dir, r.File+ReceiptSuffix)
	b, _ := json.MarshalIndent(r, "", "  ")
	if err := os.WriteFile(p, b, 0o640); err != nil {
		return err
	}
	defer os.Remove(p)
	return c.run(p)
}
