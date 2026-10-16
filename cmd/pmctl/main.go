// pmctl runs in the connected acquisition zone: it generates signing keys,
// builds signed bundles from downloaded vendor files, and hands them to the
// transfer adapter. It never holds endpoint credentials.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"offpatch/internal/manifest"
	"offpatch/internal/transfer"
)

const usage = `pmctl — offpatch acquisition-zone tool

  pmctl keygen  -out <prefix>                      write <prefix>.key (private, 0600) and <prefix>.pub
  pmctl build   -key <file.key> -spec <spec.json> -out <bundle.pmb> [-source s] [-seq n] [-state f] [-ttl 720h]
  pmctl inspect -bundle <bundle.pmb> [-pub <file.pub>]
  pmctl send    -bundle <bundle.pmb> -to <drop dir>   transfer via one-way drop-directory adapter
  pmctl auto    -config acquire.json [-dry-run]
                                                   unattended: check MSRC + vendor feeds, download, verify, build ONE bundle, send
  pmctl trust   -root root.key -seq N -key new.pub=<source> [-retire old.pub] [-revoke <key_id>:compromised] -out keys-N.trust.json
                                                   root-signed key rotation / revocation (generate the root with keygen; keep it offline)

acquisition (connected zone; see docs/08-acquisition.md):
  pmctl catalog-search -q <query>                  search the Microsoft Update Catalog
  pmctl msrc      -month 2026-Oct [-product "Windows 10"] [-arch x64]   list KBs/severity/CVEs from MSRC
  pmctl fetch     -kb KB5044273 -product "Windows 10 Version 22H2" -arch x64 -min-build 19045 -max-build 19045
                  [-severity critical | -msrc-month 2026-Oct] [-match s] [-file s] -out <dir> -spec <spec.json>
  pmctl fetch-url -url https://... -sha256 <hex> -package-id X -title T -vendor V -kind msi -product-code {GUID}
                  -severity s [-version v] [-arch any] -out <dir> -spec <spec.json>

spec.json lists the packages; each entry is a manifest package without "file"
but with "path" pointing at the downloaded vendor file. size and sha256 are
computed. On Windows, "vendor_signature" is filled in automatically via
Get-AuthenticodeSignature unless already present.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Print(usage)
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "keygen":
		err = keygen(os.Args[2:])
	case "build":
		err = build(os.Args[2:])
	case "inspect":
		err = inspect(os.Args[2:])
	case "send":
		err = send(os.Args[2:])
	case "trust":
		err = trustCmd(os.Args[2:])
	case "auto":
		err = autoCmd(os.Args[2:])
	case "catalog-search":
		err = catalogSearch(os.Args[2:])
	case "fetch":
		err = fetchKB(os.Args[2:])
	case "fetch-url":
		err = fetchURL(os.Args[2:])
	case "msrc":
		err = msrcCmd(os.Args[2:])
	default:
		fmt.Print(usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func keygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	out := fs.String("out", "bundle", "output path prefix")
	fs.Parse(args)
	pub, priv, err := manifest.GenerateKey()
	if err != nil {
		return err
	}
	if _, err := os.Stat(*out + ".key"); err == nil {
		return fmt.Errorf("%s.key already exists; refusing to overwrite", *out)
	}
	if err := os.WriteFile(*out+".key", manifest.EncodePrivate(priv), 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(*out+".pub", manifest.EncodePublic(pub), 0o644); err != nil {
		return err
	}
	fmt.Printf("key_id: %s\nprivate: %s.key (keep in the acquisition zone / HSM)\npublic:  %s.pub (install on pmserver and agents)\n", manifest.KeyID(pub), *out, *out)
	return nil
}

type specPackage struct {
	manifest.Package
	Path string `json:"path"`
}

type pmctlState struct {
	Sequences map[string]int64 `json:"sequences"`
}

func build(args []string) error {
	fs := flag.NewFlagSet("build", flag.ExitOnError)
	keyPath := fs.String("key", "", "private signing key file, or exec:<command> to sign via an HSM tool (see signer.go)")
	pubPath := fs.String("pub", "", "public key (required with -key exec:...)")
	specPath := fs.String("spec", "", "package spec JSON")
	out := fs.String("out", "", "output bundle path (.pmb)")
	source := fs.String("source", "acq-zone-1", "source identifier")
	seq := fs.Int64("seq", 0, "sequence number (default: next from -state)")
	statePath := fs.String("state", ".pmctl-state.json", "sequence state file")
	ttl := fs.Duration("ttl", 30*24*time.Hour, "bundle validity")
	fs.Parse(args)
	if *keyPath == "" || *specPath == "" || *out == "" {
		return fmt.Errorf("-key, -spec and -out are required")
	}
	r, err := buildBundle(buildOpts{Key: *keyPath, Pub: *pubPath, Spec: *specPath, Out: *out, Source: *source, Seq: *seq, State: *statePath, TTL: *ttl})
	if err != nil {
		return err
	}
	fmt.Printf("bundle:   %s\nbundle_id: %s\nsource:   %s  sequence: %d\npackages: %d\nsha256:   %s\n", r.Path, r.BundleID, *source, r.Sequence, r.Packages, r.SHA256)
	return nil
}

type buildOpts struct {
	Key, Pub, Spec, Out, Source, State string
	Seq                                int64
	TTL                                time.Duration
}

type buildResult struct {
	Path, BundleID, SHA256 string
	Sequence               int64
	Packages               int
}

// buildBundle signs every entry of a spec.json into one .pmb bundle and
// advances the per-source sequence in the state file.
func buildBundle(o buildOpts) (buildResult, error) {
	priv, err := openSigner(o.Key, o.Pub)
	if err != nil {
		return buildResult{}, err
	}
	sb, err := os.ReadFile(o.Spec)
	if err != nil {
		return buildResult{}, err
	}
	var spec []specPackage
	if err := json.Unmarshal(sb, &spec); err != nil {
		return buildResult{}, fmt.Errorf("spec: %w", err)
	}
	specDir := filepath.Dir(o.Spec)
	if o.Source == "" {
		o.Source = "acq-zone-1"
	}
	if o.TTL == 0 {
		o.TTL = 30 * 24 * time.Hour
	}
	st := pmctlState{Sequences: map[string]int64{}}
	if b, err := os.ReadFile(o.State); err == nil {
		json.Unmarshal(b, &st)
	}
	if o.Seq == 0 {
		o.Seq = st.Sequences[o.Source] + 1
	}
	now := time.Now().UTC().Truncate(time.Second)
	m := manifest.Manifest{
		SchemaVersion: manifest.SchemaVersion,
		BundleID:      fmt.Sprintf("b-%s-%04d", now.Format("20060102"), o.Seq),
		Source:        o.Source,
		Sequence:      o.Seq,
		KeyID:         priv.KeyID(),
		CreatedAt:     now,
		ExpiresAt:     now.Add(o.TTL),
	}
	files := map[string]string{}
	for _, sp := range spec {
		p := sp.Package
		path := sp.Path
		if !filepath.IsAbs(path) {
			path = filepath.Join(specDir, path)
		}
		size, sha, err := manifest.HashFile(path)
		if err != nil {
			return buildResult{}, fmt.Errorf("%s: %w", p.PackageID, err)
		}
		p.File = manifest.FileRef{Name: "payload/" + filepath.Base(path), Size: size, SHA256: sha}
		if p.Supersedes == nil {
			p.Supersedes = []string{}
		}
		if p.VendorSignature.Status == "" {
			if p.Kind == "msu" || p.Kind == "msi" {
				p.VendorSignature = vendorSignature(path)
			} else {
				// Authenticode does not apply to deb/rpm/pkg/agent payloads.
				p.VendorSignature = manifest.VendorSignature{Status: "not_checked", CheckedAt: time.Now().UTC().Format(time.RFC3339)}
			}
		}
		files[p.File.Name] = path
		m.Packages = append(m.Packages, p)
	}
	if err := m.ValidateSchema(now); err != nil {
		return buildResult{}, fmt.Errorf("manifest invalid: %w", err)
	}
	mb, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return buildResult{}, err
	}
	sig, err := priv.Sign(mb)
	if err != nil {
		return buildResult{}, err
	}
	if err := manifest.WriteBundle(o.Out, mb, sig, files); err != nil {
		return buildResult{}, err
	}
	st.Sequences[o.Source] = o.Seq
	sbytes, _ := json.MarshalIndent(st, "", "  ")
	if err := os.WriteFile(o.State, sbytes, 0o600); err != nil {
		return buildResult{}, err
	}
	_, bsha, _ := manifest.HashFile(o.Out)
	return buildResult{Path: o.Out, BundleID: m.BundleID, SHA256: bsha, Sequence: o.Seq, Packages: len(m.Packages)}, nil
}

func inspect(args []string) error {
	fs := flag.NewFlagSet("inspect", flag.ExitOnError)
	bundle := fs.String("bundle", "", "bundle path")
	pubPath := fs.String("pub", "", "public key to verify with (optional)")
	fs.Parse(args)
	dir, err := os.MkdirTemp("", "pmctl-inspect-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	ex, err := manifest.ExtractSafe(*bundle, dir, manifest.Limits{MaxFiles: 500})
	if err != nil {
		return err
	}
	m, err := manifest.Parse(ex.ManifestBytes)
	if err != nil {
		return err
	}
	fmt.Printf("bundle_id %s  source %s  sequence %d  key %s\ncreated %s  expires %s\n", m.BundleID, m.Source, m.Sequence, m.KeyID, m.CreatedAt.Format(time.RFC3339), m.ExpiresAt.Format(time.RFC3339))
	if err := m.ValidateSchema(time.Now()); err != nil {
		fmt.Println("SCHEMA: FAIL —", err)
	} else {
		fmt.Println("SCHEMA: ok")
	}
	if *pubPath != "" {
		pub, err := manifest.LoadPublic(*pubPath)
		if err != nil {
			return err
		}
		if err := manifest.Verify(pub, ex.ManifestBytes, ex.Signature); err != nil {
			fmt.Println("SIGNATURE: FAIL —", err)
		} else {
			fmt.Println("SIGNATURE: ok")
		}
	}
	for _, p := range m.Packages {
		f, ok := ex.Files[p.File.Name]
		status := "ok"
		if !ok {
			status = "MISSING"
		} else if f.SHA256 != p.File.SHA256 || f.Size != p.File.Size {
			status = "HASH MISMATCH"
		}
		fmt.Printf("  %-24s %-4s %-10s %-9s %10d  %s  %s\n", p.PackageID, p.Kind, p.KB+p.ProductCode, p.Severity, p.File.Size, p.File.SHA256[:16], status)
	}
	return nil
}

func send(args []string) error {
	fs := flag.NewFlagSet("send", flag.ExitOnError)
	bundle := fs.String("bundle", "", "bundle path")
	via := fs.String("via", "dropdir", "transfer adapter: dropdir | command")
	to := fs.String("to", "", "dropdir: drop directory (transfer boundary)")
	command := fs.String("command", "", "command: gateway upload command, {file} is replaced by the path, e.g. \"diodectl push {file}\"")
	keyPath := fs.String("key", "", "sign the transfer receipt with this bundle key (recommended); file or exec:<command>")
	pubPath := fs.String("pub", "", "public key (required with -key exec:...)")
	logPath := fs.String("log", "sent.jsonl", "append receipts to this sender-side log")
	fs.Parse(args)
	if *bundle == "" {
		return fmt.Errorf("-bundle is required")
	}
	rc, err := sendBundle(sendOpts{Via: *via, To: *to, Command: *command, Key: *keyPath, Pub: *pubPath, Log: *logPath}, *bundle)
	if err != nil {
		return err
	}
	b, _ := json.MarshalIndent(rc, "", "  ")
	fmt.Println(string(b))
	return nil
}

// vendorSignature records Authenticode status where the platform can check it.
func vendorSignature(path string) manifest.VendorSignature {
	vs := manifest.VendorSignature{Status: "not_checked", CheckedAt: time.Now().UTC().Format(time.RFC3339)}
	if runtime.GOOS != "windows" {
		return vs
	}
	status, signer, err := authenticode(path)
	if err != nil {
		return vs
	}
	switch strings.ToLower(status) {
	case "valid":
		vs.Status = "valid"
	default:
		vs.Status = "invalid"
	}
	vs.Signer = signer
	return vs
}

type sendOpts struct {
	Via     string `json:"via"`     // dropdir | command
	To      string `json:"to"`      // dropdir target
	Command string `json:"command"` // command adapter; {file} is replaced
	Key     string `json:"-"`       // receipt signing key (file or exec:)
	Pub     string `json:"-"`
	Log     string `json:"log"` // sender-side receipt log
}

// sendBundle hands a bundle (or trust document) to the transfer adapter,
// then delivers a signed receipt and appends it to the sender log.
func adapterFor(o sendOpts) (transfer.Adapter, error) {
	switch o.Via {
	case "", "dropdir":
		if o.To == "" {
			return nil, fmt.Errorf("-to is required for the dropdir adapter")
		}
		return transfer.DropDir{Dir: o.To}, nil
	case "command":
		argv := strings.Fields(o.Command)
		if len(argv) == 0 {
			return nil, fmt.Errorf("-command is required for the command adapter")
		}
		return transfer.Command{Argv: argv}, nil
	}
	return nil, fmt.Errorf("unknown adapter %q", o.Via)
}

func sendBundle(o sendOpts, path string) (transfer.Receipt, error) {
	a, err := adapterFor(o)
	if err != nil {
		return transfer.Receipt{}, err
	}
	rc, err := a.Send(path)
	if err != nil {
		return rc, err
	}
	if o.Key != "" {
		k, err := openSigner(o.Key, o.Pub)
		if err != nil {
			return rc, err
		}
		if err := rc.SignWith(k.KeyID(), k.Sign); err != nil {
			return rc, err
		}
	}
	if err := a.SendReceipt(rc); err != nil {
		return rc, fmt.Errorf("bundle sent, but receipt failed: %w", err)
	}
	if o.Log != "" {
		line, _ := json.Marshal(rc)
		f, err := os.OpenFile(o.Log, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			return rc, err
		}
		f.Write(append(line, '\n'))
		f.Close()
	}
	return rc, nil
}
