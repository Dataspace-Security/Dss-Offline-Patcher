package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"offpatch/internal/acquire"
	"offpatch/internal/intel"
)

// intelOpts configures update intelligence (pmctl intel, and the "intel"
// section of pmctl auto's config).
type intelOpts struct {
	Disabled  bool                     `json:"disabled"`
	WingetURL string                   `json:"winget_url"` // default: winget community source
	NoApps    bool                     `json:"no_apps"`
	NoWindows bool                     `json:"no_windows"`
	Windows   []acquire.WindowsProduct `json:"windows"` // default: acquire.DefaultWindowsProducts()
}

// buildIntel collects the document. Partial failures become warnings; it
// fails only when there is nothing at all to send.
func buildIntel(ctx context.Context, o intelOpts, source, workDir, catalogURL string) (intel.Doc, error) {
	d := intel.Doc{Source: source, GeneratedAt: autoNow().UTC().Format(time.RFC3339)}
	if !o.NoWindows {
		cat := acquire.NewCatalog()
		if catalogURL != "" {
			cat.BaseURL = catalogURL
		}
		products := o.Windows
		if len(products) == 0 {
			products = acquire.DefaultWindowsProducts()
		}
		rels, warns := acquire.WindowsReleases(ctx, cat, products)
		d.Windows = rels
		d.Warnings = append(d.Warnings, warns...)
	}
	if !o.NoApps {
		apps, src, err := acquire.WingetApps(ctx, nil, o.WingetURL, filepath.Join(workDir, "intel-work"))
		if err != nil {
			d.Warnings = append(d.Warnings, err.Error())
		} else {
			d.Apps, d.AppsSource = apps, src
		}
	}
	if len(d.Windows) == 0 && len(d.Apps) == 0 {
		return d, fmt.Errorf("no update intelligence collected: %s", strings.Join(d.Warnings, "; "))
	}
	return d, nil
}

// writeIntel signs d into dir and returns the file path.
func writeIntel(d intel.Doc, keySpec, pubSpec, dir string) (string, error) {
	k, err := openSigner(keySpec, pubSpec)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return "", err
	}
	p := filepath.Join(dir, fmt.Sprintf("intel-%s-%d%s", d.Source, autoNow().UnixNano(), intel.FileSuffix))
	f, err := os.OpenFile(p, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o640)
	if err != nil {
		return "", err
	}
	if err := intel.Write(f, d, k.KeyID(), k.Sign); err != nil {
		f.Close()
		os.Remove(p)
		return "", err
	}
	return p, f.Close()
}

// sendIntel builds, signs and sends update intelligence through the
// transfer adapter (no receipt: it is not a bundle).
func sendIntel(ctx context.Context, c *autoConfig) (intel.Doc, error) {
	src := c.Source
	if src == "" {
		src = "acq-zone-1"
	}
	d, err := buildIntel(ctx, *c.Intel, src, c.WorkDir, c.CatalogURL)
	if err != nil {
		return d, err
	}
	p, err := writeIntel(d, c.Key, c.Pub, filepath.Join(c.WorkDir, "intel"))
	if err != nil {
		return d, err
	}
	a, err := adapterFor(c.Send)
	if err != nil {
		return d, err
	}
	if _, err := a.Send(p); err != nil {
		return d, err
	}
	return d, nil
}

func intelCmd(args []string) error {
	fs := flag.NewFlagSet("intel", flag.ExitOnError)
	key := fs.String("key", "", "bundle signing key file, or exec:<command> (HSM)")
	pub := fs.String("pub", "", "public key (required with -key exec:...)")
	source := fs.String("source", "acq-zone-1", "source identifier")
	out := fs.String("out", ".", "directory to write the signed *.intel.gz into")
	to := fs.String("to", "", "also deliver it to this drop directory (transfer boundary)")
	via := fs.String("via", "dropdir", "transfer adapter: dropdir | command")
	command := fs.String("command", "", "command adapter: upload command, {file} is replaced by the path")
	wingetURL := fs.String("winget-url", "", "winget index URL (default: the winget community source)")
	noApps := fs.Bool("no-apps", false, "skip the application index")
	noWindows := fs.Bool("no-windows", false, "skip Windows cumulative updates")
	fs.Parse(args)
	if *key == "" {
		return fmt.Errorf("-key is required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	d, err := buildIntel(ctx, intelOpts{WingetURL: *wingetURL, NoApps: *noApps, NoWindows: *noWindows}, *source, *out, "")
	for _, w := range d.Warnings {
		fmt.Fprintln(os.Stderr, "warning:", w)
	}
	if err != nil {
		return err
	}
	p, err := writeIntel(d, *key, *pub, *out)
	if err != nil {
		return err
	}
	fmt.Printf("intel:    %s\nwindows:  %d builds\napps:     %d (%s)\n", p, len(d.Windows), len(d.Apps), d.AppsSource)
	for _, w := range d.Windows {
		fmt.Printf("  %-28s %-6d %-10s %s\n", w.Product, w.Build, w.KB, w.ReleaseDate)
	}
	if *to != "" || *via == "command" {
		a, err := adapterFor(sendOpts{Via: *via, To: *to, Command: *command})
		if err != nil {
			return err
		}
		if _, err := a.Send(p); err != nil {
			return err
		}
		fmt.Println("sent:     delivered through the", *via, "adapter")
	}
	return nil
}
