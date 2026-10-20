package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"offpatch/internal/acqpolicy"
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
	// Library: winget ids to describe in the console's Library besides the
	// requested ones and the built-in common list (see library.go).
	Library   []string `json:"library"`
	NoLibrary bool     `json:"no_library"`
	// LibraryNoCommon: only configured and requested ids, not the built-in list.
	LibraryNoCommon bool `json:"library_no_common"`
	// LibraryMaxLookups: new manifest lookups per run (default and maximum 300).
	LibraryMaxLookups int `json:"library_max_lookups"`
}

// addLibrary fills d.Resolved for ids (needs the app index for versions).
func addLibrary(ctx context.Context, hc *http.Client, d *intel.Doc, o intelOpts, manifestsURL string, configured []string, requested map[string]string,
	cache map[string]intel.Resolved) libraryResult {
	if hc == nil {
		hc = libraryHTTP()
	}
	if o.NoLibrary || len(d.Apps) == 0 {
		return libraryResult{}
	}
	common := commonLibrary
	if o.LibraryNoCommon {
		common = nil
	}
	max := o.LibraryMaxLookups
	if max <= 0 || max > libraryMaxLookups {
		max = libraryMaxLookups
	}
	ids := libraryIDs(append(slices.Clone(o.Library), configured...), requested, common)
	res := resolveLibrary(ctx, hc, manifestsURL, d.Apps, ids, cache, max, autoNow())
	d.Resolved = res.resolved
	return res
}

// libraryHTTP is the client for Library lookups (overridable in tests).
var libraryHTTP = func() *http.Client { return autoHTTP() }

// buildIntel collects the document. Partial failures become warnings; it
// fails only when there is nothing at all to send.
// catHC / wingetHC: clients for the catalog and the winget index (nil =
// the defaults).
func buildIntel(ctx context.Context, o intelOpts, source, workDir, catalogURL string, catHC, wingetHC *http.Client) (intel.Doc, error) {
	d := intel.Doc{Source: source, GeneratedAt: autoNow().UTC().Format(time.RFC3339)}
	if !o.NoWindows {
		cat := acquire.NewCatalog()
		if catalogURL != "" {
			cat.BaseURL = catalogURL
		}
		if catHC != nil {
			cat.HTTP = catHC
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
		apps, src, err := acquire.WingetApps(ctx, wingetHC, o.WingetURL, filepath.Join(workDir, "intel-work"))
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
func sendIntel(ctx context.Context, c *autoConfig, st *autoState) (intel.Doc, libraryResult, error) {
	src := c.Source
	if src == "" {
		src = "acq-zone-1"
	}
	// The SSRF guard always; allowed_source_hosts where the auto-download
	// policy set the address (netpolicy.go).
	base := c.guarded(acquire.DefaultHTTPClient())
	d, err := buildIntel(ctx, *c.Intel, src, c.WorkDir, c.CatalogURL, c.msClient(base),
		c.sourceClient(base, acqpolicy.UpstreamWingetIndex))
	if err != nil {
		return d, libraryResult{}, err
	}
	backfillRequested(*st, c.Requests)
	libHC := c.sourceClient(c.guarded(libraryHTTP()), acqpolicy.UpstreamWingetManifests)
	lib := addLibrary(ctx, libHC, &d, *c.Intel, c.WingetManifestsURL, configuredLibraryIDs(c), st.Requested, st.Library)
	if lib.ran {
		st.Library = lib.cache
	}
	for _, w := range d.Windows {
		if w.UBR > 0 {
			st.WindowsUBR[strings.ToUpper(w.KB)+"/"+strconv.Itoa(w.Build)] = w.UBR
		}
	}
	p, err := writeIntel(d, c.Key, c.Pub, filepath.Join(c.WorkDir, "intel"))
	if err != nil {
		return d, lib, err
	}
	a, err := adapterFor(c.Send)
	if err != nil {
		return d, lib, err
	}
	if _, err := a.Send(p); err != nil {
		return d, lib, err
	}
	return d, lib, nil
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
	noLibrary := fs.Bool("no-library", false, "skip the Library (winget installer details of common packages)")
	libraryIDs := fs.String("library", "", "comma-separated extra winget ids for the Library")
	manifestsURL := fs.String("winget-manifests-url", "", "winget manifests URL (default: the winget-pkgs repository)")
	fs.Parse(args)
	if *key == "" {
		return fmt.Errorf("-key is required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	o := intelOpts{WingetURL: *wingetURL, NoApps: *noApps, NoWindows: *noWindows, NoLibrary: *noLibrary}
	for _, id := range strings.Split(*libraryIDs, ",") {
		if id = strings.TrimSpace(id); id != "" {
			o.Library = append(o.Library, id)
		}
	}
	d, err := buildIntel(ctx, o, *source, *out, "", nil, nil)
	for _, w := range d.Warnings {
		fmt.Fprintln(os.Stderr, "warning:", w)
	}
	if err != nil {
		return err
	}
	// No state here: every Library entry is looked up (within the budget).
	lib := addLibrary(ctx, nil, &d, o, *manifestsURL, nil, nil, nil)
	for _, w := range lib.warnings {
		fmt.Fprintln(os.Stderr, "warning:", w)
	}
	p, err := writeIntel(d, *key, *pub, *out)
	if err != nil {
		return err
	}
	fmt.Printf("intel:    %s\nwindows:  %d builds\napps:     %d (%s)\n", p, len(d.Windows), len(d.Apps), d.AppsSource)
	if lib.ran {
		fmt.Println(lib.summary())
	}
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
