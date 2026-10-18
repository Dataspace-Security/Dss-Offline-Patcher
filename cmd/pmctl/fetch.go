package main

// Acquisition subcommands (connected zone only): catalog-search, fetch,
// msrc, fetch-url. They find and download vendor files, verify them, and
// write spec.json entries for `pmctl build`. See docs/08-acquisition.md.

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"text/tabwriter"

	"offpatch/internal/acquire"
)

// Injectable for tests.
var (
	catalogBaseURL           = acquire.DefaultCatalogURL
	msrcBaseURL              = acquire.DefaultMSRCURL
	newHTTPClient            = acquire.DefaultHTTPClient
	progressOut    io.Writer = os.Stderr
)

func newCatalog() *acquire.Catalog {
	return &acquire.Catalog{BaseURL: catalogBaseURL, HTTP: newHTTPClient()}
}

func newMSRC() *acquire.MSRC {
	return &acquire.MSRC{BaseURL: msrcBaseURL, HTTP: newHTTPClient()}
}

// interruptible returns a context cancelled on Ctrl-C; an interrupted
// download leaves its .part file so the next run resumes.
func interruptible() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt)
}

// progressPrinter returns a progress callback and a finish func that ends the
// progress line (only if something was printed).
func progressPrinter(name string) (func(done, total int64), func()) {
	printed := false
	finish := func() {
		if printed {
			fmt.Fprintln(progressOut)
		}
	}
	return func(done, total int64) {
		printed = true
		if total > 0 {
			fmt.Fprintf(progressOut, "\r  %s  %6.1f%%  %d/%d bytes", name, float64(done)*100/float64(total), done, total)
		} else {
			fmt.Fprintf(progressOut, "\r  %s  %d bytes", name, done)
		}
	}, finish
}

func catalogSearch(args []string) error {
	fs := flag.NewFlagSet("catalog-search", flag.ContinueOnError)
	q := fs.String("q", "", "catalog search query, e.g. KB5044273")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *q == "" {
		return errors.New("-q is required")
	}
	ctx, cancel := interruptible()
	defer cancel()
	res, err := newCatalog().Search(ctx, *q)
	if err != nil {
		return err
	}
	if len(res.Updates) == 0 {
		fmt.Printf("no results for %q\n", *q)
		return nil
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "UPDATE ID\tLAST UPDATED\tCLASSIFICATION\tSIZE\tVERSION\tPRODUCTS\tTITLE")
	for _, u := range res.Updates {
		v := u.Version
		if v == "" {
			v = "-"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", u.ID, u.LastUpdated, u.Classification, u.Size, v, u.Products, u.Title)
	}
	tw.Flush()
	if res.Summary != "" {
		fmt.Printf("(%s; only the first page is shown — refine the query to narrow it)\n", res.Summary)
	}
	return nil
}

func fetchKB(args []string) error {
	fs := flag.NewFlagSet("fetch", flag.ContinueOnError)
	var o acquire.FetchKBOptions
	fs.StringVar(&o.KB, "kb", "", "KB number, e.g. KB5044273")
	fs.StringVar(&o.Product, "product", "", `product substring matched against the catalog title/products, e.g. "Windows 10 Version 22H2"`)
	fs.StringVar(&o.Arch, "arch", "x64", "x64|x86|arm64")
	fs.StringVar(&o.Match, "match", "", "extra title substring to disambiguate catalog rows (optional)")
	fs.StringVar(&o.FileMatch, "file", "", "file name substring when an update has several files (optional)")
	fs.IntVar(&o.MinBuild, "min-build", 0, "applicability min OS build")
	fs.IntVar(&o.MaxBuild, "max-build", 0, "applicability max OS build (0 = no max)")
	fs.StringVar(&o.Severity, "severity", "", "critical|important|moderate|low (default: from -msrc-month, else catalog, else important)")
	fs.StringVar(&o.MSRCMonth, "msrc-month", "", "look up severity in the MSRC release, e.g. 2026-Oct")
	fs.StringVar(&o.ProductCode, "product-code", "", "{GUID}; only needed if the catalog file is an .msi")
	fs.BoolVar(&o.RecordUBR, "expected-ubr", false, "record expected_ubr from the catalog title (only once every agent runs 0.6.5 or later; older agents refuse the bundle)")
	fs.StringVar(&o.PackageID, "package-id", "", "package id (default <KB>-<arch>)")
	fs.StringVar(&o.OutDir, "out", "", "download directory")
	fs.StringVar(&o.SpecPath, "spec", "", "spec.json to append to / update")
	if err := fs.Parse(args); err != nil {
		return err
	}
	ctx, cancel := interruptible()
	defer cancel()
	var done func()
	o.Progress, done = progressPrinter(o.KB)
	res, err := acquire.FetchKB(ctx, newCatalog(), newMSRC(), o)
	done()
	if err != nil {
		return err
	}
	printFetchResult(res, o.SpecPath)
	return nil
}

func fetchURL(args []string) error {
	fs := flag.NewFlagSet("fetch-url", flag.ContinueOnError)
	var o acquire.FetchURLOptions
	var sup string
	fs.StringVar(&o.URL, "url", "", "vendor download URL (https only)")
	fs.StringVar(&o.SHA256, "sha256", "", "expected SHA-256 published by the vendor (required)")
	fs.StringVar(&o.FileName, "file", "", "local file name (default: last URL path segment)")
	fs.StringVar(&o.PackageID, "package-id", "", "package id, e.g. AcmeAgent-2.1")
	fs.StringVar(&o.Title, "title", "", "package title")
	fs.StringVar(&o.Vendor, "vendor", "", "vendor name")
	fs.StringVar(&o.Kind, "kind", "", "msi|msu|deb|rpm|pkg|agent (default from file extension)")
	fs.StringVar(&o.ProductCode, "product-code", "", "{GUID} (required for msi)")
	fs.StringVar(&o.PackageName, "package-name", "", "package name (deb/rpm) or pkg receipt id (macOS); required for those kinds")
	fs.StringVar(&o.OS, "os", "", "windows|linux|macos (default from -kind; needed for agent packages)")
	fs.StringVar(&o.KB, "kb", "", "KB number (required for msu)")
	fs.StringVar(&o.Version, "version", "", "version")
	fs.StringVar(&o.Severity, "severity", "", "critical|important|moderate|low")
	fs.StringVar(&o.ReleaseDate, "release-date", "", "YYYY-MM-DD (default today)")
	fs.StringVar(&sup, "supersedes", "", "comma-separated KBs this package supersedes")
	fs.StringVar(&o.Arch, "arch", "any", "x64|x86|arm64|any")
	fs.IntVar(&o.MinBuild, "min-build", 0, "applicability min OS build")
	fs.IntVar(&o.MaxBuild, "max-build", 0, "applicability max OS build (0 = no max)")
	fs.StringVar(&o.OutDir, "out", "", "download directory")
	fs.StringVar(&o.SpecPath, "spec", "", "spec.json to append to / update")
	if err := fs.Parse(args); err != nil {
		return err
	}
	for _, s := range strings.Split(sup, ",") {
		if s = strings.TrimSpace(s); s != "" {
			o.Supersedes = append(o.Supersedes, s)
		}
	}
	ctx, cancel := interruptible()
	defer cancel()
	o.HTTP = newHTTPClient()
	var done func()
	o.Progress, done = progressPrinter(o.PackageID)
	res, err := acquire.FetchURL(ctx, o)
	done()
	if err != nil {
		return err
	}
	printFetchResult(res, o.SpecPath)
	return nil
}

func printFetchResult(res *acquire.FetchResult, specPath string) {
	for _, w := range res.Warnings {
		fmt.Fprintln(os.Stderr, "warning:", w)
	}
	e := res.Entry
	if res.Update != nil {
		fmt.Printf("catalog:    %s  %s\n", res.Update.ID, res.Update.Title)
	}
	state := "downloaded"
	switch {
	case res.Download.Reused:
		state = "already present, verified"
	case res.Download.Resumed:
		state = "downloaded (resumed), verified"
	default:
		state += ", verified"
	}
	fmt.Printf("file:       %s (%d bytes, %s)\n", res.Download.Path, res.Download.Size, state)
	fmt.Printf("verified:   %s\n", e.Acquired.Verified)
	fmt.Printf("sha256:     %s\n", res.Download.SHA256)
	fmt.Printf("package:    %s  kind=%s severity=%s release=%s arch=%s builds=%d..%d\n",
		e.PackageID, e.Kind, e.Severity, e.ReleaseDate, e.Applicability.Arch, e.Applicability.MinBuild, e.Applicability.MaxBuild)
	if len(e.Supersedes) > 0 {
		fmt.Printf("supersedes: %s\n", strings.Join(e.Supersedes, ", "))
	}
	if len(e.Prerequisites) > 0 {
		fmt.Printf("requires:   %s (checkpoint updates)\n", strings.Join(e.Prerequisites, ", "))
	}
	for _, pe := range res.Prerequisites {
		fmt.Printf("checkpoint: %s  %s (also added to the spec)\n", pe.PackageID, pe.Path)
	}
	action := "added to"
	if res.Replaced {
		action = "replaced in"
	}
	fmt.Printf("spec:       %s %s (vendor_signature is filled in by `pmctl build`)\n", action, specPath)
}

func msrcCmd(args []string) error {
	fs := flag.NewFlagSet("msrc", flag.ContinueOnError)
	month := fs.String("month", "", "release month, e.g. 2026-Oct")
	product := fs.String("product", "", `only KBs for products containing this text, e.g. "Windows 10"`)
	arch := fs.String("arch", "", "optionally narrow products to x64|x86|arm64")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *month == "" {
		return errors.New("-month is required, e.g. 2026-Oct")
	}
	ctx, cancel := interruptible()
	defer cancel()
	list, err := newMSRC().Month(ctx, *month)
	if err != nil {
		return err
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "KB\tSEVERITY\tCVES\tPRODUCTS")
	n := 0
	for _, u := range list {
		if *product != "" || *arch != "" {
			var ok bool
			if u, ok = u.ForProduct(*product, *arch); !ok {
				continue
			}
		}
		sev := u.Severity
		if sev == "" {
			sev = "-"
		}
		fmt.Fprintf(tw, "%s\t%s\t%d\t%s\n", u.KB, sev, len(u.CVEs), strings.Join(u.Products, "; "))
		n++
	}
	tw.Flush()
	fmt.Printf("(%d KBs in MSRC %s release)\n", n, *month)
	return nil
}
