// pmserver is the isolated-zone management plane: intake, quarantine,
// catalog, approval, repository, deployment orchestration, audit and console.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"offpatch/internal/auditexport"
	"offpatch/internal/backup"
	"offpatch/internal/intake"
	"offpatch/internal/manifest"
	"offpatch/internal/pki"
	"offpatch/internal/repo"
	"offpatch/internal/server"
	"offpatch/internal/store"
	"offpatch/web"
)

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "new-token":
			newToken()
			return
		case "backup", "restore", "verify-backup":
			if err := backupCmd(os.Args[1], os.Args[2:]); err != nil {
				fmt.Fprintln(os.Stderr, "error:", err)
				os.Exit(1)
			}
			return
		case "verify-audit":
			if err := verifyAudit(os.Args[2:]); err != nil {
				fmt.Fprintln(os.Stderr, "error:", err)
				os.Exit(1)
			}
			return
		case "reissue-server-cert":
			if err := reissueCert(os.Args[2:]); err != nil {
				fmt.Fprintln(os.Stderr, "error:", err)
				os.Exit(1)
			}
			return
		case "init-pki":
			if err := initPKI(os.Args[2:]); err != nil {
				fmt.Fprintln(os.Stderr, "error:", err)
				os.Exit(1)
			}
			return
		}
	}
	cfgPath := flag.String("config", "pmserver.json", "path to config file")
	flag.Parse()
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	if err := run(*cfgPath, log); err != nil {
		log.Error("fatal", "err", err)
		os.Exit(1)
	}
}

// newToken prints a random admin token and the hash to put in the config.
func newToken() {
	b := make([]byte, 24)
	rand.Read(b)
	tok := "adm_" + hex.EncodeToString(b)
	fmt.Printf("token:        %s\ntoken_sha256: %s\n", tok, store.HashSecret(tok))
}

func run(cfgPath string, log *slog.Logger) error {
	cfg, err := server.LoadConfig(cfgPath)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(cfg.DataDir, 0o750); err != nil {
		return err
	}
	st, err := store.Open(filepath.Join(cfg.DataDir, "pm.db"))
	if err != nil {
		return err
	}
	defer st.Close()
	rp, err := repo.New(filepath.Join(cfg.DataDir, "repository"))
	if err != nil {
		return err
	}
	icfg, err := cfg.IntakeConfig()
	if err != nil {
		return err
	}
	in, err := intake.New(icfg, st, log.With("component", "intake"))
	if err != nil {
		return err
	}
	if err := in.LoadStoredTrust(context.Background()); err != nil {
		return err
	}
	ui, err := fs.Sub(web.Dist, "dist")
	if err != nil {
		return err
	}

	h, err := server.New(cfg, st, rp, ui, log)
	if err != nil {
		return err
	}
	h.SetIntelKeys(in.ActiveKeys)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go in.Run(ctx)
	go h.RunAlerts(ctx, cfg.AlertSweepEvery.Duration)
	if cfg.AuditExportDir != "" {
		key, err := auditexport.LoadOrCreateKey(filepath.Join(cfg.DataDir, "audit-signing.key"))
		if err != nil {
			return err
		}
		x := &auditexport.Exporter{Store: st, Dir: cfg.AuditExportDir, Key: key, Log: log.With("component", "audit-export")}
		go x.Run(ctx, cfg.AuditCheckpointEvery.Duration, cfg.AuditRetention.Duration)
		log.Info("audit export enabled", "dir", cfg.AuditExportDir, "every", cfg.AuditCheckpointEvery.Duration, "retention", cfg.AuditRetention.Duration,
			"verify_with", filepath.Join(cfg.DataDir, "audit-signing.pub"))
	} else {
		log.Warn("audit_export_dir not set: audit evidence lives only in the database (roadmap B9)")
	}

	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           h.Handler(),
		TLSConfig:         h.TLSConfig(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		srv.Shutdown(sctx)
	}()
	log.Info("pmserver listening", "addr", cfg.Listen, "tls", cfg.TLSCert != "", "mtls_agents", cfg.PKIDir != "", "data", cfg.DataDir, "inbox", icfg.Inbox)
	if cfg.TLSCert != "" && len(srv.TLSConfig.Certificates) > 0 {
		err = srv.ListenAndServeTLS("", "") // certificate chain already loaded in TLSConfig
	} else if cfg.TLSCert != "" {
		err = srv.ListenAndServeTLS(cfg.TLSCert, cfg.TLSKey)
	} else {
		log.Warn("insecure_http: TLS disabled and agents use bearer secrets — isolated lab only (docs/01-decisions.md D10)")
		err = srv.ListenAndServe()
	}
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}

// initPKI creates the internal CA and the server certificate.
func initPKI(args []string) error {
	fs := flag.NewFlagSet("init-pki", flag.ExitOnError)
	dir := fs.String("dir", "pki", "output directory (keep ca.key offline-backed-up and readable only by pmserver)")
	hosts := fs.String("hosts", "", "comma-separated DNS names / IPs endpoints use to reach this server")
	fs.Parse(args)
	if *hosts == "" {
		return fmt.Errorf("-hosts is required, e.g. -hosts pm.corp.internal,10.20.0.5")
	}
	if err := pki.Init(*dir, strings.Split(*hosts, ",")); err != nil {
		return err
	}
	ca, err := pki.Load(*dir)
	if err != nil {
		return err
	}
	fmt.Printf("CA:          %s (fingerprint %s)\nserver cert: %s\nSet \"pki_dir\": %q in pmserver.json and give ca.pem to endpoints (-ca).\n",
		filepath.Join(*dir, pki.CAFile), pki.Fingerprint(ca.Cert)[:32], filepath.Join(*dir, pki.ServerCert), *dir)
	return nil
}

// verifyAudit checks exported audit files and signed checkpoints, optionally
// against the live database (detects a rewritten chain).
func verifyAudit(args []string) error {
	fs := flag.NewFlagSet("verify-audit", flag.ExitOnError)
	dir := fs.String("export", "", "audit export directory (checkpoints.jsonl + audit-*.jsonl)")
	pubPath := fs.String("pub", "", "audit-signing.pub of the server")
	dbPath := fs.String("db", "", "optional: pm.db to cross-check")
	fs.Parse(args)
	if *dir == "" || *pubPath == "" {
		return fmt.Errorf("-export and -pub are required")
	}
	pub, err := manifest.LoadPublic(*pubPath)
	if err != nil {
		return err
	}
	var st *store.Store
	if *dbPath != "" {
		if st, err = store.Open(*dbPath); err != nil {
			return err
		}
		defer st.Close()
	}
	rep, err := auditexport.Verify(context.Background(), *dir, pub, st)
	if err != nil {
		return err
	}
	b, _ := json.MarshalIndent(rep, "", "  ")
	fmt.Println(string(b))
	if !rep.OK {
		return fmt.Errorf("audit verification FAILED")
	}
	return nil
}

// backupCmd implements backup / restore / verify-backup.
func backupCmd(cmd string, args []string) error {
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	cfgPath := fs.String("config", "pmserver.json", "server config")
	dir := fs.String("dir", "", "backup directory")
	noPKI := fs.Bool("no-pki", false, "backup: exclude the CA private key and server key")
	force := fs.Bool("force", false, "restore: overwrite an existing database (stop the server first)")
	fs.Parse(args)
	if *dir == "" {
		return fmt.Errorf("-dir is required")
	}
	ctx := context.Background()
	if cmd == "verify-backup" {
		m, err := backup.Verify(*dir)
		if err != nil {
			return err
		}
		fmt.Printf("backup OK: %d files, created %s, audit seq %d\n", len(m.Files), m.CreatedAt, m.AuditSeq)
		return nil
	}
	cfg, err := server.LoadConfig(*cfgPath)
	if err != nil {
		return err
	}
	l := backup.Layout{DataDir: cfg.DataDir, PKIDir: cfg.PKIDir, ConfigFile: *cfgPath}
	if cmd == "restore" {
		m, err := backup.Restore(ctx, *dir, l, *force)
		if err != nil {
			return err
		}
		fmt.Printf("restored %d files into %s; audit chain verified to seq %d; approved content verified\n", len(m.Files), cfg.DataDir, m.AuditSeq)
		return nil
	}
	st, err := store.Open(filepath.Join(cfg.DataDir, "pm.db"))
	if err != nil {
		return err
	}
	defer st.Close()
	m, err := backup.Create(ctx, st, l, *dir, !*noPKI)
	if err != nil {
		return err
	}
	if !*noPKI && cfg.PKIDir != "" {
		fmt.Println("WARNING: backup contains the CA private key — store it encrypted and access-controlled")
	}
	fmt.Printf("backup written to %s: %d files, audit seq %d\nverify with: pmserver verify-backup -dir %s\n", *dir, len(m.Files), m.AuditSeq, *dir)
	return nil
}

// reissueCert replaces server.pem/server.key (e.g. before the 2-year expiry
// or when host names change) using the existing CA; agents keep trusting it.
func reissueCert(args []string) error {
	fs := flag.NewFlagSet("reissue-server-cert", flag.ExitOnError)
	dir := fs.String("dir", "pki", "PKI directory containing ca.pem and ca.key")
	hosts := fs.String("hosts", "", "comma-separated DNS names / IPs")
	fs.Parse(args)
	if *hosts == "" {
		return fmt.Errorf("-hosts is required")
	}
	ca, err := pki.Load(*dir)
	if err != nil {
		return err
	}
	for _, f := range []string{pki.ServerCert, pki.ServerKey} {
		p := filepath.Join(*dir, f)
		if _, err := os.Stat(p); err == nil {
			if err := os.Rename(p, p+".old"); err != nil {
				return err
			}
		}
	}
	if err := ca.IssueServer(*dir, strings.Split(*hosts, ",")); err != nil {
		return err
	}
	fmt.Printf("new server certificate written to %s (previous kept as *.old); restart pmserver to use it\n", filepath.Join(*dir, pki.ServerCert))
	return nil
}
