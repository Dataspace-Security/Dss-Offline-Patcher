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
	"sync"
	"syscall"
	"time"
	_ "time/tzdata" // maintenance windows and deadlines resolve zones on hosts without tzdata

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
		case "create-admin", "reset-admin":
			if err := adminCmd(os.Args[1], os.Args[2:]); err != nil {
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
	// Background work (intake, alerts, audit export) and in-flight requests
	// finish before the database closes (deferred above, so it runs after
	// this): an intake stopped mid-way is re-ingested on the next start.
	var wg sync.WaitGroup
	background := func(f func()) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			f()
		}()
	}
	defer func() {
		stop()
		wg.Wait()
		log.Info("pmserver stopped")
	}()
	background(func() { in.Run(ctx) })
	background(func() { h.RunAlerts(ctx, cfg.AlertSweepEvery.Duration) })
	if cfg.AuditExportDir != "" {
		key, err := auditexport.LoadOrCreateKey(filepath.Join(cfg.DataDir, "audit-signing.key"))
		if err != nil {
			return err
		}
		x := &auditexport.Exporter{Store: st, Dir: cfg.AuditExportDir, Key: key, Log: log.With("component", "audit-export")}
		background(func() { x.Run(ctx, cfg.AuditCheckpointEvery.Duration, cfg.AuditRetention.Duration) })
		log.Info("audit export enabled", "dir", cfg.AuditExportDir, "every", cfg.AuditCheckpointEvery.Duration, "retention", cfg.AuditRetention.Duration,
			"verify_with", filepath.Join(cfg.DataDir, "audit-signing.pub"))
	} else {
		log.Warn("audit_export_dir not set: audit evidence lives only in the database (roadmap B9)")
	}

	if d := cfg.AcquisitionRequestsDir; d != "" {
		if err := server.CheckAcquisitionRequestsDir(d); err != nil {
			log.Warn("acquisition_requests_dir not writable: requests will not be queued directly (operators carry the downloaded file)", "dir", d, "err", err)
		} else {
			log.Info("acquisition requests are queued directly (co-located acquisition)", "dir", d)
		}
	}

	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           h.Handler(),
		TLSConfig:         h.TLSConfig(),
		ReadHeaderTimeout: 10 * time.Second,
		// Bounds reading a request (headers + body: check-ins, reports). No
		// WriteTimeout: content downloads stream for as long as they take.
		ReadTimeout:    5 * time.Minute,
		IdleTimeout:    2 * time.Minute,
		MaxHeaderBytes: 64 << 10,
	}
	background(func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := srv.Shutdown(sctx); err != nil {
			log.Warn("shutdown: in-flight requests did not finish", "err", err)
		}
	})
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

// adminCmd: create-admin creates the built-in super admin (the vendor)
// with a generated password; reset-admin gives an existing local super
// admin a new generated password (recovery, as root on the server). The
// password is printed once and only its PBKDF2 hash is stored. Run as the
// service user so the database keeps its owner.
func adminCmd(cmd string, args []string) error {
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	cfgPath := fs.String("config", "pmserver.json", "server config")
	email := fs.String("email", "", "sign-in email of the super admin")
	name := fs.String("name", "Vendor support", "create-admin: display name")
	ifNone := fs.Bool("if-none", false, "create-admin: do nothing when an enabled local super admin already exists (installer upgrades)")
	fs.Parse(args)
	if *email == "" {
		return fmt.Errorf("-email is required")
	}
	cfg, err := server.LoadConfig(*cfgPath)
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
	st.Policy.ReservedUsers = map[string]bool{}
	for _, t := range cfg.AdminTokens {
		st.Policy.ReservedUsers[strings.ToLower(t.User)] = true
	}
	ctx := context.Background()
	pw := store.GeneratePassword()
	if cmd == "reset-admin" {
		if err := st.RecoverSuperAdmin(ctx, *email, pw); err != nil {
			return err
		}
		e, _ := store.NormalizeEmail(*email)
		fmt.Printf("super admin password reset (shown ONCE; other sessions of this account ended)\nemail:    %s\npassword: %s\n", e, pw)
		return nil
	}
	if *ifNone {
		has, err := st.HasLocalSuperAdmin(ctx)
		if err != nil {
			return err
		}
		if has {
			fmt.Println("a local super admin already exists; nothing to do (lost the password? pmserver reset-admin -email ...)")
			return nil
		}
	}
	u, err := st.CreateBuiltinSuperAdmin(ctx, *email, *name, pw)
	if err != nil {
		return err
	}
	fmt.Printf("created the built-in super admin (password shown ONCE; only its hash is stored)\nemail:    %s\npassword: %s\n", u.Email, pw)
	return nil
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
