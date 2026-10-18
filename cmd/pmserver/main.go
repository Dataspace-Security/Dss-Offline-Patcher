// pmserver is the isolated-zone management plane: intake, quarantine,
// catalog, approval, repository, deployment orchestration, audit and console.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
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
	"offpatch/internal/compliance"
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
		case "enroll-token":
			if err := enrollTokenCmd(os.Args[2:], os.Stdout); err != nil {
				fmt.Fprintln(os.Stderr, "error:", err)
				os.Exit(1)
			}
			return
		case "backup", "restore", "verify-backup":
			if err := backupCmd(os.Args[1], os.Args[2:]); err != nil {
				fmt.Fprintln(os.Stderr, "error:", err)
				os.Exit(1)
			}
			return
		case "verify-report":
			if err := verifyReport(os.Args[2:]); err != nil {
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
	if who, err := st.DefaultSuperAdminPasswordInUse(context.Background()); err != nil {
		return err
	} else if len(who) > 0 {
		log.Warn("the built-in super admin still uses the vendor's default password: sign in to the console and change it", "users", strings.Join(who, ","))
	}

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

// adminCmd: create-admin creates the built-in super admin (the vendor),
// by default DefaultSuperAdminEmail with the vendor's default password
// (only its PBKDF2 hash is embedded; the console asks for a new one at the
// first sign-in), or with -password-random a generated password printed
// once. reset-admin gives an existing local super admin a new generated
// password (recovery, as root on the server; printed once). Run as the
// service user so the database keeps its owner.
func adminCmd(cmd string, args []string) error { return runAdminCmd(cmd, args, os.Stdout) }

func runAdminCmd(cmd string, args []string, out io.Writer) error {
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	cfgPath := fs.String("config", "pmserver.json", "server config")
	email := fs.String("email", store.DefaultSuperAdminEmail, "sign-in email of the super admin")
	name := fs.String("name", "Vendor support", "create-admin: display name")
	ifNone := fs.Bool("if-none", false, "create-admin: do nothing when an enabled local super admin already exists (installer upgrades)")
	random := fs.Bool("password-random", false, "create-admin: a generated password (shown once) instead of the vendor's default password")
	if err := fs.Parse(args); err != nil {
		return err
	}
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
	ctx := context.Background()
	if cmd == "reset-admin" {
		pw := store.GeneratePassword()
		if err := st.RecoverSuperAdmin(ctx, *email, pw); err != nil {
			return err
		}
		e, _ := store.NormalizeEmail(*email)
		fmt.Fprintf(out, "super admin password reset, MFA cleared (password shown ONCE; other sessions of this account ended)\nemail:    %s\npassword: %s\n", e, pw)
		return nil
	}
	if *ifNone {
		has, err := st.HasLocalSuperAdmin(ctx)
		if err != nil {
			return err
		}
		if has {
			fmt.Fprintln(out, "a local super admin already exists; nothing to do (lost the password? pmserver reset-admin -email ...)")
			return nil
		}
	}
	if !*random {
		u, err := st.CreateBuiltinSuperAdminDefault(ctx, *email, *name)
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "created the built-in super admin with the default password (see the vendor handbook); change it after the first sign-in\nemail:    %s\ndefault_password: yes\n", u.Email)
		return nil
	}
	pw := store.GeneratePassword()
	u, err := st.CreateBuiltinSuperAdmin(ctx, *email, *name, pw)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "created the built-in super admin (password shown ONCE; only its hash is stored)\nemail:    %s\npassword: %s\n", u.Email, pw)
	return nil
}

// enrollTokenCmd: pmserver enroll-token prints a one-use enrollment token
// (the installer's --with-agent; audited as created by system:cli).
func enrollTokenCmd(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("enroll-token", flag.ContinueOnError)
	cfgPath := fs.String("config", "pmserver.json", "server config")
	groups := fs.String("groups", "", "comma-separated endpoint groups")
	site := fs.String("site", "", "site")
	hours := fs.Int("hours", 1, "valid for this many hours")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := server.LoadConfig(*cfgPath)
	if err != nil {
		return err
	}
	st, err := store.Open(filepath.Join(cfg.DataDir, "pm.db"))
	if err != nil {
		return err
	}
	defer st.Close()
	var gs []string
	for _, g := range strings.Split(*groups, ",") {
		if g = strings.TrimSpace(g); g != "" {
			gs = append(gs, g)
		}
	}
	t, err := st.CreateEnrollmentToken(context.Background(), "system:cli", gs, *site, *hours, 1)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "token: %s\nexpires_at: %s\n", t.Token, t.ExpiresAt)
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

// verifyReport checks a compliance evidence package offline: the manifest
// signature (with the server's audit-signing.pub, obtained independently)
// and every file's SHA-256.
func verifyReport(args []string) error {
	fs := flag.NewFlagSet("verify-report", flag.ExitOnError)
	zipPath := fs.String("zip", "", "compliance-*.zip downloaded from Reports")
	pubPath := fs.String("pub", "", "audit-signing.pub of the server")
	fs.Parse(args)
	if *zipPath == "" || *pubPath == "" {
		return fmt.Errorf("-zip and -pub are required")
	}
	pub, err := manifest.LoadPublic(*pubPath)
	if err != nil {
		return err
	}
	b, err := os.ReadFile(*zipPath)
	if err != nil {
		return err
	}
	m, err := compliance.VerifyZip(b, pub)
	if err != nil {
		return fmt.Errorf("compliance package verification FAILED: %w", err)
	}
	fmt.Printf("compliance package OK: report %s, period %s to %s, generated %s by %s, %d files, key %s\n",
		m.ReportID, m.Period.From, m.Period.To, m.GeneratedAt, m.GeneratedBy.User, len(m.Files), m.PublicKeyFingerprint)
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
		// Restore evidence for the compliance report (PM-16), in the restored database.
		if st, err := store.Open(filepath.Join(cfg.DataDir, "pm.db")); err == nil {
			st.Audit(ctx, store.Ev{Actor: "system:backup", Action: "backup.restored", ObjectType: "backup", ObjectID: *dir,
				Details: map[string]any{"files": len(m.Files), "backup_created_at": m.CreatedAt, "audit_seq": m.AuditSeq}})
			st.Close()
		}
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
	// Backup evidence for the compliance report (PM-12 / PM-16).
	if err := st.Audit(ctx, store.Ev{Actor: "system:backup", Action: "backup.created", ObjectType: "backup", ObjectID: *dir,
		Details: map[string]any{"files": len(m.Files), "audit_seq": m.AuditSeq, "include_pki": m.IncludePKI, "created_at": m.CreatedAt}}); err != nil {
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
