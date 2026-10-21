// pmserver is the isolated-zone management plane: intake, quarantine,
// catalog, approval, repository, deployment orchestration, audit and console.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"
	_ "time/tzdata" // maintenance windows and deadlines resolve zones on hosts without tzdata

	"offpatch/internal/auditexport"
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
		case "backup", "restore", "verify-backup", "decrypt-backup":
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
		case "setup-code":
			if err := setupCodeCmd(os.Args[2:], os.Stdout); err != nil {
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
		case "policy-key":
			if err := policyKeyCmd(os.Args[2:], os.Stdout); err != nil {
				fmt.Fprintln(os.Stderr, "error:", err)
				os.Exit(1)
			}
			return
		case "backup-keygen":
			if err := backupKeygenCmd(os.Args[2:], os.Stdout); err != nil {
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
		log.Warn("the built-in super admin still uses the vendor's default password: sign in with it and the setup code (pmserver setup-code) and change it", "users", strings.Join(who, ","))
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
			h.QueueSignedPolicy(ctx) // signed copy of the policy in force (S-4), once per version and key
		}
	}

	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           h.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		// Bounds reading a request (headers + body: check-ins, reports). No
		// WriteTimeout: content downloads stream for as long as they take.
		ReadTimeout:    5 * time.Minute,
		IdleTimeout:    2 * time.Minute,
		MaxHeaderBytes: 64 << 10,
	}
	// SIGHUP (systemctl reload offpatch-server, the certbot deploy hook)
	// re-reads the public console certificate now; it is also re-read within
	// a minute of its files changing. Handled even without public_tls, so a
	// leftover hook never terminates the server.
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	background(func() {
		defer signal.Stop(hup)
		for {
			select {
			case <-ctx.Done():
				return
			case <-hup:
				if cfg.PublicTLS == nil {
					log.Info("SIGHUP: nothing to reload (public_tls is not configured)")
					continue
				}
				log.Info("SIGHUP: reloading the public console certificate")
				h.ReloadPublicCert()
			}
		}
	})
	if cfg.PublicTLS != nil {
		log.Info("public console certificate enabled: browsers on these names get it; agents keep the internal CA",
			"names", strings.Join(cfg.PublicTLS.Names, ","), "cert_file", cfg.PublicTLS.CertFile)
	}
	h.ConfigureHTTPServer(srv) // TLS (internal + public certificate) and connection hooks
	proxyFailed := make(chan error, 1)
	psrv, err := startConsoleProxy(cfg, h, log, proxyFailed)
	if err != nil {
		return err
	}
	var proxyErr error
	background(func() {
		select {
		case <-ctx.Done():
		case proxyErr = <-proxyFailed: // the console listener died: stop, do not run half-reachable
			log.Error("console proxy listener failed; stopping", "err", proxyErr)
		}
		sctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if psrv != nil {
			if err := psrv.Shutdown(sctx); err != nil {
				log.Warn("shutdown: in-flight console proxy requests did not finish", "err", err)
			}
		}
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
		stop()
		wg.Wait()
		return proxyErr
	}
	return err
}

// adminCmd: create-admin creates the built-in super admin (the vendor),
// by default DefaultSuperAdminEmail with the vendor's default password
// (only its PBKDF2 hash is embedded; the console asks for a new one at the
// first sign-in), or with -password-random a generated password printed
// once. It never fails because the account already exists (enabled or
// disabled): it reports that and changes nothing, so installer re-runs stay
// idempotent. -if-fresh creates the account only in a database that has no
// users at all (a fresh install; upgrades never create users). reset-admin
// gives an existing local super admin a new generated password (recovery, as
// root on the server; printed once). Run as the service user so the database
// keeps its owner.
func adminCmd(cmd string, args []string) error { return runAdminCmd(cmd, args, os.Stdout) }

func runAdminCmd(cmd string, args []string, out io.Writer) error {
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	cfgPath := fs.String("config", "pmserver.json", "server config")
	email := fs.String("email", store.DefaultSuperAdminEmail, "sign-in email of the super admin")
	name := fs.String("name", "Vendor support", "create-admin: display name")
	ifNone := fs.Bool("if-none", false, "create-admin: do nothing when an enabled local super admin already exists")
	ifFresh := fs.Bool("if-fresh", false, "create-admin: create only when the database has no users at all (fresh install; the installer uses this)")
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
	users, err := st.ListUsers(ctx)
	if err != nil {
		return fmt.Errorf("list users: %w", err)
	}
	if *ifFresh && len(users) > 0 {
		fmt.Fprintf(out, "the database already has %d user(s): not a fresh install; no account created (lost the password? pmserver reset-admin -email ...)\n", len(users))
		return nil
	}
	if msg, exists := existingAccount(users, *email); exists {
		fmt.Fprintln(out, msg)
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

// setupCodeCmd: pmserver setup-code gives the built-in super admin, while
// it still has the vendor's default password, a new one-time setup code
// (replacing an earlier one), printed once: the first sign-in needs it with
// the default password (store/setupcode.go). Only its hash is stored. With
// -if-needed (the installer) an account that does not exist or has its own
// password is not an error: nothing is printed but a note.
func setupCodeCmd(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("setup-code", flag.ContinueOnError)
	cfgPath := fs.String("config", "pmserver.json", "server config")
	email := fs.String("email", store.DefaultSuperAdminEmail, "sign-in email of the built-in super admin")
	ifNeeded := fs.Bool("if-needed", false, "succeed without a code when the account has its own password or does not exist")
	if err := fs.Parse(args); err != nil {
		return err
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
	if !cfg.RequireSetupCode {
		if *ifNeeded {
			fmt.Fprintln(out, "no setup code needed: not required (require_setup_code is off)")
			return nil
		}
		return fmt.Errorf("setup codes are off: set \"require_setup_code\": true in %s first", *cfgPath)
	}
	emailSet := false
	fs.Visit(func(f *flag.Flag) { emailSet = emailSet || f.Name == "email" })
	if !emailSet {
		// The built-in account may have been created under another e-mail
		// (install-ubuntu.sh --admin-email): pick the account that still has
		// the default password.
		who, err := st.DefaultSuperAdminPasswordInUse(context.Background())
		if err != nil {
			return err
		}
		if len(who) > 0 && !slices.Contains(who, store.DefaultSuperAdminEmail) {
			*email = who[0]
		}
	}
	code, expires, err := st.CreateSetupCode(context.Background(), *email)
	if *ifNeeded && (errors.Is(err, store.ErrNotFound) || errors.Is(err, store.ErrConflict)) {
		fmt.Fprintln(out, "no setup code needed:", err)
		return nil
	}
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "setup code for the first sign-in (shown ONCE; only its hash is stored; valid until the password is changed)\nemail:      %s\nsetup_code: %s\nexpires_at: %s\n",
		strings.ToLower(strings.TrimSpace(*email)), code, expires.Format("2006-01-02T15:04:05Z"))
	return nil
}

// existingAccount reports an account that already uses email (any state,
// any role), so create-admin can stop without a conflict error.
func existingAccount(users []store.User, email string) (string, bool) {
	e, err := store.NormalizeEmail(email)
	if err != nil {
		return "", false // createLocalUser reports the invalid email
	}
	for _, u := range users {
		if !strings.EqualFold(u.Username, e) {
			continue
		}
		state := "enabled"
		if u.Disabled {
			state = "disabled (re-enable it in Settings -> Users, or pmserver reset-admin -email " + e + ")"
		}
		return fmt.Sprintf("a user %s already exists (role %s, %s); nothing to do", e, u.Role, state), true
	}
	return "", false
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
