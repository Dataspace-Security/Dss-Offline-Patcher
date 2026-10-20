package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"offpatch/internal/auditexport"
	"offpatch/internal/backup"
	"offpatch/internal/manifest"
	"offpatch/internal/server"
	"offpatch/internal/store"
)

// Default recipient files, next to the config (written by the installer).
const (
	recipientsFile     = "backup-recipients.txt"
	keyRecipientsFile  = "backup-keys-recipients.txt"
	plaintextBackupMsg = "WARNING: this backup is NOT encrypted (format 1, made by an earlier version): it holds the CA key, mfa.key and the audit-signing key in plaintext. Delete it once a newer encrypted backup is verified."
)

// backupCmd implements backup / restore / verify-backup / decrypt-backup.
func backupCmd(cmd string, args []string) error {
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	cfgPath := fs.String("config", "pmserver.json", "server config")
	dir := fs.String("dir", "", "backup directory")
	noPKI := fs.Bool("no-pki", false, "backup: exclude the CA private key and server key")
	force := fs.Bool("force", false, "restore: overwrite an existing database (stop the server first)")
	recips := fs.String("recipients", "", "backup: age recipients file (default: "+recipientsFile+" next to -config)")
	keyRecips := fs.String("keys-recipients", "", "backup: other recipients for keys.tar.age (default: "+keyRecipientsFile+" next to -config if present, else -recipients)")
	identity := fs.String("identity", "", "restore / decrypt-backup / verify-backup: the bank's backup identity (private key) file")
	pubPath := fs.String("pub", "", "verify-backup / restore / decrypt-backup: the server's audit-signing.pub (default: from data_dir of -config)")
	out := fs.String("out", "", "decrypt-backup: new directory for the decrypted files")
	fs.Parse(args)
	if *dir == "" {
		return fmt.Errorf("-dir is required")
	}
	ctx := context.Background()
	if cmd == "backup" {
		return createBackup(ctx, *cfgPath, *dir, *recips, *keyRecips, !*noPKI)
	}
	o, err := verifyOptions(*cfgPath, *pubPath, *identity)
	if err != nil {
		return err
	}
	switch cmd {
	case "verify-backup":
		m, err := backup.Verify(*dir, o)
		if err != nil {
			return err
		}
		if !m.Encrypted() {
			fmt.Println(plaintextBackupMsg)
		}
		what := "signature and encrypted parts verified"
		if len(o.Identities) > 0 {
			what = "signature verified, decrypted, every file verified"
		}
		if !m.Encrypted() {
			what = "every file verified"
		}
		fmt.Printf("backup OK: %d files, created %s, audit seq %d (%s)\n", len(m.Files), m.CreatedAt, m.AuditSeq, what)
		return nil
	case "decrypt-backup":
		if *out == "" {
			return errors.New("-out is required: a new directory for the decrypted files")
		}
		m, err := backup.Decrypt(*dir, *out, o)
		if err != nil {
			return err
		}
		fmt.Printf("decrypted %d files into %s (an unencrypted backup: it holds every key in plaintext; delete it when done)\n", len(m.Files), *out)
		return nil
	}
	cfg, err := server.LoadConfig(*cfgPath)
	if err != nil {
		return err
	}
	l := backup.Layout{DataDir: cfg.DataDir, PKIDir: cfg.PKIDir, ConfigFile: *cfgPath}
	m, err := backup.Restore(ctx, *dir, l, *force, o)
	if err != nil {
		return err
	}
	if !m.Encrypted() {
		fmt.Println(plaintextBackupMsg)
	}
	fmt.Printf("restored %d files into %s; audit chain verified to seq %d; approved content verified\n", len(m.Files), cfg.DataDir, m.AuditSeq)
	// Restore evidence for the compliance report (PM-16), in the restored database.
	if st, err := store.Open(filepath.Join(cfg.DataDir, "pm.db")); err == nil {
		st.Audit(ctx, store.Ev{Actor: "system:backup", Action: "backup.restored", ObjectType: "backup", ObjectID: *dir,
			Details: map[string]any{"files": len(m.Files), "backup_created_at": m.CreatedAt, "audit_seq": m.AuditSeq, "format": m.Format}})
		st.Close()
	}
	return nil
}

func createBackup(ctx context.Context, cfgPath, dir, recips, keyRecips string, includePKI bool) error {
	cfg, err := server.LoadConfig(cfgPath)
	if err != nil {
		return err
	}
	if recips == "" {
		recips = filepath.Join(filepath.Dir(cfgPath), recipientsFile)
		if _, err := os.Stat(recips); errors.Is(err, os.ErrNotExist) {
			return backup.ErrNoRecipients
		}
	}
	o := backup.Options{IncludePKI: includePKI}
	if o.Recipients, err = backup.LoadRecipients(recips); err != nil {
		return err
	}
	if keyRecips == "" {
		if p := filepath.Join(filepath.Dir(cfgPath), keyRecipientsFile); fileExists(p) {
			keyRecips = p
		}
	}
	if keyRecips != "" {
		if o.KeyRecipients, err = backup.LoadRecipients(keyRecips); err != nil {
			return err
		}
	}
	if o.SigningKey, err = auditexport.LoadOrCreateKey(filepath.Join(cfg.DataDir, "audit-signing.key")); err != nil {
		return fmt.Errorf("audit-signing key (signs backup.json): %w", err)
	}
	st, err := store.Open(filepath.Join(cfg.DataDir, "pm.db"))
	if err != nil {
		return err
	}
	defer st.Close()
	l := backup.Layout{DataDir: cfg.DataDir, PKIDir: cfg.PKIDir, ConfigFile: cfgPath}
	m, err := backup.Create(ctx, st, l, dir, o)
	if err != nil {
		return err
	}
	// Backup evidence for the compliance report (PM-12 / PM-16).
	if err := st.Audit(ctx, store.Ev{Actor: "system:backup", Action: "backup.created", ObjectType: "backup", ObjectID: dir,
		Details: map[string]any{"files": len(m.Files), "audit_seq": m.AuditSeq, "include_pki": m.IncludePKI, "created_at": m.CreatedAt,
			"encrypted_to": m.Recipients, "signed_by": m.Signature.KeyID}}); err != nil {
		return err
	}
	fmt.Printf("encrypted backup written to %s: %d files, audit seq %d, signed by %s\nverify with: pmserver verify-backup -config %s -dir %s\n",
		dir, len(m.Files), m.AuditSeq, m.Signature.KeyID, cfgPath, dir)
	return nil
}

func fileExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.Mode().IsRegular()
}

// verifyOptions: the audit-signing public key (-pub, else data_dir of
// -config when it can be read) and the backup identity (-identity).
func verifyOptions(cfgPath, pubPath, identity string) (backup.VerifyOptions, error) {
	var o backup.VerifyOptions
	if pubPath == "" && fileExists(cfgPath) {
		if cfg, err := server.LoadConfig(cfgPath); err == nil {
			if p := filepath.Join(cfg.DataDir, "audit-signing.pub"); fileExists(p) {
				pubPath = p
			}
		}
	}
	if pubPath != "" {
		pub, err := manifest.LoadPublic(pubPath)
		if err != nil {
			return o, fmt.Errorf("-pub %s: %w", pubPath, err)
		}
		o.Pub = pub
	}
	if identity != "" {
		ids, err := backup.LoadIdentities(identity)
		if err != nil {
			return o, err
		}
		o.Identities = ids
	}
	return o, nil
}

// backupKeygenCmd creates the bank's backup key pair: the identity
// (private key, to be kept offline) and the recipient (public key) the
// server encrypts its backups to.
//
//	pmserver backup-keygen -out /root/offpatch-backup-identity.txt -recipient-out /etc/offpatch/backup-recipients.txt
func backupKeygenCmd(args []string, w io.Writer) error {
	fs := flag.NewFlagSet("backup-keygen", flag.ExitOnError)
	out := fs.String("out", "", "new file for the identity (private key; written mode 0400, never overwritten)")
	recOut := fs.String("recipient-out", "", "new file for the recipient (public key); default: print only")
	comment := fs.String("comment", "", "text written as a comment at the top of the identity file")
	fs.Parse(args)
	if *out == "" {
		return errors.New("-out is required")
	}
	idFile, recipient, err := backup.GenerateIdentity("DSS Patcher backup identity: decrypts the server's backups. Keep it OFFLINE (safe, HSM or password manager), never on the server.\n" + *comment)
	if err != nil {
		return err
	}
	if err := backup.WriteNewFile(*out, []byte(idFile), 0o400); err != nil {
		return fmt.Errorf("identity: %w", err)
	}
	if *recOut != "" {
		if err := backup.WriteNewFile(*recOut, []byte("# DSS Patcher backups are encrypted to this key\n"+recipient+"\n"), 0o644); err != nil {
			os.Remove(*out)
			return fmt.Errorf("recipient: %w", err)
		}
	}
	fmt.Fprintln(w, recipient)
	return nil
}

// policyKeyCmd prints the public key of the auto-download policy signing
// key (creating the key if needed), for acquire.json policy_public_keys.
//
//	pmserver policy-key -config /etc/offpatch/pmserver.json
func policyKeyCmd(args []string, w io.Writer) error {
	fs := flag.NewFlagSet("policy-key", flag.ExitOnError)
	cfgPath := fs.String("config", "pmserver.json", "server config")
	fs.Parse(args)
	cfg, err := server.LoadConfig(*cfgPath)
	if err != nil {
		return err
	}
	k, err := server.PolicySigningKey(cfg.DataDir)
	if err != nil {
		return err
	}
	pub := k.Public().(ed25519.PublicKey)
	fmt.Fprintln(w, server.PolicyPin(pub))
	fmt.Fprintf(os.Stderr, "%s: put the line above in acquire.json on the acquisition host: \"policy_public_keys\": [\"%s\"]\n",
		strings.TrimSpace(manifest.KeyID(pub)), server.PolicyPin(pub))
	return nil
}
