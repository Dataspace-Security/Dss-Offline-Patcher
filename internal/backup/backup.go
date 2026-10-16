// Package backup creates, verifies and restores consistent backups of the
// management server: database snapshot, approved-content repository,
// quarantine, received-bundle evidence, PKI, audit signing key, staged agent
// binaries and the config file. Every file is hashed into backup.json.
package backup

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"offpatch/internal/manifest"
	"offpatch/internal/store"
)

type File struct {
	Path   string `json:"path"` // slash-separated, relative to the backup root
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

type Manifest struct {
	Format     int    `json:"format"`
	CreatedAt  string `json:"created_at"`
	AuditSeq   int64  `json:"audit_seq"`
	AuditHash  string `json:"audit_hash"`
	IncludePKI bool   `json:"include_pki"`
	Files      []File `json:"files"`
}

// Layout tells backup where things live.
type Layout struct {
	DataDir    string
	PKIDir     string // optional
	ConfigFile string // optional
}

// dataSubdirs are copied from the data dir (the DB is snapshotted separately).
var dataSubdirs = []string{"repository", "quarantine", "received", "agent-dist"}
var dataFiles = []string{"audit-signing.key", "audit-signing.pub"}

func copyFile(src, dst string, mode fs.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o750); err != nil {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp := dst + ".tmp"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	if err := out.Sync(); err != nil {
		out.Close()
		return err
	}
	out.Close()
	if err := os.Chmod(tmp, mode); err != nil {
		return err
	}
	return os.Rename(tmp, dst)
}

// Create writes a backup into out (which must not already contain one).
func Create(ctx context.Context, st *store.Store, l Layout, out string, includePKI bool) (Manifest, error) {
	if _, err := os.Stat(filepath.Join(out, "backup.json")); err == nil {
		return Manifest{}, fmt.Errorf("%s already contains a backup", out)
	}
	if err := os.MkdirAll(filepath.Join(out, "data"), 0o700); err != nil {
		return Manifest{}, err
	}
	m := Manifest{Format: 1, CreatedAt: time.Now().UTC().Format(time.RFC3339), IncludePKI: includePKI}
	var err error
	if m.AuditSeq, m.AuditHash, err = st.AuditHead(ctx); err != nil {
		return m, err
	}
	if err := st.BackupTo(ctx, filepath.Join(out, "data", "pm.db")); err != nil {
		return m, fmt.Errorf("database snapshot: %w", err)
	}
	for _, sub := range dataSubdirs {
		root := filepath.Join(l.DataDir, sub)
		err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if errors.Is(err, fs.ErrNotExist) {
				return filepath.SkipDir
			}
			if err != nil || !d.Type().IsRegular() || strings.HasSuffix(p, ".tmp") || strings.HasSuffix(p, ".part") {
				return err
			}
			rel, _ := filepath.Rel(l.DataDir, p)
			fi, _ := d.Info()
			return copyFile(p, filepath.Join(out, "data", rel), fi.Mode().Perm()|0o400)
		})
		if err != nil {
			return m, err
		}
	}
	for _, f := range dataFiles {
		if fi, err := os.Stat(filepath.Join(l.DataDir, f)); err == nil {
			if err := copyFile(filepath.Join(l.DataDir, f), filepath.Join(out, "data", f), fi.Mode().Perm()); err != nil {
				return m, err
			}
		}
	}
	if includePKI && l.PKIDir != "" {
		entries, _ := os.ReadDir(l.PKIDir)
		for _, e := range entries {
			if e.Type().IsRegular() {
				fi, _ := e.Info()
				if err := copyFile(filepath.Join(l.PKIDir, e.Name()), filepath.Join(out, "pki", e.Name()), fi.Mode().Perm()); err != nil {
					return m, err
				}
			}
		}
	}
	if l.ConfigFile != "" {
		if err := copyFile(l.ConfigFile, filepath.Join(out, "config", filepath.Base(l.ConfigFile)), 0o600); err != nil {
			return m, err
		}
	}
	if m.Files, err = hashTree(out); err != nil {
		return m, err
	}
	b, _ := json.MarshalIndent(m, "", "  ")
	return m, os.WriteFile(filepath.Join(out, "backup.json"), b, 0o600)
}

func hashTree(root string) ([]File, error) {
	var files []File
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || !d.Type().IsRegular() {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		if rel == "backup.json" {
			return nil
		}
		n, h, err := manifest.HashFile(p)
		if err != nil {
			return err
		}
		files = append(files, File{Path: filepath.ToSlash(rel), Size: n, SHA256: h})
		return nil
	})
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	return files, err
}

// Verify checks every file in the backup against backup.json, and that no
// unexpected files were added.
func Verify(dir string) (Manifest, error) {
	var m Manifest
	b, err := os.ReadFile(filepath.Join(dir, "backup.json"))
	if err != nil {
		return m, err
	}
	if err := json.Unmarshal(b, &m); err != nil {
		return m, fmt.Errorf("backup.json: %w", err)
	}
	have, err := hashTree(dir)
	if err != nil {
		return m, err
	}
	want := map[string]File{}
	for _, f := range m.Files {
		want[f.Path] = f
	}
	var problems []string
	for _, f := range have {
		w, ok := want[f.Path]
		switch {
		case !ok:
			problems = append(problems, "unexpected file "+f.Path)
		case w.SHA256 != f.SHA256 || w.Size != f.Size:
			problems = append(problems, "modified "+f.Path)
		}
		delete(want, f.Path)
	}
	for p := range want {
		problems = append(problems, "missing "+p)
	}
	if len(problems) > 0 {
		sort.Strings(problems)
		return m, fmt.Errorf("backup verification failed: %s", strings.Join(problems, "; "))
	}
	return m, nil
}

// Restore verifies the backup, copies it into place and checks integrity
// (audit chain, approved content present with the right hashes).
func Restore(ctx context.Context, dir string, l Layout, force bool) (Manifest, error) {
	m, err := Verify(dir)
	if err != nil {
		return m, err
	}
	if _, err := os.Stat(filepath.Join(l.DataDir, "pm.db")); err == nil && !force {
		return m, fmt.Errorf("%s already has a database; stop the server and use -force to overwrite", l.DataDir)
	}
	for _, f := range m.Files {
		src := filepath.Join(dir, filepath.FromSlash(f.Path))
		var dst string
		switch {
		case strings.HasPrefix(f.Path, "data/"):
			dst = filepath.Join(l.DataDir, filepath.FromSlash(strings.TrimPrefix(f.Path, "data/")))
		case strings.HasPrefix(f.Path, "pki/") && l.PKIDir != "":
			dst = filepath.Join(l.PKIDir, filepath.FromSlash(strings.TrimPrefix(f.Path, "pki/")))
		default:
			continue // config is restored by the operator deliberately
		}
		fi, _ := os.Stat(src)
		if err := copyFile(src, dst, fi.Mode().Perm()); err != nil {
			return m, err
		}
	}
	os.Remove(filepath.Join(l.DataDir, "pm.db-wal"))
	os.Remove(filepath.Join(l.DataDir, "pm.db-shm"))
	return m, Check(ctx, l.DataDir, m)
}

// Check opens a restored data dir and validates it.
func Check(ctx context.Context, dataDir string, m Manifest) error {
	st, err := store.Open(filepath.Join(dataDir, "pm.db"))
	if err != nil {
		return err
	}
	defer st.Close()
	cr, err := st.VerifyAudit(ctx)
	if err != nil {
		return err
	}
	if !cr.OK {
		return fmt.Errorf("restored audit chain broken at %d: %s", cr.FirstBadSeq, cr.Error)
	}
	if h, err := st.AuditHashAt(ctx, m.AuditSeq); m.AuditSeq > 0 && (err != nil || h != m.AuditHash) {
		return fmt.Errorf("restored audit head does not match backup manifest")
	}
	pkgs, err := st.ListPackages(ctx, "approved")
	if err != nil {
		return err
	}
	for _, p := range pkgs {
		n, h, err := manifest.HashFile(filepath.Join(dataDir, "repository", p.SHA256[:2], p.SHA256))
		if err != nil || h != p.SHA256 || n != p.Size {
			return fmt.Errorf("approved package %s content missing or corrupt after restore", p.PackageID)
		}
	}
	return nil
}
