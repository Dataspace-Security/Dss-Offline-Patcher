// Package backup creates, verifies and restores consistent backups of the
// management server: database snapshot, approved-content repository,
// quarantine, received-bundle evidence, PKI, audit and policy signing
// keys, the MFA key, staged agent binaries and the config file.
//
// Backups are encrypted to the bank's backup recipient and the manifest
// (backup.json) is signed (format 2, crypto.go). Earlier unencrypted
// backups (format 1) are still verified and restored.
package backup

import (
	"archive/tar"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
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

	"filippo.io/age"

	"offpatch/internal/manifest"
	"offpatch/internal/store"
)

type File struct {
	Path   string `json:"path"` // slash-separated, relative to the backup root
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
	Part   string `json:"part,omitempty"` // format 2: data | keys
}

type Manifest struct {
	Format     int    `json:"format"`
	CreatedAt  string `json:"created_at"`
	AuditSeq   int64  `json:"audit_seq"`
	AuditHash  string `json:"audit_hash"`
	IncludePKI bool   `json:"include_pki"`
	Files      []File `json:"files"`
	// Format 2: who can decrypt each part, the encrypted parts, the signature.
	Recipients    []string   `json:"recipients,omitempty"`
	KeyRecipients []string   `json:"key_recipients,omitempty"`
	Parts         []Part     `json:"parts,omitempty"`
	Signature     *Signature `json:"signature,omitempty"`
}

// Encrypted reports whether m describes an encrypted, signed backup.
func (m Manifest) Encrypted() bool { return m.Format >= FormatEncrypted }

func (m Manifest) payload() []byte {
	m.Signature = nil
	b, _ := json.Marshal(m)
	return b
}

// Layout tells backup where things live.
type Layout struct {
	DataDir    string
	PKIDir     string // optional
	ConfigFile string // optional
}

// dataSubdirs are copied from the data dir (the DB is snapshotted separately).
var dataSubdirs = []string{"repository", "quarantine", "received", "agent-dist"}

// dataFiles: keys in the data dir. mfa.key decrypts local users'
// authenticator secrets: without it a restored server cannot verify MFA
// codes. They go into keys.tar.age.
var dataFiles = []string{"audit-signing.key", "audit-signing.pub", "mfa.key", "policy-signing.key", "policy-signing.pub"}

type entry struct {
	src  string // file on disk
	path string // path in the backup
}

func recipientNames(rs []age.Recipient) []string {
	out := []string{}
	for _, r := range rs {
		if s, ok := r.(fmt.Stringer); ok {
			out = append(out, s.String())
		} else {
			out = append(out, fmt.Sprintf("%T", r))
		}
	}
	return out
}

// Create writes an encrypted backup into out (which must not already
// contain one).
func Create(ctx context.Context, st *store.Store, l Layout, out string, o Options) (Manifest, error) {
	if len(o.Recipients) == 0 {
		return Manifest{}, ErrNoRecipients
	}
	if len(o.SigningKey) != ed25519.PrivateKeySize {
		return Manifest{}, errors.New("backup: no manifest signing key")
	}
	keyRecips := o.KeyRecipients
	if len(keyRecips) == 0 {
		keyRecips = o.Recipients
	}
	if _, err := os.Stat(filepath.Join(out, "backup.json")); err == nil {
		return Manifest{}, fmt.Errorf("%s already contains a backup", out)
	}
	if err := os.MkdirAll(out, 0o700); err != nil {
		return Manifest{}, err
	}
	m := Manifest{Format: FormatEncrypted, CreatedAt: time.Now().UTC().Format(time.RFC3339), IncludePKI: o.IncludePKI,
		Recipients: recipientNames(o.Recipients), KeyRecipients: recipientNames(keyRecips)}
	var err error
	if m.AuditSeq, m.AuditHash, err = st.AuditHead(ctx); err != nil {
		return m, err
	}
	// The snapshot is plaintext for a moment: it is written next to the
	// live database (same protection), never into the backup directory.
	snap := filepath.Join(l.DataDir, fmt.Sprintf(".backup-snapshot-%d.db", time.Now().UnixNano()))
	defer os.Remove(snap)
	if err := st.BackupTo(ctx, snap); err != nil {
		return m, fmt.Errorf("database snapshot: %w", err)
	}
	data := []entry{{snap, "data/pm.db"}}
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
			data = append(data, entry{p, "data/" + filepath.ToSlash(rel)})
			return nil
		})
		if err != nil {
			return m, err
		}
	}
	var keys []entry
	for _, f := range dataFiles {
		if fi, err := os.Stat(filepath.Join(l.DataDir, f)); err == nil && fi.Mode().IsRegular() {
			keys = append(keys, entry{filepath.Join(l.DataDir, f), "data/" + f})
		}
	}
	if o.IncludePKI && l.PKIDir != "" {
		entries, _ := os.ReadDir(l.PKIDir)
		for _, e := range entries {
			if e.Type().IsRegular() {
				keys = append(keys, entry{filepath.Join(l.PKIDir, e.Name()), "pki/" + e.Name()})
			}
		}
	}
	if l.ConfigFile != "" {
		keys = append(keys, entry{l.ConfigFile, "config/" + filepath.Base(l.ConfigFile)})
	}
	for _, pt := range []struct {
		name    string
		entries []entry
		recips  []age.Recipient
	}{{partData, data, o.Recipients}, {partKeys, keys, keyRecips}} {
		part, files, err := writePart(ctx, out, pt.name, pt.entries, pt.recips)
		if err != nil {
			os.Remove(filepath.Join(out, partFile(partData)))
			os.Remove(filepath.Join(out, partFile(partKeys)))
			return m, fmt.Errorf("%s: %w", partFile(pt.name), err)
		}
		m.Parts = append(m.Parts, part)
		m.Files = append(m.Files, files...)
	}
	sort.Slice(m.Files, func(i, j int) bool { return m.Files[i].Path < m.Files[j].Path })
	m.Signature = &Signature{KeyID: manifest.KeyID(o.SigningKey.Public().(ed25519.PublicKey)), Value: manifest.Sign(o.SigningKey, m.payload())}
	b, _ := json.MarshalIndent(m, "", "  ")
	return m, WriteNewFile(filepath.Join(out, "backup.json"), b, 0o600)
}

// writePart streams entries as a tar archive encrypted to recips into
// out/<name>.tar.age.
func writePart(ctx context.Context, out, name string, entries []entry, recips []age.Recipient) (Part, []File, error) {
	path := filepath.Join(out, partFile(name))
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return Part{}, nil, err
	}
	defer f.Close()
	ch := sha256.New()
	cw := &countingWriter{w: io.MultiWriter(f, ch)}
	aw, err := age.Encrypt(cw, recips...)
	if err != nil {
		return Part{}, nil, err
	}
	tw := tar.NewWriter(aw)
	var files []File
	for _, e := range entries {
		if err := ctx.Err(); err != nil {
			return Part{}, nil, err
		}
		fl, err := addFile(tw, e)
		if err != nil {
			return Part{}, nil, err
		}
		fl.Part = name
		files = append(files, fl)
	}
	if err := tw.Close(); err != nil {
		return Part{}, nil, err
	}
	if err := aw.Close(); err != nil {
		return Part{}, nil, err
	}
	if err := f.Sync(); err != nil {
		return Part{}, nil, err
	}
	return Part{Name: partFile(name), Size: cw.n, SHA256: hex.EncodeToString(ch.Sum(nil))}, files, nil
}

func addFile(tw *tar.Writer, e entry) (File, error) {
	in, err := os.Open(e.src)
	if err != nil {
		return File{}, err
	}
	defer in.Close()
	fi, err := in.Stat()
	if err != nil {
		return File{}, err
	}
	hdr := &tar.Header{Typeflag: tar.TypeReg, Name: e.path, Mode: int64(fi.Mode().Perm() | 0o400), Size: fi.Size(), ModTime: fi.ModTime().UTC()}
	if err := tw.WriteHeader(hdr); err != nil {
		return File{}, err
	}
	h := sha256.New()
	if _, err := io.CopyN(tw, io.TeeReader(in, h), fi.Size()); err != nil {
		return File{}, fmt.Errorf("%s changed while it was backed up: %w", e.src, err)
	}
	return File{Path: e.path, Size: fi.Size(), SHA256: hex.EncodeToString(h.Sum(nil))}, nil
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

// VerifyOptions: what Verify, Restore and Decrypt check with.
type VerifyOptions struct {
	// Pub is the server's audit-signing public key (format 2: required).
	Pub ed25519.PublicKey
	// Identities decrypt the parts (Verify: optional, checks every file).
	Identities []age.Identity
}

func readManifest(dir string) (Manifest, error) {
	var m Manifest
	b, err := os.ReadFile(filepath.Join(dir, "backup.json"))
	if err != nil {
		return m, err
	}
	if err := json.Unmarshal(b, &m); err != nil {
		return m, fmt.Errorf("backup.json: %w", err)
	}
	for _, f := range m.Files {
		if !filepath.IsLocal(filepath.FromSlash(f.Path)) || strings.Contains(f.Path, "\\") {
			return m, fmt.Errorf("backup.json: invalid path %q", f.Path)
		}
	}
	return m, nil
}

func problemsErr(problems []string) error {
	if len(problems) == 0 {
		return nil
	}
	sort.Strings(problems)
	return fmt.Errorf("backup verification failed: %s", strings.Join(problems, "; "))
}

// Verify checks a backup. Format 2: the manifest signature (o.Pub) and
// the encrypted parts' hashes, no other files; with o.Identities also every
// file inside. Format 1 (unencrypted): every file against backup.json, and
// that no unexpected files were added.
func Verify(dir string, o VerifyOptions) (Manifest, error) {
	m, err := readManifest(dir)
	if err != nil {
		return m, err
	}
	if !m.Encrypted() {
		return m, verifyPlain(dir, m)
	}
	if err := verifySigned(dir, m, o.Pub); err != nil {
		return m, err
	}
	if len(o.Identities) == 0 {
		return m, nil
	}
	return m, extract(dir, m, o.Identities, func(string) (string, bool) { return "", false })
}

func verifyPlain(dir string, m Manifest) error {
	have, err := hashTree(dir)
	if err != nil {
		return err
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
	return problemsErr(problems)
}

func verifySigned(dir string, m Manifest, pub ed25519.PublicKey) error {
	if len(pub) == 0 {
		return ErrNeedPublicKey
	}
	if m.Signature == nil {
		return errors.New("backup verification failed: backup.json is not signed")
	}
	if id := manifest.KeyID(pub); id != m.Signature.KeyID {
		return fmt.Errorf("backup verification failed: backup.json is signed with key %s, not with the given audit-signing key %s", m.Signature.KeyID, id)
	}
	if err := manifest.Verify(pub, m.payload(), m.Signature.Value); err != nil {
		return fmt.Errorf("backup verification failed: backup.json signature: %w", err)
	}
	have, err := hashTree(dir)
	if err != nil {
		return err
	}
	want := map[string]Part{}
	for _, p := range m.Parts {
		want[p.Name] = p
	}
	if len(want) != 2 || want[partFile(partData)].Name == "" || want[partFile(partKeys)].Name == "" {
		return errors.New("backup verification failed: backup.json does not list data.tar.age and keys.tar.age")
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
	return problemsErr(problems)
}

// extract decrypts every part and checks each file against the manifest.
// dest maps a backup path to where it is written (false: only checked).
func extract(dir string, m Manifest, ids []age.Identity, dest func(path string) (string, bool)) error {
	if len(ids) == 0 {
		return ErrNeedIdentity
	}
	want := map[string]File{}
	for _, f := range m.Files {
		want[f.Path] = f
	}
	var problems []string
	for _, p := range m.Parts {
		part := strings.TrimSuffix(p.Name, ".tar.age")
		if err := extractPart(filepath.Join(dir, p.Name), part, ids, want, dest, &problems); err != nil {
			return fmt.Errorf("%s: %w", p.Name, err)
		}
	}
	for p := range want {
		problems = append(problems, "missing "+p)
	}
	return problemsErr(problems)
}

func extractPart(path, part string, ids []age.Identity, want map[string]File, dest func(string) (string, bool), problems *[]string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	r, err := age.Decrypt(f, ids...)
	if err != nil {
		return fmt.Errorf("cannot decrypt (wrong backup identity?): %w", err)
	}
	tr := tar.NewReader(r)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		w, ok := want[hdr.Name]
		if !ok || w.Part != part || hdr.Typeflag != tar.TypeReg {
			*problems = append(*problems, "unexpected file "+hdr.Name)
			continue
		}
		delete(want, hdr.Name)
		dst, write := dest(hdr.Name)
		sum, n, err := copyOut(tr, dst, write, fs.FileMode(hdr.Mode).Perm())
		if err != nil {
			return err
		}
		if sum != w.SHA256 || n != w.Size {
			if write {
				os.Remove(dst + ".tmp")
			}
			*problems = append(*problems, "modified "+hdr.Name)
			continue
		}
		if write {
			if err := os.Rename(dst+".tmp", dst); err != nil {
				return err
			}
		}
	}
}

// copyOut hashes r and, if write, writes it to dst+".tmp" (renamed by the
// caller once the hash is right).
func copyOut(r io.Reader, dst string, write bool, mode fs.FileMode) (string, int64, error) {
	h := sha256.New()
	if !write {
		n, err := io.Copy(h, r)
		return hex.EncodeToString(h.Sum(nil)), n, err
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o750); err != nil {
		return "", 0, err
	}
	out, err := os.OpenFile(dst+".tmp", os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return "", 0, err
	}
	n, err := io.Copy(io.MultiWriter(out, h), r)
	if err == nil {
		err = out.Sync()
	}
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Chmod(dst+".tmp", mode|0o400)
	}
	if err != nil {
		os.Remove(dst + ".tmp")
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

// restoreDest maps a backup path into the layout (config is restored by
// the operator deliberately: see Decrypt).
func restoreDest(l Layout) func(string) (string, bool) {
	return func(p string) (string, bool) {
		switch {
		case strings.HasPrefix(p, "data/"):
			return filepath.Join(l.DataDir, filepath.FromSlash(strings.TrimPrefix(p, "data/"))), true
		case strings.HasPrefix(p, "pki/") && l.PKIDir != "":
			return filepath.Join(l.PKIDir, filepath.FromSlash(strings.TrimPrefix(p, "pki/"))), true
		}
		return "", false
	}
}

// Restore verifies the backup, copies (format 2: decrypts) it into place
// and checks integrity (audit chain, approved content present with the
// right hashes).
func Restore(ctx context.Context, dir string, l Layout, force bool, o VerifyOptions) (Manifest, error) {
	m, err := readManifest(dir)
	if err != nil {
		return m, err
	}
	if m.Encrypted() && len(o.Identities) == 0 {
		return m, ErrNeedIdentity
	}
	if m, err = Verify(dir, VerifyOptions{Pub: o.Pub}); err != nil {
		return m, err
	}
	if _, err := os.Stat(filepath.Join(l.DataDir, "pm.db")); err == nil && !force {
		return m, fmt.Errorf("%s already has a database; stop the server and use -force to overwrite", l.DataDir)
	}
	if m.Encrypted() {
		if err := extract(dir, m, o.Identities, restoreDest(l)); err != nil {
			return m, err
		}
	} else if err := restorePlain(dir, m, l); err != nil {
		return m, err
	}
	os.Remove(filepath.Join(l.DataDir, "pm.db-wal"))
	os.Remove(filepath.Join(l.DataDir, "pm.db-shm"))
	return m, Check(ctx, l.DataDir, m)
}

func restorePlain(dir string, m Manifest, l Layout) error {
	dest := restoreDest(l)
	for _, f := range m.Files {
		dst, ok := dest(f.Path)
		if !ok {
			continue
		}
		src := filepath.Join(dir, filepath.FromSlash(f.Path))
		fi, err := os.Stat(src)
		if err != nil {
			return err
		}
		if err := copyFile(src, dst, fi.Mode().Perm()); err != nil {
			return err
		}
	}
	return nil
}

func copyFile(src, dst string, mode fs.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	if _, _, err := copyOut(in, dst, true, mode); err != nil {
		return err
	}
	return os.Rename(dst+".tmp", dst)
}

// Decrypt verifies an encrypted backup and writes its files into the new
// directory out (mode 0700) as an unencrypted format 1 backup, e.g. to
// take the config file or inspect it. out then holds every key in
// plaintext: delete it when done.
func Decrypt(dir, out string, o VerifyOptions) (Manifest, error) {
	m, err := Verify(dir, VerifyOptions{Pub: o.Pub})
	if err != nil {
		return m, err
	}
	if !m.Encrypted() {
		return m, errors.New("this backup is not encrypted")
	}
	if err := os.Mkdir(out, 0o700); err != nil {
		return m, err
	}
	err = extract(dir, m, o.Identities, func(p string) (string, bool) { return filepath.Join(out, filepath.FromSlash(p)), true })
	if err != nil {
		return m, err
	}
	plain := Manifest{Format: FormatPlain, CreatedAt: m.CreatedAt, AuditSeq: m.AuditSeq, AuditHash: m.AuditHash, IncludePKI: m.IncludePKI}
	for _, f := range m.Files {
		plain.Files = append(plain.Files, File{Path: f.Path, Size: f.Size, SHA256: f.SHA256})
	}
	b, _ := json.MarshalIndent(plain, "", "  ")
	return m, WriteNewFile(filepath.Join(out, "backup.json"), b, 0o600)
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
