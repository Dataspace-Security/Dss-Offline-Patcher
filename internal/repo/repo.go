// Package repo is the internal content repository: approved package
// binaries stored immutably by SHA-256. Quarantine is a separate directory
// and is never served.
package repo

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"

	"offpatch/internal/manifest"
)

type Repo struct{ Dir string }

var shaRe = regexp.MustCompile(`^[0-9a-f]{64}$`)

func New(dir string) (*Repo, error) {
	return &Repo{Dir: dir}, os.MkdirAll(dir, 0o750)
}

func (r *Repo) Path(sha string) (string, error) {
	if !shaRe.MatchString(sha) {
		return "", fmt.Errorf("invalid sha256")
	}
	return filepath.Join(r.Dir, sha[:2], sha), nil
}

// Publish copies a quarantined file into the repository, re-verifying the
// hash on the copy. Idempotent for identical content.
func (r *Repo) Publish(src, sha string, size int64) error {
	dst, err := r.Path(sha)
	if err != nil {
		return err
	}
	if n, h, err := manifest.HashFile(dst); err == nil {
		if h == sha && n == size {
			return nil
		}
		return fmt.Errorf("repository object %s exists with different content", sha)
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o750); err != nil {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp := dst + ".tmp"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o640)
	if err != nil {
		return err
	}
	defer os.Remove(tmp)
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	if err := out.Sync(); err != nil {
		out.Close()
		return err
	}
	out.Close()
	n, h, err := manifest.HashFile(tmp)
	if err != nil {
		return err
	}
	if h != sha || n != size {
		return fmt.Errorf("quarantined file no longer matches manifest (sha256 %s, size %d)", h, n)
	}
	if err := os.Chmod(tmp, 0o440); err != nil {
		return err
	}
	if err := os.Rename(tmp, dst); err != nil {
		return err
	}
	// Make the rename itself durable: the database is about to say "approved".
	return syncDir(filepath.Dir(dst))
}

// syncDir fsyncs a directory so a rename into it survives a crash. Windows
// cannot sync directory handles (NTFS journals metadata), so it is a no-op there.
func syncDir(dir string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
