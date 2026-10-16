package manifest

import (
	"archive/tar"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	EntryManifest = "manifest.json"
	EntrySig      = "manifest.sig"
	payloadDir    = "payload/"
)

// WriteBundle writes a .pmb tar atomically (out.part → out).
// files maps manifest file names ("payload/x.msu") to local paths.
func WriteBundle(out string, manifestBytes []byte, sigB64 string, files map[string]string) error {
	tmp := out + ".part"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer os.Remove(tmp)
	tw := tar.NewWriter(f)
	now := time.Now().UTC()
	addBytes := func(name string, b []byte) error {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(b)), ModTime: now, Typeflag: tar.TypeReg, Format: tar.FormatPAX}); err != nil {
			return err
		}
		_, err := tw.Write(b)
		return err
	}
	if err := addBytes(EntryManifest, manifestBytes); err != nil {
		f.Close()
		return err
	}
	if err := addBytes(EntrySig, []byte(sigB64+"\n")); err != nil {
		f.Close()
		return err
	}
	for name, path := range files {
		if err := addFile(tw, name, path, now); err != nil {
			f.Close()
			return err
		}
	}
	if err := tw.Close(); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, out)
}

func addFile(tw *tar.Writer, name, path string, mt time.Time) error {
	src, err := os.Open(path)
	if err != nil {
		return err
	}
	defer src.Close()
	st, err := src.Stat()
	if err != nil {
		return err
	}
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: st.Size(), ModTime: mt, Typeflag: tar.TypeReg, Format: tar.FormatPAX}); err != nil {
		return err
	}
	_, err = io.Copy(tw, src)
	return err
}

// Limits bound what ExtractSafe will accept.
type Limits struct {
	MaxFiles     int
	MaxFileBytes int64
	MaxTotal     int64
}

// ExtractedFile describes one payload file written to disk during extraction.
type ExtractedFile struct {
	Path   string
	Size   int64
	SHA256 string
}

// Extracted is the result of a safe extraction.
type Extracted struct {
	ManifestBytes []byte
	Signature     string
	Files         map[string]ExtractedFile // keyed by "payload/<base>"
}

// ExtractSafe extracts a bundle into destDir, rejecting anything outside the
// allowed layout (links, devices, traversal, unexpected names, duplicates,
// oversize). Payload hashes are computed while streaming.
func ExtractSafe(bundlePath, destDir string, lim Limits) (*Extracted, error) {
	f, err := os.Open(bundlePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if err := os.MkdirAll(filepath.Join(destDir, "payload"), 0o750); err != nil {
		return nil, err
	}
	tr := tar.NewReader(f)
	ex := &Extracted{Files: map[string]ExtractedFile{}}
	var total int64
	seen := map[string]bool{}
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("tar: %w", err)
		}
		name := h.Name
		if seen[name] {
			return nil, fmt.Errorf("duplicate entry %q", name)
		}
		seen[name] = true
		if name == "payload/" || name == "payload" {
			if h.Typeflag != tar.TypeDir {
				return nil, fmt.Errorf("entry %q must be a directory", name)
			}
			continue
		}
		if h.Typeflag != tar.TypeReg {
			return nil, fmt.Errorf("entry %q: only regular files allowed (type %q)", name, string(h.Typeflag))
		}
		if h.Size < 0 || (lim.MaxFileBytes > 0 && h.Size > lim.MaxFileBytes) {
			return nil, fmt.Errorf("entry %q: size %d exceeds limit", name, h.Size)
		}
		total += h.Size
		if lim.MaxTotal > 0 && total > lim.MaxTotal {
			return nil, errors.New("bundle content exceeds total size limit")
		}
		switch {
		case name == EntryManifest:
			if h.Size > 16<<20 {
				return nil, errors.New("manifest too large")
			}
			b, err := io.ReadAll(tr)
			if err != nil {
				return nil, err
			}
			ex.ManifestBytes = b
		case name == EntrySig:
			b, err := io.ReadAll(io.LimitReader(tr, 4096))
			if err != nil {
				return nil, err
			}
			ex.Signature = strings.TrimSpace(string(b))
		case strings.HasPrefix(name, payloadDir):
			base := strings.TrimPrefix(name, payloadDir)
			if !validBase(base) {
				return nil, fmt.Errorf("entry %q: illegal payload name", name)
			}
			if lim.MaxFiles > 0 && len(ex.Files) >= lim.MaxFiles {
				return nil, errors.New("too many payload files")
			}
			dst := filepath.Join(destDir, "payload", base)
			out, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o640)
			if err != nil {
				return nil, err
			}
			hs := sha256.New()
			n, err := io.Copy(io.MultiWriter(out, hs), tr)
			cerr := out.Close()
			if err != nil {
				return nil, err
			}
			if cerr != nil {
				return nil, cerr
			}
			ex.Files[name] = ExtractedFile{Path: dst, Size: n, SHA256: hex.EncodeToString(hs.Sum(nil))}
		default:
			return nil, fmt.Errorf("unexpected entry %q", name)
		}
	}
	if ex.ManifestBytes == nil {
		return nil, errors.New("manifest.json missing")
	}
	if ex.Signature == "" {
		return nil, errors.New("manifest.sig missing")
	}
	return ex, nil
}

// HashFile returns the size and lowercase hex SHA-256 of a file.
func HashFile(path string) (int64, string, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, "", err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return 0, "", err
	}
	return n, hex.EncodeToString(h.Sum(nil)), nil
}
