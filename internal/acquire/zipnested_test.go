package acquire

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

type zipEntry struct {
	name string
	body []byte
	mode fs.FileMode // 0: regular file
	enc  bool        // mark as encrypted
}

// writeZip builds a zip of entries in a temp dir and returns its path.
func writeZip(t *testing.T, entries ...zipEntry) string {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, e := range entries {
		h := &zip.FileHeader{Name: e.name, Method: zip.Deflate}
		if e.mode != 0 {
			h.SetMode(e.mode)
		}
		if e.enc {
			h.Flags |= 0x1
		}
		w, err := zw.CreateHeader(h)
		if err != nil {
			t.Fatal(err)
		}
		w.Write(e.body)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "in.zip")
	if err := os.WriteFile(p, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestCleanZipPath(t *testing.T) {
	ok := map[string]string{`Adobe Acrobat\setup.exe`: "Adobe Acrobat/setup.exe", "a/b.msi": "a/b.msi", "dir/": "dir", "x.msi": "x.msi"}
	for in, want := range ok {
		if got, err := CleanZipPath(in); err != nil || got != want {
			t.Errorf("%q: %q %v, want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"", "/etc/x", `\x.msi`, `C:\x.msi`, "c:x.msi", "a/../b.msi", "../b.msi", "a/./b", "a//b", "a/b.msi:ads", "a\x00b", "dir./x", "dir /x", `\\server\share\x`} {
		if got, err := CleanZipPath(in); err == nil {
			t.Errorf("%q accepted as %q", in, got)
		}
	}
}

func TestExtractNested(t *testing.T) {
	inst := []byte("MZ installer body " + strings.Repeat("x", 1000))
	sum := sha256.Sum256(inst)
	p := writeZip(t, zipEntry{name: "Tool/"}, zipEntry{name: "Tool/Setup.EXE", body: inst}, zipEntry{name: "Tool/README.txt", body: []byte("hi")},
		zipEntry{name: "Tool/data1.cab", body: []byte("cab")})
	dest := t.TempDir()
	nf, err := ExtractNested(p, `tool\setup.exe`, dest, "pkg.exe") // case-insensitive, backslashes
	if err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(filepath.Join(dest, "pkg.exe"))
	if !bytes.Equal(got, inst) || nf.SHA256 != hex.EncodeToString(sum[:]) || nf.Size != int64(len(inst)) || nf.Path != filepath.Join(dest, "pkg.exe") {
		t.Errorf("extracted %+v", nf)
	}
	if !slices.Equal(nf.Others, []string{"Tool/README.txt", "Tool/data1.cab"}) {
		t.Errorf("others %v", nf.Others)
	}
	if s := ZipSiblings(nf.Others); !slices.Equal(s, []string{"Tool/data1.cab"}) {
		t.Errorf("siblings %v", s)
	}
	if s := ZipSiblings([]string{"README.md", "License.TXT", "__MACOSX/._x", "a/.DS_Store", "notes.pdf"}); len(s) != 0 {
		t.Errorf("documentation counted as siblings: %v", s)
	}
	// The destination is never overwritten.
	if _, err := ExtractNested(p, "Tool/Setup.EXE", dest, "pkg.exe"); err == nil {
		t.Error("existing destination overwritten")
	}
	if _, err := ExtractNested(p, "Tool/Setup.EXE", dest, "../pkg.exe"); err == nil {
		t.Error("unsafe destination name accepted")
	}
}

func TestExtractNestedRefuses(t *testing.T) {
	body := []byte("installer")
	big := bytes.Repeat([]byte{0}, 3<<20) // deflates ~1000:1
	cases := []struct {
		name    string
		entries []zipEntry
		rel     string
		want    string
	}{
		{"traversal", []zipEntry{{name: "a.msi", body: body}, {name: "../evil.dll", body: body}}, "a.msi", "unsafe entry"},
		{"absolute", []zipEntry{{name: "a.msi", body: body}, {name: "/etc/evil", body: body}}, "a.msi", "unsafe entry"},
		{"drive", []zipEntry{{name: "a.msi", body: body}, {name: `C:\evil`, body: body}}, "a.msi", "unsafe entry"},
		{"symlink", []zipEntry{{name: "a.msi", body: []byte("/etc/passwd"), mode: fs.ModeSymlink | 0o777}}, "a.msi", "symbolic link"},
		{"duplicate case", []zipEntry{{name: "Setup.exe", body: body}, {name: "setup.EXE", body: []byte("other")}}, "setup.exe", "two entries"},
		{"duplicate exact", []zipEntry{{name: "a.msi", body: body}, {name: "a.msi", body: body}}, "a.msi", "two entries"},
		{"file and dir", []zipEntry{{name: "a", body: body}, {name: "a/b.msi", body: body}}, "a/b.msi", "both as a file and as a directory"},
		{"encrypted", []zipEntry{{name: "a.msi", body: body, enc: true}}, "a.msi", "encrypted"},
		{"bomb ratio", []zipEntry{{name: "a.msi", body: big}}, "a.msi", "zip bomb"},
		{"missing", []zipEntry{{name: "other.msi", body: body}}, "a.msi", "has no a.msi"},
		{"unsafe nested path", []zipEntry{{name: "a.msi", body: body}}, `..\a.msi`, "path in the zip is unsafe"},
		{"directory named", []zipEntry{{name: "a.msi/"}}, "a.msi", "has no a.msi"},
	}
	for _, c := range cases {
		p := writeZip(t, c.entries...)
		_, err := ExtractNested(p, c.rel, t.TempDir(), "pkg.msi")
		var un *UnsupportedError
		if !errors.As(err, &un) || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want unsupported %q", c.name, err, c.want)
		}
	}
	// Not a zip at all.
	bad := filepath.Join(t.TempDir(), "x.zip")
	os.WriteFile(bad, []byte("not a zip"), 0o600)
	if _, err := ExtractNested(bad, "a.msi", t.TempDir(), "pkg.msi"); err == nil || !strings.Contains(err.Error(), "cannot be read") {
		t.Errorf("garbage zip: %v", err)
	}
}

func TestExtractNestedLimits(t *testing.T) {
	oldTotal, oldEntries := MaxZipUncompressed, MaxZipEntries
	t.Cleanup(func() { MaxZipUncompressed, MaxZipEntries = oldTotal, oldEntries })
	body := []byte(strings.Repeat("abc", 100))
	p := writeZip(t, zipEntry{name: "a.msi", body: body}, zipEntry{name: "b.cab", body: body}, zipEntry{name: "c.cab", body: body})

	MaxZipEntries = 2
	if _, err := ExtractNested(p, "a.msi", t.TempDir(), "pkg.msi"); err == nil || !strings.Contains(err.Error(), "entries") {
		t.Errorf("entry count: %v", err)
	}
	MaxZipEntries = oldEntries
	MaxZipUncompressed = int64(2*len(body) + 10)
	if _, err := ExtractNested(p, "a.msi", t.TempDir(), "pkg.msi"); err == nil || !strings.Contains(err.Error(), "unpacks to more than") {
		t.Errorf("total size: %v", err)
	}
}
