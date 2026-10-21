package safezip

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func mkZip(t *testing.T, files [][2]string) string {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, f := range files {
		w, err := zw.Create(f[0])
		if err != nil {
			t.Fatal(err)
		}
		w.Write([]byte(f[1]))
	}
	zw.Close()
	p := filepath.Join(t.TempDir(), "a.zip")
	os.WriteFile(p, buf.Bytes(), 0o600)
	return p
}

func sum(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }

func TestCleanPath(t *testing.T) {
	for in, want := range map[string]string{`a\b.exe`: "a/b.exe", "dir/": "dir", "a/b c/d.msi": "a/b c/d.msi",
		"console.exe": "console.exe", "com10.txt": "com10.txt", "lpt/nullable.dll": "lpt/nullable.dll", "auxiliary/x": "auxiliary/x"} {
		if got, err := CleanPath(in); err != nil || got != want {
			t.Errorf("%q: %q %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "/a", "C:x", "a/../b", "./a", "a//b", "a./b", "a /b", "a\x01b",
		// Windows reserved device names, in any element, with or without an extension.
		"con", "CON.txt", "app/nul", "app/Nul.dll", "PRN/a", "aux.h", "com1", "COM9.log", "lpt1.txt", "a/LPT9/b",
		"nul .txt", "com¹.txt", "conout$"} {
		if _, err := CleanPath(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestExtract(t *testing.T) {
	zp := mkZip(t, [][2]string{{"app/setup.exe", "MZ"}, {"app/data.cab", "cab"}})
	dir := t.TempDir()
	files, err := ExtractAll(zp, dir, Limits{})
	if err != nil || len(files) != 2 || files[0].Path != "app/data.cab" || files[0].SHA256 != sum("cab") {
		t.Fatalf("extract all: %v %+v", err, files)
	}
	want := []File{{Path: "APP/setup.exe", Size: 2, SHA256: sum("MZ")}, {Path: "app/data.cab", Size: 3, SHA256: sum("cab")}}
	if err := ExtractVerified(zp, t.TempDir(), want, Limits{}); err != nil {
		t.Fatalf("verified (case-insensitive paths): %v", err)
	}
	want[1].SHA256 = sum("other")
	if err := ExtractVerified(zp, t.TempDir(), want, Limits{}); !errors.Is(err, ErrUnsafe) || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("hash mismatch: %v", err)
	}
	if err := ExtractVerified(zp, t.TempDir(), want[:1], Limits{}); !errors.Is(err, ErrUnsafe) {
		t.Fatalf("unlisted file: %v", err)
	}
	// Duplicates by case, traversal, too many entries, a bomb-like ratio.
	for name, z := range map[string]string{
		"case dup":  mkZip(t, [][2]string{{"a.txt", "1"}, {"A.TXT", "2"}}),
		"traversal": mkZip(t, [][2]string{{"../x", "1"}}),
		"file+dir":  mkZip(t, [][2]string{{"a", "1"}, {"a/b", "2"}}),
	} {
		if _, err := ExtractAll(z, t.TempDir(), Limits{}); !errors.Is(err, ErrUnsafe) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := ExtractAll(zp, t.TempDir(), Limits{MaxEntries: 1}); !errors.Is(err, ErrUnsafe) {
		t.Errorf("entry cap: %v", err)
	}
	bomb := mkZip(t, [][2]string{{"z.bin", strings.Repeat("\x00", 4<<20)}})
	if _, err := ExtractAll(bomb, t.TempDir(), Limits{MaxRatio: 10}); !errors.Is(err, ErrUnsafe) || !strings.Contains(err.Error(), "compressed more than") {
		t.Errorf("ratio cap: %v", err)
	}
}
