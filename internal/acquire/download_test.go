package acquire

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"offpatch/internal/acquire/acquiretest"
)

func TestSHA1FromCatalogName(t *testing.T) {
	if got := SHA1FromCatalogName("windows10.0-kb5126657-x64_6EA46AD975176D6C6E9DCC79859D67C5193D6FC0.msu"); got != "6ea46ad975176d6c6e9dcc79859d67c5193d6fc0" {
		t.Fatalf("got %q", got)
	}
	if got := SHA1FromCatalogName("acme-agent-2.1.msi"); got != "" {
		t.Fatalf("got %q", got)
	}
}

func catalogReq(srv *acquiretest.Server, dir string) DownloadRequest {
	return DownloadRequest{
		URL: srv.URL + "/dl/" + srv.FileName, DestDir: dir, FileName: srv.FileName,
		SHA1: SHA1FromCatalogName(srv.FileName), Size: int64(len(srv.Payload)),
	}
}

func TestDownloadVerifies(t *testing.T) {
	srv := acquiretest.New(t, "testdata", acquiretest.Payload(300_000))
	dir := t.TempDir()
	res, err := Download(context.Background(), srv.Client(), catalogReq(srv, dir))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(srv.Payload)
	if res.SHA256 != hex.EncodeToString(sum[:]) || res.Size != 300_000 || res.Resumed || res.Reused {
		t.Fatalf("res = %+v", res)
	}
	if _, err := os.Stat(res.Path + ".part"); !os.IsNotExist(err) {
		t.Fatal(".part left behind")
	}
	// Second run reuses the verified file without downloading.
	n := len(srv.Ranges())
	res2, err := Download(context.Background(), srv.Client(), catalogReq(srv, dir))
	if err != nil || !res2.Reused || len(srv.Ranges()) != n {
		t.Fatalf("reuse: %+v %v", res2, err)
	}
}

func TestDownloadSHA1MismatchRejected(t *testing.T) {
	srv := acquiretest.New(t, "testdata", acquiretest.Payload(50_000))
	tampered := append([]byte(nil), srv.Payload...)
	tampered[100] ^= 0xff
	srv.Served = tampered // same size, different content than the catalog name's SHA-1
	dir := t.TempDir()
	_, err := Download(context.Background(), srv.Client(), catalogReq(srv, dir))
	if !errors.Is(err, ErrHashMismatch) || !strings.Contains(err.Error(), "SHA-1") {
		t.Fatalf("want SHA-1 mismatch, got %v", err)
	}
	ents, _ := os.ReadDir(dir)
	if len(ents) != 0 {
		t.Fatalf("files left after mismatch: %v", ents)
	}
}

func TestDownloadResume(t *testing.T) {
	srv := acquiretest.New(t, "testdata", acquiretest.Payload(200_000))
	dir := t.TempDir()
	part := filepath.Join(dir, srv.FileName+".part")
	if err := os.WriteFile(part, srv.Payload[:120_000], 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := Download(context.Background(), srv.Client(), catalogReq(srv, dir))
	if err != nil {
		t.Fatal(err)
	}
	if !res.Resumed {
		t.Fatal("expected resume")
	}
	if r := srv.Ranges(); len(r) != 1 || r[0] != "bytes=120000-" {
		t.Fatalf("range headers = %v", r)
	}
}

func TestDownloadResumeServerIgnoresRange(t *testing.T) {
	srv := acquiretest.New(t, "testdata", acquiretest.Payload(80_000))
	srv.IgnoreRange = true
	dir := t.TempDir()
	part := filepath.Join(dir, srv.FileName+".part")
	os.WriteFile(part, srv.Payload[:30_000], 0o644)
	res, err := Download(context.Background(), srv.Client(), catalogReq(srv, dir))
	if err != nil {
		t.Fatal(err)
	}
	if res.Resumed || res.Size != 80_000 {
		t.Fatalf("res = %+v", res)
	}
}

func TestDownloadCorruptPartRestarts(t *testing.T) {
	srv := acquiretest.New(t, "testdata", acquiretest.Payload(60_000))
	dir := t.TempDir()
	junk := make([]byte, 20_000) // wrong prefix: resume would produce a bad file
	os.WriteFile(filepath.Join(dir, srv.FileName+".part"), junk, 0o644)
	res, err := Download(context.Background(), srv.Client(), catalogReq(srv, dir))
	if err != nil {
		t.Fatal(err)
	}
	if r := srv.Ranges(); len(r) != 2 || r[0] == "" || r[1] != "" {
		t.Fatalf("want resume attempt then full restart, got %v", r)
	}
	if res.Size != 60_000 {
		t.Fatalf("res = %+v", res)
	}
}

func TestDownloadRefusals(t *testing.T) {
	srv := acquiretest.New(t, "testdata", acquiretest.Payload(10))
	dir := t.TempDir()
	r := catalogReq(srv, dir)
	r.URL = strings.Replace(r.URL, "https://", "http://", 1)
	if _, err := Download(context.Background(), srv.Client(), r); err == nil || !strings.Contains(err.Error(), "non-HTTPS") {
		t.Fatalf("http allowed: %v", err)
	}
	r = catalogReq(srv, dir)
	r.SHA1 = ""
	if _, err := Download(context.Background(), srv.Client(), r); err == nil {
		t.Fatal("download without expected hash allowed")
	}
	r = catalogReq(srv, dir)
	r.FileName = "../evil.msu"
	if _, err := Download(context.Background(), srv.Client(), r); err == nil {
		t.Fatal("unsafe file name allowed")
	}
}
