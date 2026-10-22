package acquire

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestOracleJDKAlternate(t *testing.T) {
	cases := []struct{ u, ver, want string }{
		{"https://download.oracle.com/java/21/archive/jdk-21.0.13_windows-x64_bin.msi", "",
			"https://download.oracle.com/java/21/latest/jdk-21_windows-x64_bin.msi"},
		{"https://download.oracle.com/java/25/archive/jdk-25.0.5.0.2_windows-x64_bin.msi", "",
			"https://download.oracle.com/java/25/latest/jdk-25_windows-x64_bin.msi"},
		{"https://download.oracle.com/java/21/archive/jdk-21_windows-x64_bin.exe", "",
			"https://download.oracle.com/java/21/latest/jdk-21_windows-x64_bin.exe"},
		{"https://download.oracle.com/java/21/latest/jdk-21_windows-x64_bin.msi", "21.0.12.0",
			"https://download.oracle.com/java/21/archive/jdk-21.0.12_windows-x64_bin.msi"},
		{"https://download.oracle.com/java/25/latest/jdk-25_windows-x64_bin.msi", "25.0.4.1",
			"https://download.oracle.com/java/25/archive/jdk-25.0.4.1_windows-x64_bin.msi"},
		{"https://download.oracle.com/java/21/latest/jdk-21_windows-x64_bin.msi", "21.0.0.0",
			"https://download.oracle.com/java/21/archive/jdk-21_windows-x64_bin.msi"},
		// No version for a /latest/ URL, another feature's version, or not Oracle's layout.
		{"https://download.oracle.com/java/21/latest/jdk-21_windows-x64_bin.msi", "", ""},
		{"https://download.oracle.com/java/21/latest/jdk-21_windows-x64_bin.msi", "17.0.12", ""},
		{"https://download.oracle.com/java/21/archive/jdk-17.0.12_windows-x64_bin.msi", "", ""},
		{"https://download.oracle.com/java/21/archive/../latest/jdk-21_windows-x64_bin.msi", "", ""},
		{"https://example.com/java/21/archive/jdk-21.0.12_windows-x64_bin.msi", "", ""},
		{"http://download.oracle.com/java/21/archive/jdk-21.0.12_windows-x64_bin.msi", "", ""},
		{"https://download.oracle.com/otn/java/jdk/21.0.13/jdk-21.0.13_windows-x64_bin.msi", "", ""},
	}
	for _, c := range cases {
		if got := OracleJDKAlternate(c.u, c.ver); got != c.want {
			t.Errorf("OracleJDKAlternate(%q, %q) = %q, want %q", c.u, c.ver, got, c.want)
		}
	}
}

// oracleServer stands in for download.oracle.com: files maps a path to its
// content (absent = 404). It records the paths requested.
type oracleServer struct {
	srv   *httptest.Server
	mu    sync.Mutex
	files map[string][]byte
	paths []string
}

func newOracleServer(t *testing.T, files map[string][]byte) *oracleServer {
	t.Helper()
	o := &oracleServer{files: files}
	o.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		o.mu.Lock()
		o.paths = append(o.paths, r.URL.Path)
		b, ok := o.files[r.URL.Path]
		o.mu.Unlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Write(b)
	}))
	t.Cleanup(o.srv.Close)
	return o
}

// client sends every request (whatever host) to the test server.
func (o *oracleServer) client() *http.Client {
	tr := o.srv.Client().Transport.(*http.Transport).Clone()
	addr := o.srv.Listener.Addr().String()
	tr.DialTLSContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		var d tls.Dialer
		d.Config = &tls.Config{InsecureSkipVerify: true} // test server only
		return d.DialContext(ctx, network, addr)
	}
	return &http.Client{Transport: tr}
}

func (o *oracleServer) requested() []string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]string(nil), o.paths...)
}

func sha(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

const (
	jdkArchive  = "/java/21/archive/jdk-21.0.12_windows-x64_bin.msi"
	jdkLatest   = "/java/21/latest/jdk-21_windows-x64_bin.msi"
	jdkArchiveU = "https://download.oracle.com" + jdkArchive
	jdkLatestU  = "https://download.oracle.com" + jdkLatest
)

func TestDownloadOracleCurrentUpdateFromLatest(t *testing.T) {
	// The manifest names /archive/, but the update is the current one: it is
	// only under /latest/, whose published SHA-256 matches.
	payload := []byte(strings.Repeat("current jdk ", 5000))
	o := newOracleServer(t, map[string][]byte{
		jdkLatest:             payload,
		jdkLatest + ".sha256": []byte(sha(payload) + "\n"),
	})
	dir := t.TempDir()
	res, err := Download(context.Background(), o.client(), DownloadRequest{URL: jdkArchiveU, DestDir: dir, FileName: "jdk.msi", SHA256: sha(payload)})
	if err != nil {
		t.Fatal(err)
	}
	if res.URL != jdkLatestU || res.SHA256 != sha(payload) {
		t.Fatalf("res = %+v", res)
	}
	// Probe, then straight to /latest/: the archive is not tried first.
	if got := o.requested(); strings.Join(got, ",") != jdkLatest+".sha256,"+jdkLatest {
		t.Fatalf("requests: %v", got)
	}
}

func TestDownloadOracleOlderUpdateFromArchive(t *testing.T) {
	// /latest/ now serves a newer update (other hash): the archive is used
	// first, without downloading /latest/.
	old := []byte(strings.Repeat("older jdk ", 5000))
	newer := []byte(strings.Repeat("newer jdk ", 5000))
	o := newOracleServer(t, map[string][]byte{
		jdkArchive:            old,
		jdkLatest:             newer,
		jdkLatest + ".sha256": []byte(sha(newer)),
	})
	res, err := Download(context.Background(), o.client(), DownloadRequest{URL: jdkLatestU, Version: "21.0.12.0", DestDir: t.TempDir(), FileName: "jdk.msi", SHA256: sha(old)})
	if err != nil {
		t.Fatal(err)
	}
	if res.URL != jdkArchiveU {
		t.Fatalf("res = %+v", res)
	}
	for _, p := range o.requested() {
		if p == jdkLatest {
			t.Fatalf("downloaded /latest/ although its hash differs: %v", o.requested())
		}
	}
}

func TestDownloadOracleFallbackOn404(t *testing.T) {
	// No .sha256 published: the manifest's URL first, the other on 404.
	payload := []byte(strings.Repeat("jdk ", 9000))
	o := newOracleServer(t, map[string][]byte{jdkLatest: payload})
	res, err := Download(context.Background(), o.client(), DownloadRequest{URL: jdkArchiveU, DestDir: t.TempDir(), FileName: "jdk.msi", SHA256: sha(payload)})
	if err != nil {
		t.Fatal(err)
	}
	if res.URL != jdkLatestU {
		t.Fatalf("res = %+v", res)
	}
	if got := o.requested(); strings.Join(got, ",") != jdkLatest+".sha256,"+jdkArchive+","+jdkLatest {
		t.Fatalf("requests: %v", got)
	}
}

func TestDownloadOracleLatestMovedOn(t *testing.T) {
	// The manifest names /latest/, which now serves a newer update and
	// publishes no .sha256: the hash fails there and the archive is used.
	old := []byte(strings.Repeat("older jdk ", 5000))
	o := newOracleServer(t, map[string][]byte{
		jdkArchive: old,
		jdkLatest:  []byte(strings.Repeat("newer jdk ", 5000)),
	})
	res, err := Download(context.Background(), o.client(), DownloadRequest{URL: jdkLatestU, Version: "21.0.12", DestDir: t.TempDir(), FileName: "jdk.msi", SHA256: sha(old)})
	if err != nil {
		t.Fatal(err)
	}
	if res.URL != jdkArchiveU || res.SHA256 != sha(old) {
		t.Fatalf("res = %+v", res)
	}
}

func TestDownloadOracleStillHashChecked(t *testing.T) {
	// The alternate location serves other content: refused, nothing kept.
	o := newOracleServer(t, map[string][]byte{jdkLatest: []byte("not the expected file")})
	dir := t.TempDir()
	want := sha([]byte("the expected file"))
	_, err := Download(context.Background(), o.client(), DownloadRequest{URL: jdkArchiveU, DestDir: dir, FileName: "jdk.msi", SHA256: want})
	if !errors.Is(err, ErrHashMismatch) {
		t.Fatalf("err = %v, want hash mismatch", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "jdk.msi")); !os.IsNotExist(err) {
		t.Fatal("mismatching file kept")
	}
}

func TestDownloadOracleNeitherLocation(t *testing.T) {
	// Oracle JDK 21.0.13: the winget manifest names an /archive/ file that
	// was never published, and /latest/ is gone (OTN license): unsupported,
	// with a reason, instead of a bare HTTP 404 retried every run.
	o := newOracleServer(t, map[string][]byte{})
	u := "https://download.oracle.com/java/21/archive/jdk-21.0.13_windows-x64_bin.msi"
	_, err := Download(context.Background(), o.client(), DownloadRequest{URL: u, DestDir: t.TempDir(), FileName: "jdk.msi", SHA256: sha([]byte("x"))})
	var un *UnsupportedError
	if !errors.As(err, &un) {
		t.Fatalf("err = %v, want UnsupportedError", err)
	}
	for _, s := range []string{"No-Fee", u, "https://download.oracle.com/java/21/latest/jdk-21_windows-x64_bin.msi"} {
		if !strings.Contains(err.Error(), s) {
			t.Errorf("error %q lacks %q", err, s)
		}
	}
}

func TestDownloadNonOracle404Unchanged(t *testing.T) {
	o := newOracleServer(t, map[string][]byte{})
	_, err := Download(context.Background(), o.client(), DownloadRequest{URL: "https://example.com/a.msi", DestDir: t.TempDir(), FileName: "a.msi", SHA256: sha([]byte("x"))})
	var un *UnsupportedError
	if !IsNotFound(err) || errors.As(err, &un) {
		t.Fatalf("err = %v, want plain HTTP 404", err)
	}
	if got := o.requested(); len(got) != 1 {
		t.Fatalf("requests: %v", got)
	}
}
