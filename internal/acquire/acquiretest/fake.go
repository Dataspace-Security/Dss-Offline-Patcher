// Package acquiretest provides an httptest TLS server that imitates the
// Microsoft Update Catalog, its download host, the MSRC CVRF API and a
// third-party vendor site, using the recorded fixtures in
// internal/acquire/testdata. For tests only.
package acquiretest

import (
	"bytes"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// Recorded fixture facts (live catalog, 2026-10-16).
const (
	UpdateID     = "ac395651-eed0-47e7-a5cf-bd9ceccd6299"
	KB           = "KB5126657"
	Title        = "2026-10 Cumulative Update for Windows 10 Version 22H2 for x64-based Systems (KB5126657)"
	origFileName = "windows10.0-kb5126657-x64_6ea46ad975176d6c6e9dcc79859d67c5193d6fc0.msu"
	origURLBase  = "https://catalog.s.download.windowsupdate.com/c/msdownload/update/software/secu/2026/10/"
	origDigest   = "bqRq2XUXbWxuncx5hZ1nxRk9b8A="
	origSize     = "1236404149"
)

// Server is a fake of the Microsoft endpoints.
type Server struct {
	*httptest.Server
	Payload  []byte // the .msu content the catalog advertises (hash in file name)
	Served   []byte // what /dl/ actually serves (defaults to Payload)
	FileName string // catalog file name, with the payload SHA-1 embedded
	// IgnoreRange makes the download host answer 200 to Range requests.
	IgnoreRange bool
	// Vendor files served at /vendor/<name>.
	Vendor map[string][]byte

	mu          sync.Mutex
	RangeHeader []string // Range header of each /dl/ request ("" if none)
	MSRCAccept  string
	DialogForm  string
}

// New starts the fake. fixtures is the path to internal/acquire/testdata.
func New(t testing.TB, fixtures string, payload []byte) *Server {
	t.Helper()
	read := func(name string) []byte {
		b, err := os.ReadFile(filepath.Join(fixtures, name))
		if err != nil {
			t.Fatalf("fixture: %v", err)
		}
		return b
	}
	search := read("search-KB5126657.html")
	noRes := read("search-noresults.html")
	dialog := read("downloaddialog-ac395651.html")
	details := read("details-ac395651.html")
	cvrf := read("cvrf-2026-Oct.json")

	sum := sha1.Sum(payload)
	s := &Server{Payload: payload, Vendor: map[string][]byte{}}
	s.FileName = "windows10.0-kb5126657-x64_" + hex.EncodeToString(sum[:]) + ".msu"

	mux := http.NewServeMux()
	s.Server = httptest.NewTLSServer(mux)
	t.Cleanup(s.Close)

	mux.HandleFunc("/Search.aspx", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if strings.Contains(r.URL.Query().Get("q"), "5126657") {
			// Advertise the fake payload's size for our row.
			w.Write(bytes.ReplaceAll(search, []byte(">"+origSize+"<"), []byte(">"+strconv.Itoa(len(payload))+"<")))
			return
		}
		w.Write(noRes)
	})
	mux.HandleFunc("/DownloadDialog.aspx", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "post only", http.StatusMethodNotAllowed)
			return
		}
		r.ParseForm()
		s.mu.Lock()
		s.DialogForm = r.PostForm.Get("updateIDs")
		s.mu.Unlock()
		if !strings.Contains(r.PostForm.Get("updateIDs"), `"updateID":"`+UpdateID+`"`) {
			http.NotFound(w, r)
			return
		}
		page := string(dialog)
		page = strings.ReplaceAll(page, origURLBase+origFileName, s.URL+"/dl/"+s.FileName)
		page = strings.ReplaceAll(page, origFileName, s.FileName)
		page = strings.ReplaceAll(page, origDigest, base64.StdEncoding.EncodeToString(sum[:]))
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(page))
	})
	mux.HandleFunc("/ScopedViewInline.aspx", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("updateid") != UpdateID {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(details)
	})
	mux.HandleFunc("/dl/", func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.RangeHeader = append(s.RangeHeader, r.Header.Get("Range"))
		served := s.Served
		ignore := s.IgnoreRange
		s.mu.Unlock()
		if served == nil {
			served = s.Payload
		}
		if strings.TrimPrefix(r.URL.Path, "/dl/") != s.FileName {
			http.NotFound(w, r)
			return
		}
		if ignore {
			r.Header.Del("Range")
		}
		http.ServeContent(w, r, s.FileName, time.Time{}, bytes.NewReader(served))
	})
	mux.HandleFunc("/cvrf/v3.0/cvrf/", func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.MSRCAccept = r.Header.Get("Accept")
		s.mu.Unlock()
		if strings.TrimPrefix(r.URL.Path, "/cvrf/v3.0/cvrf/") != "2026-Oct" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(cvrf)
	})
	mux.HandleFunc("/vendor/", func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		b, ok := s.Vendor[strings.TrimPrefix(r.URL.Path, "/vendor/")]
		s.mu.Unlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
		http.ServeContent(w, r, "f", time.Time{}, bytes.NewReader(b))
	})
	return s
}

// Ranges returns the Range headers seen by the download host so far.
func (s *Server) Ranges() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.RangeHeader...)
}

// Payload returns n deterministic pseudo-random bytes.
func Payload(n int) []byte {
	b := make([]byte, n)
	x := uint32(2463534242)
	for i := range b {
		x ^= x << 13
		x ^= x >> 17
		x ^= x << 5
		b[i] = byte(x)
	}
	return b
}
