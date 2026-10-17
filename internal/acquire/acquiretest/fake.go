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

	// CheckpointKB is the checkpoint cumulative update the download dialog
	// lists next to KB when Server.Checkpoint is set.
	CheckpointKB = "KB5043080"
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
	// Checkpoint, if set, makes the download dialog list a second .msu (a
	// checkpoint cumulative update, CheckpointKB) with this content, as the
	// catalog does for Windows 11 24H2 and later. CheckpointName is its
	// catalog file name (set by SetCheckpoint).
	Checkpoint     []byte
	CheckpointName string
	// Fail5xx makes the next n catalog/MSRC page requests answer 503.
	Fail5xx int

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
	dialog2 := read("downloaddialog-checkpoint.html")
	details := read("details-ac395651.html")
	cvrf := read("cvrf-2026-Oct.json")

	sum := sha1.Sum(payload)
	s := &Server{Payload: payload, Vendor: map[string][]byte{}}
	s.FileName = "windows10.0-kb5126657-x64_" + hex.EncodeToString(sum[:]) + ".msu"

	mux := http.NewServeMux()
	s.Server = httptest.NewTLSServer(failing(s, mux))
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
		s.mu.Lock()
		cp, cpName := s.Checkpoint, s.CheckpointName
		s.mu.Unlock()
		if cp != nil {
			csum := sha1.Sum(cp)
			page = strings.NewReplacer(
				"{{CHECKPOINT_URL}}", s.URL+"/dl/"+cpName, "{{CHECKPOINT_NAME}}", cpName,
				"{{CHECKPOINT_DIGEST}}", base64.StdEncoding.EncodeToString(csum[:]),
				"{{MAIN_URL}}", s.URL+"/dl/"+s.FileName, "{{MAIN_NAME}}", s.FileName,
				"{{MAIN_DIGEST}}", base64.StdEncoding.EncodeToString(sum[:]),
			).Replace(string(dialog2))
		}
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
		name := strings.TrimPrefix(r.URL.Path, "/dl/")
		s.mu.Lock()
		if s.Checkpoint != nil && name == s.CheckpointName {
			served = s.Checkpoint
		} else if name != s.FileName {
			served = nil
		}
		s.mu.Unlock()
		if served == nil {
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

// SetCheckpoint makes the download dialog list a checkpoint update with
// content b (see Server.Checkpoint).
func (s *Server) SetCheckpoint(b []byte) {
	sum := sha1.Sum(b)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Checkpoint = b
	s.CheckpointName = "windows11.0-" + strings.ToLower(CheckpointKB) + "-x64_" + hex.EncodeToString(sum[:]) + ".msu"
}

// failing answers 503 to catalog/MSRC page requests while Fail5xx > 0.
func failing(s *Server, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		page := strings.HasSuffix(r.URL.Path, ".aspx") || strings.HasPrefix(r.URL.Path, "/cvrf/")
		s.mu.Lock()
		fail := page && s.Fail5xx > 0
		if fail {
			s.Fail5xx--
		}
		s.mu.Unlock()
		if fail {
			http.Error(w, "busy", http.StatusServiceUnavailable)
			return
		}
		next.ServeHTTP(w, r)
	})
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
