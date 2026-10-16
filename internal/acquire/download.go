package acquire

import (
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// MaxDownloadBytes is a hard cap on any single downloaded file (matches the
// server's default max_file_bytes).
const MaxDownloadBytes = 4 << 30

var (
	// ErrHashMismatch is returned when a downloaded file does not match the
	// expected SHA-1/SHA-256. The partial file is removed.
	ErrHashMismatch = errors.New("hash mismatch")

	safeNameRe    = regexp.MustCompile(`^[A-Za-z0-9._-]{1,200}$`)
	catalogSHA1Re = regexp.MustCompile(`_([0-9a-fA-F]{40})\.[A-Za-z0-9]+$`)
	hex40Re       = regexp.MustCompile(`^[0-9a-f]{40}$`)
	hex64Re       = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// SHA1FromCatalogName extracts the lowercase SHA-1 that Microsoft Update
// Catalog embeds in file names ("..._<40 hex>.msu"), or "".
func SHA1FromCatalogName(name string) string {
	m := catalogSHA1Re.FindStringSubmatch(name)
	if m == nil {
		return ""
	}
	return strings.ToLower(m[1])
}

// DownloadRequest describes one file to fetch.
type DownloadRequest struct {
	URL      string // must be https
	DestDir  string
	FileName string // basename; [A-Za-z0-9._-]
	// At least one of SHA1/SHA256 is required: unverified downloads are refused.
	SHA1   string // lowercase hex
	SHA256 string // lowercase hex
	Size   int64  // expected size, 0 = unknown
	// IdleTimeout aborts a download that makes no progress (default 2m).
	IdleTimeout time.Duration
	// Progress, if set, is called with bytes written so far and total (-1 unknown).
	Progress func(done, total int64)
}

// DownloadResult describes the verified file on disk.
type DownloadResult struct {
	Path    string
	Size    int64
	SHA1    string
	SHA256  string
	Resumed bool // a .part file was continued
	Reused  bool // final file already existed and matched
}

// Download fetches req.URL into req.DestDir/req.FileName. It writes to
// "<name>.part", resumes an existing .part with an HTTP Range request, and
// renames into place only after the expected hashes match. On mismatch the
// partial file is deleted and ErrHashMismatch is returned.
func Download(ctx context.Context, hc *http.Client, req DownloadRequest) (*DownloadResult, error) {
	u, err := url.Parse(req.URL)
	if err != nil {
		return nil, fmt.Errorf("download url: %w", err)
	}
	if u.Scheme != "https" {
		return nil, fmt.Errorf("refusing non-HTTPS download URL %s", u.Redacted())
	}
	if !safeNameRe.MatchString(req.FileName) || req.FileName == "." || req.FileName == ".." {
		return nil, fmt.Errorf("unsafe file name %q", req.FileName)
	}
	req.SHA1 = strings.ToLower(strings.TrimSpace(req.SHA1))
	req.SHA256 = strings.ToLower(strings.TrimSpace(req.SHA256))
	if req.SHA1 == "" && req.SHA256 == "" {
		return nil, errors.New("refusing download without an expected SHA-1 or SHA-256")
	}
	if req.SHA1 != "" && !hex40Re.MatchString(req.SHA1) {
		return nil, fmt.Errorf("expected SHA-1 %q is not 40 hex chars", req.SHA1)
	}
	if req.SHA256 != "" && !hex64Re.MatchString(req.SHA256) {
		return nil, fmt.Errorf("expected SHA-256 %q is not 64 hex chars", req.SHA256)
	}
	if req.Size > MaxDownloadBytes {
		return nil, fmt.Errorf("file size %d exceeds limit %d", req.Size, int64(MaxDownloadBytes))
	}
	if req.IdleTimeout <= 0 {
		req.IdleTimeout = 2 * time.Minute
	}
	if err := os.MkdirAll(req.DestDir, 0o755); err != nil {
		return nil, err
	}
	final := filepath.Join(req.DestDir, req.FileName)
	part := final + ".part"

	// Already downloaded? Reuse only if it verifies; never overwrite silently.
	if _, err := os.Stat(final); err == nil {
		res, err := verifyFile(final, req)
		if err != nil {
			return nil, fmt.Errorf("%s already exists and does not match the expected hash (remove it to re-download): %w", final, err)
		}
		res.Reused = true
		return res, nil
	}

	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		resumed, err := fetchToPart(ctx, hc, req, part)
		if err != nil {
			return nil, err
		}
		res, err := verifyFile(part, req)
		if err != nil {
			os.Remove(part)
			lastErr = err
			if resumed {
				// A stale/corrupt .part may have caused it; retry once from scratch.
				continue
			}
			return nil, err
		}
		if err := os.Rename(part, final); err != nil {
			return nil, err
		}
		res.Path = final
		res.Resumed = resumed
		return res, nil
	}
	return nil, lastErr
}

// fetchToPart downloads into part, resuming if it already has content.
// It reports whether an existing .part was continued.
func fetchToPart(ctx context.Context, hc *http.Client, req DownloadRequest, part string) (bool, error) {
	var offset int64
	if fi, err := os.Stat(part); err == nil {
		offset = fi.Size()
		if req.Size > 0 && offset > req.Size {
			os.Remove(part)
			offset = 0
		}
	}
	if req.Size > 0 && offset == req.Size {
		return true, nil // complete; caller verifies
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	hreq, err := http.NewRequestWithContext(ctx, http.MethodGet, req.URL, nil)
	if err != nil {
		return false, err
	}
	hreq.Header.Set("User-Agent", DefaultUserAgent)
	if offset > 0 {
		hreq.Header.Set("Range", fmt.Sprintf("bytes=%d-", offset))
	}
	dc := *clientOrDefault(hc)
	dc.Timeout = 0 // large files; the idle watchdog below bounds stalls
	dc.CheckRedirect = httpsOnlyRedirect
	resp, err := dc.Do(hreq)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	flags := os.O_CREATE | os.O_WRONLY
	resumed := false
	switch {
	case offset > 0 && resp.StatusCode == http.StatusPartialContent:
		start, ok := contentRangeStart(resp.Header.Get("Content-Range"))
		if !ok || start != offset {
			return false, fmt.Errorf("server returned unexpected Content-Range %q for resume at %d", resp.Header.Get("Content-Range"), offset)
		}
		flags |= os.O_APPEND
		resumed = true
	case offset > 0 && resp.StatusCode == http.StatusRequestedRangeNotSatisfiable:
		// .part is probably already complete; let the caller verify it.
		return true, nil
	case resp.StatusCode == http.StatusOK:
		flags |= os.O_TRUNC // server ignored Range (or fresh download): start over
		offset = 0
	default:
		return false, fmt.Errorf("GET %s: HTTP %d", hreq.URL.Redacted(), resp.StatusCode)
	}

	total := int64(-1)
	if resp.ContentLength >= 0 {
		total = offset + resp.ContentLength
		if total > MaxDownloadBytes || (req.Size > 0 && total != req.Size) {
			return false, fmt.Errorf("server reports %d bytes, expected %d (limit %d)", total, req.Size, int64(MaxDownloadBytes))
		}
	}
	limit := int64(MaxDownloadBytes)
	if req.Size > 0 {
		limit = req.Size
	}

	f, err := os.OpenFile(part, flags, 0o644)
	if err != nil {
		return false, err
	}
	w := &progressWriter{w: f, done: offset, total: total, fn: req.Progress}
	body := newIdleReader(resp.Body, req.IdleTimeout, cancel)
	n, cerr := io.Copy(w, io.LimitReader(body, limit-offset+1))
	body.stop()
	if req.Progress != nil {
		req.Progress(w.done, total)
	}
	if serr := f.Sync(); cerr == nil {
		cerr = serr
	}
	if ferr := f.Close(); cerr == nil {
		cerr = ferr
	}
	if body.timedOut() {
		return false, fmt.Errorf("download stalled for %s; re-run to resume", req.IdleTimeout)
	}
	if cerr != nil {
		return false, fmt.Errorf("download interrupted after %d bytes (re-run to resume): %w", offset+n, cerr)
	}
	if offset+n > limit {
		os.Remove(part)
		return false, fmt.Errorf("download exceeded expected size %d", limit)
	}
	return resumed, nil
}

func contentRangeStart(v string) (int64, bool) {
	// "bytes 100-199/200"
	v = strings.TrimSpace(v)
	if !strings.HasPrefix(v, "bytes ") {
		return 0, false
	}
	rng, _, _ := strings.Cut(strings.TrimPrefix(v, "bytes "), "/")
	s, _, ok := strings.Cut(rng, "-")
	if !ok {
		return 0, false
	}
	n, err := strconv.ParseInt(s, 10, 64)
	return n, err == nil
}

// verifyFile hashes path and compares with the request's expectations.
func verifyFile(path string, req DownloadRequest) (*DownloadResult, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	h1, h256 := sha1.New(), sha256.New()
	n, err := io.Copy(io.MultiWriter(h1, h256), f)
	if err != nil {
		return nil, err
	}
	res := &DownloadResult{Path: path, Size: n, SHA1: hex.EncodeToString(h1.Sum(nil)), SHA256: hex.EncodeToString(h256.Sum(nil))}
	if req.Size > 0 && n != req.Size {
		return nil, fmt.Errorf("%w: size %d, expected %d", ErrHashMismatch, n, req.Size)
	}
	if req.SHA1 != "" && res.SHA1 != req.SHA1 {
		return nil, fmt.Errorf("%w: SHA-1 %s, expected %s", ErrHashMismatch, res.SHA1, req.SHA1)
	}
	if req.SHA256 != "" && res.SHA256 != req.SHA256 {
		return nil, fmt.Errorf("%w: SHA-256 %s, expected %s", ErrHashMismatch, res.SHA256, req.SHA256)
	}
	return res, nil
}

type progressWriter struct {
	w           io.Writer
	done, total int64
	fn          func(done, total int64)
	last        time.Time
}

func (p *progressWriter) Write(b []byte) (int, error) {
	n, err := p.w.Write(b)
	p.done += int64(n)
	if p.fn != nil && (time.Since(p.last) > 500*time.Millisecond || err != nil) {
		p.last = time.Now()
		p.fn(p.done, p.total)
	}
	return n, err
}

// idleReader cancels the request if no bytes arrive within d.
type idleReader struct {
	r     io.Reader
	d     time.Duration
	t     *time.Timer
	mu    sync.Mutex
	fired bool
}

func newIdleReader(r io.Reader, d time.Duration, cancel func()) *idleReader {
	ir := &idleReader{r: r, d: d}
	ir.t = time.AfterFunc(d, func() {
		ir.mu.Lock()
		ir.fired = true
		ir.mu.Unlock()
		cancel()
	})
	return ir
}

func (ir *idleReader) Read(b []byte) (int, error) {
	n, err := ir.r.Read(b)
	if n > 0 {
		ir.t.Reset(ir.d)
	}
	return n, err
}

func (ir *idleReader) stop() { ir.t.Stop() }

func (ir *idleReader) timedOut() bool {
	ir.mu.Lock()
	defer ir.mu.Unlock()
	return ir.fired
}
