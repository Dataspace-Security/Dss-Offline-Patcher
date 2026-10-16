// Package acquire automates patch acquisition in the CONNECTED acquisition
// zone: it searches the Microsoft Update Catalog, reads the MSRC security
// update feed, downloads vendor files with resume and hash verification, and
// writes spec.json entries for `pmctl build`.
//
// Nothing in this package may run in the isolated zone. Everything fetched
// from the internet is treated as untrusted data: pages are only parsed with
// size limits, and downloaded files are only hashed, never executed.
package acquire

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

const (
	// DefaultUserAgent identifies the tool to Microsoft endpoints.
	DefaultUserAgent = "offpatch-pmctl/1 (+acquisition zone)"
	// maxPageBytes bounds catalog HTML responses.
	maxPageBytes = 16 << 20
	// maxJSONBytes bounds MSRC CVRF documents (a month is ~25 MiB).
	maxJSONBytes = 256 << 20
)

// DefaultHTTPClient returns a client for page/API requests with conservative
// timeouts. Downloads derive a client from it without the overall timeout
// (large files) but with an idle-read watchdog instead.
func DefaultHTTPClient() *http.Client {
	tr := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout:   20 * time.Second,
		ResponseHeaderTimeout: 90 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		IdleConnTimeout:       90 * time.Second,
		MaxIdleConns:          10,
		ForceAttemptHTTP2:     true,
	}
	return &http.Client{Transport: tr, Timeout: 2 * time.Minute, CheckRedirect: httpsOnlyRedirect}
}

// httpsOnlyRedirect refuses redirects that would downgrade to plain HTTP.
func httpsOnlyRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= 10 {
		return errors.New("too many redirects")
	}
	if req.URL.Scheme != "https" {
		return fmt.Errorf("refusing redirect to non-HTTPS URL %s", req.URL.Redacted())
	}
	return nil
}

func clientOrDefault(c *http.Client) *http.Client {
	if c == nil {
		return DefaultHTTPClient()
	}
	return c
}

// doRead performs req and returns the body (bounded by limit) for a 200 response.
func doRead(ctx context.Context, hc *http.Client, req *http.Request, limit int64) ([]byte, error) {
	req = req.WithContext(ctx)
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", DefaultUserAgent)
	}
	resp, err := clientOrDefault(hc).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		return nil, fmt.Errorf("%s %s: HTTP %d", req.Method, req.URL.Redacted(), resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("%s: response larger than %d bytes", req.URL.Redacted(), limit)
	}
	return b, nil
}
