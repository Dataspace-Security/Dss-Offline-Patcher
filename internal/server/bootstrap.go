package server

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"text/template"

	"offpatch/internal/manifest"
)

// One-command endpoint install. An endpoint admin pastes a single PowerShell
// line from the console. It pins the server's CA by fingerprint, fetches a
// generated installer from here and runs it. Both bootstrap routes require a
// usable enrollment token (header X-Enrollment-Token) instead of an admin login.

//go:embed bootstrap_windows.ps1.tmpl
var windowsBootstrapSrc string

var windowsBootstrap = template.Must(template.New("windows.ps1").Parse(windowsBootstrapSrc))

// Host header values we are willing to template into a script.
var hostRe = regexp.MustCompile(`^[A-Za-z0-9.\-]+(:[0-9]{1,5})?$|^\[[0-9A-Fa-f:.]+\](:[0-9]{1,5})?$`)

const bootstrapExe = "pmagent.exe"

func (s *Server) bootstrapAllowed(w http.ResponseWriter, r *http.Request) bool {
	if !s.store.EnrollmentTokenUsable(r.Context(), r.Header.Get("X-Enrollment-Token")) {
		writeErr(w, http.StatusUnauthorized, "enrollment token invalid, used or expired")
		return false
	}
	return true
}

// serverURL is the base URL the endpoint used to reach us, so the agent
// enrolls against an address that is known to work from that network.
func serverURL(r *http.Request) (string, bool) {
	if !hostRe.MatchString(r.Host) {
		return "", false
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + r.Host, true
}

func (s *Server) bootstrapWindows(w http.ResponseWriter, r *http.Request) {
	if !s.bootstrapAllowed(w, r) {
		return
	}
	url, ok := serverURL(r)
	if !ok {
		writeErr(w, http.StatusBadRequest, "invalid Host header")
		return
	}
	_, exeSHA, err := manifest.HashFile(filepath.Join(s.distDir(), bootstrapExe))
	if err != nil {
		s.log.Warn("windows bootstrap requested but pmagent.exe is not staged", "dir", s.distDir())
		writeErr(w, http.StatusNotFound, "pmagent.exe is not staged on the server")
		return
	}
	keys, rootPEM, err := s.setupKeys(r)
	if err != nil {
		s.fail(w, err)
		return
	}
	pems := make([]string, 0, len(keys))
	for _, k := range keys {
		pems = append(pems, strings.TrimSpace(k.PublicKey))
	}
	var buf bytes.Buffer
	if err := windowsBootstrap.Execute(&buf, map[string]any{
		"Server":    url,
		"ExeSHA256": exeSHA,
		"Keys":      pems,
		"Root":      strings.TrimSpace(rootPEM),
		"CA":        strings.TrimSpace(caPEM(s)),
	}); err != nil {
		s.fail(w, err)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Write(buf.Bytes())
}

func (s *Server) bootstrapFile(w http.ResponseWriter, r *http.Request) {
	if !s.bootstrapAllowed(w, r) {
		return
	}
	if r.PathValue("name") != bootstrapExe {
		writeErr(w, http.StatusNotFound, "only pmagent.exe is offered here")
		return
	}
	s.agentSetupFile(w, r)
}

// caFingerprint is the SHA-256 of the CA certificate (DER), upper-case hex as
// printed by PowerShell's X509Certificate.GetCertHashString('SHA256').
func caFingerprint(s *Server) string {
	if s.ca == nil {
		return ""
	}
	sum := sha256.Sum256(s.ca.Cert.Raw)
	return strings.ToUpper(hex.EncodeToString(sum[:]))
}

func agentDistHas(s *Server, name string) bool {
	st, err := os.Stat(filepath.Join(s.distDir(), name))
	return err == nil && st.Mode().IsRegular()
}
