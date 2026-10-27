package server

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"net"
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

// A second, cmd.exe-only installer for endpoints where PowerShell itself is
// blocked by policy (AppLocker/SRP, not just a cautious admin). Same contract
// as windows.ps1 — same enrollment token header, same staged pmagent.exe, same
// pinned keys/CA — rendered as batch instead. It requires curl.exe (bundled
// since Windows 10 1803 / Server 2019); see the template for why there is no
// scripted fallback for older images.
//
//go:embed bootstrap_windows.cmd.tmpl
var windowsBootstrapCmdSrc string

var windowsBootstrapCmd = template.Must(template.New("windows.cmd").Parse(windowsBootstrapCmdSrc))

// pemLines splits a PEM block (or any multi-line text) into the lines a batch
// script writes one at a time with `echo` — cmd has no heredoc. nil for an
// empty/blank input so `{{if .Field}}` in the cmd template works the same way
// as the plain-string `{{if .Field}}` in the PowerShell one. A blank line is
// dropped rather than written out: valid PEM never has one, and `echo` with
// nothing after it prints "ECHO is on."/"ECHO is off." instead of a blank
// line, which would otherwise corrupt the file it's appended to.
func pemLines(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	var lines []string
	for _, l := range strings.Split(s, "\n") {
		l = strings.TrimRight(l, "\r")
		if l != "" {
			lines = append(lines, l)
		}
	}
	return lines
}

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

// serverURL is the base URL the generated installer downloads from and the
// agent enrolls against: agent_url (by default https://<server IP>:<port>).
// Agents connect by IP, never by the console's server name, so endpoints
// need no DNS or hosts-file entry. Without an explicit agent_url, an IP the
// endpoint already used (Host header) is kept: it is known to work from that
// network.
func (s *Server) serverURL(r *http.Request) (string, bool) {
	if !hostRe.MatchString(r.Host) {
		return "", false
	}
	if s.cfg.AgentURL != "" {
		return s.cfg.AgentURL, true
	}
	if proxiedInfo(r) != nil {
		return s.agentURL(), true // the reverse proxy's address never reaches agents
	}
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if net.ParseIP(strings.Trim(host, "[]")) == nil {
		return s.agentURL(), true // a name (server_name, public_tls name): agents use the IP
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + r.Host, true
}

// windowsBootstrapData gathers what both Windows installer templates need
// (server URL, pmagent.exe's staged hash, pinned keys/root key) and writes
// the appropriate error response itself on failure. ok is false when it has
// already written that response and the caller should return without
// rendering a template.
func (s *Server) windowsBootstrapData(w http.ResponseWriter, r *http.Request) (url, exeSHA string, keys []setupKey, rootPEM string, ok bool) {
	url, hostOK := s.serverURL(r)
	if !hostOK {
		writeErr(w, http.StatusBadRequest, "invalid Host header")
		return "", "", nil, "", false
	}
	_, exeSHA, err := manifest.HashFile(filepath.Join(s.distDir(), bootstrapExe))
	if err != nil {
		s.log.Warn("windows bootstrap requested but pmagent.exe is not staged", "dir", s.distDir())
		writeErr(w, http.StatusNotFound, "pmagent.exe is not staged on the server")
		return "", "", nil, "", false
	}
	keys, rootPEM, err = s.setupKeys(r)
	if err != nil {
		s.fail(w, err)
		return "", "", nil, "", false
	}
	return url, exeSHA, keys, rootPEM, true
}

func (s *Server) bootstrapWindows(w http.ResponseWriter, r *http.Request) {
	if !s.bootstrapAllowed(w, r) {
		return
	}
	url, exeSHA, keys, rootPEM, ok := s.windowsBootstrapData(w, r)
	if !ok {
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

func (s *Server) bootstrapWindowsCmd(w http.ResponseWriter, r *http.Request) {
	if !s.bootstrapAllowed(w, r) {
		return
	}
	url, exeSHA, keys, rootPEM, ok := s.windowsBootstrapData(w, r)
	if !ok {
		return
	}
	keyLines := make([][]string, 0, len(keys))
	for _, k := range keys {
		keyLines = append(keyLines, pemLines(k.PublicKey))
	}
	var buf bytes.Buffer
	if err := windowsBootstrapCmd.Execute(&buf, map[string]any{
		"Server":    url,
		"ExeSHA256": exeSHA,
		"Keys":      keyLines,
		"Root":      pemLines(rootPEM),
		"CA":        pemLines(caPEM(s)),
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
