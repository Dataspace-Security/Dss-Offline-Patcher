package server

import (
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"

	"offpatch/internal/manifest"
	"offpatch/internal/trust"
)

// Agent setup support for the console: the public keys agents must pin, and
// agent binaries staged by an operator in <data_dir>/agent-dist/ so endpoint
// admins can fetch them from inside the isolated zone.

type setupKey struct {
	KeyID     string   `json:"key_id"`
	PublicKey string   `json:"public_key"`
	Sources   []string `json:"sources"`
}

type setupFile struct {
	Name   string `json:"name"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

var distNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$`)

func (s *Server) distDir() string {
	d := filepath.Join(s.cfg.DataDir, "agent-dist")
	if abs, err := filepath.Abs(d); err == nil {
		return abs
	}
	return d
}

func (s *Server) agentSetup(w http.ResponseWriter, r *http.Request) {
	icfg, err := s.cfg.IntakeConfig()
	if err != nil {
		s.fail(w, err)
		return
	}
	keys := []setupKey{}
	// After a key rotation the latest verified trust document is authoritative.
	if raw, _ := s.store.GetMeta(r.Context(), "trust_doc"); raw != "" && icfg.RootPub != nil {
		if signed, err := trust.Parse([]byte(raw)); err == nil {
			if doc, err := trust.Verify(signed, icfg.RootPub); err == nil {
				for _, k := range doc.Keys {
					keys = append(keys, setupKey{KeyID: k.KeyID, PublicKey: k.PublicKey, Sources: k.Sources})
				}
			}
		}
	}
	if len(keys) == 0 {
		for id, k := range icfg.Keys {
			keys = append(keys, setupKey{KeyID: id, PublicKey: string(manifest.EncodePublic(k.Pub)), Sources: k.Sources})
		}
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].KeyID < keys[j].KeyID })

	files := []setupFile{}
	if entries, err := os.ReadDir(s.distDir()); err == nil {
		for _, e := range entries {
			if !e.Type().IsRegular() || !distNameRe.MatchString(e.Name()) {
				continue
			}
			size, sha, err := manifest.HashFile(filepath.Join(s.distDir(), e.Name()))
			if err == nil {
				files = append(files, setupFile{Name: e.Name(), Size: size, SHA256: sha})
			}
		}
	}
	writeJSON(w, 200, map[string]any{
		"trusted_keys":             keys,
		"tls":                      s.cfg.TLSCert != "",
		"checkin_interval_seconds": s.cfg.CheckinIntervalSeconds,
		"agent_files":              files,
		"agent_dist_dir":           s.distDir(),
		"ca_certificate":           caPEM(s),
	})
}

func (s *Server) agentSetupFile(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !distNameRe.MatchString(name) {
		writeErr(w, 400, "invalid file name")
		return
	}
	f, err := os.Open(filepath.Join(s.distDir(), name))
	if err != nil {
		writeErr(w, 404, "file not staged in agent-dist")
		return
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() {
		writeErr(w, 404, "file not staged in agent-dist")
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	http.ServeContent(w, r, name, st.ModTime(), f)
}

func caPEM(s *Server) string {
	if s.ca == nil {
		return ""
	}
	return string(s.ca.CertPEM)
}
