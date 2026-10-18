package server

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"offpatch/internal/acqrequest"
	"offpatch/internal/store"
)

// Acquisition requests: the operator picks outdated apps and missing KBs on
// the Updates page and downloads a request file to carry to the acquisition
// zone (see internal/acqrequest). The server only answers the browser; it
// never sends anything out. Every export is audited with what it listed.

type acqRequestBody struct {
	Apps []string `json:"apps"` // winget ids from GET /api/updates or the Library
	KBs  []string `json:"kbs"`
	// AppArchs: winget id -> architecture (x64 | x86 | arm64) for apps that
	// no endpoint has installed (a Library import of something new); used
	// only then (default x64). Installed apps take the fleet's architectures.
	AppArchs map[string]string `json:"app_archs,omitempty"`
}

func (s *Server) exportAcqRequest(w http.ResponseWriter, r *http.Request) {
	var body acqRequestBody
	if !decode(w, r, &body) {
		return
	}
	if len(body.Apps)+len(body.KBs) == 0 {
		writeErr(w, http.StatusBadRequest, "select at least one application or Windows update")
		return
	}
	if len(body.Apps)+len(body.KBs) > acqrequest.MaxItems {
		writeErr(w, http.StatusBadRequest, fmt.Sprintf("at most %d items per request", acqrequest.MaxItems))
		return
	}
	sum, updates, err := s.fleet(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	if sum == nil || updates == nil {
		writeErr(w, http.StatusConflict, "no usable update intelligence: nothing to request")
		return
	}
	if len(body.AppArchs) > acqrequest.MaxItems {
		writeErr(w, http.StatusBadRequest, "too many app_archs entries")
		return
	}
	li, err := s.libraryIndex(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	req, missing, err := buildAcqRequest(updates, li, body)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if len(missing) > 0 {
		writeErr(w, http.StatusBadRequest, "not in the update intelligence (reload the page): "+strings.Join(missing, ", "))
		return
	}
	var rnd [3]byte
	rand.Read(rnd[:])
	now := time.Now().UTC()
	req.RequestID = acqrequest.NewID(now, hex.EncodeToString(rnd[:]))
	req.CreatedAt = now.Format(time.RFC3339)
	req.CreatedBy = actor(r)
	req.IntelGeneratedAt = sum.GeneratedAt
	if err := req.Validate(); err != nil {
		// Inventory text that the strict file format refuses (control characters, very long names).
		s.log.Warn("acquisition request not exportable", "err", err)
		writeErr(w, http.StatusUnprocessableEntity, "cannot export: "+err.Error())
		return
	}
	apps := make([]string, 0, len(req.Apps))
	for _, a := range req.Apps {
		apps = append(apps, a.WingetID+"@"+a.Version)
	}
	kbs := make([]string, 0, len(req.KBs))
	for _, k := range req.KBs {
		kbs = append(kbs, k.KB+"/"+k.Arch)
	}
	rec := store.AcqRequestRecord{RequestID: req.RequestID, CreatedAt: req.CreatedAt, CreatedBy: req.CreatedBy, IntelGeneratedAt: req.IntelGeneratedAt}
	for _, a := range req.Apps {
		rec.Items = append(rec.Items, store.AcqRequestItem{Kind: "app", Key: a.WingetID, Version: a.Version})
	}
	for _, k := range req.KBs {
		rec.Items = append(rec.Items, store.AcqRequestItem{Kind: "kb", Key: k.KB, Version: k.Arch})
	}
	// Direct hand-off when configured. The file is written before the audit
	// record so the record says where it went; it is removed again if the
	// record cannot be written (no audit record, no export).
	queuedTo, queuedErr := "", ""
	if dir := s.cfg.AcquisitionRequestsDir; dir != "" {
		if err := queueAcqRequest(dir, req); err != nil {
			s.log.Error("acquisition request not queued (operator must carry the file)", "request_id", req.RequestID, "dir", dir, "err", err)
			queuedErr = err.Error()
		} else {
			queuedTo = dir
		}
	}
	details := map[string]any{"apps": apps, "kbs": kbs, "intel_generated_at": req.IntelGeneratedAt, "queued_to": queuedTo}
	if queuedErr != "" {
		details["queued_error"] = queuedErr
	}
	// Tracked (seen / fulfilled) and audited in one transaction.
	if err := s.store.RecordAcqRequest(r.Context(), rec, store.Ev{Actor: req.CreatedBy, Action: "acquisition.request_exported", ObjectType: "acquisition_request",
		ObjectID: req.RequestID, Details: details}); err != nil {
		if queuedTo != "" {
			if rmErr := os.Remove(filepath.Join(queuedTo, req.RequestID+".json")); rmErr != nil {
				s.log.Error("unaudited acquisition request left queued", "request_id", req.RequestID, "err", rmErr)
			}
		}
		s.fail(w, err) // no audit record, no export
		return
	}
	w.Header().Set("Content-Disposition", `attachment; filename="`+req.RequestID+`.json"`)
	writeJSON(w, 200, queuedRequest{Request: req, QueuedTo: queuedTo})
}

// buildAcqRequest fills a request from the fleet view for the selected keys
// (only what the server itself knows is written out). Keys no endpoint
// needs are taken from the update intelligence (li; a Library import): an
// app with the architecture from app_archs and no installed forms, a KB
// with every architecture the intelligence lists for it. missing lists
// keys that are in neither.
func buildAcqRequest(updates []*fleetUpdate, li *libIndex, body acqRequestBody) (*acqrequest.Request, []string, error) {
	byKey := map[string]*fleetUpdate{}
	for _, u := range updates {
		byKey[u.Kind+"\x00"+strings.ToLower(u.Key)] = u
	}
	req := &acqrequest.Request{Format: acqrequest.Format, Version: acqrequest.Version, Apps: []acqrequest.App{}, KBs: []acqrequest.KB{}}
	var missing []string
	seen := map[string]bool{}
	for _, id := range body.Apps {
		u := byKey["app\x00"+strings.ToLower(strings.TrimSpace(id))]
		if u == nil {
			e := li.entry("app", strings.TrimSpace(id))
			if e == nil {
				missing = append(missing, id)
				continue
			}
			if seen["app\x00"+e.item.ID] {
				continue
			}
			seen["app\x00"+e.item.ID] = true
			arch, err := libraryArchFor(body.AppArchs, e.item.ID)
			if err != nil {
				return nil, nil, err
			}
			req.Apps = append(req.Apps, acqrequest.App{WingetID: e.item.ID, Name: acqrequest.CleanText(e.item.Name), Version: e.appVer,
				Architectures: []string{arch}})
			continue
		}
		if seen["app\x00"+u.Key] {
			continue
		}
		seen["app\x00"+u.Key] = true
		a := acqrequest.App{WingetID: u.Key, Name: acqrequest.CleanText(u.Name), Version: u.Latest, Endpoints: len(u.Endpoints), Architectures: []string{}}
		for ar := range u.arches {
			if acqrequest.ValidArch(ar) {
				a.Architectures = append(a.Architectures, ar)
			}
		}
		sort.Strings(a.Architectures)
		if len(a.Architectures) == 0 {
			a.Architectures = []string{"x64"}
		}
		for in := range u.installed {
			if !acqrequest.ValidProductCode(in.ProductCode) {
				in.ProductCode = ""
			}
			in.Name, in.Version = acqrequest.CleanText(in.Name), acqrequest.CleanText(in.Version)
			if !slices.Contains(a.Installed, in) {
				a.Installed = append(a.Installed, in)
			}
		}
		sort.Slice(a.Installed, func(i, j int) bool {
			x, y := a.Installed[i], a.Installed[j]
			if x.Name != y.Name {
				return x.Name < y.Name
			}
			if x.Version != y.Version {
				return x.Version < y.Version
			}
			return x.ProductCode < y.ProductCode
		})
		if len(a.Installed) > 50 {
			a.Installed = a.Installed[:50]
		}
		req.Apps = append(req.Apps, a)
	}
	for _, kb := range body.KBs {
		u := byKey["os\x00"+strings.ToLower(strings.TrimSpace(kb))]
		if u == nil {
			e := li.entry("os", strings.TrimSpace(kb))
			if e == nil {
				missing = append(missing, kb)
				continue
			}
			if seen["os\x00"+e.item.ID] {
				continue
			}
			seen["os\x00"+e.item.ID] = true
			for _, rel := range e.kbs {
				if !acqrequest.ValidArch(strings.ToLower(rel.Arch)) {
					continue
				}
				req.KBs = append(req.KBs, acqrequest.KB{KB: strings.ToUpper(rel.KB), Product: acqrequest.CleanText(rel.Product), Title: acqrequest.CleanText(rel.Title),
					Build: rel.Build, Arch: strings.ToLower(rel.Arch), Server: rel.Server})
			}
			continue
		}
		if seen["os\x00"+u.Key] {
			continue
		}
		seen["os\x00"+u.Key] = true
		arches := make([]string, 0, len(u.releases))
		for a := range u.releases {
			arches = append(arches, a)
		}
		sort.Strings(arches)
		for _, a := range arches {
			rel := u.releases[a]
			if !acqrequest.ValidArch(strings.ToLower(rel.Arch)) {
				continue
			}
			n := 0
			for _, e := range u.Endpoints {
				if strings.EqualFold(e.arch, rel.Arch) {
					n++
				}
			}
			req.KBs = append(req.KBs, acqrequest.KB{KB: strings.ToUpper(rel.KB), Product: acqrequest.CleanText(rel.Product), Title: acqrequest.CleanText(rel.Title),
				Build: rel.Build, Arch: strings.ToLower(rel.Arch), Server: rel.Server, Endpoints: n})
		}
	}
	return req, missing, nil
}
