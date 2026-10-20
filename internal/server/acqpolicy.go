package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"offpatch/internal/acqpolicy"
	"offpatch/internal/acqstatus"
	"offpatch/internal/store"
)

// Auto-download policy (Settings → Auto-download, super admin only): what
// the acquisition zone downloads on every run, merged by pmctl over
// acquire.json. Saved versions are delivered like acquisition requests:
// written to acquisition_requests_dir when it is set (single server), else
// downloaded and carried by a person (two machines). See
// docs/08-acquisition.md "Auto-download policy".

// acquireConfigPaths: where pmserver looks for the installer's acquire.json
// to offer it as the starting policy (it is usually readable only by the
// acquisition user; the downloader then reports it in its status report).
var acquireConfigPaths = func() []string {
	if p := os.Getenv("OFFPATCH_ACQUIRE_CONFIG"); p != "" {
		return []string{p}
	}
	return []string{"/etc/offpatch/acquire.json"}
}

// downloaderView is what the newest acquisition status report says.
type downloaderView struct {
	Source          string                   `json:"source"`
	Host            string                   `json:"host"`
	FinishedAt      string                   `json:"finished_at"`
	Outcome         string                   `json:"outcome"`
	Schedule        string                   `json:"schedule"`
	PolicyVersion   int                      `json:"policy_version"`
	PolicySHA256    string                   `json:"policy_sha256"`
	PolicyAppliedAt string                   `json:"policy_applied_at"`
	PolicyError     string                   `json:"policy_error,omitempty"`
	PolicySignature string                   `json:"policy_signature,omitempty"`
	RunRequest      string                   `json:"run_request,omitempty"`
	Sources         []acqstatus.SourceResult `json:"sources"`
	// Reports: false when the downloader's pmctl predates the policy (it
	// sends no policy fields at all).
	Reports bool `json:"reports_policy"`
}

type policyResponse struct {
	store.AcqPolicyRecord
	IsDefault bool `json:"is_default"`
	// DefaultSource: where version 0 came from: acquire.json (read by the
	// server), downloader (acquire.json as reported by pmctl) or none.
	DefaultSource string `json:"default_source"`
	Banner        string `json:"banner,omitempty"`
	// DefaultFeeds: acquire.json feeds the policy cannot express (they
	// keep running from acquire.json).
	DefaultFeeds []string                 `json:"default_feeds"`
	Downloader   *downloaderView          `json:"downloader"`
	Delivery     policyDelivery           `json:"delivery"`
	Choices      []acqpolicy.KnownWindows `json:"windows_choices"`
	LastRun      *runRequested            `json:"last_run_request"`
	// Pending: a source change waiting for a second super admin (S-4);
	// CanApprove: the signed-in user may approve it (is not the proposer).
	Pending    *store.AcqPolicyPending `json:"pending"`
	CanApprove bool                    `json:"can_approve"`
	Signing    policySigning           `json:"signing"`
}

type policyDelivery struct {
	// Direct: acquisition_requests_dir is set (the server hands files over).
	Direct bool `json:"direct"`
}

type runRequested struct {
	RunID       string `json:"run_id"`
	RequestedBy string `json:"requested_by"`
	RequestedAt string `json:"requested_at"`
	QueuedTo    string `json:"queued_to"`
}

const metaLastRunRequest = "acq_last_run_request"

type reportPolicyFields struct {
	Host            string                   `json:"host"`
	Schedule        string                   `json:"schedule"`
	PolicyVersion   *int                     `json:"policy_version"`
	PolicySHA256    string                   `json:"policy_sha256"`
	PolicyAppliedAt string                   `json:"policy_applied_at"`
	PolicyError     string                   `json:"policy_error"`
	PolicySignature string                   `json:"policy_signature"`
	RunRequest      string                   `json:"run_request"`
	Sources         []acqstatus.SourceResult `json:"sources"`
	Defaults        *acqpolicy.Base          `json:"defaults"`
}

// downloaderState reads the newest status report and the newest report
// that carries acquire.json defaults.
func (s *Server) downloaderState(ctx context.Context) (*downloaderView, *acqpolicy.Base, error) {
	_, hist, err := s.store.Acquisition(ctx, 100)
	if err != nil {
		return nil, nil, err
	}
	var view *downloaderView
	var base *acqpolicy.Base
	for _, rec := range hist {
		var f reportPolicyFields
		if json.Unmarshal(rec.Report, &f) != nil {
			continue
		}
		if view == nil {
			view = &downloaderView{Source: rec.Source, Host: f.Host, FinishedAt: rec.FinishedAt, Outcome: rec.Outcome, Schedule: f.Schedule,
				PolicySHA256: f.PolicySHA256, PolicyAppliedAt: f.PolicyAppliedAt, PolicyError: f.PolicyError, PolicySignature: f.PolicySignature, RunRequest: f.RunRequest,
				Sources: f.Sources, Reports: f.Defaults != nil || f.PolicyVersion != nil}
			if f.PolicyVersion != nil {
				view.PolicyVersion = *f.PolicyVersion
			}
			if view.Sources == nil {
				view.Sources = []acqstatus.SourceResult{}
			}
		}
		if base == nil && f.Defaults != nil {
			b := *f.Defaults
			if b.Policy.Normalize() == nil {
				base = &b
			}
		}
		if view != nil && base != nil {
			break
		}
	}
	return view, base, nil
}

// policyDefaults is version 0: acquire.json if the server can read it,
// else what the downloader reported from it, else empty.
func (s *Server) policyDefaults(reported *acqpolicy.Base) (acqpolicy.Base, string, string) {
	for _, p := range acquireConfigPaths() {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		base, err := acqpolicy.FromAcquireJSON(b)
		if err != nil {
			s.log.Warn("acquire.json not usable as the starting auto-download policy", "path", p, "err", err)
			continue
		}
		return base, "acquire.json", ""
	}
	if reported != nil {
		return *reported, "downloader", ""
	}
	return acqpolicy.Base{Policy: acqpolicy.Empty(), Feeds: []string{}}, "none",
		"The installer's settings (acquire.json) could not be read here, and the downloader has not reported them yet. " +
			"Until you save a policy, the downloader keeps using acquire.json unchanged."
}

func (s *Server) getAcqPolicy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if v := r.URL.Query().Get("version"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			writeErr(w, http.StatusBadRequest, "version must be a positive number")
			return
		}
		rec, err := s.store.GetAcqPolicyVersion(ctx, n)
		if err != nil {
			s.fail(w, err)
			return
		}
		writeJSON(w, 200, rec)
		return
	}
	view, reported, err := s.downloaderState(ctx)
	if err != nil {
		s.fail(w, err)
		return
	}
	rec, ok, err := s.store.GetAcqPolicy(ctx)
	if err != nil {
		s.fail(w, err)
		return
	}
	base, src, banner := s.policyDefaults(reported)
	resp := policyResponse{AcqPolicyRecord: rec, IsDefault: !ok, DefaultSource: src, DefaultFeeds: base.Feeds, Downloader: view,
		Delivery: policyDelivery{Direct: s.cfg.AcquisitionRequestsDir != ""}, Choices: s.windowsChoices(ctx)}
	if !ok {
		resp.Policy, resp.SHA256, resp.Banner, resp.Summary = base.Policy, acqpolicy.Hash(base.Policy), banner, []string{}
	}
	if resp.DefaultFeeds == nil {
		resp.DefaultFeeds = []string{}
	}
	if resp.Pending, err = s.store.GetAcqPolicyPending(ctx); err != nil {
		s.fail(w, err)
		return
	}
	resp.CanApprove = resp.Pending != nil && !strings.EqualFold(resp.Pending.ProposedBy, actor(r))
	resp.Signing = s.policySigningView()
	if raw, _ := s.store.GetMeta(ctx, metaLastRunRequest); raw != "" {
		var lr runRequested
		if json.Unmarshal([]byte(raw), &lr) == nil {
			resp.LastRun = &lr
		}
	}
	writeJSON(w, 200, resp)
}

// windowsChoices: the releases the downloader knows, plus every release the
// update intelligence lists.
func (s *Server) windowsChoices(ctx context.Context) []acqpolicy.KnownWindows {
	out := append([]acqpolicy.KnownWindows{}, acqpolicy.Known...)
	seen := map[string]bool{}
	key := func(p string, b int, a string) string { return strings.ToLower(p) + "/" + strconv.Itoa(b) + "/" + a }
	for _, k := range out {
		seen[key(k.Product, k.Build, k.Arch)] = true
	}
	if ix, _, err := s.intelIndex(ctx); err == nil && ix != nil {
		for _, rel := range ix.Doc.Windows {
			arch := strings.ToLower(rel.Arch)
			k := key(rel.Product, rel.Build, arch)
			if seen[k] || rel.Product == "" || rel.Build <= 0 {
				continue
			}
			seen[k] = true
			out = append(out, acqpolicy.KnownWindows{Product: acqrequestClean(rel.Product), Build: rel.Build, Arch: arch, Server: rel.Server,
				CatalogProduct: acqrequestClean(rel.Product)})
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Server != out[j].Server {
			return !out[i].Server
		}
		if out[i].Product != out[j].Product {
			return out[i].Product < out[j].Product
		}
		return out[i].Arch < out[j].Arch
	})
	return out
}

func acqrequestClean(s string) string { return cleanLibText(s, 80) }

type savedPolicy struct {
	store.AcqPolicyRecord
	QueuedTo    string `json:"queued_to"`
	QueuedError string `json:"queued_error,omitempty"`
}

func (s *Server) putAcqPolicy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	base := -1
	if v := r.URL.Query().Get("base_version"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			writeErr(w, http.StatusBadRequest, "base_version must be a number")
			return
		}
		base = n
	}
	var p acqpolicy.Policy
	if !decode(w, r, &p) {
		return
	}
	// The editor of every new source is recorded by the server, not taken
	// from the browser; existing sources keep who added them.
	prev, ok, err := s.store.GetAcqPolicy(ctx)
	if err != nil {
		s.fail(w, err)
		return
	}
	_, reported, err := s.downloaderState(ctx)
	if err != nil {
		s.fail(w, err)
		return
	}
	defaults, _, _ := s.policyDefaults(reported)
	before := defaults.Policy
	if ok {
		before = prev.Policy
	}
	addedBy := map[string]string{}
	for _, src := range before.Sources {
		addedBy[src.ID] = src.AddedBy
	}
	p.Sources = append([]acqpolicy.Source{}, p.Sources...)
	for i := range p.Sources {
		if who, had := addedBy[strings.TrimSpace(p.Sources[i].ID)]; had {
			p.Sources[i].AddedBy = who
		} else {
			p.Sources[i].AddedBy = actor(r)
		}
	}
	rec, err := s.store.SaveAcqPolicy(ctx, actor(r), p, base, defaults.Policy)
	if errors.Is(err, store.ErrNeedsSecondApprover) {
		// Adds or changes a download source: a second super admin approves it (S-4).
		s.proposeAcqPolicy(w, r, p, base, defaults.Policy)
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	out := savedPolicy{AcqPolicyRecord: rec}
	out.QueuedTo, out.QueuedError = s.queuePolicy(ctx, r, rec)
	writeJSON(w, 200, out)
}

// queuePolicy hands the saved version to the downloader when
// acquisition_requests_dir is set; the delivery is audited.
func (s *Server) queuePolicy(ctx context.Context, r *http.Request, rec store.AcqPolicyRecord) (string, string) {
	dir := s.cfg.AcquisitionRequestsDir
	if dir == "" {
		return "", ""
	}
	details := map[string]any{"version": rec.Version, "sha256": rec.SHA256, "queued_to": dir}
	qerr := ""
	b, err := s.signedPolicyFile(rec)
	if err == nil {
		err = writeQueued(dir, acqpolicy.FileName(rec.Version), b)
	}
	if err != nil {
		s.log.Error("auto-download policy not queued (download the file and carry it)", "version", rec.Version, "dir", dir, "err", err)
		qerr, dir = err.Error(), ""
		details["queued_to"], details["queued_error"] = "", qerr
	} else if v := s.policySigningView(); v.Error == "" {
		details["signed_by"] = v.KeyID
		s.store.SetMeta(ctx, metaPolicySignedQueued, strconv.Itoa(rec.Version)+" "+v.KeyID)
	}
	s.store.Audit(ctx, store.Ev{Actor: actor(r), Action: "acquisition.policy_queued", ObjectType: "acquisition_policy",
		ObjectID: strconv.Itoa(rec.Version), Failure: qerr != "", Details: details})
	return dir, qerr
}

func (s *Server) acqPolicyHistory(w http.ResponseWriter, r *http.Request) {
	h, err := s.store.AcqPolicyHistory(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 200, h)
}

// acqPolicyFile downloads a saved version as the file to carry to the
// acquisition host (two-machine layout); latest when no version is given.
func (s *Server) acqPolicyFile(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var rec store.AcqPolicyRecord
	var err error
	if v := r.URL.Query().Get("version"); v != "" {
		n, perr := strconv.Atoi(v)
		if perr != nil || n < 1 {
			writeErr(w, http.StatusBadRequest, "version must be a positive number")
			return
		}
		rec, err = s.store.GetAcqPolicyVersion(ctx, n)
	} else {
		var ok bool
		rec, ok, err = s.store.GetAcqPolicy(ctx)
		if err == nil && !ok {
			writeErr(w, http.StatusNotFound, "no auto-download policy saved yet: save it first")
			return
		}
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	b, err := s.signedPolicyFile(rec)
	if err != nil {
		s.fail(w, err)
		return
	}
	s.store.Audit(ctx, store.Ev{Actor: actor(r), Action: "acquisition.policy_downloaded", ObjectType: "acquisition_policy",
		ObjectID: strconv.Itoa(rec.Version), Details: map[string]any{"version": rec.Version, "sha256": rec.SHA256, "signed_by": s.policySigningView().KeyID}})
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", `attachment; filename="`+acqpolicy.FileName(rec.Version)+`"`)
	w.WriteHeader(200)
	w.Write(b)
}

// requeueAcqPolicy writes the latest version to acquisition_requests_dir
// again (after a failed hand-off).
func (s *Server) requeueAcqPolicy(w http.ResponseWriter, r *http.Request) {
	if s.cfg.AcquisitionRequestsDir == "" {
		writeErr(w, http.StatusConflict, noDirectHandOff)
		return
	}
	rec, ok, err := s.store.GetAcqPolicy(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	if !ok {
		writeErr(w, http.StatusNotFound, "no auto-download policy saved yet: save it first")
		return
	}
	to, qerr := s.queuePolicy(r.Context(), r, rec)
	if qerr != "" {
		writeErr(w, http.StatusInternalServerError, "could not hand the policy to the downloader: "+qerr)
		return
	}
	writeJSON(w, 200, map[string]any{"version": rec.Version, "queued_to": to})
}

const noDirectHandOff = "the downloader runs on another machine (acquisition_requests_dir is not set): it applies the policy file you carry over and runs on its own schedule"

// runAcquisitionNow queues a "run now" request for the downloader.
func (s *Server) runAcquisitionNow(w http.ResponseWriter, r *http.Request) {
	dir := s.cfg.AcquisitionRequestsDir
	if dir == "" {
		writeErr(w, http.StatusConflict, noDirectHandOff)
		return
	}
	var rnd [3]byte
	rand.Read(rnd[:])
	now := time.Now().UTC()
	rr := acqpolicy.RunRequest{Format: acqpolicy.RunFormat, Version: acqpolicy.RunVersion, RunID: acqpolicy.NewRunID(now, hex.EncodeToString(rnd[:])),
		RequestedBy: actor(r), RequestedAt: now.Format(time.RFC3339)}
	if err := rr.Validate(); err != nil {
		s.fail(w, err)
		return
	}
	b, _ := json.MarshalIndent(rr, "", "  ")
	if err := writeQueued(dir, rr.RunID+".json", append(b, '\n')); err != nil {
		s.log.Error("run request not queued", "dir", dir, "err", err)
		s.store.Audit(r.Context(), store.Ev{Actor: actor(r), Action: "acquisition.run_requested", ObjectType: "acquisition", ObjectID: rr.RunID,
			Failure: true, Details: map[string]any{"queued_error": err.Error()}})
		writeErr(w, http.StatusInternalServerError, "could not hand the request to the downloader: "+err.Error())
		return
	}
	lr := runRequested{RunID: rr.RunID, RequestedBy: rr.RequestedBy, RequestedAt: rr.RequestedAt, QueuedTo: dir}
	if err := s.store.Audit(r.Context(), store.Ev{Actor: actor(r), Action: "acquisition.run_requested", ObjectType: "acquisition", ObjectID: rr.RunID,
		Details: map[string]any{"queued_to": dir}}); err != nil {
		os.Remove(filepath.Join(dir, rr.RunID+".json")) // no audit record, no request
		s.fail(w, err)
		return
	}
	lb, _ := json.Marshal(lr)
	s.store.SetMeta(r.Context(), metaLastRunRequest, string(lb))
	writeJSON(w, 200, lr)
}

// writeQueued writes b as dir/name atomically (temp file, fsync, rename;
// mode 0640), the hand-off format shared by requests, policies and runs.
func writeQueued(dir, name string, b []byte) (err error) {
	f, err := os.CreateTemp(dir, ".tmp-"+name+"-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() {
		if err != nil {
			os.Remove(tmp)
		}
	}()
	if err := f.Chmod(0o640); err != nil {
		f.Close()
		return err
	}
	if _, err := bytes.NewReader(b).WriteTo(f); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, filepath.Join(dir, name)); err != nil {
		return err
	}
	if d, err := os.Open(dir); err == nil {
		d.Sync()
		d.Close()
	}
	return nil
}
