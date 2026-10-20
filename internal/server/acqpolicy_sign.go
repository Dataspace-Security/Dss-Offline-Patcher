package server

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"

	"offpatch/internal/acqpolicy"
	"offpatch/internal/auditexport"
	"offpatch/internal/manifest"
	"offpatch/internal/store"
)

// Signed auto-download policy files and the two-person rule for download
// sources (finding S-4; acqpolicy/signature.go, store/acqpolicy_pending.go).
//
// Every policy file the server writes for pmctl (acquisition_requests_dir,
// or the download the super admin carries) is signed with the policy
// signing key <data_dir>/policy-signing.key (Ed25519, created on first
// use, mode 0600, owned by the server user). pmctl pins the public key in
// acquire.json policy_public_keys: `pmserver policy-key` prints it.

// PolicySigningKeyFile is the key's file name in data_dir.
const PolicySigningKeyFile = "policy-signing.key"

// PolicySigningKey loads (or creates) the policy signing key of dataDir.
func PolicySigningKey(dataDir string) (ed25519.PrivateKey, error) {
	return auditexport.LoadOrCreateKey(filepath.Join(dataDir, PolicySigningKeyFile))
}

// PolicyPin is how acquire.json pins a key: base64 of the Ed25519 public key.
func PolicyPin(pub ed25519.PublicKey) string { return base64.StdEncoding.EncodeToString(pub) }

func (s *Server) policyKey() (ed25519.PrivateKey, error) {
	s.polKey.mu.Lock()
	defer s.polKey.mu.Unlock()
	if s.polKey.key != nil {
		return s.polKey.key, nil
	}
	k, err := PolicySigningKey(s.cfg.DataDir)
	if err != nil {
		return nil, fmt.Errorf("policy signing key: %w", err)
	}
	s.polKey.key = k
	return k, nil
}

// signedPolicyFile is the signed file pmctl reads for rec.
func (s *Server) signedPolicyFile(rec store.AcqPolicyRecord) ([]byte, error) {
	k, err := s.policyKey()
	if err != nil {
		return nil, err
	}
	f := acqpolicy.NewFile(rec.Version, rec.EditedBy, rec.EditedAt, rec.Policy)
	f.Sign(k)
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// policySigning is what the console shows about the signing key.
type policySigning struct {
	KeyID string `json:"key_id"`
	// PublicKey: the value for acquire.json policy_public_keys.
	PublicKey string `json:"public_key"`
	Error     string `json:"error,omitempty"`
}

func (s *Server) policySigningView() policySigning {
	k, err := s.policyKey()
	if err != nil {
		return policySigning{Error: err.Error()}
	}
	pub := k.Public().(ed25519.PublicKey)
	return policySigning{KeyID: manifest.KeyID(pub), PublicKey: PolicyPin(pub)}
}

const metaPolicySignedQueued = "acq_policy_signed_queued"

// QueueSignedPolicy hands the latest policy version to the downloader
// again, signed, once per version and key (after an upgrade from a version
// that wrote unsigned files: pmctl with a pin refuses the unsigned copy it
// holds and takes the signed one). Single-server layout only.
func (s *Server) QueueSignedPolicy(ctx context.Context) {
	if s.cfg.AcquisitionRequestsDir == "" {
		return
	}
	rec, ok, err := s.store.GetAcqPolicy(ctx)
	if err != nil || !ok {
		return
	}
	v := s.policySigningView()
	mark := strconv.Itoa(rec.Version) + " " + v.KeyID
	if v.Error != "" {
		s.log.Error("auto-download policy cannot be signed", "err", v.Error)
		return
	}
	if cur, _ := s.store.GetMeta(ctx, metaPolicySignedQueued); cur == mark {
		return
	}
	b, err := s.signedPolicyFile(rec)
	if err == nil {
		err = writeQueued(s.cfg.AcquisitionRequestsDir, acqpolicy.FileName(rec.Version), b)
	}
	failed := err != nil
	details := map[string]any{"version": rec.Version, "sha256": rec.SHA256, "queued_to": s.cfg.AcquisitionRequestsDir, "signed_by": v.KeyID, "reason": "signed copy"}
	if failed {
		details["queued_error"] = err.Error()
		s.log.Error("signed auto-download policy not queued", "version", rec.Version, "err", err)
	}
	s.store.Audit(ctx, store.Ev{Actor: "system:server", Action: "acquisition.policy_queued", ObjectType: "acquisition_policy",
		ObjectID: strconv.Itoa(rec.Version), Failure: failed, Details: details})
	if !failed {
		s.store.SetMeta(ctx, metaPolicySignedQueued, mark)
	}
}

// ---- two-person rule ----

type pendingResponse struct {
	Pending *store.AcqPolicyPending `json:"pending"`
	// NeedsApproval: the save was stored as a proposal, not applied.
	NeedsApproval bool `json:"needs_approval"`
}

// proposeAcqPolicy stores a source change for a second super admin.
func (s *Server) proposeAcqPolicy(w http.ResponseWriter, r *http.Request, p acqpolicy.Policy, base int, defaults acqpolicy.Policy) {
	pend, err := s.store.ProposeAcqPolicy(r.Context(), actor(r), p, base, defaults)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, pendingResponse{Pending: &pend, NeedsApproval: true})
}

func (s *Server) approveAcqPolicy(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SHA256 string `json:"sha256"`
	}
	if !decode(w, r, &req) {
		return
	}
	if strings.TrimSpace(req.SHA256) == "" {
		writeErr(w, http.StatusBadRequest, "sha256 of the reviewed change is required")
		return
	}
	rec, err := s.store.ApproveAcqPolicy(r.Context(), actor(r), req.SHA256)
	if err != nil {
		s.fail(w, err)
		return
	}
	out := savedPolicy{AcqPolicyRecord: rec}
	out.QueuedTo, out.QueuedError = s.queuePolicy(r.Context(), r, rec)
	writeJSON(w, 200, out)
}

func (s *Server) rejectAcqPolicy(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Reason string `json:"reason"`
	}
	if !decode(w, r, &req) {
		return
	}
	if len(req.Reason) > 500 {
		writeErr(w, http.StatusBadRequest, "reason: at most 500 characters")
		return
	}
	if err := s.store.RejectAcqPolicy(r.Context(), actor(r), strings.TrimSpace(req.Reason)); err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"rejected": true})
}
