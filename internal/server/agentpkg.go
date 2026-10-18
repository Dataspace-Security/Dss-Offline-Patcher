package server

import (
	"errors"
	"net/http"
	"strings"

	"offpatch/internal/store"
)

// Agent versions (packages of kind "agent", offpatch-agent-*) are the
// vendor's: only the super admin approves, rejects or revokes them and
// creates their deployments and rollbacks. Their deployments still follow
// the bank's two-person rule, but with bank admins only (not users, not the
// creator, not the vendor): an agent upgrade changes the software that runs
// on every machine.
const (
	agentVendorOnly     = "agent versions are managed by the vendor (super admin)"
	agentAdminApprovals = "agent version deployments are approved by bank admins"
)

func isAgentPackage(p store.Package) bool {
	return p.Kind == "agent" || strings.HasPrefix(p.PackageID, "offpatch-agent-")
}

// agentAllowed reports whether the caller may act on packageID: true for
// packages that are not agent versions (or do not exist: the normal path
// reports that), else allow(role). When refused it writes 403 and audits
// access.denied.
func (s *Server) agentAllowed(w http.ResponseWriter, r *http.Request, packageID string, allow func(role string) bool, msg, required string) bool {
	p, err := s.store.GetPackage(r.Context(), packageID)
	if errors.Is(err, store.ErrNotFound) || err == nil && !isAgentPackage(p) {
		return true
	}
	if err != nil {
		s.fail(w, err)
		return false
	}
	pr := r.Context().Value(keyPrincipal).(*principal)
	if allow(store.CanonicalRole(pr.Role)) {
		return true
	}
	s.store.Audit(r.Context(), store.Ev{Actor: actor(r), Action: "access.denied", ObjectType: "package", ObjectID: packageID, PackageID: packageID, Failure: true,
		Details: map[string]any{"role": pr.Role, "required": required, "api": r.Method + " " + r.URL.Path, "reason": msg}})
	writeErr(w, http.StatusForbidden, msg)
	return false
}

func superAdminOnly(role string) bool { return role == store.RoleSuperAdmin }

func bankAdminOnly(role string) bool { return role == store.RoleAdmin }

// agentDeploymentAllowed: approving or rejecting a deployment of an agent
// version needs a bank admin.
func (s *Server) agentDeploymentAllowed(w http.ResponseWriter, r *http.Request, deploymentID string) bool {
	d, err := s.store.GetDeployment(r.Context(), deploymentID)
	if errors.Is(err, store.ErrNotFound) {
		return true
	}
	if err != nil {
		s.fail(w, err)
		return false
	}
	return s.agentAllowed(w, r, d.PackageID, bankAdminOnly, agentAdminApprovals, store.RoleAdmin)
}
