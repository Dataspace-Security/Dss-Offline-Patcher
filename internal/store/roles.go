package store

import "strings"

// Roles, lowest to highest (docs/07-admin-guide.md "Roles"). viewer reads;
// user (bank) runs the day-to-day work and approves deployments; admin
// (bank) also manages bank users and exceptions; super_admin is the vendor
// (setup and support) and may do everything.
const (
	RoleViewer     = "viewer"
	RoleUser       = "user"
	RoleAdmin      = "admin"
	RoleSuperAdmin = "super_admin"
)

var roleRanks = map[string]int{RoleViewer: 1, RoleUser: 2, RoleAdmin: 3, RoleSuperAdmin: 4}

// roleAliases: names used by earlier versions (config admin_tokens, SSO
// role_groups, stored sessions) keep working.
var roleAliases = map[string]string{"operator": RoleUser, "approver": RoleUser}

// Roles lists the canonical roles, lowest first.
var Roles = []string{RoleViewer, RoleUser, RoleAdmin, RoleSuperAdmin}

// CanonicalRole maps a role or alias to its canonical name ("" if unknown).
func CanonicalRole(r string) string {
	r = strings.ToLower(strings.TrimSpace(r))
	if a, ok := roleAliases[r]; ok {
		return a
	}
	if roleRanks[r] > 0 {
		return r
	}
	return ""
}

// RoleRank is the rank of a role or alias (0 = unknown, no access).
func RoleRank(r string) int { return roleRanks[CanonicalRole(r)] }

// CanApproveDeployments: bank users and admins approve deployments and
// rollbacks; the vendor super_admin and viewers do not.
func CanApproveDeployments(role string) bool {
	r := CanonicalRole(role)
	return r == RoleUser || r == RoleAdmin
}
