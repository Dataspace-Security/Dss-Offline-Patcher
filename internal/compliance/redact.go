package compliance

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"regexp"
	"sort"
	"strings"

	"offpatch/internal/store"
)

// Redaction (template §6 "Export integrity and handling"): hostnames,
// endpoint IDs, IP addresses and product user IDs are replaced with stable
// pseudonyms: HMAC-SHA-256 with the server's secret salt, so the same host
// has the same pseudonym in every report and names cannot be recovered by
// hashing guesses. System actors (system:*) are kept.

type pseudonymizer struct {
	salt []byte
	memo map[string]string
}

func newPseudonymizer(salt []byte) *pseudonymizer {
	return &pseudonymizer{salt: salt, memo: map[string]string{}}
}

func (p *pseudonymizer) name(kind, v string) string {
	if v == "" {
		return ""
	}
	k := kind + ":" + strings.ToLower(v)
	if out, ok := p.memo[k]; ok {
		return out
	}
	m := hmac.New(sha256.New, p.salt)
	m.Write([]byte(k))
	out := kind + "-" + hex.EncodeToString(m.Sum(nil))[:10]
	p.memo[k] = out
	return out
}

func (p *pseudonymizer) host(v string) string { return p.name("host", v) }
func (p *pseudonymizer) ep(v string) string   { return p.name("ep", v) }

// user maps "user:<name>" and bare names; "system:..." stays.
func (p *pseudonymizer) user(v string) string {
	switch {
	case v == "" || strings.HasPrefix(v, "system:"):
		return v
	case strings.HasPrefix(v, "user:"):
		return "user:" + p.name("user", strings.TrimPrefix(v, "user:"))
	}
	return p.name("user", v)
}

var (
	ipv4Re = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	ipv6Re = regexp.MustCompile(`\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b`)
)

// text replaces every known name in free text, then IP addresses.
type textRedactor struct {
	r *strings.Replacer
	p *pseudonymizer
}

func (t textRedactor) apply(s string) string {
	if s == "" {
		return s
	}
	if t.r != nil {
		s = t.r.Replace(s)
	}
	s = ipv4Re.ReplaceAllStringFunc(s, func(m string) string { return t.p.name("ip", m) })
	return ipv6Re.ReplaceAllStringFunc(s, func(m string) string { return t.p.name("ip", m) })
}

// redactInput returns a copy of in with identities pseudonymized. Shared
// inputs (cached fleet views) are never modified.
func redactInput(in *Input, salt []byte) *Input {
	p := newPseudonymizer(salt)
	out := *in
	var pairs []string
	add := func(from, to string) {
		if len(from) >= 3 && from != to {
			pairs = append(pairs, from, to)
		}
	}
	out.Endpoints = make([]store.Endpoint, len(in.Endpoints))
	for i, e := range in.Endpoints {
		add(e.Hostname, p.host(e.Hostname))
		add(e.EndpointID, p.ep(e.EndpointID))
		e.Hostname, e.EndpointID = p.host(e.Hostname), p.ep(e.EndpointID)
		e.Owner = redactOwner(p, e.Owner)
		out.Endpoints[i] = e
	}
	users := map[string]bool{}
	note := func(u string) {
		if u != "" && !strings.HasPrefix(u, "system:") {
			users[strings.TrimPrefix(u, "user:")] = true
		}
	}
	for _, u := range in.Users {
		note(u.Username)
	}
	for _, d := range in.Deployments {
		note(d.CreatedBy)
		for _, a := range d.Approvals {
			note(a.By)
		}
	}
	for _, pk := range in.Packages {
		for _, a := range pk.Approvals {
			note(a.By)
		}
	}
	for _, x := range in.Exceptions {
		note(x.CreatedBy)
	}
	for _, evs := range [][]store.AuditEvent{in.PrivilegedEvents, in.DeploymentEvents, in.ReportEvents, in.BackupEvents} {
		for _, e := range evs {
			note(e.Actor)
			if e.ObjectType == "user" {
				note(e.ObjectID)
			}
		}
	}
	note(in.GeneratedBy.User)
	for u := range users {
		add(u, p.name("user", u))
	}
	// Longest names first: a hostname that contains another is replaced whole.
	type kv struct{ k, v string }
	var kvs []kv
	for i := 0; i < len(pairs); i += 2 {
		kvs = append(kvs, kv{pairs[i], pairs[i+1]})
	}
	sort.Slice(kvs, func(i, j int) bool { return len(kvs[i].k) > len(kvs[j].k) })
	flat := make([]string, 0, 2*len(kvs))
	for _, x := range kvs {
		flat = append(flat, x.k, x.v)
	}
	tr := textRedactor{p: p}
	if len(flat) > 0 {
		tr.r = strings.NewReplacer(flat...)
	}

	out.Targets = make([]store.PackTarget, len(in.Targets))
	for i, t := range in.Targets {
		t.EndpointID = p.ep(t.EndpointID)
		t.Detail, t.Evidence = tr.apply(t.Detail), tr.apply(t.Evidence)
		out.Targets[i] = t
	}
	out.InstallTimes = make(map[string]string, len(in.InstallTimes))
	for k, v := range in.InstallTimes {
		dep, ep, _ := strings.Cut(k, "/")
		out.InstallTimes[dep+"/"+p.ep(ep)] = v
	}
	out.Needs = make(map[string][]string, len(in.Needs))
	for pkg, eps := range in.Needs {
		r := make([]string, len(eps))
		for i, e := range eps {
			r[i] = p.ep(e)
		}
		out.Needs[pkg] = r
	}
	out.Exceptions = make([]store.Exception, len(in.Exceptions))
	for i, x := range in.Exceptions {
		x.EndpointID, x.CreatedBy = p.ep(x.EndpointID), p.user(x.CreatedBy)
		x.Reason, x.CompensatingControls, x.Owner = tr.apply(x.Reason), tr.apply(x.CompensatingControls), redactOwner(p, x.Owner)
		out.Exceptions[i] = x
	}
	out.Deployments = make([]store.Deployment, len(in.Deployments))
	for i, d := range in.Deployments {
		d.CreatedBy, d.RejectedBy = p.user(d.CreatedBy), p.user(d.RejectedBy)
		d.StateReason, d.Justification = tr.apply(d.StateReason), tr.apply(d.Justification)
		ap := make([]store.Approval, len(d.Approvals))
		for j, a := range d.Approvals {
			a.By, a.Reason = p.user(a.By), tr.apply(a.Reason)
			ap[j] = a
		}
		d.Approvals = ap
		out.Deployments[i] = d
	}
	out.Packages = make([]store.Package, len(in.Packages))
	for i, pk := range in.Packages {
		pk.StateBy, pk.StateReason = p.user(pk.StateBy), tr.apply(pk.StateReason)
		ap := make([]store.Approval, len(pk.Approvals))
		for j, a := range pk.Approvals {
			a.By, a.Reason = p.user(a.By), tr.apply(a.Reason)
			ap[j] = a
		}
		pk.Approvals = ap
		out.Packages[i] = pk
	}
	out.Users = make([]store.User, len(in.Users))
	for i, u := range in.Users {
		u.Username, u.Email, u.DisplayName, u.CreatedBy = p.user(u.Username), "", "", p.user(u.CreatedBy)
		out.Users[i] = u
	}
	redactEvents := func(evs []store.AuditEvent) []store.AuditEvent {
		r := make([]store.AuditEvent, len(evs))
		for i, e := range evs {
			e.Actor = p.user(e.Actor)
			e.ObjectID = tr.apply(e.ObjectID)
			if e.ObjectType == "user" {
				e.ObjectID = p.user(e.ObjectID)
			}
			d := tr.apply(string(e.Details))
			if !json.Valid([]byte(d)) {
				d = `{"redacted":true}`
			}
			e.Details = json.RawMessage(d)
			r[i] = e
		}
		return r
	}
	out.PrivilegedEvents = redactEvents(in.PrivilegedEvents)
	out.DeploymentEvents = redactEvents(in.DeploymentEvents)
	out.ReportEvents = redactEvents(in.ReportEvents)
	out.BackupEvents = redactEvents(in.BackupEvents)
	out.Receipts = make([]store.TransferReceipt, len(in.Receipts))
	copy(out.Receipts, in.Receipts)
	for i := range out.Receipts {
		out.Receipts[i].File = tr.apply(out.Receipts[i].File)
	}
	out.GeneratedBy = User{User: p.user(in.GeneratedBy.User), Role: in.GeneratedBy.Role}
	hist := make([]store.ReportProfileVersion, len(in.ProfileHistory))
	for i, h := range in.ProfileHistory {
		h.EditedBy = p.user(h.EditedBy)
		hist[i] = h
	}
	out.ProfileHistory = hist
	out.Profile.EditedBy = p.user(in.Profile.EditedBy)
	return &out
}

// redactOwner: owners are people or teams; an email-looking owner is a
// user ID.
func redactOwner(p *pseudonymizer, v string) string {
	if strings.Contains(v, "@") {
		return p.name("user", v)
	}
	return v
}
