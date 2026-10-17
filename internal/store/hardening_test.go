package store

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func openTest(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "pm.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func auditN(t *testing.T, s *Store, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		if err := s.Audit(context.Background(), Ev{Actor: "test", Action: "test.event", ObjectType: "t", ObjectID: "x"}); err != nil {
			t.Fatal(err)
		}
	}
}

// H5: status pages verify only new events, but still notice a modified tip
// and, at the full-verify interval, a modified older event.
func TestAuditChainStatusIncremental(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	auditN(t, s, 5)
	if r, err := s.AuditChainStatus(ctx); err != nil || !r.OK || r.Count != 5 {
		t.Fatalf("initial: %+v %v", r, err)
	}
	auditN(t, s, 3)
	if r, _ := s.AuditChainStatus(ctx); !r.OK || r.Count != 8 {
		t.Fatalf("incremental: %+v", r)
	}
	if _, err := s.db.Exec(`DROP TRIGGER audit_no_update`); err != nil {
		t.Fatal(err)
	}
	// An older, already verified event: not re-hashed until the full walk.
	s.db.Exec(`UPDATE audit SET actor='mallory' WHERE seq=2`)
	if r, _ := s.AuditChainStatus(ctx); !r.OK {
		t.Fatalf("cached prefix should not be re-walked yet: %+v", r)
	}
	old := auditFullVerifyEvery
	auditFullVerifyEvery = 0
	defer func() { auditFullVerifyEvery = old }()
	if r, _ := s.AuditChainStatus(ctx); r.OK || r.FirstBadSeq != 2 {
		t.Fatalf("full re-verify must find the modified event: %+v", r)
	}
	auditFullVerifyEvery = old
	// Still failing (no OK cache), and a modified tip is caught too.
	s.db.Exec(`UPDATE audit SET actor='test' WHERE seq=2`)
	if r, _ := s.AuditChainStatus(ctx); !r.OK {
		t.Fatalf("restored chain: %+v", r)
	}
	s.db.Exec(`UPDATE audit SET hash='00' WHERE seq=8`)
	if r, _ := s.AuditChainStatus(ctx); r.OK {
		t.Fatalf("modified last verified event must be detected: %+v", r)
	}
}

func TestAuditAfterSeq(t *testing.T) {
	s := openTest(t)
	auditN(t, s, 6)
	evs, err := s.ListAudit(context.Background(), AuditQuery{Ascending: true, AfterSeq: 4, Limit: 10})
	if err != nil || len(evs) != 2 || evs[0].Seq != 5 {
		t.Fatalf("after seq 4: %v %+v", err, evs)
	}
}

func fakeIssuer(serial string) CertIssuer {
	return func(string) (string, string, string, error) {
		return "PEM-" + serial, serial, time.Now().Add(365 * 24 * time.Hour).UTC().Format(time.RFC3339), nil
	}
}

// M3: after renewal the old certificate keeps working until the new one is
// used once; renewing again before that keeps the old one as the fallback.
func TestCertRenewalGrace(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	tok, err := s.CreateEnrollmentToken(ctx, "user:o", []string{"g"}, "hq", 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	id, _, _, err := s.Enroll(ctx, EnrollRequest{Token: tok.Token, Hostname: "pc-1", OS: "windows"}, fakeIssuer("aa01"))
	if err != nil {
		t.Fatal(err)
	}
	ok := func(serial string) bool { return s.CheckEndpointCert(ctx, id, serial) == nil }
	if _, err := s.RenewCert(ctx, id, fakeIssuer("bb02")); err != nil {
		t.Fatal(err)
	}
	if !ok("aa01") || !ok("AA01") {
		t.Fatal("previous certificate must stay valid until the new one is used")
	}
	// Renewed again (the agent never saved bb02): aa01 is still what it holds.
	if _, err := s.RenewCert(ctx, id, fakeIssuer("cc03")); err != nil {
		t.Fatal(err)
	}
	if !ok("aa01") || ok("bb02") {
		t.Fatal("unused intermediate renewal must not replace the fallback")
	}
	if !ok("cc03") {
		t.Fatal("new certificate rejected")
	}
	if ok("aa01") {
		t.Fatal("old certificate must stop working once the new one is used")
	}
	if _, err := s.RetireEndpoint(ctx, "user:o", id, "decommissioned"); err != nil {
		t.Fatal(err)
	}
	if ok("cc03") {
		t.Fatal("retired endpoint's certificate accepted")
	}
}

// H3: denied enrollments are audited at most once per source per minute.
func TestEnrollDeniedAuditThrottled(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	now := time.Now().UTC()
	s.Now = func() time.Time { return now }
	for i := 0; i < 5; i++ {
		if _, _, _, err := s.Enroll(ctx, EnrollRequest{Token: "enr_bad", Hostname: "x", Source: "192.0.2.1"}, nil); err != ErrEnrollDenied {
			t.Fatalf("want ErrEnrollDenied, got %v", err)
		}
	}
	s.Enroll(ctx, EnrollRequest{Token: "enr_bad", Hostname: "y", Source: "192.0.2.2"}, nil)
	count := func() int {
		evs, _ := s.ListAudit(ctx, AuditQuery{Action: "endpoint.enroll_denied"})
		return len(evs)
	}
	if n := count(); n != 2 {
		t.Fatalf("audit events: %d, want 2 (one per source)", n)
	}
	now = now.Add(61 * time.Second)
	s.Enroll(ctx, EnrollRequest{Token: "enr_bad", Hostname: "x", Source: "192.0.2.1"}, nil)
	evs, _ := s.ListAudit(ctx, AuditQuery{Action: "endpoint.enroll_denied", Limit: 1})
	if count() != 3 || !strings.Contains(string(evs[0].Details), `"suppressed_before":4`) {
		t.Fatalf("after a minute: %d events, latest %s", count(), evs[0].Details)
	}
}

func TestValidHostname(t *testing.T) {
	for h, ok := range map[string]bool{
		"pc-01": true, "srv_db.corp.internal": true, "": false, strings.Repeat("a", 254): false,
		strings.Repeat("a", 253): true, "pc 01": false, "pc\n01": false, "<script>": false, "pc-ü": false,
	} {
		if got := ValidHostname(h) == nil; got != ok {
			t.Errorf("%q: valid=%v want %v", h, got, ok)
		}
	}
}

// H6: failures before the installer starts count as attempts.
func TestAttemptDelta(t *testing.T) {
	for _, c := range []struct {
		from, to string
		want     int
	}{
		{"pending", "installing", 1}, {"installing", "failed", 0}, {"downloading", "failed", 1},
		{"pending", "failed", 1}, {"failed", "failed", 1}, {"pending", "downloading", 0}, {"installing", "installed", 0},
	} {
		if got := attemptDelta(c.from, c.to); got != c.want {
			t.Errorf("%s→%s: %d want %d", c.from, c.to, got, c.want)
		}
	}
	if !integrityFailure("manifest verification failed: bad signature") || !integrityFailure("download/verify failed: content does not match signed manifest — possible tampering") || integrityFailure("exit code 1603") {
		t.Error("integrityFailure classification")
	}
}
