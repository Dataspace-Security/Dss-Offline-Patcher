package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func countAudit(t *testing.T, s *Store, action, objectID string) int {
	t.Helper()
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM audit WHERE action=? AND object_id=?`, action, objectID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// Wrong passwords lock (account, source); many sources together lock the
// account; an admin unlock clears both (M-1).
func TestPasswordLockPerSourceAndAccount(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	mkUser(t, s, byAdmin, "uma@bank.example", RoleUser)
	now := time.Date(2026, 10, 20, 9, 0, 0, 0, time.UTC)
	s.Now = func() time.Time { return now }
	login := func(source, password string) error {
		_, err := s.LoginPasswordFrom(ctx, "uma@bank.example", password, source, time.Hour)
		return err
	}
	for i := 0; i < MaxFailedLogins; i++ {
		if err := login("203.0.113.1", "wrong password!"); !errors.Is(err, ErrBadCredentials) {
			t.Fatalf("guess %d: %v", i, err)
		}
	}
	if err := login("203.0.113.1", pw); !errors.Is(err, ErrBadCredentials) {
		t.Fatalf("locked source signed in: %v", err)
	}
	if err := login("198.51.100.7", pw); err != nil {
		t.Fatalf("the user from another address: %v", err)
	}
	// Distributed: MaxAccountFailures from many sources within the window.
	for i := 0; i < MaxAccountFailures-MaxFailedLogins; i++ {
		login(fmt.Sprintf("192.0.2.%d", i%200), "wrong password!")
	}
	if err := login("198.51.100.7", pw); !errors.Is(err, ErrBadCredentials) {
		t.Fatalf("account lock after %d failures: %v", MaxAccountFailures, err)
	}
	if countAudit(t, s, "auth.locked", "uma@bank.example") < 2 {
		t.Fatal("source and account locks not audited")
	}
	if al, _ := s.ListAlerts(ctx, true); len(al) != 1 || al[0].Kind != "auth.account_locked" {
		t.Fatalf("account lock alert: %+v", al)
	}
	if err := s.SetUserDisabled(ctx, byAdmin, "uma@bank.example", false, "unlock"); err != nil {
		t.Fatal(err)
	}
	if err := login("203.0.113.1", pw); err != nil {
		t.Fatalf("after admin unlock: %v", err)
	}
	// The account window expires: old failures stop counting.
	for i := 0; i < MaxAccountFailures-1; i++ {
		login(fmt.Sprintf("192.0.2.%d", i%200), "wrong password!")
	}
	now = now.Add(AccountFailureWindow + time.Second)
	login("192.0.2.250", "wrong password!")
	if err := login("198.51.100.8", pw); err != nil {
		t.Fatalf("failures outside the window locked the account: %v", err)
	}
}

// L-1: a lock set while a sign-in was in its slow password check wins.
func TestPasswordLockRecheckedAfterVerify(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	mkUser(t, s, byAdmin, "uma@bank.example", RoleUser)
	locked := false
	afterPasswordCheck = func() {
		if !locked {
			locked = true
			for i := 0; i < MaxFailedLogins; i++ { // a parallel attacker locks the source meanwhile
				s.LoginPasswordFrom(ctx, "uma@bank.example", "wrong password!", "203.0.113.1", time.Hour)
			}
		}
	}
	defer func() { afterPasswordCheck = nil }()
	if _, err := s.LoginPasswordFrom(ctx, "uma@bank.example", pw, "203.0.113.1", time.Hour); !errors.Is(err, ErrBadCredentials) {
		t.Fatalf("right password while the source got locked: %v", err)
	}
}

// Failed sign-ins are audited at most once a minute per (account, source),
// with the number folded; lock events are never folded.
func TestFailedLoginAuditFolding(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	mkUser(t, s, byAdmin, "uma@bank.example", RoleUser)
	now := time.Date(2026, 10, 20, 9, 0, 0, 0, time.UTC)
	s.Now = func() time.Time { return now }
	for i := 0; i < 3; i++ {
		s.LoginPasswordFrom(ctx, "uma@bank.example", "wrong password!", "203.0.113.1", time.Hour)
		s.LoginPasswordFrom(ctx, "nobody@bank.example", "x", "203.0.113.1", time.Hour)
	}
	s.LoginPasswordFrom(ctx, "uma@bank.example", "wrong password!", "203.0.113.2", time.Hour)
	if n := countAudit(t, s, "auth.login_failed", "uma@bank.example"); n != 2 {
		t.Fatalf("folded events for uma: %d (want one per source)", n)
	}
	if n := countAudit(t, s, "auth.login_failed", "nobody@bank.example"); n != 1 {
		t.Fatalf("folded events for an unknown email: %d", n)
	}
	now = now.Add(time.Minute)
	s.LoginPasswordFrom(ctx, "uma@bank.example", "wrong password!", "203.0.113.1", time.Hour)
	evs := auditActions(t, s, "uma@bank.example")
	if n := countAudit(t, s, "auth.login_failed", "uma@bank.example"); n != 3 {
		t.Fatalf("after a minute: %d events %v", n, evs)
	}
	if e := evs[len(evs)-1]; !containsAll(e, `"suppressed":2`, `"client":"203.0.113.1"`) {
		t.Fatalf("folded count: %s", e)
	}
	// The 5th failure from the source locks it: audited even if folded.
	s.LoginPasswordFrom(ctx, "uma@bank.example", "wrong password!", "203.0.113.1", time.Hour)
	if countAudit(t, s, "auth.locked", "uma@bank.example") != 1 {
		t.Fatalf("lock not audited: %v", auditActions(t, s, "uma@bank.example"))
	}
}

func containsAll(s string, subs ...string) bool {
	for _, x := range subs {
		if !strings.Contains(s, x) {
			return false
		}
	}
	return true
}

// M-1: at most PasswordChecksAtOnce password checks at a time; a sign-in
// that cannot get a slot in time gets ErrBusy (nothing audited or counted).
func TestPasswordCheckSlots(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	mkUser(t, s, byAdmin, "uma@bank.example", RoleUser)
	old := passwordCheckWait
	passwordCheckWait = 50 * time.Millisecond
	defer func() { passwordCheckWait = old }()
	ch := s.pwSlots.get()
	for i := 0; i < cap(ch); i++ {
		ch <- struct{}{}
	}
	if cap(ch) != PasswordChecksAtOnce {
		t.Fatalf("slots %d", cap(ch))
	}
	if _, err := s.LoginPassword(ctx, "uma@bank.example", pw, time.Hour); !errors.Is(err, ErrBusy) {
		t.Fatalf("saturated: %v", err)
	}
	if _, err := s.LoginPassword(ctx, "nobody@bank.example", pw, time.Hour); !errors.Is(err, ErrBusy) {
		t.Fatalf("saturated (unknown email): %v", err)
	}
	if err := s.ChangeOwnPassword(ctx, "uma@bank.example", pw, "another long passphrase", ""); !errors.Is(err, ErrBusy) {
		t.Fatalf("saturated (password change): %v", err)
	}
	<-ch
	if _, err := s.LoginPassword(ctx, "uma@bank.example", pw, time.Hour); err != nil {
		t.Fatalf("a free slot: %v", err)
	}
	if n := countAudit(t, s, "auth.login_failed", "uma@bank.example"); n != 0 {
		t.Fatalf("busy refusals audited as failures: %d", n)
	}
}

// Wrong current passwords in a password change lock that path and end the
// user's sessions; sign-in from elsewhere is not locked by them.
func TestChangePasswordLock(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	mkUser(t, s, byAdmin, "uma@bank.example", RoleUser)
	l, err := s.LoginPassword(ctx, "uma@bank.example", pw, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < MaxFailedLogins; i++ {
		if err := s.ChangeOwnPassword(ctx, "uma@bank.example", "wrong password!", "another long passphrase", l.Token); !errors.Is(err, ErrInvalid) {
			t.Fatalf("wrong current %d: %v", i, err)
		}
	}
	if _, err := s.LookupSession(ctx, l.Token); err == nil {
		t.Fatal("session survives the lock")
	}
	if err := s.ChangeOwnPassword(ctx, "uma@bank.example", pw, "another long passphrase", ""); !errors.Is(err, ErrInvalid) {
		t.Fatalf("locked password change accepted: %v", err)
	}
	if _, err := s.LoginPasswordFrom(ctx, "uma@bank.example", pw, "198.51.100.1", time.Hour); err != nil {
		t.Fatalf("sign-in after a password-change lock: %v", err)
	}
}
