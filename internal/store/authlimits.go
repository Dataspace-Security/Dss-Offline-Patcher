package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sync"
	"time"
)

// Sign-in abuse limits (docs/07-admin-guide.md "Sign-in protection"):
//
//   - wrong passwords lock the account for one client address (source) after
//     MaxFailedLogins, so an attacker cannot lock a bank user out from
//     elsewhere; MaxAccountFailures within AccountFailureWindow from any
//     sources lock the account outright (a distributed guessing attack).
//   - wrong authenticator codes have their own counter that a correct
//     password never resets: MaxMFAFailures lock the authenticator step for
//     MFALockFor, doubling at each lockout up to MFALockMax; only a correct
//     code (or an admin unlock / MFA reset) clears it. Raises an alert.
//   - at most PasswordChecksAtOnce PBKDF2 verifications run at a time; a
//     sign-in that cannot start one within passwordCheckWait gets ErrBusy.
//   - failed sign-in audit events are folded per (account, source) to one
//     per minute (deniedAuditEvery, like denied enrollments).

const (
	// MaxAccountFailures wrong passwords from any sources within
	// AccountFailureWindow lock the account (all sources) for LockFor.
	MaxAccountFailures   = 50
	AccountFailureWindow = 15 * time.Minute
	// MaxMFAFailures wrong codes in a row lock the authenticator step.
	MaxMFAFailures = 5
	MFALockFor     = 15 * time.Minute
	MFALockMax     = 24 * time.Hour
	// loginFailuresKeep: idle per-source counters are dropped after this.
	loginFailuresKeep = 24 * time.Hour
	// alertMFALocked: alert kind raised when an authenticator step locks.
	alertMFALocked = "auth.mfa_locked"
)

// PasswordChecksAtOnce bounds concurrent PBKDF2 verifications (CPU).
var PasswordChecksAtOnce = 4

// passwordCheckWait: how long a sign-in waits for a free verification slot.
var passwordCheckWait = 2 * time.Second

// afterPasswordCheck: test hook between the slow check and the lock re-check.
var afterPasswordCheck func()

var (
	// ErrBusy: too many sign-ins are being checked right now (503).
	ErrBusy = errors.New("the server is busy checking other sign-ins; try again in a few seconds")
	// ErrMFALocked: too many wrong codes; the authenticator step is locked.
	ErrMFALocked = errors.New("too many wrong codes: two-step sign-in is locked for a while; try again later or ask an administrator")
)

// loginFailuresSchema: wrong passwords per (account, source).
const loginFailuresSchema = `CREATE TABLE IF NOT EXISTS login_failures(
  email TEXT NOT NULL, source TEXT NOT NULL, failed INTEGER NOT NULL DEFAULT 0,
  locked_until TEXT NOT NULL DEFAULT '', last_at TEXT NOT NULL, PRIMARY KEY(email, source))`

type passwordSlots struct {
	once sync.Once
	ch   chan struct{}
}

func (p *passwordSlots) get() chan struct{} {
	p.once.Do(func() {
		n := PasswordChecksAtOnce
		if n < 1 {
			n = 1
		}
		p.ch = make(chan struct{}, n)
	})
	return p.ch
}

// acquirePasswordCheck takes a verification slot (release it when done), or
// returns ErrBusy after passwordCheckWait.
func (s *Store) acquirePasswordCheck(ctx context.Context) (func(), error) {
	ch := s.pwSlots.get()
	t := time.NewTimer(passwordCheckWait)
	defer t.Stop()
	select {
	case ch <- struct{}{}:
		return func() { <-ch }, nil
	case <-t.C:
		return nil, ErrBusy
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// verifyPasswordLimited is VerifyPassword in a verification slot.
func (s *Store) verifyPasswordLimited(ctx context.Context, hash, password string) (bool, error) {
	release, err := s.acquirePasswordCheck(ctx)
	if err != nil {
		return false, err
	}
	defer release()
	return VerifyPassword(hash, password), nil
}

// loginSource: the rate-limit key of the client ("" = local caller).
func loginSource(source string) string {
	if source == "" {
		return "local"
	}
	return source
}

// passwordLocked reports why email may not sign in from source right now
// ("" = not locked) and until when. Read inside the transaction that
// records the outcome, after the slow password check (no race past a lock).
func (s *Store) passwordLocked(tx *sql.Tx, email, source string) (string, string, error) {
	now := s.Now()
	var acct string
	if err := tx.QueryRow(`SELECT locked_until FROM local_users WHERE email=?`, email).Scan(&acct); err != nil {
		return "", "", err
	}
	if acct != "" && now.Before(parseTime(acct)) {
		return "account locked", acct, nil
	}
	var src string
	err := tx.QueryRow(`SELECT locked_until FROM login_failures WHERE email=? AND source=?`, email, source).Scan(&src)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return "", "", err
	}
	if src != "" && now.Before(parseTime(src)) {
		return "account locked for this address", src, nil
	}
	return "", "", nil
}

// recordPasswordFailure counts a wrong password from source: MaxFailedLogins
// in a row lock (email, source); MaxAccountFailures in the window lock the
// account. Reports whether a lock was set.
func (s *Store) recordPasswordFailure(tx *sql.Tx, email, source, what string) (bool, error) {
	now := s.Now()
	nowS := now.UTC().Format(time.RFC3339Nano)
	locked := false
	var n int
	if err := tx.QueryRow(`INSERT INTO login_failures(email,source,failed,last_at) VALUES(?,?,1,?)
		ON CONFLICT(email,source) DO UPDATE SET failed=failed+1, last_at=excluded.last_at RETURNING failed`, email, source, nowS).Scan(&n); err != nil {
		return false, err
	}
	if n >= MaxFailedLogins {
		locked = true
		until := now.Add(LockFor).UTC().Format(time.RFC3339Nano)
		if _, err := tx.Exec(`UPDATE login_failures SET failed=0, locked_until=? WHERE email=? AND source=?`, until, email, source); err != nil {
			return false, err
		}
		if err := s.audit(tx, Ev{Actor: "system:auth", Action: "auth.locked", ObjectType: "user", ObjectID: email, Failure: true,
			Details: map[string]any{"scope": "source", "client": source, "failed_attempts": n, "locked_until": until, "last_failure": what}}); err != nil {
			return false, err
		}
	}
	var count int
	var start string
	if err := tx.QueryRow(`SELECT failed_attempts, failed_window_start FROM local_users WHERE email=?`, email).Scan(&count, &start); err != nil {
		return false, err
	}
	if start == "" || now.Sub(parseTime(start)) >= AccountFailureWindow {
		count, start = 0, nowS
	}
	count++
	if count >= MaxAccountFailures {
		locked = true
		until := now.Add(LockFor).UTC().Format(time.RFC3339Nano)
		if _, err := tx.Exec(`UPDATE local_users SET failed_attempts=0, failed_window_start='', locked_until=? WHERE email=?`, until, email); err != nil {
			return false, err
		}
		if err := s.audit(tx, Ev{Actor: "system:auth", Action: "auth.locked", ObjectType: "user", ObjectID: email, Failure: true,
			Details: map[string]any{"scope": "account", "failed_attempts": count, "window": AccountFailureWindow.String(), "locked_until": until, "last_failure": what}}); err != nil {
			return false, err
		}
		if err := s.raiseAlertWith(tx, "critical", "auth.account_locked", "user", email,
			fmt.Sprintf("%s: %d wrong passwords in %s from several addresses; the account is locked until %s", email, count, AccountFailureWindow, until),
			map[string]any{"failed_attempts": count}); err != nil {
			return false, err
		}
	} else if _, err := tx.Exec(`UPDATE local_users SET failed_attempts=?, failed_window_start=? WHERE email=?`, count, start, email); err != nil {
		return false, err
	}
	// Forget idle per-source counters (bounded table).
	old := now.Add(-loginFailuresKeep).UTC().Format(time.RFC3339Nano)
	if _, err := tx.Exec(`DELETE FROM login_failures WHERE last_at < ? AND locked_until < ?`, old, nowS); err != nil {
		return false, err
	}
	return locked, nil
}

// auditLoginFailure writes auth.login_failed, folded per (name, source) to
// one event per deniedAuditEvery (with the count of folded ones).
func (s *Store) auditLoginFailure(ctx context.Context, name, source, reason string, details map[string]any) {
	suppressed, ok := s.loginAudits.take(name+"|"+source, s.Now())
	if !ok {
		return
	}
	d := map[string]any{"reason": reason, "source": "password", "client": source}
	for k, v := range details {
		d[k] = v
	}
	if suppressed > 0 {
		d["suppressed"] = suppressed
	}
	s.Audit(ctx, Ev{Actor: "user:" + name, Action: "auth.login_failed", ObjectType: "user", ObjectID: name, Failure: true, Details: d})
}

// mfaLockDuration: MFALockFor, doubling with each lockout, at most MFALockMax.
func mfaLockDuration(lockouts int) time.Duration {
	d := MFALockFor
	for i := 1; i < lockouts && d < MFALockMax; i++ {
		d *= 2
	}
	if d > MFALockMax {
		d = MFALockMax
	}
	return d
}

// mfaLocked reports whether email's authenticator step is locked.
func (s *Store) mfaLocked(ctx context.Context, email string) (bool, error) {
	var until string
	err := s.db.QueryRowContext(ctx, `SELECT locked_until FROM mfa WHERE email=?`, email).Scan(&until)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return until != "" && s.Now().Before(parseTime(until)), err
}

// recordMFAFailure counts a wrong code (never reset by a correct password):
// MaxMFAFailures lock the authenticator step (exponential), audited and
// alerted. Reports whether this failure set the lock.
func (s *Store) recordMFAFailure(ctx context.Context, email, what string) (bool, error) {
	var locked bool
	err := s.tx(ctx, func(tx *sql.Tx) error {
		var n, lockouts int
		if err := tx.QueryRow(`UPDATE mfa SET failed_attempts=failed_attempts+1 WHERE email=? RETURNING failed_attempts, lockouts`, email).Scan(&n, &lockouts); err != nil {
			return err
		}
		if n < MaxMFAFailures {
			return nil
		}
		locked = true
		lockouts++
		d := mfaLockDuration(lockouts)
		until := s.Now().Add(d).UTC().Format(time.RFC3339Nano)
		if _, err := tx.Exec(`UPDATE mfa SET failed_attempts=0, lockouts=?, locked_until=? WHERE email=?`, lockouts, until, email); err != nil {
			return err
		}
		det := map[string]any{"failed_codes": n, "lockouts": lockouts, "lock_for": d.String(), "locked_until": until, "last_failure": what}
		if err := s.audit(tx, Ev{Actor: "system:auth", Action: "auth.mfa_locked", ObjectType: "user", ObjectID: email, Failure: true, Details: det}); err != nil {
			return err
		}
		return s.raiseAlertWith(tx, "critical", alertMFALocked, "user", email,
			fmt.Sprintf("%s: %d wrong authenticator codes after a correct password; two-step sign-in is locked for %s (someone may know the password)", email, n, d), det)
	})
	return locked, err
}

// clearAuthLocks: an admin unlock (enable) clears every sign-in lock.
func clearAuthLocks(tx *sql.Tx, email string) error {
	if _, err := tx.Exec(`UPDATE local_users SET failed_attempts=0, failed_window_start='', locked_until='' WHERE email=?`, email); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM login_failures WHERE email=?`, email); err != nil {
		return err
	}
	_, err := tx.Exec(`UPDATE mfa SET failed_attempts=0, locked_until='', lockouts=0 WHERE email=?`, email)
	return err
}

// anyAuthLock: the latest active lock of a local user (account, MFA or any
// source), for the users list ("" = none).
func (s *Store) anyAuthLock(acct, mfa, src string) string {
	now := s.Now()
	best := ""
	var bestT time.Time
	for _, v := range []string{acct, mfa, src} {
		if v == "" {
			continue
		}
		if t := parseTime(v); t.After(now) && t.After(bestT) {
			best, bestT = v, t
		}
	}
	return best
}
