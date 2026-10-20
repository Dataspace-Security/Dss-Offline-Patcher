package main

import "testing"

// stubAuthenticode makes synthetic test payloads pass the Windows Authenticode
// check (on other hosts it is not run at all).
func stubAuthenticode(t *testing.T) {
	t.Helper()
	orig := authenticode
	authenticode = func(string) (psSignature, error) { return psSignature{Status: "Valid", Subject: "CN=test vendor"}, nil }
	t.Cleanup(func() { authenticode = orig })
}
