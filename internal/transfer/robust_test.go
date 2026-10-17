package transfer

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A .part left by an interrupted send blocks the O_EXCL create; once it is
// older than StalePartAge it is removed and the send succeeds. A fresh one
// (a send in progress) is left alone.
func TestDropDirRemovesStalePart(t *testing.T) {
	src, dst := t.TempDir(), t.TempDir()
	b := filepath.Join(src, "b-1.pmb")
	os.WriteFile(b, []byte("bundle"), 0o640)
	part := filepath.Join(dst, "b-1.pmb.part")
	os.WriteFile(part, []byte("half"), 0o640)
	if _, err := (DropDir{Dir: dst}).Send(b); err == nil || !strings.Contains(err.Error(), "in progress") {
		t.Fatalf("fresh .part must block: %v", err)
	}
	old := time.Now().Add(-2 * StalePartAge)
	os.Chtimes(part, old, old)
	if _, err := (DropDir{Dir: dst}).Send(b); err != nil {
		t.Fatalf("stale .part not cleared: %v", err)
	}
	if got, _ := os.ReadFile(filepath.Join(dst, "b-1.pmb")); string(got) != "bundle" {
		t.Fatalf("delivered %q", got)
	}
}

// TestHelperSleep is the fake gateway CLI for TestCommandTimeout.
func TestHelperSleep(t *testing.T) {
	if os.Getenv("TRANSFER_HELPER_SLEEP") != "1" {
		t.Skip("helper process")
	}
	time.Sleep(time.Minute)
}

func TestCommandTimeout(t *testing.T) {
	t.Setenv("TRANSFER_HELPER_SLEEP", "1")
	b := filepath.Join(t.TempDir(), "b-1.pmb")
	os.WriteFile(b, []byte("bundle"), 0o640)
	c := Command{Argv: []string{os.Args[0], "-test.run=^TestHelperSleep$", "{file}"}, Timeout: 300 * time.Millisecond}
	start := time.Now()
	_, err := c.Send(b)
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("want timeout, got %v", err)
	}
	if time.Since(start) > 30*time.Second {
		t.Fatal("timeout not enforced")
	}
}
