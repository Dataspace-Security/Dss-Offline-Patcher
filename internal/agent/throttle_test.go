package agent

import (
	"bytes"
	"context"
	"io"
	"testing"
	"time"
)

func TestThrottle(t *testing.T) {
	data := bytes.Repeat([]byte("x"), 20000) // 20 KB
	start := time.Now()
	n, err := io.Copy(io.Discard, throttle(context.Background(), bytes.NewReader(data), 320)) // 40 KB/s
	if err != nil || n != int64(len(data)) {
		t.Fatal(n, err)
	}
	if el := time.Since(start); el < 400*time.Millisecond || el > 2*time.Second {
		t.Fatalf("20 KB at 40 KB/s should take ~0.5s, took %v", el)
	}
	start = time.Now()
	io.Copy(io.Discard, throttle(context.Background(), bytes.NewReader(data), 0))
	if time.Since(start) > 50*time.Millisecond {
		t.Fatal("unlimited should not sleep")
	}
}
