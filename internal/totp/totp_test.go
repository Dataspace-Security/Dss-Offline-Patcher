package totp

import (
	"testing"
	"time"
)

// RFC 6238 appendix B, SHA-1 (8 digits), secret "12345678901234567890".
func TestRFC6238Vectors(t *testing.T) {
	secret := []byte("12345678901234567890")
	for _, v := range []struct {
		unix int64
		want string
	}{
		{59, "94287082"}, {1111111109, "07081804"}, {1111111111, "14050471"},
		{1234567890, "89005924"}, {2000000000, "69279037"}, {20000000000, "65353130"},
	} {
		if got := HOTP(secret, uint64(v.unix/Period), 8); got != v.want {
			t.Errorf("T=%d: %s, want %s", v.unix, got, v.want)
		}
		// The 6-digit code is the last six digits.
		if got := Code(secret, time.Unix(v.unix, 0)); got != v.want[2:] {
			t.Errorf("T=%d 6 digits: %s, want %s", v.unix, got, v.want[2:])
		}
	}
}

func TestVerifyWindowAndReplay(t *testing.T) {
	secret, _ := NewSecret()
	now := time.Unix(1_800_000_000, 0)
	cur := Step(now)
	for _, d := range []time.Duration{-30 * time.Second, 0, 30 * time.Second} {
		if s, ok := Verify(secret, Code(secret, now.Add(d)), now, 0); !ok || s != cur+int64(d/(30*time.Second)) {
			t.Fatalf("offset %v refused (step %d)", d, s)
		}
	}
	for _, d := range []time.Duration{-90 * time.Second, 90 * time.Second} {
		if _, ok := Verify(secret, Code(secret, now.Add(d)), now, 0); ok {
			t.Fatalf("offset %v accepted", d)
		}
	}
	// A used step (and anything before it) is refused.
	if _, ok := Verify(secret, Code(secret, now), now, cur); ok {
		t.Fatal("replayed code accepted")
	}
	if _, ok := Verify(secret, Code(secret, now.Add(30*time.Second)), now, cur); !ok {
		t.Fatal("next step refused after use of the current one")
	}
	if _, ok := Verify(secret, "12345", now, 0); ok {
		t.Fatal("short code accepted")
	}
}

func TestSecretAndURI(t *testing.T) {
	secret, err := NewSecret()
	if err != nil || len(secret) != SecretBytes {
		t.Fatal(err)
	}
	enc := EncodeSecret(secret)
	back, err := DecodeSecret(enc)
	if err != nil || string(back) != string(secret) {
		t.Fatalf("round trip: %v", err)
	}
	want := "otpauth://totp/DSS%20Patcher:uma@bank.example?secret=" + enc + "&issuer=DSS%20Patcher&digits=6&period=30"
	if got := URI("DSS Patcher", "uma@bank.example", enc); got != want {
		t.Fatalf("uri %s", got)
	}
}
