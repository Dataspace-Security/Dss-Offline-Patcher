package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"offpatch/internal/manifest"
)

// signer abstracts where the Ed25519 private key lives.
//
//   - a key file (development, or a hardened acquisition host)
//   - exec:<command>: an external program, typically the HSM/KMS vendor's
//     CLI or a small wrapper around PKCS#11, that reads the bytes to sign on
//     stdin and writes the base64 Ed25519 signature to stdout. The private
//     key never touches this process. Every signature is verified against
//     -pub before use, so a misbehaving signer cannot produce a bad bundle.
//     Quote a program path containing spaces: exec:"C:\Program Files\x.exe" -k 1.
//     Each call is killed after signerTimeout.
type signer interface {
	KeyID() string
	Public() ed25519.PublicKey
	Sign(msg []byte) (string, error)
}

type fileSigner struct{ k ed25519.PrivateKey }

func (f fileSigner) KeyID() string                   { return manifest.KeyID(f.Public()) }
func (f fileSigner) Public() ed25519.PublicKey       { return f.k.Public().(ed25519.PublicKey) }
func (f fileSigner) Sign(msg []byte) (string, error) { return manifest.Sign(f.k, msg), nil }

type execSigner struct {
	argv []string
	pub  ed25519.PublicKey
}

func (e execSigner) KeyID() string             { return manifest.KeyID(e.pub) }
func (e execSigner) Public() ed25519.PublicKey { return e.pub }

// signerTimeout bounds one external signer call (an HSM that waits for a
// PIN or a dead network HSM must not hang the scheduled run).
var signerTimeout = 60 * time.Second

func (e execSigner) Sign(msg []byte) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), signerTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, e.argv[0], e.argv[1:]...)
	cmd.WaitDelay = 5 * time.Second
	cmd.Stdin = bytes.NewReader(msg)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if ctx.Err() == context.DeadlineExceeded {
		return "", fmt.Errorf("external signer timed out after %s: %s", signerTimeout, strings.TrimSpace(stderr.String()))
	}
	if err != nil {
		return "", fmt.Errorf("external signer: %v: %s", err, strings.TrimSpace(stderr.String()))
	}
	sig := strings.TrimSpace(string(out))
	if err := manifest.Verify(e.pub, msg, sig); err != nil {
		return "", fmt.Errorf("external signer returned an invalid signature: %w", err)
	}
	return sig, nil
}

func openSigner(key, pub string) (signer, error) {
	if key == "" {
		return nil, fmt.Errorf("a signing key is required")
	}
	if cmd, ok := strings.CutPrefix(key, "exec:"); ok {
		argv, err := splitArgs(cmd)
		if err != nil {
			return nil, fmt.Errorf("exec: signer: %w", err)
		}
		if len(argv) == 0 {
			return nil, fmt.Errorf("exec: signer needs a command")
		}
		if pub == "" {
			return nil, fmt.Errorf("-pub is required with an exec: signer")
		}
		p, err := manifest.LoadPublic(pub)
		if err != nil {
			return nil, err
		}
		return execSigner{argv: argv, pub: p}, nil
	}
	k, err := manifest.LoadPrivate(key)
	if err != nil {
		return nil, err
	}
	return fileSigner{k}, nil
}
