package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"offpatch/internal/manifest"
	"offpatch/internal/trust"
)

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

// trustCmd issues a root-signed trust document (key rotation/revocation).
//
//	pmctl trust -root root.key -seq 2 \
//	  -key bundle-2026.pub=acq-zone-1 -retire bundle-2025.pub -revoke ed25519:abcd...:compromised \
//	  -out keys-2.trust.json
func trustCmd(args []string) error {
	fs := flag.NewFlagSet("trust", flag.ExitOnError)
	root := fs.String("root", "", "ROOT private key file, or exec:<command> (HSM); keep offline")
	rootPub := fs.String("root-pub", "", "root public key (required with exec:)")
	seq := fs.Int64("seq", 0, "document sequence; must increase every time")
	out := fs.String("out", "", "output file, must end in .trust.json")
	var active, retired, revoked multiFlag
	fs.Var(&active, "key", "active bundle key: <file.pub>=<source>[,<source>...] (repeatable)")
	fs.Var(&retired, "retire", "retired bundle key: <file.pub> (still valid for already-signed content)")
	fs.Var(&revoked, "revoke", "revoked key: <key_id>:<compromised|other> (compromised also revokes its packages)")
	fs.Parse(args)
	if *root == "" || *seq < 1 || !strings.HasSuffix(*out, trust.FileSuffix) {
		return fmt.Errorf("-root, -seq >= 1 and -out <name>%s are required", trust.FileSuffix)
	}
	doc := trust.Document{Version: 1, Sequence: *seq, Keys: []trust.Key{}, Revoked: []trust.Revoked{}}
	addKey := func(path, status string, sources []string) error {
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		pub, err := manifest.ParsePublic(string(b))
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		doc.Keys = append(doc.Keys, trust.Key{KeyID: manifest.KeyID(pub), PublicKey: string(manifest.EncodePublic(pub)), Sources: sources, Status: status})
		return nil
	}
	for _, a := range active {
		path, srcs, ok := strings.Cut(a, "=")
		if !ok || srcs == "" {
			return fmt.Errorf("-key %q: expected <file.pub>=<source>", a)
		}
		if err := addKey(path, "active", strings.Split(srcs, ",")); err != nil {
			return err
		}
	}
	for _, r := range retired {
		if err := addKey(r, "retired", nil); err != nil {
			return err
		}
	}
	for _, r := range revoked {
		i := strings.LastIndex(r, ":")
		if i < 0 {
			return fmt.Errorf("-revoke %q: expected <key_id>:<reason>", r)
		}
		doc.Revoked = append(doc.Revoked, trust.Revoked{KeyID: r[:i], Reason: r[i+1:]})
	}
	s, err := openSigner(*root, *rootPub)
	if err != nil {
		return err
	}
	if err := doc.Validate(); err != nil {
		return err
	}
	if doc.IssuedAt == "" {
		doc.IssuedAt = nowRFC3339()
	}
	b, _ := json.Marshal(doc)
	sig, err := s.Sign(b)
	if err != nil {
		return err
	}
	signed := trust.Signed{Document: encodeB64(b), Signature: sig, RootKeyID: s.KeyID()}
	ob, _ := json.MarshalIndent(signed, "", "  ")
	if err := os.WriteFile(*out, ob, 0o644); err != nil {
		return err
	}
	fmt.Printf("trust document %s: sequence %d, %d key(s), %d revoked, signed by root %s\nsend it like a bundle: pmctl send -bundle %s -to <drop dir>\n",
		*out, doc.Sequence, len(doc.Keys), len(doc.Revoked), s.KeyID(), *out)
	return nil
}

func nowRFC3339() string { return time.Now().UTC().Format(time.RFC3339) }

func encodeB64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }
