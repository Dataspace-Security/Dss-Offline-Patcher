package manifest

// Native Go fuzz tests for the untrusted-input surface of the manifest
// package: manifest JSON parsing/validation, bundle (tar) extraction and
// signature verification. Run one fuzzer at a time, e.g.
//
//	go test -run='^$' -fuzz=FuzzExtractSafe -fuzztime=60s ./internal/manifest/
//
// Regression inputs found by fuzzing live in testdata/fuzz/<FuzzName>/ and
// are replayed by a plain `go test`.

import (
	"archive/tar"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fuzzNow is a fixed clock so ValidateSchema results are reproducible.
var fuzzNow = time.Date(2026, 10, 16, 9, 30, 0, 0, time.UTC)

func seedManifestJSON() []byte {
	m := Manifest{
		SchemaVersion: 1, BundleID: "b-20261016-0001-3f9c", Source: "acq-zone-1", Sequence: 7,
		KeyID:     "ed25519:9a1c0b7e4d2f6a13",
		CreatedAt: fuzzNow.Add(-30 * time.Minute), ExpiresAt: fuzzNow.Add(30 * 24 * time.Hour),
		Packages: []Package{{
			PackageID: "KB5044273-x64", Title: "2026-10 Cumulative Update", Vendor: "Microsoft", Kind: "msu",
			Version: "19045.5011", KB: "KB5044273", Severity: "critical", ReleaseDate: "2026-10-08",
			Supersedes:      []string{"KB5043064"},
			Applicability:   Applicability{OS: "windows", Arch: "x64", MinBuild: 19045, MaxBuild: 19045},
			File:            FileRef{Name: "payload/windows10.0-kb5044273-x64.msu", Size: 5, SHA256: strings.Repeat("a", 64)},
			VendorSignature: VendorSignature{Status: "valid", Signer: "Microsoft Corporation"},
		}, {
			PackageID: "app-1.2.3", Title: "App", Kind: "msi", ProductCode: "{12345678-1234-1234-1234-123456789ABC}",
			Severity: "low", Applicability: Applicability{OS: "windows", Arch: "any"},
			File:            FileRef{Name: "payload/app.msi", Size: 3, SHA256: strings.Repeat("b", 64)},
			VendorSignature: VendorSignature{Status: "not_checked"},
		}},
	}
	b, _ := json.Marshal(m)
	return b
}

func FuzzParse(f *testing.F) {
	f.Add(seedManifestJSON())
	f.Add([]byte(`{}`))
	f.Add([]byte(`null`))
	f.Add([]byte(`[]`))
	f.Add([]byte(`{"schema_version":1,"packages":[{}]}`))
	f.Add([]byte(`{"schema_version":1} {"x":1}`))
	f.Add([]byte(`{"unknown":1}`))
	f.Add([]byte(`{"created_at":"0001-01-01T00:00:00Z","expires_at":"9999-12-31T23:59:59Z"}`))
	f.Add([]byte(`{"created_at":"-0001-01-01T00:00:00Z"}`))
	f.Add([]byte(`{"sequence":-9223372036854775808,"packages":null}`))
	f.Add([]byte(`{"packages":[{"file":{"name":"payload/../x","size":-1}}]}`))
	// Valid manifests whose file name is a dot-segment, has a trailing dot or
	// is a Windows device name (CON, NUL, COM1...).
	for _, n := range []string{"payload/..", "payload/.", "payload/...", "payload/a.msu.", "payload/CON", "payload/nul.msu", "payload/com1.msi"} {
		f.Add(bytes.Replace(seedManifestJSON(), []byte("payload/app.msi"), []byte(n), 1))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		m, err := Parse(b)
		if err != nil {
			if m != nil {
				t.Fatal("Parse returned a manifest together with an error")
			}
			return
		}
		if m == nil {
			t.Fatal("Parse returned nil manifest without error")
		}
		_ = m.ValidateSchema(fuzzNow)
		_ = m.ValidateSchema(time.Time{})
		if m.ValidateSchema(fuzzNow) == nil {
			// Anything that passes validation must satisfy the invariants the
			// server relies on when building quarantine paths.
			if n := len(m.Packages); n < 1 || n > MaxPackages {
				t.Fatalf("validated manifest has %d packages", n)
			}
			for _, p := range m.Packages {
				base := strings.TrimPrefix(p.File.Name, "payload/")
				if base == p.File.Name || strings.ContainsAny(base, `/\`) || base == "." || base == ".." ||
					strings.HasSuffix(base, ".") || isWindowsDeviceName(base) {
					t.Fatalf("validated manifest has unsafe file name %q", p.File.Name)
				}
				if p.File.Size <= 0 || !hexRe.MatchString(p.File.SHA256) {
					t.Fatalf("validated manifest has bad file ref %+v", p.File)
				}
			}
		}
	})
}

// ---- FuzzExtractSafe ----

// fuzzLimits are deliberately small so the fuzzer can reach every limit.
var fuzzLimits = Limits{MaxFiles: 4, MaxFileBytes: 4 << 10, MaxTotal: 8 << 10}

type seedEntry struct {
	name     string
	typ      byte
	body     string
	link     string
	sizeHint int64 // if non-zero, declared header size (body is truncated/short)
}

// rawTar builds a tar archive. Entries with sizeHint declare a size different
// from the body actually written, producing truncated/inconsistent archives.
func rawTar(entries []seedEntry, truncateTo int) []byte {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		typ := e.typ
		if typ == 0 {
			typ = tar.TypeReg
		}
		h := &tar.Header{Name: e.name, Typeflag: typ, Mode: 0o644, Linkname: e.link, ModTime: fuzzNow, Format: tar.FormatPAX}
		if typ == tar.TypeReg {
			h.Size = int64(len(e.body))
			if e.sizeHint != 0 {
				h.Size = e.sizeHint
			}
		}
		if err := tw.WriteHeader(h); err != nil {
			continue
		}
		if typ == tar.TypeReg {
			_, _ = tw.Write([]byte(e.body))
		}
	}
	_ = tw.Close()
	b := buf.Bytes()
	if truncateTo > 0 && truncateTo < len(b) {
		b = b[:truncateTo]
	}
	return b
}

// structuredTar decodes fuzz bytes into a list of tar entries so the fuzzer
// explores entry names, types, sizes and ordering rather than tar checksums.
//
// Encoding, repeated: [type][flags][nameLen][name...][bodyLen][body...]
// flags&1 → declared size is inflated by a varint that follows the body
// flags&2 → linkname = name of previous entry.
// A leading byte 0xFF means "truncate the archive at a position given by the
// next two bytes".
func structuredTar(data []byte) []byte {
	trunc := 0
	if len(data) >= 3 && data[0] == 0xFF {
		trunc = int(binary.BigEndian.Uint16(data[1:3]))
		data = data[3:]
	}
	types := []byte{tar.TypeReg, tar.TypeDir, tar.TypeSymlink, tar.TypeLink, tar.TypeChar, tar.TypeBlock, tar.TypeFifo, tar.TypeReg, tar.TypeGNUSparse, tar.TypeCont}
	var entries []seedEntry
	prev := ""
	take := func(n int) []byte {
		if n > len(data) {
			n = len(data)
		}
		b := data[:n]
		data = data[n:]
		return b
	}
	for len(data) >= 3 && len(entries) < 32 {
		hdr := take(3)
		e := seedEntry{typ: types[int(hdr[0])%len(types)]}
		e.name = string(take(int(hdr[2]) % 128))
		if len(data) == 0 {
			entries = append(entries, e)
			break
		}
		bl := int(take(1)[0])
		e.body = string(take(bl * 40)) // up to ~10 KiB per entry
		if hdr[1]&1 != 0 {
			v, n := binary.Uvarint(data)
			if n > 0 {
				data = data[n:]
				e.sizeHint = int64(len(e.body)) + int64(v&(1<<62-1))
				if e.sizeHint == int64(len(e.body)) {
					e.sizeHint = 0
				}
			}
		}
		if hdr[1]&2 != 0 {
			e.link = prev
		}
		prev = e.name
		entries = append(entries, e)
	}
	return rawTar(entries, trunc)
}

func encodeStructured(entries []seedEntry) []byte {
	var b []byte
	for _, e := range entries {
		ti := 0
		switch e.typ {
		case tar.TypeDir:
			ti = 1
		case tar.TypeSymlink:
			ti = 2
		case tar.TypeLink:
			ti = 3
		case tar.TypeChar:
			ti = 4
		}
		var flags byte
		if e.link != "" {
			flags |= 2
		}
		b = append(b, byte(ti), flags, byte(len(e.name)))
		b = append(b, e.name...)
		n := (len(e.body) + 39) / 40
		body := e.body + strings.Repeat("\x00", n*40-len(e.body))
		b = append(b, byte(n))
		b = append(b, body...)
	}
	return b
}

func seedBundles() [][]seedEntry {
	man := string(seedManifestJSON())
	_, priv, _ := ed25519.GenerateKey(bytes.NewReader(make([]byte, 64)))
	sig := Sign(priv, []byte(man)) + "\n"
	ok := []seedEntry{
		{name: EntryManifest, body: man},
		{name: EntrySig, body: sig},
		{name: "payload/", typ: tar.TypeDir},
		{name: "payload/windows10.0-kb5044273-x64.msu", body: "hello"},
		{name: "payload/app.msi", body: "abc"},
	}
	with := func(extra ...seedEntry) []seedEntry {
		return append(append([]seedEntry{}, ok...), extra...)
	}
	return [][]seedEntry{
		ok,
		with(seedEntry{name: "payload/../../escape"}),
		with(seedEntry{name: "../escape", body: "x"}),
		with(seedEntry{name: "/tmp/escape", body: "x"}),
		with(seedEntry{name: "payload/..", body: "x"}),
		with(seedEntry{name: "payload/.", body: "x"}),
		with(seedEntry{name: `payload\..\..\escape`, body: "x"}),
		with(seedEntry{name: "payload/a/b", body: "x"}),
		with(seedEntry{name: "payload/link", typ: tar.TypeSymlink, link: "../../../escape"}),
		with(seedEntry{name: "payload/hl", typ: tar.TypeLink, link: EntryManifest}),
		with(seedEntry{name: "payload/dev", typ: tar.TypeChar}),
		with(seedEntry{name: "payload/fifo", typ: tar.TypeFifo}),
		with(seedEntry{name: "payload/sub", typ: tar.TypeDir}),
		with(seedEntry{name: "payload/app.msi", body: "dup"}),
		with(seedEntry{name: EntryManifest, body: "{}"}),
		with(seedEntry{name: "payload/huge.msu", body: "x", sizeHint: 1 << 40}),
		with(seedEntry{name: "payload/big.msu", body: strings.Repeat("A", 5000)}),
		with(seedEntry{name: "payload/b1", body: strings.Repeat("B", 3000)}, seedEntry{name: "payload/b2", body: strings.Repeat("C", 3000)}),
		with(seedEntry{name: "payload/f1", body: "1"}, seedEntry{name: "payload/f2", body: "2"}, seedEntry{name: "payload/f3", body: "3"}),
		with(seedEntry{name: "payload/A.MSI", body: "case"}),
		with(seedEntry{name: "payload/CON", body: "dev"}),
		with(seedEntry{name: "payload/x.msu.", body: "dot"}),
		{{name: EntryManifest, body: man, sizeHint: 32 << 20}},
		{{name: EntrySig, body: strings.Repeat("s", 10000)}, {name: EntryManifest, body: man}},
		{{name: "payload", typ: tar.TypeReg, body: "notadir"}},
		{{name: "payload", typ: tar.TypeSymlink, link: "/"}, {name: "payload/x", body: "x"}},
		{},
	}
}

func FuzzExtractSafe(f *testing.F) {
	for i, s := range seedBundles() {
		f.Add(rawTar(s, 0), false)
		f.Add(encodeStructured(s), true)
		// truncated variants of the raw archive
		full := rawTar(s, 0)
		if len(full) > 600 {
			f.Add(full[:len(full)-600+i%400], false)
		}
	}
	f.Add([]byte{}, false)
	f.Add([]byte("not a tar file at all"), false)
	f.Add(bytes.Repeat([]byte{0}, 1024), false)
	f.Fuzz(func(t *testing.T, data []byte, structured bool) {
		archive := data
		if structured {
			archive = structuredTar(data)
		}
		bundleDir := t.TempDir()
		bundle := filepath.Join(bundleDir, "b.pmb")
		if err := os.WriteFile(bundle, archive, 0o600); err != nil {
			t.Fatal(err)
		}
		parent := t.TempDir()
		dest := filepath.Join(parent, "dest")
		if err := os.Mkdir(filepath.Join(parent, "sibling"), 0o700); err != nil {
			t.Fatal(err)
		}

		ex, err := ExtractSafe(bundle, dest, fuzzLimits)

		// Property: nothing outside dest is created; inside dest only
		// payload/ and regular files directly inside it; no links; the
		// bytes on disk never exceed the configured limits.
		payload := filepath.Join(dest, "payload")
		var onDisk int64
		var nfiles int
		werr := filepath.WalkDir(parent, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			switch p {
			case parent, dest, payload, filepath.Join(parent, "sibling"):
				if !d.IsDir() {
					t.Fatalf("%s is not a directory (type %v)", p, d.Type())
				}
				return nil
			}
			if filepath.Dir(p) != payload {
				t.Fatalf("file written outside dest/payload: %s", p)
			}
			if b := filepath.Base(p); strings.HasSuffix(b, ".") || isWindowsDeviceName(b) {
				t.Fatalf("Windows-unsafe payload name extracted: %s", p)
			}
			if !d.Type().IsRegular() {
				t.Fatalf("non-regular entry extracted: %s (%v)", p, d.Type())
			}
			info, err := d.Info()
			if err != nil {
				return err
			}
			if info.Size() > fuzzLimits.MaxFileBytes {
				t.Fatalf("%s is %d bytes, over per-file limit", p, info.Size())
			}
			onDisk += info.Size()
			nfiles++
			return nil
		})
		if werr != nil {
			t.Fatalf("walk: %v", werr)
		}
		if onDisk > fuzzLimits.MaxTotal {
			t.Fatalf("extracted %d bytes, over total limit %d", onDisk, fuzzLimits.MaxTotal)
		}
		if nfiles > fuzzLimits.MaxFiles {
			t.Fatalf("extracted %d files, over limit %d", nfiles, fuzzLimits.MaxFiles)
		}

		if err != nil {
			if ex != nil {
				t.Fatal("ExtractSafe returned a result together with an error")
			}
			return
		}
		if ex == nil || ex.ManifestBytes == nil || ex.Signature == "" {
			t.Fatalf("success without manifest/signature: %+v", ex)
		}
		if len(ex.Files) != nfiles {
			t.Fatalf("result lists %d files, %d on disk", len(ex.Files), nfiles)
		}
		var total int64
		for name, fe := range ex.Files {
			if !strings.HasPrefix(name, "payload/") {
				t.Fatalf("file key %q not under payload/", name)
			}
			rel, rerr := filepath.Rel(payload, fe.Path)
			if rerr != nil || rel != filepath.Base(fe.Path) || rel == "." || rel == ".." || strings.HasPrefix(rel, "..") {
				t.Fatalf("file %q path %q not directly inside %q", name, fe.Path, payload)
			}
			if rel != strings.TrimPrefix(name, "payload/") {
				t.Fatalf("file key %q does not match on-disk name %q", name, rel)
			}
			b, rerr := os.ReadFile(fe.Path)
			if rerr != nil {
				t.Fatalf("listed file unreadable: %v", rerr)
			}
			sum := sha256.Sum256(b)
			if int64(len(b)) != fe.Size || hex.EncodeToString(sum[:]) != fe.SHA256 {
				t.Fatalf("file %q size/hash in result does not match disk", name)
			}
			total += fe.Size
		}
		if total > fuzzLimits.MaxTotal {
			t.Fatalf("result total %d over limit", total)
		}
	})
}

// ---- FuzzVerify ----

func FuzzVerify(f *testing.F) {
	pub, priv, _ := ed25519.GenerateKey(bytes.NewReader(make([]byte, 64)))
	msg := seedManifestJSON()
	sig := Sign(priv, msg)
	f.Add([]byte(pub), msg, sig)
	f.Add([]byte(pub), msg, sig+"\n")
	f.Add([]byte(pub), append(append([]byte{}, msg...), ' '), sig)
	f.Add([]byte{}, msg, sig)
	f.Add([]byte(pub[:31]), msg, sig)
	f.Add(append([]byte(pub), 0), msg, sig)
	f.Add(EncodePublic(pub), msg, sig)
	f.Add([]byte(base64.StdEncoding.EncodeToString(pub)), []byte{}, "")
	f.Add([]byte(pub), msg, "!!!!")
	f.Add([]byte(pub), msg, base64.StdEncoding.EncodeToString(make([]byte, 64)))
	f.Add([]byte(pub), msg, base64.StdEncoding.EncodeToString(make([]byte, 65)))
	f.Add([]byte("-----BEGIN OFFPATCH ED25519 PUBLIC KEY-----\nAAAA\n-----END OFFPATCH ED25519 PUBLIC KEY-----\n"), msg, sig)
	f.Fuzz(func(t *testing.T, key []byte, m []byte, s string) {
		// Raw key bytes of arbitrary length must not panic.
		err := Verify(ed25519.PublicKey(key), m, s)
		if err == nil && len(key) != ed25519.PublicKeySize {
			t.Fatalf("verified with %d-byte public key", len(key))
		}
		// Keys parsed from text (PEM or base64) as config/agent do.
		if pk, perr := ParsePublic(string(key)); perr == nil {
			if len(pk) != ed25519.PublicKeySize {
				t.Fatalf("ParsePublic returned %d-byte key", len(pk))
			}
			_ = KeyID(pk)
			_ = Verify(pk, m, s)
		}
		// The genuine key must never accept a signature for a different
		// message than the one it signed.
		if !bytes.Equal(m, msg) && Verify(pub, m, sig) == nil {
			t.Fatal("signature verified for a modified manifest")
		}
	})
}

// isWindowsDeviceName is an independent oracle for the property checks: the
// stem (text before the first dot) is a reserved DOS device name.
func isWindowsDeviceName(base string) bool {
	stem := strings.ToUpper(strings.SplitN(base, ".", 2)[0])
	switch stem {
	case "CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$":
		return true
	}
	if len(stem) == 4 && (strings.HasPrefix(stem, "COM") || strings.HasPrefix(stem, "LPT")) && stem[3] >= '0' && stem[3] <= '9' {
		return true
	}
	return false
}
