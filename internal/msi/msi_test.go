package msi

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"offpatch/internal/msi/msitest"
)

var testProps = [][2]string{
	{"Manufacturer", "Contoso Ltd."},
	{"ProductCode", "{0228b730-26aa-39e9-b2e1-0fc0e3ea58c8}"},
	{"ProductName", "Contoso Widget"},
	{"ProductVersion", "1.2.3.4"},
	{"UpgradeCode", "{C1DFDF69-5945-32F2-A35E-EE94C99C7CF4}"},
	{"ALLUSERS", "1"},
}

func TestNameEncoding(t *testing.T) {
	for _, s := range []string{"!_StringPool", "!_StringData", "!Property", "!_Tables", "Binary.Icon", "a", "abc"} {
		if got := decodeName(msitest.EncodeName(s)); got != s {
			t.Errorf("round trip %q → %q", s, got)
		}
	}
}

func TestReadInfoSynthetic(t *testing.T) {
	cases := []struct {
		name     string
		sector   int
		longRefs bool
		pad      int
	}{
		{"v3 512-byte sectors, mini stream", 512, false, 0},
		{"v4 4096-byte sectors", 4096, false, 0},
		{"3-byte string refs", 512, true, 0},
		{"string data in regular sectors", 512, false, 10_000},
		{"v4 with a string over 64 KiB", 4096, true, 70_000},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := msitest.Build(tc.sector, msitest.Streams(testProps, tc.longRefs, tc.pad))
			p := filepath.Join(t.TempDir(), "test.msi")
			os.WriteFile(p, b, 0o600)
			in, err := ReadInfo(p)
			if err != nil {
				t.Fatal(err)
			}
			want := Info{ProductCode: "{0228B730-26AA-39E9-B2E1-0FC0E3EA58C8}", ProductVersion: "1.2.3.4", ProductName: "Contoso Widget",
				Manufacturer: "Contoso Ltd.", UpgradeCode: "{C1DFDF69-5945-32F2-A35E-EE94C99C7CF4}"}
			if in != want {
				t.Errorf("got %+v\nwant %+v", in, want)
			}
			props, _ := ReadFile(p)
			if props["ALLUSERS"] != "1" || len(props) != len(testProps) {
				t.Errorf("properties: %v", props)
			}
		})
	}
}

func TestReadRejectsBadInput(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, b []byte) string {
		p := filepath.Join(dir, name)
		os.WriteFile(p, b, 0o600)
		return p
	}
	good := msitest.Build(512, msitest.Streams(testProps, false, 0))
	noCode := msitest.Build(512, msitest.Streams([][2]string{{"ProductName", "x"}}, false, 0))
	badCode := msitest.Build(512, msitest.Streams([][2]string{{"ProductCode", "not-a-guid"}}, false, 0))
	noPool := msitest.Build(512, []msitest.Stream{{Name: "!Property", Data: []byte{1, 0, 2, 0}}})
	cases := map[string][]byte{
		"empty":     {},
		"text":      []byte(strings.Repeat("MZ not an msi ", 100)),
		"truncated": good[:600],
		"no code":   noCode,
		"bad code":  badCode,
		"no pool":   noPool,
	}
	// Corrupt the FAT so the directory chain loops onto itself.
	loop := bytes.Clone(good)
	dirStart := binary.LittleEndian.Uint32(loop[0x30:])
	fatSec := binary.LittleEndian.Uint32(loop[0x4C:])
	binary.LittleEndian.PutUint32(loop[(int(fatSec)+1)*512+4*int(dirStart):], dirStart)
	cases["looping chain"] = loop
	for name, b := range cases {
		if _, err := ReadInfo(write(strings.ReplaceAll(name, " ", "-")+".msi", b)); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
	if _, err := ReadInfo(write("nocode.msi", noCode)); !errors.Is(err, ErrNoProductCode) {
		t.Errorf("no ProductCode: %v", err)
	}
}

// TestRealMSIs reads every *.msi in $OFFPATCH_MSI_DIR (real vendor MSIs,
// never committed). Optional $OFFPATCH_MSI_EXPECT: "file=CODE;file=CODE".
func TestRealMSIs(t *testing.T) {
	dir := os.Getenv("OFFPATCH_MSI_DIR")
	if dir == "" {
		t.Skip("set OFFPATCH_MSI_DIR to a directory of real .msi files")
	}
	want := map[string]string{}
	for _, kv := range strings.Split(os.Getenv("OFFPATCH_MSI_EXPECT"), ";") {
		if k, v, ok := strings.Cut(kv, "="); ok {
			want[k] = strings.ToUpper(v)
		}
	}
	files, _ := filepath.Glob(filepath.Join(dir, "*.msi"))
	if len(files) == 0 {
		t.Fatalf("no .msi files in %s", dir)
	}
	for _, p := range files {
		in, err := ReadInfo(p)
		if err != nil {
			t.Errorf("%s: %v", filepath.Base(p), err)
			continue
		}
		t.Logf("%s: ProductCode=%s ProductVersion=%s ProductName=%q Manufacturer=%q UpgradeCode=%s",
			filepath.Base(p), in.ProductCode, in.ProductVersion, in.ProductName, in.Manufacturer, in.UpgradeCode)
		if w := want[filepath.Base(p)]; w != "" && w != in.ProductCode {
			t.Errorf("%s: ProductCode %s, want %s", filepath.Base(p), in.ProductCode, w)
		}
	}
}
