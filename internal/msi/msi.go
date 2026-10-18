// Package msi reads the Property table of a Windows Installer package
// (.msi) in pure Go, on any OS, so a Linux acquisition host can learn an
// MSI's ProductCode when the winget manifest does not state it.
//
// An .msi is an OLE compound file (see cfb.go). Each database table is a
// stream of the root storage whose name is compressed with the MSI stream
// name encoding; table data is stored column by column, and string columns
// hold indexes into the string pool (streams !_StringPool and !_StringData).
// The Property table has two string columns: Property and Value.
//
// The file is untrusted (downloaded from a vendor): every offset and count
// is bounds-checked and nothing is executed or extracted.
package msi

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"unicode/utf8"
)

// Info is the identifying properties of an MSI.
type Info struct {
	ProductCode    string // {GUID}, upper case
	ProductVersion string
	ProductName    string
	Manufacturer   string
	UpgradeCode    string // {GUID}, upper case, "" if absent
}

var guidRe = regexp.MustCompile(`^\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}$`)

// ErrNoProductCode: the MSI's Property table has no valid ProductCode.
var ErrNoProductCode = errors.New("the MSI has no valid ProductCode property")

// ReadInfo opens path and returns its identifying properties. It fails if
// the file is not an MSI or has no valid ProductCode.
func ReadInfo(path string) (Info, error) {
	props, err := ReadFile(path)
	if err != nil {
		return Info{}, err
	}
	return infoFrom(props)
}

func infoFrom(props map[string]string) (Info, error) {
	in := Info{ProductCode: strings.ToUpper(strings.TrimSpace(props["ProductCode"])), ProductVersion: props["ProductVersion"],
		ProductName: props["ProductName"], Manufacturer: props["Manufacturer"], UpgradeCode: strings.ToUpper(strings.TrimSpace(props["UpgradeCode"]))}
	if !guidRe.MatchString(in.UpgradeCode) {
		in.UpgradeCode = ""
	}
	if !guidRe.MatchString(in.ProductCode) {
		return in, ErrNoProductCode
	}
	return in, nil
}

// ProductCode returns the MSI's ProductCode ({GUID}, upper case).
func ProductCode(path string) (string, error) {
	in, err := ReadInfo(path)
	return in.ProductCode, err
}

// ReadFile returns every row of the MSI's Property table.
func ReadFile(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	return ReadProperties(f, st.Size())
}

// ReadProperties returns every row of the Property table of the MSI in r.
func ReadProperties(r io.ReaderAt, size int64) (map[string]string, error) {
	c, err := openCFB(r, size)
	if err != nil {
		return nil, err
	}
	streams := map[string]dirEntry{}
	for raw, e := range c.rootStreams() {
		streams[decodeName(raw)] = e
	}
	read := func(name string) ([]byte, error) {
		e, ok := streams[name]
		if !ok {
			return nil, fmt.Errorf("msi: no %s stream (not a Windows Installer database?)", name)
		}
		b, err := c.stream(e)
		if err != nil {
			return nil, fmt.Errorf("msi: %s: %w", name, err)
		}
		return b, nil
	}
	pool, err := read("!_StringPool")
	if err != nil {
		return nil, err
	}
	data, err := read("!_StringData")
	if err != nil {
		return nil, err
	}
	strs, refSize, err := loadStrings(pool, data)
	if err != nil {
		return nil, err
	}
	tbl, err := read("!Property")
	if err != nil {
		return nil, err
	}
	return propertyTable(tbl, strs, refSize)
}

// decodeName undoes the MSI stream name compression: characters
// 0x3800-0x47FF pack two characters of [0-9A-Za-z._], 0x4800-0x483F one,
// and 0x4840 marks a table ("!").
func decodeName(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 0x3800 && r < 0x4800:
			r -= 0x3800
			b.WriteByte(mime64(r & 0x3F))
			b.WriteByte(mime64((r >> 6) & 0x3F))
		case r >= 0x4800 && r < 0x4840:
			b.WriteByte(mime64(r - 0x4800))
		case r == 0x4840:
			b.WriteByte('!')
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func mime64(v rune) byte {
	switch {
	case v < 10:
		return byte('0' + v)
	case v < 36:
		return byte('A' + v - 10)
	case v < 62:
		return byte('a' + v - 36)
	case v == 62:
		return '.'
	}
	return '_'
}

// loadStrings parses the string pool. Pool entry 0 is the header (code
// page; bit 15 of the second word = string references are 3 bytes wide);
// entry i (string id i) is (length, reference count). A string of 64 KiB or
// more uses two entries: (0, refs) then (low length, high length).
func loadStrings(pool, data []byte) ([]string, int, error) {
	if len(pool) < 4 || len(pool)%4 != 0 {
		return nil, 0, errors.New("msi: string pool is malformed")
	}
	le := binary.LittleEndian
	codepage := uint32(le.Uint16(pool[0:])) | uint32(le.Uint16(pool[2:])&0x7FFF)<<16
	refSize := 2
	if le.Uint16(pool[2:])&0x8000 != 0 {
		refSize = 3
	}
	n := len(pool) / 4
	strs := make([]string, 1, n) // id 0 = null
	off := 0
	for i := 1; i < n; i++ {
		ln := int(le.Uint16(pool[4*i:]))
		refs := le.Uint16(pool[4*i+2:])
		if ln == 0 && refs != 0 {
			if i+1 >= n {
				return nil, 0, errors.New("msi: string pool truncated")
			}
			i++
			ln = int(le.Uint16(pool[4*i:])) | int(le.Uint16(pool[4*i+2:]))<<16
		}
		if ln > len(data)-off {
			return nil, 0, errors.New("msi: string pool points past the string data")
		}
		strs = append(strs, decodeString(data[off:off+ln], codepage))
		off += ln
	}
	return strs, refSize, nil
}

// decodeString: UTF-8 when it is (code page 65001, or plain ASCII), else
// each byte as Latin-1 (the identifying properties are ASCII in practice).
func decodeString(b []byte, codepage uint32) string {
	if codepage == 65001 || utf8.Valid(b) {
		return string(b)
	}
	r := make([]rune, len(b))
	for i, c := range b {
		r[i] = rune(c)
	}
	return string(r)
}

// propertyTable decodes the two string columns of the Property table.
func propertyTable(tbl []byte, strs []string, refSize int) (map[string]string, error) {
	row := 2 * refSize
	if len(tbl)%row != 0 {
		return nil, fmt.Errorf("msi: Property table is %d bytes, not a multiple of its %d-byte rows", len(tbl), row)
	}
	rows := len(tbl) / row
	ref := func(col, i int) (string, error) {
		p := tbl[(col*rows+i)*refSize:]
		id := int(p[0]) | int(p[1])<<8
		if refSize == 3 {
			id |= int(p[2]) << 16
		}
		if id >= len(strs) {
			return "", fmt.Errorf("msi: Property row %d refers to string %d of %d", i, id, len(strs))
		}
		return strs[id], nil
	}
	out := make(map[string]string, rows)
	for i := 0; i < rows; i++ {
		k, err := ref(0, i)
		if err != nil {
			return nil, err
		}
		v, err := ref(1, i)
		if err != nil {
			return nil, err
		}
		if k != "" {
			out[k] = v
		}
	}
	return out, nil
}
