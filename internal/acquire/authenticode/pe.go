package authenticode

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
)

// peImage locates the parts of a PE file the Authenticode digest skips:
// the optional header CheckSum, the certificate-table data directory entry,
// and the certificate table itself (the attribute certificates).
type peImage struct {
	size        int64
	checksumOff int64 // 4 bytes
	certDirOff  int64 // 8 bytes (data directory entry 4)
	certOff     int64 // file offset of the certificate table
	certSize    int64
}

const (
	maxPESize       = 8 << 30 // 8 GiB: larger is not an installer
	maxCertTable    = 4 << 20 // a signature with its chain is a few KiB
	winCertRevision = 0x0200
	winCertPKCS7    = 0x0002
	certDirIndex    = 4
)

// ErrNotSigned: the PE has no certificate table.
var ErrNotSigned = errors.New("file has no Authenticode signature")

func parsePE(r io.ReaderAt, size int64) (*peImage, error) {
	if size < 0x40 || size > maxPESize {
		return nil, errors.New("not a PE file (size)")
	}
	dos := make([]byte, 0x40)
	if _, err := r.ReadAt(dos, 0); err != nil {
		return nil, fmt.Errorf("read DOS header: %w", err)
	}
	if dos[0] != 'M' || dos[1] != 'Z' {
		return nil, errors.New("not a PE file (no MZ header)")
	}
	peOff := int64(binary.LittleEndian.Uint32(dos[0x3c:]))
	if peOff < 0x40 || peOff+24 > size {
		return nil, errors.New("not a PE file (bad e_lfanew)")
	}
	hdr := make([]byte, 24)
	if _, err := r.ReadAt(hdr, peOff); err != nil {
		return nil, fmt.Errorf("read PE header: %w", err)
	}
	if !bytes.Equal(hdr[:4], []byte("PE\x00\x00")) {
		return nil, errors.New("not a PE file (no PE signature)")
	}
	optSize := int64(binary.LittleEndian.Uint16(hdr[20:]))
	opt := peOff + 24
	if optSize < 2 || opt+optSize > size {
		return nil, errors.New("PE optional header truncated")
	}
	oh := make([]byte, optSize)
	if _, err := r.ReadAt(oh, opt); err != nil {
		return nil, fmt.Errorf("read optional header: %w", err)
	}
	var numRVA, dirs int64
	switch binary.LittleEndian.Uint16(oh) {
	case 0x10b: // PE32
		numRVA, dirs = 92, 96
	case 0x20b: // PE32+
		numRVA, dirs = 108, 112
	default:
		return nil, errors.New("PE optional header magic unknown")
	}
	if optSize < dirs+(certDirIndex+1)*8 {
		return nil, ErrNotSigned
	}
	if binary.LittleEndian.Uint32(oh[numRVA:]) <= certDirIndex {
		return nil, ErrNotSigned
	}
	ent := dirs + certDirIndex*8
	img := &peImage{size: size, checksumOff: opt + 64, certDirOff: opt + ent,
		certOff:  int64(binary.LittleEndian.Uint32(oh[ent:])),
		certSize: int64(binary.LittleEndian.Uint32(oh[ent+4:]))}
	if img.certOff == 0 || img.certSize == 0 {
		return nil, ErrNotSigned
	}
	headersEnd := opt + optSize
	switch {
	case img.certSize < 8 || img.certSize > maxCertTable:
		return nil, errors.New("certificate table size out of range")
	case img.certOff < headersEnd:
		return nil, errors.New("certificate table overlaps the PE headers")
	case img.certOff+img.certSize != size:
		// Data after the signature is not covered by it (and a classic way
		// to smuggle content into a signed file): refuse it.
		return nil, errors.New("certificate table is not at the end of the file (unsigned data after the signature)")
	}
	return img, nil
}

// pkcs7Blob returns the DER PKCS#7 SignedData of the single
// WIN_CERT_TYPE_PKCS_SIGNED_DATA attribute certificate. Bytes after the DER
// inside the entry may only be zero padding to the 8-byte boundary.
func (img *peImage) pkcs7Blob(r io.ReaderAt) ([]byte, error) {
	tbl := make([]byte, img.certSize)
	if _, err := r.ReadAt(tbl, img.certOff); err != nil {
		return nil, fmt.Errorf("read certificate table: %w", err)
	}
	length := int64(binary.LittleEndian.Uint32(tbl))
	rev := binary.LittleEndian.Uint16(tbl[4:])
	typ := binary.LittleEndian.Uint16(tbl[6:])
	if length < 8 || length > img.certSize {
		return nil, errors.New("WIN_CERTIFICATE length out of range")
	}
	if rev != winCertRevision || typ != winCertPKCS7 {
		return nil, fmt.Errorf("WIN_CERTIFICATE revision %#x type %#x is not PKCS#7 signed data", rev, typ)
	}
	// One attribute certificate only (padded to 8 bytes).
	if padded := (length + 7) &^ 7; padded != img.certSize && length != img.certSize {
		return nil, errors.New("certificate table holds more than one attribute certificate")
	}
	for _, b := range tbl[length:] {
		if b != 0 {
			return nil, errors.New("non-zero data after the WIN_CERTIFICATE entry")
		}
	}
	return tbl[8:length], nil
}

// digest hashes the image as Authenticode defines it: everything except the
// CheckSum field, the certificate-table directory entry and the table.
func (img *peImage) digest(r io.ReaderAt, h hash.Hash) ([]byte, error) {
	ranges := [][2]int64{
		{0, img.checksumOff},
		{img.checksumOff + 4, img.certDirOff},
		{img.certDirOff + 8, img.certOff},
	}
	for _, rg := range ranges {
		if rg[1] < rg[0] {
			return nil, errors.New("PE layout inconsistent")
		}
		if _, err := io.Copy(h, io.NewSectionReader(r, rg[0], rg[1]-rg[0])); err != nil {
			return nil, fmt.Errorf("hash image: %w", err)
		}
	}
	return h.Sum(nil), nil
}
