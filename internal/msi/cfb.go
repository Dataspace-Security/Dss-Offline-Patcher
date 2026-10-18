package msi

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"unicode/utf16"
)

// Compound File Binary (OLE structured storage, [MS-CFB]): just enough to
// read the streams of the root storage. Every count and sector number comes
// from an untrusted file, so each is checked against the file size and
// chains are bounded (no loops, no reads past the end).

const (
	cfbSignature = 0xE11AB1A1E011CFD0

	secFree       = 0xFFFFFFFF
	secEndOfChain = 0xFFFFFFFE
	secFAT        = 0xFFFFFFFD
	secDIFAT      = 0xFFFFFFFC
	noStream      = 0xFFFFFFFF

	dirEntrySize = 128
	typeStorage  = 1
	typeStream   = 2
	typeRoot     = 5

	// maxStream bounds one stream read into memory (MSI tables are small;
	// the CAB streams that make MSIs big are never read).
	maxStream = 64 << 20
)

var errNotCFB = errors.New("not an MSI (OLE compound file) file")

type cfbFile struct {
	r          io.ReaderAt
	size       int64
	sectorSize int64
	miniSize   int64
	cutoff     uint64
	nSectors   uint32 // sectors that fit in the file
	fat        []uint32
	miniFAT    []uint32
	miniStream []byte
	entries    []dirEntry
}

type dirEntry struct {
	name  string // raw UTF-16 decoded name (MSI-encoded for tables)
	typ   byte
	left  uint32
	right uint32
	child uint32
	start uint32
	size  uint64
}

func openCFB(r io.ReaderAt, size int64) (*cfbFile, error) {
	var h [512]byte
	if size < int64(len(h)) {
		return nil, errNotCFB
	}
	if _, err := r.ReadAt(h[:], 0); err != nil {
		return nil, fmt.Errorf("read header: %w", err)
	}
	le := binary.LittleEndian
	if le.Uint64(h[0:]) != cfbSignature {
		return nil, errNotCFB
	}
	if le.Uint16(h[0x1C:]) != 0xFFFE {
		return nil, errors.New("compound file: bad byte order mark")
	}
	major, shift, miniShift := le.Uint16(h[0x1A:]), le.Uint16(h[0x1E:]), le.Uint16(h[0x20:])
	switch {
	case major == 3 && shift == 9, major == 4 && shift == 12:
	default:
		return nil, fmt.Errorf("compound file: unsupported version %d / sector shift %d", major, shift)
	}
	if miniShift != 6 {
		return nil, fmt.Errorf("compound file: unsupported mini sector shift %d", miniShift)
	}
	f := &cfbFile{r: r, size: size, sectorSize: 1 << shift, miniSize: 1 << miniShift, cutoff: uint64(le.Uint32(h[0x38:]))}
	if f.cutoff == 0 {
		f.cutoff = 4096
	}
	if n := (size - f.sectorSize) / f.sectorSize; n > 0 {
		if n > secDIFAT-1 {
			n = secDIFAT - 1
		}
		f.nSectors = uint32(n)
	}
	// A truncated last sector still counts (some writers do not pad it).
	if (size-f.sectorSize)%f.sectorSize != 0 && f.nSectors < secDIFAT-1 {
		f.nSectors++
	}
	nFAT, firstDir := le.Uint32(h[0x2C:]), le.Uint32(h[0x30:])
	firstMiniFAT, nMiniFAT := le.Uint32(h[0x3C:]), le.Uint32(h[0x40:])
	firstDIFAT, nDIFAT := le.Uint32(h[0x44:]), le.Uint32(h[0x48:])
	if nFAT > f.nSectors || nDIFAT > f.nSectors || nMiniFAT > f.nSectors {
		return nil, errors.New("compound file: sector counts exceed the file size")
	}

	// FAT sector list: 109 entries in the header, then the DIFAT chain.
	fatSecs := make([]uint32, 0, nFAT)
	for i := 0; i < 109 && uint32(len(fatSecs)) < nFAT; i++ {
		fatSecs = append(fatSecs, le.Uint32(h[0x4C+4*i:]))
	}
	per := int(f.sectorSize/4) - 1
	buf := make([]byte, f.sectorSize)
	for s, n := firstDIFAT, uint32(0); uint32(len(fatSecs)) < nFAT; n++ {
		if n >= nDIFAT || s >= f.nSectors {
			return nil, errors.New("compound file: DIFAT chain is broken")
		}
		if err := f.readSector(s, buf); err != nil {
			return nil, err
		}
		for i := 0; i < per && uint32(len(fatSecs)) < nFAT; i++ {
			fatSecs = append(fatSecs, le.Uint32(buf[4*i:]))
		}
		s = le.Uint32(buf[4*per:])
	}
	f.fat = make([]uint32, 0, int64(nFAT)*f.sectorSize/4)
	for _, s := range fatSecs {
		if s >= f.nSectors {
			return nil, errors.New("compound file: FAT sector out of range")
		}
		if err := f.readSector(s, buf); err != nil {
			return nil, err
		}
		for i := int64(0); i < f.sectorSize; i += 4 {
			f.fat = append(f.fat, le.Uint32(buf[i:]))
		}
	}

	dir, err := f.readChain(firstDir, 0, false)
	if err != nil {
		return nil, fmt.Errorf("compound file: directory: %w", err)
	}
	for off := 0; off+dirEntrySize <= len(dir); off += dirEntrySize {
		f.entries = append(f.entries, parseDirEntry(dir[off:off+dirEntrySize]))
	}
	if f.sectorSize == 512 {
		for i := range f.entries {
			f.entries[i].size &= 0xFFFFFFFF // version 3: the high half may be garbage
		}
	}
	if len(f.entries) == 0 || f.entries[0].typ != typeRoot {
		return nil, errors.New("compound file: no root entry")
	}
	if nMiniFAT > 0 && firstMiniFAT != secEndOfChain {
		mf, err := f.readChain(firstMiniFAT, 0, false)
		if err != nil {
			return nil, fmt.Errorf("compound file: mini FAT: %w", err)
		}
		for i := 0; i+4 <= len(mf); i += 4 {
			f.miniFAT = append(f.miniFAT, le.Uint32(mf[i:]))
		}
	}
	if root := f.entries[0]; root.size > 0 && root.start != secEndOfChain {
		if f.miniStream, err = f.readChain(root.start, root.size, false); err != nil {
			return nil, fmt.Errorf("compound file: mini stream: %w", err)
		}
	}
	return f, nil
}

func parseDirEntry(b []byte) dirEntry {
	le := binary.LittleEndian
	n := int(le.Uint16(b[64:]))
	if n > 64 {
		n = 64
	}
	u := make([]uint16, 0, n/2)
	for i := 0; i+1 < n; i += 2 {
		c := le.Uint16(b[i:])
		if c == 0 {
			break
		}
		u = append(u, c)
	}
	return dirEntry{name: string(utf16.Decode(u)), typ: b[66], left: le.Uint32(b[68:]), right: le.Uint32(b[72:]),
		child: le.Uint32(b[76:]), start: le.Uint32(b[116:]), size: le.Uint64(b[120:])}
}

func (f *cfbFile) readSector(s uint32, buf []byte) error {
	off := (int64(s) + 1) * f.sectorSize
	n, err := f.r.ReadAt(buf, off)
	if err == io.EOF && n > 0 && off+int64(n) == f.size {
		clear(buf[n:]) // short last sector
		return nil
	}
	if err != nil {
		return fmt.Errorf("read sector %d: %w", s, err)
	}
	return nil
}

// readChain reads a sector chain from the FAT (mini: the mini FAT and the
// mini stream). size 0 reads the whole chain.
func (f *cfbFile) readChain(start uint32, size uint64, mini bool) ([]byte, error) {
	if size > maxStream {
		return nil, fmt.Errorf("stream of %d bytes is too large", size)
	}
	table, unit := f.fat, f.sectorSize
	if mini {
		table, unit = f.miniFAT, f.miniSize
	}
	var out []byte
	if size > 0 {
		out = make([]byte, 0, size)
	}
	buf := make([]byte, f.sectorSize)
	for s, n := start, 0; s != secEndOfChain; n++ {
		if size > 0 && uint64(len(out)) >= size {
			break
		}
		if int(s) >= len(table) || n > len(table) {
			return nil, errors.New("sector chain is broken")
		}
		if size == 0 && len(out) >= maxStream {
			return nil, errors.New("sector chain is too long")
		}
		if mini {
			off := int64(s) * f.miniSize
			if off+f.miniSize > int64(len(f.miniStream)) {
				return nil, errors.New("mini sector out of range")
			}
			out = append(out, f.miniStream[off:off+f.miniSize]...)
		} else {
			if s >= f.nSectors {
				return nil, errors.New("sector out of range")
			}
			if err := f.readSector(s, buf); err != nil {
				return nil, err
			}
			out = append(out, buf[:unit]...)
		}
		s = table[s]
	}
	if size > 0 {
		if uint64(len(out)) < size {
			return nil, errors.New("stream shorter than its directory size")
		}
		out = out[:size]
	}
	return out, nil
}

// rootStreams returns the streams directly under the root storage by name
// (sub-storages, e.g. embedded transforms, are not descended into).
func (f *cfbFile) rootStreams() map[string]dirEntry {
	out := map[string]dirEntry{}
	seen := map[uint32]bool{}
	var walk func(id uint32, depth int)
	walk = func(id uint32, depth int) {
		if id == noStream || int(id) >= len(f.entries) || seen[id] || depth > len(f.entries) {
			return
		}
		seen[id] = true
		e := f.entries[id]
		if e.typ == typeStream {
			if _, dup := out[e.name]; !dup {
				out[e.name] = e
			}
		}
		walk(e.left, depth+1)
		walk(e.right, depth+1)
	}
	walk(f.entries[0].child, 0)
	return out
}

// stream reads one directory entry's data.
func (f *cfbFile) stream(e dirEntry) ([]byte, error) {
	if e.size == 0 {
		return []byte{}, nil
	}
	if e.size > maxStream {
		return nil, fmt.Errorf("stream of %d bytes is too large", e.size)
	}
	return f.readChain(e.start, e.size, e.size < f.cutoff)
}
