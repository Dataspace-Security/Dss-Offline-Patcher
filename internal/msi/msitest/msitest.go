// Package msitest writes minimal synthetic MSI files (an OLE compound file
// with a string pool and a Property table) for tests. Test use only.
package msitest

import (
	"bytes"
	"encoding/binary"
	"strings"
	"unicode/utf16"
)

const (
	cfbSignature  = 0xE11AB1A1E011CFD0
	secFree       = 0xFFFFFFFF
	secEndOfChain = 0xFFFFFFFE
	secFAT        = 0xFFFFFFFD
	noStream      = 0xFFFFFFFF
	dirEntrySize  = 128
	typeStream    = 2
	typeRoot      = 5
)

// Options shape the file: SectorSize 512 (version 3, default) or 4096
// (version 4); LongRefs: 3-byte string references; Pad: a string of this
// many bytes added first (pushes the string data out of the mini stream).
type Options struct {
	SectorSize int
	LongRefs   bool
	Pad        int
}

// MSI returns an .msi whose Property table holds props (name, value pairs).
func MSI(props [][2]string, o Options) []byte {
	if o.SectorSize == 0 {
		o.SectorSize = 512
	}
	return Build(o.SectorSize, Streams(props, o.LongRefs, o.Pad))
}

// Stream is one stream of the root storage.
type Stream struct {
	Name string // decoded MSI name, e.g. "!Property"
	Data []byte
}

// EncodeName applies the MSI stream name compression.
func EncodeName(s string) string {
	idx := func(c byte) (rune, bool) {
		switch {
		case c >= '0' && c <= '9':
			return rune(c - '0'), true
		case c >= 'A' && c <= 'Z':
			return rune(c-'A') + 10, true
		case c >= 'a' && c <= 'z':
			return rune(c-'a') + 36, true
		case c == '.':
			return 62, true
		case c == '_':
			return 63, true
		}
		return 0, false
	}
	var out []rune
	if strings.HasPrefix(s, "!") {
		out = append(out, 0x4840)
		s = s[1:]
	}
	for i := 0; i < len(s); i++ {
		a, ok := idx(s[i])
		if !ok {
			out = append(out, rune(s[i]))
			continue
		}
		if i+1 < len(s) {
			if b, ok := idx(s[i+1]); ok {
				out = append(out, 0x3800+a+b<<6)
				i++
				continue
			}
		}
		out = append(out, 0x4800+a)
	}
	return string(out)
}

// Build writes a compound file with the streams in the root storage.
// Streams under 4096 bytes go to the mini stream.
func Build(sectorSize int, streams []Stream) []byte {
	const mini, cutoff = 64, 4096
	ss := sectorSize
	type placed struct {
		start uint32
		size  int
	}
	var sectors [][]byte // regular sectors, in order
	var fat []uint32
	alloc := func(data []byte) uint32 {
		if len(data) == 0 {
			return secEndOfChain
		}
		first := uint32(len(sectors))
		for off := 0; off < len(data); off += ss {
			s := make([]byte, ss)
			copy(s, data[off:])
			sectors = append(sectors, s)
			fat = append(fat, uint32(len(sectors)))
		}
		fat[len(fat)-1] = secEndOfChain
		return first
	}
	// mini stream + mini FAT
	var ministream []byte
	var minifat []uint32
	pos := make([]placed, len(streams))
	for i, s := range streams {
		if len(s.Data) >= cutoff {
			continue
		}
		first := uint32(len(ministream) / mini)
		for off := 0; off < len(s.Data); off += mini {
			blk := make([]byte, mini)
			copy(blk, s.Data[off:])
			ministream = append(ministream, blk...)
			minifat = append(minifat, uint32(len(ministream)/mini))
		}
		if len(s.Data) > 0 {
			minifat[len(minifat)-1] = secEndOfChain
		} else {
			first = secEndOfChain
		}
		pos[i] = placed{first, len(s.Data)}
	}
	for i, s := range streams {
		if len(s.Data) >= cutoff {
			pos[i] = placed{alloc(s.Data), len(s.Data)}
		}
	}
	miniStart := alloc(ministream)
	var mf []byte
	for _, v := range minifat {
		mf = binary.LittleEndian.AppendUint32(mf, v)
	}
	miniFATStart := alloc(mf)
	// directory: root, then the streams as a right-leaning chain
	entry := func(name string, typ byte, right, child, start uint32, size int) []byte {
		e := make([]byte, dirEntrySize)
		u := utf16.Encode([]rune(name))
		for i, c := range u {
			binary.LittleEndian.PutUint16(e[2*i:], c)
		}
		binary.LittleEndian.PutUint16(e[64:], uint16(2*len(u)+2))
		e[66], e[67] = typ, 1
		binary.LittleEndian.PutUint32(e[68:], noStream)
		binary.LittleEndian.PutUint32(e[72:], right)
		binary.LittleEndian.PutUint32(e[76:], child)
		binary.LittleEndian.PutUint32(e[116:], start)
		binary.LittleEndian.PutUint64(e[120:], uint64(size))
		return e
	}
	var dir []byte
	child := uint32(noStream)
	if len(streams) > 0 {
		child = 1
	}
	dir = append(dir, entry("Root Entry", typeRoot, noStream, child, miniStart, len(ministream))...)
	for i, s := range streams {
		right := uint32(noStream)
		if i+1 < len(streams) {
			right = uint32(i + 2)
		}
		dir = append(dir, entry(EncodeName(s.Name), typeStream, right, noStream, pos[i].start, pos[i].size)...)
	}
	dirStart := alloc(dir)
	// FAT sectors (covering themselves)
	per := ss / 4
	nFAT := 0
	for (len(sectors)+nFAT+per-1)/per > nFAT {
		nFAT++
	}
	fatStart := uint32(len(sectors))
	for i := 0; i < nFAT; i++ {
		sectors = append(sectors, nil)
		fat = append(fat, secFAT)
	}
	for len(fat) < nFAT*per {
		fat = append(fat, secFree)
	}
	for i := 0; i < nFAT; i++ {
		s := make([]byte, ss)
		for j := 0; j < per; j++ {
			binary.LittleEndian.PutUint32(s[4*j:], fat[i*per+j])
		}
		sectors[int(fatStart)+i] = s
	}
	if nFAT > 109 {
		panic("msitest: DIFAT sectors not supported")
	}
	h := make([]byte, ss)
	le := binary.LittleEndian
	le.PutUint64(h[0:], cfbSignature)
	le.PutUint16(h[0x18:], 0x3E)
	if ss == 512 {
		le.PutUint16(h[0x1A:], 3)
		le.PutUint16(h[0x1E:], 9)
	} else {
		le.PutUint16(h[0x1A:], 4)
		le.PutUint16(h[0x1E:], 12)
	}
	le.PutUint16(h[0x1C:], 0xFFFE)
	le.PutUint16(h[0x20:], 6)
	le.PutUint32(h[0x2C:], uint32(nFAT))
	le.PutUint32(h[0x30:], dirStart)
	le.PutUint32(h[0x38:], cutoff)
	le.PutUint32(h[0x3C:], miniFATStart)
	le.PutUint32(h[0x40:], uint32((len(mf)+ss-1)/ss))
	le.PutUint32(h[0x44:], secEndOfChain)
	for i := 0; i < 109; i++ {
		v := uint32(secFree)
		if i < nFAT {
			v = fatStart + uint32(i)
		}
		le.PutUint32(h[0x4C+4*i:], v)
	}
	out := bytes.NewBuffer(h)
	for _, s := range sectors {
		out.Write(s)
	}
	return out.Bytes()
}

// Streams builds the string pool and Property table streams.
func Streams(props [][2]string, longRefs bool, pad int) []Stream {
	var pool, data []byte
	le := binary.LittleEndian
	flags := uint16(0)
	if longRefs {
		flags = 0x8000
	}
	pool = le.AppendUint16(pool, 1252)
	pool = le.AppendUint16(pool, flags)
	ids := map[string]int{}
	n := 0
	add := func(s string) int {
		if id, ok := ids[s]; ok {
			return id
		}
		n++
		if len(s) >= 1<<16 {
			pool = le.AppendUint16(pool, 0)
			pool = le.AppendUint16(pool, 1)
			pool = le.AppendUint16(pool, uint16(len(s)))
			pool = le.AppendUint16(pool, uint16(len(s)>>16))
		} else {
			pool = le.AppendUint16(pool, uint16(len(s)))
			pool = le.AppendUint16(pool, 1)
		}
		data = append(data, s...)
		ids[s] = n
		return n
	}
	if pad > 0 {
		add(strings.Repeat("x", pad)) // pushes the string data out of the mini stream
	}
	var keys, vals []int
	for _, p := range props {
		keys = append(keys, add(p[0]))
		vals = append(vals, add(p[1]))
	}
	var tbl []byte
	put := func(id int) {
		tbl = le.AppendUint16(tbl, uint16(id))
		if longRefs {
			tbl = append(tbl, byte(id>>16))
		}
	}
	for _, k := range keys {
		put(k)
	}
	for _, v := range vals {
		put(v)
	}
	return []Stream{
		{"\x05SummaryInformation", []byte("summary")},
		{"!_StringPool", pool},
		{"!_StringData", data},
		{"!Property", tbl},
		{"!_Tables", []byte{1, 0}},
	}
}
