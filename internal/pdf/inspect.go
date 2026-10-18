package pdf

import (
	"bytes"
	"compress/zlib"
	"fmt"
	"io"
	"regexp"
	"strconv"
)

// Inspection helpers: enough of a reader to check what this package writes
// (tests here and in the report packages). Not a general PDF parser.

var (
	xrefHeadRe = regexp.MustCompile(`^xref\n0 (\d+)\n`)
	streamRe   = regexp.MustCompile(`/Length (\d+) /Filter /FlateDecode >>\nstream\n`)
	tjRe       = regexp.MustCompile(`\(((?:\\.|[^\\)])*)\) Tj`)
	startxRe   = regexp.MustCompile(`startxref\n(\d+)\n%%EOF\n$`)
	xrefRowRe  = regexp.MustCompile(`(\d{10}) 00000 n \n`)
)

// Check verifies the file structure: header, every cross-reference offset
// points at its object, startxref points at the table. It returns the
// number of objects.
func Check(b []byte) (int, error) {
	if !bytes.HasPrefix(b, []byte("%PDF-1.4\n")) {
		return 0, fmt.Errorf("pdf: no %%PDF-1.4 header")
	}
	m := startxRe.FindSubmatch(b)
	if m == nil {
		return 0, fmt.Errorf("pdf: no startxref / %%%%EOF trailer")
	}
	xref, _ := strconv.Atoi(string(m[1]))
	if xref <= 0 || xref >= len(b) || !bytes.HasPrefix(b[xref:], []byte("xref\n0 ")) {
		return 0, fmt.Errorf("pdf: startxref %d does not point at the xref table", xref)
	}
	rows := xrefRowRe.FindAllSubmatch(b[xref:], -1)
	for i, r := range rows {
		off, _ := strconv.Atoi(string(r[1]))
		want := fmt.Sprintf("%d 0 obj\n", i+1)
		if off <= 0 || off >= len(b) || !bytes.HasPrefix(b[off:], []byte(want)) {
			return 0, fmt.Errorf("pdf: xref entry %d (offset %d) does not point at its object", i+1, off)
		}
	}
	hm := xrefHeadRe.FindSubmatch(b[xref:])
	size := 0
	if hm != nil {
		size, _ = strconv.Atoi(string(hm[1]))
	}
	if size != len(rows)+1 {
		return 0, fmt.Errorf("pdf: xref header says %d entries, table has %d", size, len(rows)+1)
	}
	return len(rows), nil
}

// PageTexts returns the text drawn on each page (content stream order,
// one string per Tj), decoded from WinAnsi.
func PageTexts(b []byte) ([][]string, error) {
	var pages [][]string
	for _, loc := range streamRe.FindAllSubmatchIndex(b, -1) {
		n, _ := strconv.Atoi(string(b[loc[2]:loc[3]]))
		start := loc[1]
		if start+n > len(b) {
			return nil, fmt.Errorf("pdf: stream length past the end")
		}
		zr, err := zlib.NewReader(bytes.NewReader(b[start : start+n]))
		if err != nil {
			return nil, err
		}
		content, err := io.ReadAll(zr)
		if err != nil {
			return nil, err
		}
		var texts []string
		for _, m := range tjRe.FindAllSubmatch(content, -1) {
			texts = append(texts, string(decodeWinAnsi(unescape(m[1]))))
		}
		pages = append(pages, texts)
	}
	return pages, nil
}

func unescape(b []byte) []byte {
	out := make([]byte, 0, len(b))
	for i := 0; i < len(b); i++ {
		if b[i] != '\\' || i+1 >= len(b) {
			out = append(out, b[i])
			continue
		}
		i++
		if b[i] >= '0' && b[i] <= '7' && i+2 < len(b) {
			out = append(out, (b[i]-'0')<<6|(b[i+1]-'0')<<3|(b[i+2]-'0'))
			i += 2
			continue
		}
		out = append(out, b[i])
	}
	return out
}
