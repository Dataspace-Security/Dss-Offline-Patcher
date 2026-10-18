package pdf

import (
	"strings"
	"unicode/utf8"
)

// Font is one of the three standard PDF fonts the writer declares (no
// embedding: every PDF reader has them), all with WinAnsiEncoding.
type Font int

const (
	Helvetica Font = iota
	HelveticaBold
	Courier
)

var fontNames = [...]string{"Helvetica", "Helvetica-Bold", "Courier"}

// resName is the font's resource name in page content (/F1 …).
func (f Font) resName() string { return [...]string{"F1", "F2", "F3"}[f] }

// Standard (AFM) advance widths, 1/1000 em, for WinAnsi codes 32–126.
var helvWidths = [95]int{
	278, 278, 355, 556, 556, 889, 667, 191, 333, 333, 389, 584, 278, 333, 278, 278, // space … /
	556, 556, 556, 556, 556, 556, 556, 556, 556, 556, 278, 278, 584, 584, 584, 556, // 0 … ?
	1015, 667, 667, 722, 722, 667, 611, 778, 722, 278, 500, 667, 556, 833, 722, 778, // @ … O
	667, 778, 722, 667, 611, 722, 667, 944, 667, 667, 611, 278, 278, 278, 469, 556, // P … _
	333, 556, 556, 500, 556, 556, 278, 556, 556, 222, 222, 500, 222, 833, 556, 556, // ` … o
	556, 556, 333, 500, 278, 556, 500, 722, 500, 500, 500, 334, 260, 334, 584, // p … ~
}

var helvBoldWidths = [95]int{
	278, 333, 474, 556, 556, 889, 722, 238, 333, 333, 389, 584, 278, 333, 278, 278,
	556, 556, 556, 556, 556, 556, 556, 556, 556, 556, 333, 333, 584, 584, 584, 611,
	975, 722, 722, 722, 722, 667, 611, 778, 722, 278, 556, 722, 611, 833, 722, 778,
	667, 778, 722, 667, 611, 722, 667, 944, 667, 667, 611, 333, 278, 333, 584, 556,
	333, 556, 611, 556, 611, 556, 333, 611, 611, 278, 278, 556, 278, 889, 611, 611,
	611, 611, 389, 556, 333, 611, 556, 778, 556, 556, 500, 389, 280, 389, 584,
}

// highWidths: widths of the WinAnsi codes above 126 that differ from the
// default (556 lower half / letters; uppercase Latin-1 letters 722).
var highWidths = map[byte]int{
	0x80: 556, 0x85: 1000, 0x91: 222, 0x92: 222, 0x93: 333, 0x94: 333, 0x95: 350, 0x96: 556, 0x97: 1000,
	0x99: 1000, 0xA0: 278, 0xA7: 556, 0xA9: 737, 0xAE: 737, 0xB0: 400, 0xB7: 278, 0xD7: 584,
}

// width is the advance width of one encoded byte in 1/1000 em.
func (f Font) width(c byte) int {
	if f == Courier {
		return 600
	}
	if c >= 32 && c <= 126 {
		if f == HelveticaBold {
			return helvBoldWidths[c-32]
		}
		return helvWidths[c-32]
	}
	if w, ok := highWidths[c]; ok {
		return w
	}
	if c >= 0xC0 && c <= 0xDE {
		return 722
	}
	return 556
}

// TextWidth is the width of s (already encoded or not) at size points.
func TextWidth(f Font, size float64, s string) float64 {
	return encWidth(f, size, Encode(s))
}

func encWidth(f Font, size float64, b []byte) float64 {
	n := 0
	for _, c := range b {
		n += f.width(c)
	}
	return float64(n) * size / 1000
}

// winAnsiHigh maps the Unicode characters of WinAnsi codes 0x80–0x9F.
var winAnsiHigh = map[rune]byte{
	'€': 0x80, '‚': 0x82, 'ƒ': 0x83, '„': 0x84, '…': 0x85, '†': 0x86, '‡': 0x87, 'ˆ': 0x88, '‰': 0x89, 'Š': 0x8A,
	'‹': 0x8B, 'Œ': 0x8C, 'Ž': 0x8E, '‘': 0x91, '’': 0x92, '“': 0x93, '”': 0x94, '•': 0x95, '–': 0x96, '—': 0x97,
	'˜': 0x98, '™': 0x99, 'š': 0x9A, '›': 0x9B, 'œ': 0x9C, 'ž': 0x9E, 'Ÿ': 0x9F,
}

// replacements for characters outside WinAnsi.
var replacements = map[rune]string{
	'→': "->", '←': "<-", '↔': "<->", '⇒': "=>", '≥': ">=", '≤': "<=", '≠': "!=", '≈': "~", '✓': "v", '✔': "v",
	'✗': "x", '✘': "x", '−': "-", '‐': "-", '‑': "-", '‒': "-", '―': "-", '′': "'", '″': "\"", '⁄': "/",
	'\u200B': "", '\uFEFF': "", '\u20B9': "Rs ", '\u2502': "|", '\u25B8': ">", '\u25BA': ">", '\u25CF': "\x95",
	'∞': "inf", '×': "\xD7",
}

// Encode converts UTF-8 text to WinAnsi bytes: Latin-1 and the WinAnsi
// extras map directly, a few common symbols are spelled out (→ "->"), and
// anything else becomes "?". Control characters other than newline are
// dropped.
func Encode(s string) []byte {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); {
		r, n := utf8.DecodeRuneInString(s[i:])
		i += n
		switch {
		case r == utf8.RuneError && n == 1:
			out = append(out, '?')
		case r == '\n':
			out = append(out, '\n')
		case r < 32:
			// dropped
		case r < 127:
			out = append(out, byte(r))
		case r >= 0xA0 && r <= 0xFF:
			out = append(out, byte(r))
		default:
			if b, ok := winAnsiHigh[r]; ok {
				out = append(out, b)
			} else if rep, ok := replacements[r]; ok {
				out = append(out, rep...)
			} else {
				out = append(out, '?')
			}
		}
	}
	return out
}

// escape writes b as the inside of a PDF literal string.
func escape(b []byte) string {
	var sb strings.Builder
	for _, c := range b {
		switch {
		case c == '(' || c == ')' || c == '\\':
			sb.WriteByte('\\')
			sb.WriteByte(c)
		case c < 32 || c > 126:
			sb.WriteByte('\\')
			sb.WriteByte('0' + c>>6)
			sb.WriteByte('0' + (c>>3)&7)
			sb.WriteByte('0' + c&7)
		default:
			sb.WriteByte(c)
		}
	}
	return sb.String()
}

// wrap breaks encoded text into lines no wider than max points. Newlines
// force a break; words longer than a line are split.
func wrap(f Font, size, max float64, b []byte) [][]byte {
	var lines [][]byte
	for _, para := range splitBytes(b, '\n') {
		words := splitBytes(para, ' ')
		var line []byte
		lineW := 0.0
		space := encWidth(f, size, []byte{' '})
		for _, w := range words {
			if len(w) == 0 {
				continue
			}
			ww := encWidth(f, size, w)
			for ww > max && len(w) > 1 { // split an over-long word
				if len(line) > 0 {
					lines = append(lines, line)
					line, lineW = nil, 0
				}
				k := fitPrefix(f, size, max, w)
				lines = append(lines, w[:k])
				w = w[k:]
				ww = encWidth(f, size, w)
			}
			switch {
			case len(line) == 0:
				line, lineW = append([]byte{}, w...), ww
			case lineW+space+ww <= max:
				line = append(append(line, ' '), w...)
				lineW += space + ww
			default:
				lines = append(lines, line)
				line, lineW = append([]byte{}, w...), ww
			}
		}
		lines = append(lines, line)
	}
	return lines
}

// fitPrefix is how many leading bytes of w fit in max (at least one).
func fitPrefix(f Font, size, max float64, w []byte) int {
	total := 0.0
	for i, c := range w {
		total += float64(f.width(c)) * size / 1000
		if total > max {
			if i == 0 {
				return 1
			}
			return i
		}
	}
	return len(w)
}

func splitBytes(b []byte, sep byte) [][]byte {
	var out [][]byte
	start := 0
	for i, c := range b {
		if c == sep {
			out = append(out, b[start:i])
			start = i + 1
		}
	}
	return append(out, b[start:])
}
