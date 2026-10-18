// Package pdf is a small PDF 1.4 writer for the server's reports: A4
// pages, the standard Helvetica / Helvetica-Bold / Courier fonts with
// WinAnsi encoding, wrapped text, headings, tables (header repeated after a
// page break), coloured fills and badges, simple vector drawing, a page
// footer "<footer> · page N of M", document info and Flate-compressed
// content streams. No dependencies beyond the standard library.
package pdf

import (
	"bytes"
	"compress/zlib"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"
)

// A4 in points, and the default margins.
const (
	PageWidth    = 595.28
	PageHeight   = 841.89
	MarginLeft   = 50.0
	MarginRight  = 50.0
	MarginTop    = 54.0
	MarginBottom = 62.0
)

// Color is an RGB colour, components 0–1.
type Color struct{ R, G, B float64 }

// Hex parses "#RRGGBB" (black when malformed).
func Hex(s string) Color {
	s = strings.TrimPrefix(s, "#")
	if len(s) != 6 {
		return Color{}
	}
	v, err := strconv.ParseUint(s, 16, 32)
	if err != nil {
		return Color{}
	}
	return Color{float64(v>>16&0xFF) / 255, float64(v>>8&0xFF) / 255, float64(v&0xFF) / 255}
}

// Palette used by the reports.
var (
	Black     = Hex("#1F2937")
	Grey      = Hex("#6B7280")
	LightGrey = Hex("#E5E7EB")
	Navy      = Hex("#1F2A44")
	Teal      = Hex("#4FC1AE")
	White     = Color{1, 1, 1}
)

// Info is the document information dictionary.
type Info struct {
	Title   string
	Author  string // default "DSS Patcher"
	Subject string
	Created time.Time
}

// Doc is a document being laid out top to bottom. Not safe for concurrent
// use.
type Doc struct {
	info   Info
	footer string
	pages  []*bytes.Buffer
	cur    *bytes.Buffer
	y      float64 // cursor, points from the top of the page
	// onNewPage runs after a page break (tables repeat their header).
	onNewPage func()
}

// New starts a document; footer is the left part of every page footer
// ("DSS Patcher · <report id>"), followed by " · page N of M".
func New(info Info, footer string) *Doc {
	if info.Author == "" {
		info.Author = "DSS Patcher"
	}
	if info.Created.IsZero() {
		info.Created = time.Now()
	}
	d := &Doc{info: info, footer: footer}
	d.NewPage()
	return d
}

// NewPage starts a new page and puts the cursor at the top margin.
func (d *Doc) NewPage() {
	d.cur = &bytes.Buffer{}
	d.pages = append(d.pages, d.cur)
	d.y = MarginTop
	if d.onNewPage != nil {
		d.onNewPage()
	}
}

// PageCount is the number of pages so far.
func (d *Doc) PageCount() int { return len(d.pages) }

// Y is the cursor position (points from the top).
func (d *Doc) Y() float64 { return d.y }

// SetY moves the cursor on the current page.
func (d *Doc) SetY(y float64) { d.y = y }

// ContentWidth is the width between the margins.
func (d *Doc) ContentWidth() float64 { return PageWidth - MarginLeft - MarginRight }

// Remaining is the space left above the bottom margin.
func (d *Doc) Remaining() float64 { return PageHeight - MarginBottom - d.y }

// Ensure starts a new page unless h points fit below the cursor.
func (d *Doc) Ensure(h float64) {
	if h > d.Remaining() && d.y > MarginTop {
		d.NewPage()
	}
}

// Space moves the cursor down (never past the bottom margin).
func (d *Doc) Space(h float64) {
	d.y += h
	if d.y > PageHeight-MarginBottom {
		d.NewPage()
	}
}

// ---- drawing primitives (x from the left, y from the top) ----

func num(v float64) string {
	s := strconv.FormatFloat(v, 'f', 2, 64)
	s = strings.TrimRight(strings.TrimRight(s, "0"), ".")
	if s == "" || s == "-0" {
		return "0"
	}
	return s
}

func (d *Doc) op(format string, a ...any) { fmt.Fprintf(d.cur, format+"\n", a...) }

func rgb(c Color) string { return num(c.R) + " " + num(c.G) + " " + num(c.B) }

// Text draws one line of text with its baseline at y.
func (d *Doc) Text(x, y float64, f Font, size float64, c Color, s string) {
	d.text(x, y, f, size, c, Encode(s))
}

func (d *Doc) text(x, y float64, f Font, size float64, c Color, b []byte) {
	if len(b) == 0 {
		return
	}
	d.op("BT /%s %s Tf %s rg %s %s Td (%s) Tj ET", f.resName(), num(size), rgb(c), num(x), num(PageHeight-y), escape(b))
}

// Rect fills a rectangle (top-left x, y; width, height).
func (d *Doc) Rect(x, y, w, h float64, fill Color) {
	d.op("%s rg %s %s %s %s re f", rgb(fill), num(x), num(PageHeight-y-h), num(w), num(h))
}

// Line strokes a line.
func (d *Doc) Line(x1, y1, x2, y2, width float64, c Color) {
	d.op("%s w %s RG %s %s m %s %s l S", num(width), rgb(c), num(x1), num(PageHeight-y1), num(x2), num(PageHeight-y2))
}

// Pill fills a rounded bar (a thick line with round caps) of height h.
func (d *Doc) Pill(x, y, w, h float64, fill Color) {
	r := h / 2
	if w < h {
		w = h
	}
	d.op("q 1 J %s w %s RG %s %s m %s %s l S Q", num(h), rgb(fill), num(x+r), num(PageHeight-y-r), num(x+w-r), num(PageHeight-y-r))
}

// Logo draws the DSS Patcher "D" brand mark with its top-left corner at
// (x, y) and the given height (web/src/components/icons.tsx BrandMark:
// viewBox -1 -1 518 650, round-capped strokes of width 89, a teal bar).
// It returns the drawn width.
func (d *Doc) Logo(x, y, height float64, ink Color) float64 {
	const vbW, vbH, k = 518.0, 650.0, 0.5523
	s := height / vbH
	px := func(sx float64) float64 { return x + (sx+1)*s }
	py := func(sy float64) float64 { return PageHeight - (y + (sy+1)*s) }
	pt := func(sx, sy float64) string { return num(px(sx)) + " " + num(py(sy)) }
	arcD := func(r float64) string {
		const cx, cy = 193.0, 324.0
		top, bottom := cy-r, cy+r
		return fmt.Sprintf("%s m %s l %s %s %s c %s %s %s c %s l S",
			pt(44.5, top), pt(cx, top),
			pt(cx+k*r, top), pt(cx+r, cy-k*r), pt(cx+r, cy),
			pt(cx+r, cy+k*r), pt(cx+k*r, bottom), pt(cx, bottom),
			pt(44.5, bottom))
	}
	d.op("q 1 J 1 j %s w %s RG", num(89*s), rgb(ink))
	d.op("%s", arcD(280))
	d.op("%s", arcD(140))
	d.op("%s RG %s m %s l S Q", rgb(Teal), pt(44.5, 324), pt(186.5, 324))
	return vbW * s
}

// ---- output ----

// Bytes writes the finished document: catalog, page tree, fonts, info,
// one page object and one compressed content stream per page (with the
// footer), the cross-reference table and the trailer.
func (d *Doc) Bytes() ([]byte, error) {
	var out bytes.Buffer
	var offsets []int
	obj := func(body string) int {
		offsets = append(offsets, out.Len())
		n := len(offsets)
		fmt.Fprintf(&out, "%d 0 obj\n%s\nendobj\n", n, body)
		return n
	}
	out.WriteString("%PDF-1.4\n%\xE2\xE3\xCF\xD3\n")

	n := len(d.pages)
	const firstPage = 7
	kids := make([]string, n)
	for i := range n {
		kids[i] = fmt.Sprintf("%d 0 R", firstPage+2*i)
	}
	obj("<< /Type /Catalog /Pages 2 0 R >>")
	obj(fmt.Sprintf("<< /Type /Pages /Kids [%s] /Count %d >>", strings.Join(kids, " "), n))
	for _, f := range fontNames {
		obj("<< /Type /Font /Subtype /Type1 /BaseFont /" + f + " /Encoding /WinAnsiEncoding >>")
	}
	created := pdfDate(d.info.Created)
	obj(fmt.Sprintf("<< /Title %s /Author %s /Subject %s /Creator (DSS Patcher) /Producer (DSS Patcher) /CreationDate (%s) /ModDate (%s) >>",
		textString(d.info.Title), textString(d.info.Author), textString(d.info.Subject), created, created))

	for i, page := range d.pages {
		content := append([]byte{}, page.Bytes()...)
		content = append(content, d.footerOps(i+1, n)...)
		var z bytes.Buffer
		zw, err := zlib.NewWriterLevel(&z, zlib.BestCompression)
		if err != nil {
			return nil, err
		}
		if _, err := zw.Write(content); err != nil {
			return nil, err
		}
		if err := zw.Close(); err != nil {
			return nil, err
		}
		pageNo := obj(fmt.Sprintf("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 %s %s] /Resources << /Font << /F1 3 0 R /F2 4 0 R /F3 5 0 R >> >> /Contents %d 0 R >>",
			num(PageWidth), num(PageHeight), firstPage+2*i+1))
		if pageNo != firstPage+2*i {
			return nil, fmt.Errorf("pdf: page object %d out of order", pageNo)
		}
		offsets = append(offsets, out.Len())
		fmt.Fprintf(&out, "%d 0 obj\n<< /Length %d /Filter /FlateDecode >>\nstream\n", len(offsets), z.Len())
		out.Write(z.Bytes())
		out.WriteString("\nendstream\nendobj\n")
	}

	xref := out.Len()
	fmt.Fprintf(&out, "xref\n0 %d\n0000000000 65535 f \n", len(offsets)+1)
	for _, o := range offsets {
		fmt.Fprintf(&out, "%010d 00000 n \n", o)
	}
	id := sha256.Sum256(out.Bytes())
	hid := hex.EncodeToString(id[:16])
	fmt.Fprintf(&out, "trailer\n<< /Size %d /Root 1 0 R /Info 6 0 R /ID [<%s> <%s>] >>\nstartxref\n%d\n%%%%EOF\n", len(offsets)+1, hid, hid, xref)
	return out.Bytes(), nil
}

// footerOps: a hairline and "<footer> · page N of M" at the bottom.
func (d *Doc) footerOps(page, total int) []byte {
	saved := d.cur
	var b bytes.Buffer
	d.cur = &b
	y := PageHeight - MarginBottom + 26
	d.Line(MarginLeft, y-10, PageWidth-MarginRight, y-10, 0.5, LightGrey)
	label := fmt.Sprintf("%s · page %d of %d", d.footer, page, total)
	if d.footer == "" {
		label = fmt.Sprintf("page %d of %d", page, total)
	}
	d.Text(MarginLeft, y, Helvetica, 7.5, Grey, label)
	d.cur = saved
	return b.Bytes()
}

// pdfDate formats D:YYYYMMDDHHmmSS+HH'mm'.
func pdfDate(t time.Time) string {
	_, off := t.Zone()
	sign := '+'
	if off < 0 {
		sign, off = '-', -off
	}
	return fmt.Sprintf("D:%s%c%02d'%02d'", t.Format("20060102150405"), sign, off/3600, off%3600/60)
}

// textString is a PDF text string: UTF-16BE with a byte-order mark, hex.
func textString(s string) string {
	var sb strings.Builder
	sb.WriteString("<FEFF")
	for _, u := range utf16.Encode([]rune(s)) {
		fmt.Fprintf(&sb, "%04X", u)
	}
	sb.WriteString(">")
	return sb.String()
}
