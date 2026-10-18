package pdf

import "math"

// Tone colours a badge or a cell.
type Tone string

const (
	ToneNone  Tone = ""
	ToneGreen Tone = "green"
	ToneAmber Tone = "amber"
	ToneRed   Tone = "red"
	ToneBlue  Tone = "blue"
	ToneGrey  Tone = "grey"
	ToneTeal  Tone = "teal"
)

// toneColors: badge fill and text colour.
var toneColors = map[Tone][2]Color{
	ToneGreen: {Hex("#DCFCE7"), Hex("#166534")},
	ToneAmber: {Hex("#FEF3C7"), Hex("#92400E")},
	ToneRed:   {Hex("#FEE2E2"), Hex("#991B1B")},
	ToneBlue:  {Hex("#DBEAFE"), Hex("#1E40AF")},
	ToneGrey:  {Hex("#F3F4F6"), Hex("#374151")},
	ToneTeal:  {Hex("#D5F2EC"), Hex("#0F5F52")},
}

// ToneColors returns a tone's fill and text colours.
func ToneColors(t Tone) (fill, ink Color) {
	c, ok := toneColors[t]
	if !ok {
		c = toneColors[ToneGrey]
	}
	return c[0], c[1]
}

// Style is how a block of text is set.
type Style struct {
	Font    Font
	Size    float64
	Color   Color
	Leading float64 // line height as a multiple of Size (default 1.35)
	Indent  float64 // left indent
	After   float64 // space after the block
}

func (s Style) lineH() float64 {
	if s.Leading == 0 {
		s.Leading = 1.35
	}
	return s.Size * s.Leading
}

// Body is the default paragraph style.
var Body = Style{Font: Helvetica, Size: 9.5, Color: Black, After: 6}

// Heading draws a section heading (level 1 large with a rule, 2 and 3
// smaller); it keeps at least two body lines with it.
func (d *Doc) Heading(level int, text string) {
	size := map[int]float64{1: 15, 2: 12, 3: 10.5}[level]
	if size == 0 {
		size = 10.5
	}
	before := map[int]float64{1: 14, 2: 10, 3: 8}[level]
	if d.y > MarginTop {
		d.y += before
	}
	lines := wrap(HelveticaBold, size, d.ContentWidth(), Encode(text))
	d.Ensure(float64(len(lines))*size*1.25 + 3*Body.lineH())
	for _, l := range lines {
		d.y += size
		d.text(MarginLeft, d.y, HelveticaBold, size, Navy, l)
		d.y += size * 0.25
	}
	if level == 1 {
		d.y += 3
		d.Line(MarginLeft, d.y, PageWidth-MarginRight, d.y, 1.2, Teal)
		d.y += 4
	}
	d.y += 4
}

// Paragraph draws wrapped text.
func (d *Doc) Paragraph(text string, st Style) {
	d.Rich([]Run{{Text: text}}, st)
}

// Run is a piece of a paragraph: the style's font, or bold / monospaced.
type Run struct {
	Text  string
	Bold  bool
	Mono  bool
	Color *Color
}

type word struct {
	b     []byte
	f     Font
	c     Color
	w     float64
	space bool // a space precedes it
	br    bool // a forced line break precedes it
}

// Rich draws a paragraph made of runs (e.g. a bold label then plain text),
// wrapped as one flow.
func (d *Doc) Rich(runs []Run, st Style) {
	lh := st.lineH()
	for _, line := range layoutRich(runs, st, d.ContentWidth()-st.Indent) {
		if d.y+lh > PageHeight-MarginBottom {
			d.NewPage()
		}
		d.drawWords(line, st)
	}
	d.y += st.After
}

// drawWords draws one laid-out line at the cursor and advances it.
func (d *Doc) drawWords(line []word, st Style) {
	d.y += st.Size
	x := MarginLeft + st.Indent
	// Consecutive words in the same font and colour are one string.
	for i := 0; i < len(line); {
		w := line[i]
		if i > 0 && w.space {
			x += encWidth(w.f, st.Size, []byte{' '})
		}
		seg := append([]byte{}, w.b...)
		j := i + 1
		for ; j < len(line) && line[j].f == w.f && line[j].c == w.c; j++ {
			if line[j].space {
				seg = append(seg, ' ')
			}
			seg = append(seg, line[j].b...)
		}
		d.text(x, d.y, w.f, st.Size, w.c, seg)
		x += encWidth(w.f, st.Size, seg)
		i = j
	}
	d.y += st.lineH() - st.Size
}

// layoutRich wraps runs into lines no wider than width.
func layoutRich(runs []Run, st Style, width float64) [][]word {
	var lines [][]word
	var line []word
	lineW := 0.0
	flush := func() {
		lines = append(lines, line)
		line, lineW = nil, 0
	}
	for _, w := range runWords(runs, st) {
		sp := 0.0
		if len(line) > 0 && w.space {
			sp = encWidth(w.f, st.Size, []byte{' '})
		}
		if len(line) > 0 && (w.br || lineW+sp+w.w > width) {
			flush()
			sp = 0
		}
		for w.w > width && len(w.b) > 1 { // an over-long word: split it
			k := fitPrefix(w.f, st.Size, width, w.b)
			line = append(line, word{b: w.b[:k], f: w.f, c: w.c, w: encWidth(w.f, st.Size, w.b[:k])})
			flush()
			w.b = w.b[k:]
			w.w = encWidth(w.f, st.Size, w.b)
		}
		line = append(line, w)
		lineW += sp + w.w
	}
	if len(line) > 0 {
		flush()
	}
	return lines
}

func runWords(runs []Run, st Style) []word {
	var out []word
	pendingSpace, pendingBr := false, false
	for _, r := range runs {
		f := st.Font
		if r.Bold {
			f = HelveticaBold
		}
		if r.Mono {
			f = Courier
		}
		c := st.Color
		if r.Color != nil {
			c = *r.Color
		}
		b := Encode(r.Text)
		start := 0
		emit := func(end int) {
			if end > start {
				w := b[start:end]
				out = append(out, word{b: w, f: f, c: c, w: encWidth(f, st.Size, w), space: pendingSpace, br: pendingBr})
				pendingSpace, pendingBr = false, false
			}
		}
		for i, ch := range b {
			switch ch {
			case ' ':
				emit(i)
				pendingSpace = true
				start = i + 1
			case '\n':
				emit(i)
				pendingBr = true
				start = i + 1
			}
		}
		emit(len(b))
	}
	return out
}

// Bullets draws a bulleted list.
func (d *Doc) Bullets(items []string, st Style) {
	for _, it := range items {
		inner := st
		inner.Indent += 12
		inner.After = 2
		d.Ensure(inner.lineH())
		// The bullet sits on the item's first line (on this page: it fits).
		d.text(MarginLeft+st.Indent+2, d.y+st.Size, st.Font, st.Size, st.Color, []byte{0x95})
		d.Rich([]Run{{Text: it}}, inner)
	}
	d.y += st.After
}

// Callout draws a shaded box with a coloured left bar around runs (kept
// on one page).
func (d *Doc) Callout(runs []Run, tone Tone) {
	fill, ink := ToneColors(tone)
	st := Style{Font: Helvetica, Size: 9, Color: Black, Indent: 12}
	lines := layoutRich(runs, st, d.ContentWidth()-24)
	h := float64(len(lines))*st.lineH() + 14
	d.Ensure(h)
	top := d.y
	d.Rect(MarginLeft, top, d.ContentWidth(), h, fill)
	d.Rect(MarginLeft, top, 3, h, ink)
	d.y = top + 6
	for _, l := range lines {
		d.drawWords(l, st)
	}
	d.y = top + h + 8
}

// Badge draws a coloured pill with text at (x, y top) and returns its width.
func (d *Doc) Badge(x, y float64, size float64, tone Tone, text string) float64 {
	fill, ink := ToneColors(tone)
	b := Encode(text)
	w := encWidth(HelveticaBold, size, b) + size
	h := size + 4
	d.Pill(x, y, w, h, fill)
	d.text(x+size/2, y+h/2+size*0.35, HelveticaBold, size, ink, b)
	return w
}

// ---- tables ----

// Align is a cell's horizontal alignment.
type Align int

const (
	Left Align = iota
	Right
	Center
)

// Column describes one table column.
type Column struct {
	Header string
	Weight float64 // relative width
	Align  Align
}

// Cell is one table cell. A Badge cell draws Text as a coloured pill
// (wrapped as coloured text when it does not fit on one line).
type Cell struct {
	Text  string
	Bold  bool
	Mono  bool
	Tone  Tone // text colour (and the pill for Badge)
	Badge bool
	Fill  *Color // background
}

// T is a plain text cell.
func T(s string) Cell { return Cell{Text: s} }

// B is a bold cell.
func B(s string) Cell { return Cell{Text: s, Bold: true} }

// M is a monospaced cell.
func M(s string) Cell { return Cell{Text: s, Mono: true} }

// PillCell is a badge cell.
func PillCell(s string, t Tone) Cell { return Cell{Text: s, Tone: t, Badge: true} }

// Table is a table with a header row that is repeated on every page it
// spans.
type Table struct {
	Columns  []Column
	Rows     [][]Cell
	Size     float64 // font size (default 8)
	NoHeader bool
	Zebra    bool
}

type laidCell struct {
	lines [][]byte
	font  Font
	ink   Color
	cell  Cell
}

const cellPad = 3.5

// Table draws t. Rows taller than a page are split across pages; the
// header is drawn again at the top of each new page.
func (d *Doc) Table(t Table) {
	size := t.Size
	if size == 0 {
		size = 8
	}
	lh := size * 1.3
	total := 0.0
	for _, c := range t.Columns {
		w := c.Weight
		if w <= 0 {
			w = 1
		}
		total += w
	}
	widths := make([]float64, len(t.Columns))
	for i, c := range t.Columns {
		w := c.Weight
		if w <= 0 {
			w = 1
		}
		widths[i] = d.ContentWidth() * w / total
	}
	header := make([]laidCell, len(t.Columns))
	headerH := 0.0
	for i, c := range t.Columns {
		header[i] = laidCell{lines: wrap(HelveticaBold, size, widths[i]-2*cellPad, Encode(c.Header)), font: HelveticaBold, ink: White}
		headerH = math.Max(headerH, float64(len(header[i].lines))*lh+2*cellPad)
	}
	drawHeader := func() {
		if t.NoHeader {
			return
		}
		d.Rect(MarginLeft, d.y, d.ContentWidth(), headerH, Navy)
		x := MarginLeft
		for i, hc := range header {
			d.drawLines(x, d.y, widths[i], hc, 0, len(hc.lines), lh, size, t.Columns[i].Align)
			x += widths[i]
		}
		d.y += headerH
	}
	laid := make([][]laidCell, len(t.Rows))
	rowLines := make([]int, len(t.Rows))
	for ri, row := range t.Rows {
		laid[ri], rowLines[ri] = layoutRow(t, row, widths, size)
	}
	// Keep the header with the first row (or as much of it as a page holds).
	first := 1
	if len(rowLines) > 0 {
		first = min(rowLines[0], int((PageHeight-MarginTop-MarginBottom-headerH-2*cellPad)/lh))
	}
	d.Ensure(headerH + float64(first)*lh + 2*cellPad)
	prevHook := d.onNewPage
	d.onNewPage = drawHeader
	drawHeader()
	defer func() { d.onNewPage = prevHook }()

	for ri := range t.Rows {
		cells, maxLines := laid[ri], rowLines[ri]
		var zebra *Color
		if t.Zebra && ri%2 == 1 {
			z := Hex("#F8FAFC")
			zebra = &z
		}
		d.drawRow(cells, maxLines, widths, t.Columns, zebra, headerH, lh, size)
	}
	d.y += 8
}

// layoutRow wraps each cell of a row; it returns the cells and the row's
// line count.
func layoutRow(t Table, row []Cell, widths []float64, size float64) ([]laidCell, int) {
	cells := make([]laidCell, len(t.Columns))
	maxLines := 1
	for i := range t.Columns {
		var c Cell
		if i < len(row) {
			c = row[i]
		}
		f := Helvetica
		if c.Bold {
			f = HelveticaBold
		}
		if c.Mono {
			f = Courier
		}
		ink := Black
		if c.Tone != ToneNone {
			_, ink = ToneColors(c.Tone)
		}
		inner := widths[i] - 2*cellPad
		if c.Badge {
			f = HelveticaBold
			inner -= size // the pill's padding
		}
		text := c.Text
		if text == "" {
			text = "—"
		}
		lc := laidCell{lines: wrap(f, size, inner, Encode(text)), font: f, ink: ink, cell: c}
		cells[i] = lc
		if len(lc.lines) > maxLines {
			maxLines = len(lc.lines)
		}
	}
	return cells, maxLines
}

// drawRow draws one laid-out row: kept together when it fits on a page,
// otherwise split across pages (the page hook repeats the header).
func (d *Doc) drawRow(cells []laidCell, maxLines int, widths []float64, cols []Column, zebra *Color, headerH, lh, size float64) {
	pageLines := int((PageHeight - MarginTop - MarginBottom - headerH - 2*cellPad) / lh)
	for start := 0; start < maxLines; {
		room := int((d.Remaining() - 2*cellPad) / lh)
		if room < 1 || (start == 0 && room < maxLines && maxLines <= pageLines) {
			d.NewPage()
			continue
		}
		n := min(room, maxLines-start)
		h := float64(n)*lh + 2*cellPad
		x := MarginLeft
		for i, lc := range cells {
			fill := zebra
			if lc.cell.Fill != nil {
				fill = lc.cell.Fill
			}
			if fill != nil {
				d.Rect(x, d.y, widths[i], h, *fill)
			}
			if lc.cell.Badge && len(lc.lines) == 1 && start == 0 {
				d.Badge(x+cellPad, d.y+cellPad-1, size, lc.cell.Tone, string(decodeWinAnsi(lc.lines[0])))
			} else {
				d.drawLines(x, d.y, widths[i], lc, start, start+n, lh, size, cols[i].Align)
			}
			x += widths[i]
		}
		d.y += h
		d.Line(MarginLeft, d.y, PageWidth-MarginRight, d.y, 0.4, LightGrey)
		start += n
		if start < maxLines {
			d.NewPage()
		}
	}
}

func (d *Doc) drawLines(x, y, w float64, lc laidCell, from, to int, lh, size float64, al Align) {
	for i := from; i < to && i < len(lc.lines); i++ {
		l := lc.lines[i]
		baseline := y + cellPad + float64(i-from)*lh + size
		tx := x + cellPad
		switch al {
		case Right:
			tx = x + w - cellPad - encWidth(lc.font, size, l)
		case Center:
			tx = x + (w-encWidth(lc.font, size, l))/2
		}
		d.text(tx, baseline, lc.font, size, lc.ink, l)
	}
}

// decodeWinAnsi turns encoded bytes back into a string for Badge (which
// encodes again; WinAnsi round-trips for the bytes Encode produces).
func decodeWinAnsi(b []byte) []rune {
	out := make([]rune, 0, len(b))
	rev := map[byte]rune{}
	for r, c := range winAnsiHigh {
		rev[c] = r
	}
	for _, c := range b {
		if r, ok := rev[c]; ok {
			out = append(out, r)
		} else {
			out = append(out, rune(c))
		}
	}
	return out
}

// KeyValues draws a two-column label / value table without a header.
func (d *Doc) KeyValues(rows [][2]string, labelWeight float64) {
	t := Table{Columns: []Column{{Weight: labelWeight}, {Weight: 1 - labelWeight}}, NoHeader: true, Size: 8.5}
	for _, r := range rows {
		t.Rows = append(t.Rows, []Cell{B(r[0]), T(r[1])})
	}
	d.Table(t)
}
