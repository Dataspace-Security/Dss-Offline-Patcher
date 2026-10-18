package pdf

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
	"time"
)

func sampleDoc(t *testing.T, rows int) []byte {
	t.Helper()
	d := New(Info{Title: "Test report — ü", Subject: "unit test", Created: time.Date(2026, 10, 18, 9, 30, 0, 0, time.FixedZone("IST", 5*3600+1800))}, "DSS Patcher · TR-1")
	d.Logo(MarginLeft, MarginTop, 40, Navy)
	d.SetY(MarginTop + 50)
	d.Heading(1, "1. Executive summary")
	d.Paragraph("Plain paragraph with (parentheses), a backslash \\ and Unicode: café, “quotes”, → arrow, ✓ tick, 漢 unknown.", Body)
	d.Rich([]Run{{Text: "Bold label:", Bold: true}, {Text: " then text and "}, {Text: "mono", Mono: true}}, Body)
	d.Callout([]Run{{Text: "Important:", Bold: true}, {Text: " " + strings.Repeat("disclaimer text ", 30)}}, ToneAmber)
	d.Bullets([]string{"first item", "second item " + strings.Repeat("long ", 40)}, Body)
	tb := Table{Columns: []Column{{Header: "Endpoint", Weight: 2}, {Header: "Status", Weight: 1}, {Header: "Count", Weight: 1, Align: Right}}, Zebra: true}
	for i := range rows {
		tb.Rows = append(tb.Rows, []Cell{T(fmt.Sprintf("pc-%04d %s", i, strings.Repeat("x", i%7))), PillCell("Compliant", ToneGreen), T(fmt.Sprint(i))})
	}
	tb.Rows = append(tb.Rows, []Cell{T(strings.Repeat("a very tall cell ", 600)), PillCell("Non-compliant", ToneRed), T("1")})
	d.Heading(2, "Endpoints")
	d.Table(tb)
	b, err := d.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestStructure(t *testing.T) {
	b := sampleDoc(t, 150)
	n, err := Check(b)
	if err != nil {
		t.Fatal(err)
	}
	texts, err := PageTexts(b)
	if err != nil {
		t.Fatal(err)
	}
	pages := len(texts)
	if pages < 4 {
		t.Fatalf("pages: %d", pages)
	}
	if n != 6+2*pages {
		t.Fatalf("objects: %d for %d pages", n, pages)
	}
	if !bytes.Contains(b, []byte(fmt.Sprintf("/Type /Pages /Kids ["))) || !bytes.Contains(b, []byte(fmt.Sprintf("/Count %d >>", pages))) {
		t.Fatal("page tree count")
	}
	for _, f := range []string{"/BaseFont /Helvetica /Encoding /WinAnsiEncoding", "/BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding", "/BaseFont /Courier /Encoding /WinAnsiEncoding"} {
		if !bytes.Contains(b, []byte(f)) {
			t.Errorf("font not declared: %s", f)
		}
	}
	if !bytes.Contains(b, []byte("/CreationDate (D:20261018093000+05'30')")) || !bytes.Contains(b, []byte("/Title <FEFF")) || !bytes.Contains(b, []byte("/Author <FEFF00440053005300200050006100740063006800650072>")) {
		t.Fatalf("info: %s", b[bytes.Index(b, []byte("6 0 obj")):][:400])
	}
	if bytes.Contains(b, []byte("BT /F1")) {
		t.Fatal("content streams are not compressed")
	}
	all := strings.Join(texts[0], " ")
	for _, want := range []string{"1. Executive summary", "Plain paragraph with (parentheses), a backslash \\ and Unicode: café, “quotes”, -> arrow, v tick, ? unknown.", "Bold label:", "mono", "Important:"} {
		if !strings.Contains(all, want) {
			t.Errorf("page 1 text missing %q", want)
		}
	}
	// Footer on every page, with the total.
	for i, p := range texts {
		want := fmt.Sprintf("DSS Patcher · TR-1 · page %d of %d", i+1, pages)
		if p[len(p)-1] != want {
			t.Errorf("page %d footer: %q", i+1, p[len(p)-1])
		}
	}
}

// The table header is repeated at the top of every page the table spans,
// including the pages of a row split because it is taller than a page.
func TestTableHeaderRepeats(t *testing.T) {
	texts, err := PageTexts(sampleDoc(t, 150))
	if err != nil {
		t.Fatal(err)
	}
	tablePages := 0
	for i, p := range texts {
		rows := 0
		for _, s := range p {
			if strings.HasPrefix(s, "pc-") || strings.HasPrefix(s, "a very tall cell") {
				rows++
			}
		}
		if rows == 0 {
			continue
		}
		tablePages++
		hdr := strings.Join(p, "|")
		if !strings.Contains(hdr, "Endpoint|Status|Count") {
			t.Errorf("page %d has table rows but no header: %v", i+1, p[:min(6, len(p))])
		}
	}
	if tablePages < 3 {
		t.Fatalf("table spans %d pages", tablePages)
	}
	// Every row is there exactly once, in order.
	var got []string
	for _, p := range texts {
		for _, s := range p {
			if strings.HasPrefix(s, "pc-") {
				got = append(got, s[:7])
			}
		}
	}
	if len(got) != 150 || got[0] != "pc-0000" || got[149] != "pc-0149" {
		t.Fatalf("rows: %d %v", len(got), got[:3])
	}
}

func TestEncodeAndWrap(t *testing.T) {
	if got := Encode("a→b ≥ 1 – “x” €"); string(got) != "a->b >= 1 \x96 \x93x\x94 \x80" {
		t.Fatalf("encode: %q", got)
	}
	if got := escape([]byte("(a)\\\x96")); got != `\(a\)\\\226` {
		t.Fatalf("escape: %s", got)
	}
	lines := wrap(Helvetica, 10, 100, Encode("one two three four five six seven eight nine ten "+strings.Repeat("W", 40)))
	for _, l := range lines {
		if w := encWidth(Helvetica, 10, l); w > 100.01 {
			t.Errorf("line %q is %.1f wide", l, w)
		}
	}
	if len(lines) < 5 {
		t.Fatalf("lines: %q", lines)
	}
	if w := TextWidth(Helvetica, 10, "Hello"); w < 22 || w > 24 { // 722+556+222+222+556 = 2278
		t.Fatalf("width: %.2f", w)
	}
}
