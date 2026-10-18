package agent

import (
	"bytes"
	"io"
	"os"
	"regexp"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// A failed msiexec run says why only in its verbose log (/l*v). The last
// meaningful lines of that log go into the failure detail, so the operator
// sees "Error 1722 … CustomAction X returned 1603" in the console instead of
// a bare exit code.

const (
	msiLogTailLines = 20
	msiLogTailChars = 1500
	// msiLogReadMax bounds how much of the log is read: the end of a verbose
	// log is a property dump of a few tens of KB; the failure is just before.
	msiLogReadMax  = 256 << 10
	msiLogLineMax  = 240
	msiLogHeader   = "\nmsiexec log (last lines):\n"
	msiLogContext  = 5 // lines kept up to the first failing action
	returnValueBad = "Return value 3"
)

// withMSILog appends the log tail to a failed msiexec result. "Installer
// busy" failures are left alone: their log says nothing useful and the server
// recognises a repeat by its unchanged detail.
func withMSILog(r Result, logPath string) Result {
	if r.State != "failed" || logPath == "" || strings.HasPrefix(r.Detail, retryLater) {
		return r
	}
	tail := msiLogTail(logPath)
	if tail == "" {
		return r
	}
	r.Detail += msiLogHeader + tail
	return r
}

// msiLogTail reads the end of a verbose msiexec log (UTF-16LE or ANSI/UTF-8)
// and returns its last meaningful lines, "" when there is nothing to show.
func msiLogTail(path string) string { return logTailWith(path, msiLogHeader) }

// logTailWith is msiLogTail for any installer log; the tail fits the detail
// budget together with header.
func logTailWith(path, header string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	head := make([]byte, 512)
	n, _ := io.ReadFull(f, head)
	head = head[:n]
	st, err := f.Stat()
	if err != nil {
		return ""
	}
	off := max(st.Size()-msiLogReadMax, 0)
	if off%2 == 1 {
		off++ // UTF-16 code units start at even offsets (after the BOM)
	}
	body := make([]byte, st.Size()-off)
	m, _ := f.ReadAt(body, off)
	return meaningfulTail(decodeLogText(head, body[:m], off == 0), msiLogTailLines, msiLogTailChars-len(header))
}

// decodeLogText decodes body with the encoding detected from the start of
// the file (head). atStart: body begins at offset 0 (strip the BOM).
func decodeLogText(head, body []byte, atStart bool) string {
	switch {
	case bytes.HasPrefix(head, []byte{0xFF, 0xFE}) || looksUTF16LE(head):
		if atStart && bytes.HasPrefix(body, []byte{0xFF, 0xFE}) {
			body = body[2:]
		}
		u := make([]uint16, len(body)/2)
		for i := range u {
			u[i] = uint16(body[2*i]) | uint16(body[2*i+1])<<8
		}
		return string(utf16.Decode(u))
	case atStart && bytes.HasPrefix(body, []byte{0xEF, 0xBB, 0xBF}):
		body = body[3:]
	}
	if utf8.Valid(body) {
		return string(body)
	}
	// ANSI code page: keep the ASCII text, mark the rest.
	return strings.ToValidUTF8(string(body), "?")
}

// looksUTF16LE: ASCII text in UTF-16LE has a zero byte at every odd offset.
func looksUTF16LE(b []byte) bool {
	pairs, zeros := len(b)/2, 0
	if pairs < 4 {
		return false
	}
	for i := 1; i < len(b); i += 2 {
		if b[i] == 0 {
			zeros++
		}
	}
	return zeros*10 >= pairs*8
}

var (
	// "MSI (s) (2C:30) [12:34:56:789]: " carries no information for the reader.
	msiLinePrefix = regexp.MustCompile(`^MSI \([a-zA-Z]\) \([0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}\) \[[0-9:]+\]: `)
	// Harmless notes every log is full of (table or stream not present).
	msiNoise = regexp.MustCompile(`^Note: 1: (2205|2228|2262) `)
)

// meaningfulLines drops what never explains a failure: blank lines, the
// property dumps, logging banners, property changes and table-missing notes.
func meaningfulLines(text string) []string {
	var out []string
	for _, l := range strings.Split(text, "\n") {
		l = strings.TrimSpace(strings.TrimRight(l, "\r\x00"))
		l = msiLinePrefix.ReplaceAllString(l, "")
		switch {
		case l == "",
			strings.HasPrefix(l, "Property(") && strings.Contains(l, "):"),
			strings.HasPrefix(l, "=== "),
			strings.HasPrefix(l, "PROPERTY CHANGE:"),
			msiNoise.MatchString(l):
			continue
		}
		if utf8.RuneCountInString(l) > msiLogLineMax {
			l = string([]rune(l)[:msiLogLineMax]) + "…"
		}
		out = append(out, l)
	}
	return out
}

// meaningfulTail returns the last maxLines meaningful lines in at most
// maxChars bytes (bytes, so the server's detail limit always holds). When
// the first failing action ("Return value 3") is earlier than that window,
// the few lines leading to it come first: that is usually the cause, the
// rest is the installer unwinding.
func meaningfulTail(text string, maxLines, maxChars int) string {
	lines := meaningfulLines(text)
	if len(lines) == 0 || maxLines <= 0 || maxChars <= 0 {
		return ""
	}
	start := max(len(lines)-maxLines, 0)
	tail := lines[start:]
	var lead []string
	for i, l := range lines[:start] {
		if strings.Contains(l, returnValueBad) {
			lead = append(lead, lines[max(i+1-msiLogContext, 0):i+1]...)
			lead = append(lead, "…")
			keep := max(maxLines-len(lead), 1)
			tail = lines[len(lines)-keep:]
			break
		}
	}
	size := func() int { return joinedLen(lead) + joinedLen(tail) + boolInt(len(lead) > 0 && len(tail) > 0) }
	for size() > maxChars && len(tail) > 1 {
		tail = tail[1:]
	}
	for size() > maxChars && len(lead) > 0 {
		lead = lead[1:]
	}
	out := strings.Join(append(append([]string{}, lead...), tail...), "\n")
	if len(out) > maxChars { // one very long line: keep its end
		out = out[len(out)-maxChars:]
		for len(out) > 0 && !utf8.RuneStart(out[0]) {
			out = out[1:]
		}
	}
	return out
}

func joinedLen(ls []string) int {
	n := max(len(ls)-1, 0)
	for _, l := range ls {
		n += len(l)
	}
	return n
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
