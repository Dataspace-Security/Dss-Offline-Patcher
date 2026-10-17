package acquire

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// A deliberately small YAML reader for winget manifests (block mappings,
// block sequences, plain/quoted scalars, block scalars, simple flow
// sequences). It returns map[string]any, []any and string values; anything
// it does not understand is an error rather than a guess. Keeping it here
// avoids a YAML dependency in the acquisition tool for one well-defined,
// schema-validated input.

type yLine struct {
	n      int // 1-based line number
	indent int
	text   string
}

const maxYAMLDepth = 32

func parseYAMLMini(src []byte) (any, error) {
	var lines []yLine
	for i, raw := range strings.Split(strings.ReplaceAll(string(src), "\r\n", "\n"), "\n") {
		if i == 0 {
			raw = strings.TrimPrefix(raw, "\ufeff")
		}
		body := strings.TrimLeft(raw, " ")
		if strings.HasPrefix(body, "\t") {
			return nil, fmt.Errorf("line %d: tab indentation", i+1)
		}
		lines = append(lines, yLine{n: i + 1, indent: len(raw) - len(body), text: strings.TrimRight(body, " \t")})
	}
	p := &yParser{lines: lines}
	p.skip()
	if p.i >= len(p.lines) {
		return map[string]any{}, nil
	}
	v, err := p.block(p.lines[p.i].indent, 0)
	if err != nil {
		return nil, err
	}
	p.skip()
	if p.i < len(p.lines) && p.lines[p.i].text != "..." {
		return nil, fmt.Errorf("line %d: unexpected content", p.lines[p.i].n)
	}
	return v, nil
}

type yParser struct {
	lines []yLine
	i     int
}

// skip moves past blank lines, comments, directives and the document start.
func (p *yParser) skip() {
	for p.i < len(p.lines) {
		t := p.lines[p.i].text
		if t == "" || strings.HasPrefix(t, "#") || t == "---" || strings.HasPrefix(t, "%") {
			p.i++
			continue
		}
		return
	}
}

func isSeqItem(t string) bool { return t == "-" || strings.HasPrefix(t, "- ") }

func (p *yParser) block(indent, depth int) (any, error) {
	if depth > maxYAMLDepth {
		return nil, errors.New("manifest nested too deeply")
	}
	if isSeqItem(p.lines[p.i].text) {
		return p.seq(indent, depth)
	}
	return p.mapping(indent, depth)
}

func (p *yParser) mapping(indent, depth int) (map[string]any, error) {
	m := map[string]any{}
	for {
		p.skip()
		if p.i >= len(p.lines) || p.lines[p.i].indent < indent || p.lines[p.i].text == "..." {
			return m, nil
		}
		ln := p.lines[p.i]
		if ln.indent > indent || isSeqItem(ln.text) {
			return nil, fmt.Errorf("line %d: unexpected indentation", ln.n)
		}
		key, rest, ok := splitKey(ln.text)
		if !ok {
			return nil, fmt.Errorf("line %d: expected \"key: value\"", ln.n)
		}
		if _, dup := m[key]; dup {
			return nil, fmt.Errorf("line %d: duplicate key %q", ln.n, key)
		}
		p.i++
		v, err := p.value(rest, indent, depth, ln.n)
		if err != nil {
			return nil, err
		}
		m[key] = v
	}
}

// value parses what follows "key:" (or "- "): an inline scalar, a block
// scalar, or a nested block on the following lines.
func (p *yParser) value(rest string, indent, depth, n int) (any, error) {
	rest = stripComment(rest)
	switch {
	case rest == "":
		p.skip()
		if p.i < len(p.lines) {
			next := p.lines[p.i]
			// A sequence may sit at the same indentation as its key.
			if next.indent > indent || (next.indent == indent && isSeqItem(next.text)) {
				return p.block(next.indent, depth+1)
			}
		}
		return "", nil
	case rest[0] == '|' || rest[0] == '>':
		return p.blockScalar(rest, indent), nil
	case rest[0] == '[':
		return flowSeq(rest, n)
	case rest[0] == '{':
		if rest == "{}" {
			return map[string]any{}, nil
		}
		return nil, fmt.Errorf("line %d: flow mappings are not supported", n)
	case rest[0] == '&' || rest[0] == '*' || rest[0] == '!':
		return nil, fmt.Errorf("line %d: anchors, aliases and tags are not supported", n)
	}
	return scalar(rest, n)
}

func (p *yParser) seq(indent, depth int) ([]any, error) {
	out := []any{}
	for {
		p.skip()
		if p.i >= len(p.lines) || p.lines[p.i].indent < indent || p.lines[p.i].text == "..." {
			return out, nil
		}
		ln := p.lines[p.i]
		if ln.indent > indent {
			return nil, fmt.Errorf("line %d: unexpected indentation", ln.n)
		}
		if !isSeqItem(ln.text) {
			return out, nil // the parent mapping continues ("key:\n- a\nnext: b")
		}
		item := strings.TrimLeft(strings.TrimPrefix(ln.text, "-"), " ")
		col := ln.indent + len(ln.text) - len(item)
		item = stripComment(item)
		if item == "" {
			p.i++
			v, err := p.value("", indent, depth, ln.n)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
			continue
		}
		if _, _, isMap := splitKey(item); isMap || isSeqItem(item) {
			// "- key: v" opens a mapping whose further keys align with "key".
			p.lines[p.i] = yLine{n: ln.n, indent: col, text: item}
			v, err := p.block(col, depth+1)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
			continue
		}
		p.i++
		v, err := p.value(item, indent, depth, ln.n)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
}

func (p *yParser) blockScalar(header string, indent int) string {
	fold := header[0] == '>'
	var parts []string
	for p.i < len(p.lines) {
		ln := p.lines[p.i]
		if ln.text != "" && ln.indent <= indent {
			break
		}
		parts = append(parts, ln.text)
		p.i++
	}
	sep := "\n"
	if fold {
		sep = " "
	}
	return strings.TrimRight(strings.Join(parts, sep), " \n")
}

// splitKey splits "key: rest" (key possibly quoted); ok is false if the
// text is not a mapping entry.
func splitKey(t string) (key, rest string, ok bool) {
	if t == "" {
		return "", "", false
	}
	if t[0] == '"' || t[0] == '\'' {
		end := closingQuote(t)
		if end < 0 || end+1 >= len(t) || t[end+1] != ':' || (end+2 < len(t) && t[end+2] != ' ') {
			return "", "", false
		}
		k, err := scalar(t[:end+1], 0)
		if err != nil {
			return "", "", false
		}
		return k.(string), strings.TrimSpace(t[end+2:]), true
	}
	for i := 0; i < len(t); i++ {
		if t[i] == ':' && (i+1 == len(t) || t[i+1] == ' ') {
			k := strings.TrimSpace(t[:i])
			if k == "" || strings.ContainsAny(k[:1], "-[{#&*!|>%@`") {
				return "", "", false
			}
			return k, strings.TrimSpace(t[i+1:]), true
		}
		if t[i] == ' ' && i+1 < len(t) && t[i+1] == '#' {
			return "", "", false
		}
	}
	return "", "", false
}

// closingQuote returns the index of the quote closing t[0], or -1.
func closingQuote(t string) int {
	q := t[0]
	for i := 1; i < len(t); i++ {
		switch {
		case q == '"' && t[i] == '\\':
			i++
		case t[i] == q && q == '\'' && i+1 < len(t) && t[i+1] == '\'':
			i++
		case t[i] == q:
			return i
		}
	}
	return -1
}

// stripComment removes a trailing " # comment" outside quotes.
func stripComment(t string) string {
	if t == "" {
		return t
	}
	if t[0] == '"' || t[0] == '\'' {
		if end := closingQuote(t); end >= 0 {
			if tail := strings.TrimSpace(t[end+1:]); tail == "" || strings.HasPrefix(tail, "#") {
				return t[:end+1]
			}
		}
		return t
	}
	if strings.HasPrefix(t, "#") {
		return ""
	}
	if i := strings.Index(t, " #"); i >= 0 {
		return strings.TrimSpace(t[:i])
	}
	return t
}

func scalar(t string, n int) (any, error) {
	switch t[0] {
	case '\'':
		if len(t) < 2 || t[len(t)-1] != '\'' {
			return nil, fmt.Errorf("line %d: unterminated quoted string", n)
		}
		return strings.ReplaceAll(t[1:len(t)-1], "''", "'"), nil
	case '"':
		if len(t) < 2 || t[len(t)-1] != '"' {
			return nil, fmt.Errorf("line %d: unterminated quoted string", n)
		}
		s, err := strconv.Unquote(t)
		if err != nil {
			// YAML allows escapes Go does not (\/, \_, \e…): keep the text.
			return strings.ReplaceAll(t[1:len(t)-1], `\"`, `"`), nil
		}
		return s, nil
	}
	if t == "~" || t == "null" || t == "Null" || t == "NULL" {
		return "", nil
	}
	return t, nil
}

func flowSeq(t string, n int) ([]any, error) {
	if !strings.HasSuffix(t, "]") {
		return nil, fmt.Errorf("line %d: multi-line flow sequences are not supported", n)
	}
	inner := strings.TrimSpace(t[1 : len(t)-1])
	out := []any{}
	if inner == "" {
		return out, nil
	}
	for _, part := range strings.Split(inner, ",") {
		part = strings.TrimSpace(part)
		if part == "" || strings.ContainsAny(part[:1], "[{") {
			return nil, fmt.Errorf("line %d: nested flow collections are not supported", n)
		}
		v, err := scalar(part, n)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}
