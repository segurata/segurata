package redact

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/segurata/segurata/connectors/localsecrets"
)

// finder returns the secrets in scope in a piece of text.
type finder func(text string) []localsecrets.Hit

// memo caches find per text: rewriting a line searches unchanged texts again.
func (find finder) memo() finder {
	seen := map[string][]localsecrets.Hit{}
	return func(text string) []localsecrets.Hit {
		if hs, ok := seen[text]; ok {
			return hs
		}
		hs := find(text)
		seen[text] = hs
		return hs
	}
}

// tag names the secret's type and fingerprint prefix, so the redacted copy points at its rotation
// item.
func tag(h localsecrets.Hit) string {
	fp := h.Fingerprint
	if len(fp) > 8 {
		fp = fp[:8]
	}
	return "[REDACTED:" + h.Type + ":" + fp + "]"
}

type result struct {
	out     []byte
	applied []localsecrets.Hit // the secrets replaced; their offsets refer to the text they were found in
	bytes   int                // bytes of secret text replaced
	residue int                // secrets found that could not be replaced without breaking JSON
}

var errBrokeJSON = errors.New("the replacement would break its JSON")

// rewrite replaces the secrets on the given lines (1-based, ascending) of raw, keeping every other
// byte. Valid JSON, a line or the whole file, stays valid.
func rewrite(raw []byte, lines []int, find finder) (result, error) {
	var res result
	var b bytes.Buffer
	copied, pos, n := 0, 0, 1
	for _, want := range lines {
		for n < want && pos <= len(raw) {
			i := bytes.IndexByte(raw[pos:], '\n')
			if i < 0 {
				pos = len(raw) + 1
				break
			}
			pos += i + 1
			n++
		}
		if n != want || pos > len(raw) {
			break // the file is shorter than ripgrep said: it changed, and the caller will see it
		}
		end := len(raw)
		if i := bytes.IndexByte(raw[pos:], '\n'); i >= 0 {
			end = pos + i
		}
		out, err := rewriteLine(string(raw[pos:end]), find, &res)
		if err != nil {
			return result{}, fmt.Errorf("line %d: %w", n, err)
		}
		b.Write(raw[copied:pos])
		b.WriteString(out)
		copied = end
	}
	b.Write(raw[copied:])
	res.out = b.Bytes()
	if len(res.applied) > 0 && json.Valid(raw) && !json.Valid(res.out) {
		return result{}, errBrokeJSON
	}
	return res, nil
}

// rewriteLine replaces the secrets of one line. A plain line is spliced where each secret stands.
// A JSON line is edited inside its strings, first in the raw bytes, then in the decoded value of
// each string holding escapes, re-encoding only that string so field order is kept.
func rewriteLine(line string, find finder, res *result) (string, error) {
	find = find.memo()
	t := strings.TrimSpace(line)
	isJSON := t != "" && (t[0] == '{' || t[0] == '[') && json.Valid([]byte(line))
	if !isJSON {
		out := splice(line, find(line), res)
		res.residue += len(find(out))
		return out, nil
	}
	out, err := rewriteRaw(line, find, res)
	if err != nil {
		return "", err
	}
	applied := len(res.applied)
	out, err = rewriteEscaped(out, find, res)
	if err != nil {
		return "", err
	}
	if !json.Valid([]byte(out)) {
		return "", errBrokeJSON
	}
	// A second escaped pass counts what the first left; it finds more only if the first changed the line.
	var probe result
	if len(res.applied) > applied {
		if _, err := rewriteEscaped(out, find, &probe); err != nil {
			return "", err
		}
	}
	res.residue += len(find(out)) + len(probe.applied)
	return out, nil
}

// rewriteRaw replaces the secrets that stand byte for byte inside one JSON string of the line, when
// the text before, the match and the text after are each whole string content (no escape cut).
func rewriteRaw(line string, find finder, res *result) (string, error) {
	hs := find(line)
	if len(hs) == 0 {
		return line, nil
	}
	spans, err := stringSpans(line)
	if err != nil {
		return "", err
	}
	var ok []localsecrets.Hit
	k := 0
	for _, h := range hs {
		for k < len(spans) && spans[k][1] <= h.Start {
			k++
		}
		if k == len(spans) {
			break
		}
		s, e := spans[k][0]+1, spans[k][1]-1 // the content, between the quotes
		if h.Start >= s && h.End <= e && wholeContent(line[s:h.Start]) && wholeContent(line[h.Start:h.End]) && wholeContent(line[h.End:e]) {
			ok = append(ok, h)
		}
	}
	return splice(line, ok, res), nil
}

// wholeContent is json.Valid of s between quotes, without copying s.
func wholeContent(s string) bool {
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == '"' || c < 0x20:
			return false
		case c == '\\':
			if i+1 == len(s) {
				return false
			}
			switch s[i+1] {
			case '"', '\\', '/', 'b', 'f', 'n', 'r', 't':
				i++
			case 'u':
				if i+6 > len(s) || !isHex(s[i+2]) || !isHex(s[i+3]) || !isHex(s[i+4]) || !isHex(s[i+5]) {
					return false
				}
				i += 5
			default:
				return false
			}
		}
	}
	return true
}

func isHex(c byte) bool { return '0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F' }

// rewriteEscaped replaces secrets in the decoded value of each JSON string holding an escape; a
// string without one is its raw bytes, which rewriteRaw handled.
func rewriteEscaped(line string, find finder, res *result) (string, error) {
	spans, err := stringSpans(line)
	if err != nil {
		return "", err
	}
	for i := len(spans) - 1; i >= 0; i-- {
		s, e := spans[i][0], spans[i][1]
		if !strings.Contains(line[s:e], `\`) {
			continue
		}
		var v string
		if err := json.Unmarshal([]byte(line[s:e]), &v); err != nil {
			return "", err
		}
		hs := find(v)
		if len(hs) == 0 {
			continue
		}
		enc, err := encodeString(splice(v, hs, res))
		if err != nil {
			return "", err
		}
		line = line[:s] + enc + line[e:]
	}
	return line, nil
}

// stringSpans returns the span of every string token of valid JSON: outside strings no quote
// appears, so each quote opens a token that runs to the next unescaped quote.
func stringSpans(line string) ([][2]int, error) {
	var spans [][2]int
	for i := 0; i < len(line); i++ {
		if line[i] != '"' {
			continue
		}
		start := i
		for i++; i < len(line) && line[i] != '"'; i++ {
			if line[i] == '\\' {
				i++
			}
		}
		if i >= len(line) {
			return nil, errors.New("unterminated JSON string")
		}
		spans = append(spans, [2]int{start, i + 1})
	}
	return spans, nil
}

func encodeString(s string) (string, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(s); err != nil {
		return "", err
	}
	return strings.TrimSuffix(b.String(), "\n"), nil
}

// splice replaces each hit (ascending, not overlapping) with its tag.
func splice(text string, hs []localsecrets.Hit, res *result) string {
	if len(hs) == 0 {
		return text
	}
	var b strings.Builder
	last := 0
	for _, h := range hs {
		b.WriteString(text[last:h.Start])
		b.WriteString(tag(h))
		last = h.End
		res.applied = append(res.applied, h)
		res.bytes += h.End - h.Start
	}
	b.WriteString(text[last:])
	return b.String()
}
