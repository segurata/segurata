package redact

import (
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"strings"
	"testing"

	"github.com/segurata/segurata/connectors/localsecrets"
	"github.com/segurata/segurata/internal/testcorpus"
)

// literalFinder finds every occurrence of the given values, standing in for local-secrets.
func literalFinder(values ...string) finder {
	return func(text string) []localsecrets.Hit {
		var hs []localsecrets.Hit
		for i := 0; i < len(text); {
			best, bestV := -1, ""
			for _, v := range values {
				if j := strings.Index(text[i:], v); j >= 0 && (best < 0 || j < best) {
					best, bestV = j, v
				}
			}
			if best < 0 {
				break
			}
			s := i + best
			hs = append(hs, localsecrets.Hit{Start: s, End: s + len(bestV), Type: "t", Fingerprint: "0123456789abcdef"})
			i = s + len(bestV)
		}
		return hs
	}
}

func TestStringSpans(t *testing.T) {
	line := `{"a" : "x\"y", "b":[1,"z",{"c":null}], "d":true}`
	spans, err := stringSpans(line)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, s := range spans {
		got = append(got, line[s[0]:s[1]])
	}
	if want := []string{`"a"`, `"x\"y"`, `"b"`, `"z"`, `"c"`, `"d"`}; strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("spans %q, want %q", got, want)
	}
}

func TestEscapedSecretIsReplacedInsideTheDecodedString(t *testing.T) {
	secret := fake("tok", 30)
	// The raw line spells one character of the secret as a \u escape, so it is not a substring.
	esc := secret[:10] + `\u00` + strings.ToLower(hex2(secret[10])) + secret[11:]
	line := `{"z":1,"m":"a\tb ` + esc + ` <c>","k":"plain"}`
	if !json.Valid([]byte(line)) {
		t.Fatal("bad fixture")
	}
	var res result
	out, err := rewriteLine(line, literalFinder(secret), &res)
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"z":1,"m":"a\tb [REDACTED:t:01234567] <c>","k":"plain"}`; out != want {
		t.Errorf("got  %s\nwant %s", out, want)
	}
	if len(res.applied) != 1 || res.residue != 0 {
		t.Errorf("applied %d residue %d", len(res.applied), res.residue)
	}
}

func hex2(b byte) string {
	const h = "0123456789abcdef"
	return string([]byte{h[b>>4], h[b&15]})
}

func TestPlainLineKeepsEveryOtherByte(t *testing.T) {
	secret := fake("", 30)
	raw := []byte(": 1:0;a\n: 2:0;b " + secret + " c\r\nlast " + secret)
	res, err := rewrite(raw, []int{2, 3}, literalFinder(secret))
	if err != nil {
		t.Fatal(err)
	}
	want := ": 1:0;a\n: 2:0;b [REDACTED:t:01234567] c\r\nlast [REDACTED:t:01234567]"
	if string(res.out) != want || len(res.applied) != 2 || res.bytes != 60 {
		t.Errorf("got %q applied %d bytes %d", res.out, len(res.applied), res.bytes)
	}
}

func TestRewriteToleratesAShorterFile(t *testing.T) {
	res, err := rewrite([]byte("one\n"), []int{5}, literalFinder("x"))
	if err != nil || string(res.out) != "one\n" {
		t.Errorf("got %q, %v", res.out, err)
	}
}

func TestSecretAcrossJSONStructureIsResidue(t *testing.T) {
	// A "secret" spanning a quote cannot be replaced without breaking the line: it stays and is
	// counted, and the line is still valid.
	line := `{"a":"xx","b":"yy"}`
	var res result
	out, err := rewriteLine(line, literalFinder(`xx","b":"yy`), &res)
	if err != nil {
		t.Fatal(err)
	}
	if out != line || res.residue != 1 || len(res.applied) != 0 {
		t.Errorf("out %s residue %d applied %d", out, res.residue, len(res.applied))
	}
}

func TestWholeJSONFileStaysValid(t *testing.T) {
	secret := fake("", 30)
	raw := []byte("{\n  \"k\": \"" + secret + "\"\n}\n")
	res, err := rewrite(raw, []int{2}, literalFinder(secret))
	if err != nil || !json.Valid(res.out) {
		t.Fatalf("got %q, %v", res.out, err)
	}
	if _, err := rewrite(raw, []int{2}, literalFinder(`"`+secret)); err != errBrokeJSON {
		t.Errorf("a replacement eating a quote: %v", err)
	}
}

// The hand-written JSON scanners must agree with encoding/json: wholeContent with json.Valid of
// the text between quotes, stringSpans with the string tokens json.Decoder reads.

func decoderSpans(line string) [][2]int {
	dec := json.NewDecoder(strings.NewReader(line))
	var spans [][2]int
	for {
		prev := int(dec.InputOffset())
		tok, err := dec.Token()
		if err != nil {
			return spans
		}
		if _, ok := tok.(string); ok {
			end := int(dec.InputOffset())
			spans = append(spans, [2]int{prev + strings.IndexByte(line[prev:end], '"'), end})
		}
	}
}

func jsonCorpus() []string {
	r := rand.New(rand.NewPCG(4, 4))
	pool := testcorpus.Secrets(r)
	var out []string
	for _, s := range testcorpus.ShortLines(r, pool) {
		enc, _ := json.Marshal(map[string]any{"k": s, "n": []any{1, s, map[string]any{"x\"y": s}, nil, true}, "e": ""})
		out = append(out, string(enc))
	}
	out = append(out, testcorpus.Line(r, 200_000, 8, pool), `[]`, `{}`, `[ "a" , {"b" : "\"\\"} ]`)
	return out
}

func TestStringSpansAgreesWithTheDecoder(t *testing.T) {
	for _, line := range jsonCorpus() {
		got, err := stringSpans(line)
		if err != nil {
			t.Fatal(err)
		}
		if want := decoderSpans(line); fmt.Sprint(got) != fmt.Sprint(want) {
			t.Errorf("%.80q: %v, decoder %v", line, got, want)
		}
	}
}

func wholeContentSamples() []string {
	out := []string{"", `\`, `\\`, `\"`, `"`, `a"b`, "\x1f", "\x7f", "\xff\xfe", `\u`, `\u12`, `\u12g4`, `ኯ`, `\x`,
		`\/`, `\b\f\n\r\t`, `abc\`, `\\\`, "é", `\ud800`}
	for _, line := range jsonCorpus() {
		for i := 0; i+40 <= len(line) && i < 4000; i += 7 {
			out = append(out, line[i:i+40], line[i:i+3])
		}
	}
	return out
}

func TestWholeContentAgreesWithJSONValid(t *testing.T) {
	for _, s := range wholeContentSamples() {
		if got, want := wholeContent(s), json.Valid([]byte(`"`+s+`"`)); got != want {
			t.Errorf("%q: %v, json.Valid %v", s, got, want)
		}
	}
}

func FuzzWholeContent(f *testing.F) {
	for _, s := range wholeContentSamples() {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if got, want := wholeContent(s), json.Valid([]byte(`"`+s+`"`)); got != want {
			t.Fatalf("%q: %v, json.Valid %v", s, got, want)
		}
	})
}

func FuzzStringSpans(f *testing.F) {
	for _, s := range jsonCorpus()[:50] {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if !json.Valid([]byte(s)) {
			return
		}
		got, err := stringSpans(s)
		if err != nil {
			t.Fatal(err)
		}
		if want := decoderSpans(s); fmt.Sprint(got) != fmt.Sprint(want) {
			t.Fatalf("%q: %v, decoder %v", s, got, want)
		}
	})
}
