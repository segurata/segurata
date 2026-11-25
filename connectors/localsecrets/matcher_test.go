package localsecrets

import (
	"math/rand/v2"
	"reflect"
	"regexp/syntax"
	"strings"
	"testing"

	"github.com/segurata/segurata/internal/testcorpus"
)

// The matcher must give exactly the matches of the plain alternation: same spans, so Find gives
// the same hits (type, fingerprint, offsets).

func reference(ps []pattern) func(string) [][]int {
	re := combined(ps)
	return func(s string) [][]int { return re.FindAllStringIndex(s, -1) }
}

// trickyLines are hand-made edge cases: anchors at the very start and end, word boundaries,
// matches that touch or overlap, long runs before a keyword, and the two non-ASCII runes that
// case folding maps onto ASCII letters.
func trickyLines(r *rand.Rand) []string {
	f := func(prefix string, n int) string { return testcorpus.Fake(r, prefix, n, testcorpus.Alnum) }
	return []string{
		"", "s", "sk-", "://", "a://b:c@d", "x" + f("sk-ant-", 40), f("sk-ant-", 40) + "x",
		"_" + f("ghp_", 36), "-" + f("ghp_", 36), "é" + f("ghp_", 36), f("ghp_", 36) + "é",
		f("sk-", 20) + "T3BlbkFJ" + f("", 20), "zz" + f("sk-", 20) + "T3BlbkFJ" + f("", 20),
		"1234567890:AA" + f("", 33), "12345678901:AA" + f("", 33), "123:AA" + f("", 33),
		strings.Repeat("a", 3000) + "_token=" + f("", 20), strings.Repeat("a.b-c_", 500) + "secret: " + f("", 20),
		"MY_API_KEY=" + f("", 20) + " OTHER_SECRET=" + f("", 20) + " password=" + f("", 20),
		"token token token token=" + f("", 20), "x-secret-y-token-z-key=" + f("", 20),
		"AWS_SECRET_ACCESS_KEY=" + f("", 40), "aws_ſecret_access_key=" + f("", 40), "awſ_secret_access_key: " + f("", 40),
		"CF_API_TOKEN=" + f("", 40), "cloudflare_token=" + f("", 38), "CLOUDFLARE_API_\u212aEY=" + f("", 40),
		"https://x.example/?token=" + f("", 20), "https://x.example/?Access_Token=" + f("", 20) + "&key=" + f("", 20),
		"user@" + f("sk-proj-", 50), "postgres://u:" + f("", 10) + "@h https://" + f("", 32) + "@o.sentry.io/1",
		"ab://" + f("", 4) + ":" + f("", 8) + "@host", strings.Repeat("z", 25) + "://u:" + f("", 8) + "@host",
		`{"type":"service_account","private_key":"-----BEGIN PRIVATE KEY-----\nMIIE` + f("", 60) + `\n-----END PRIVATE KEY-----\n"}`,
		`"refresh_token" :  "` + f("", 30) + `", "client_secret":"` + f("", 12) + `"`,
		"sb_secret_" + f("", 30) + " sbp_" + testcorpus.Fake(r, "", 40, testcorpus.Hex), "secret_" + f("", 43) + " ntn_" + f("", 40),
		f("eyJ", 20) + "." + f("eyJ", 20) + "." + f("", 20), f("sk-", 40) + f("sk-", 40),
		"password " + f("", 10), "\x80\xff" + f("sk-ant-", 40) + "\xc3", "ſ" + f("ghp_", 36), "K" + "_TOKEN=" + f("", 20),
	}
}

func corpusFor(r *rand.Rand) []string {
	pool := testcorpus.Secrets(r)
	lines := append(testcorpus.ShortLines(r, pool), trickyLines(r)...)
	for i := range 3 {
		lines = append(lines, testcorpus.Line(r, 100_000+i*50_000, 12, pool))
	}
	return lines
}

func TestMatcherAgreesWithAlternation(t *testing.T) {
	r := rand.New(rand.NewPCG(5, 8))
	lines := corpusFor(r)
	for _, ps := range [][]pattern{specific, withAssignment} {
		m, ref := newMatcher(ps), reference(ps)
		total := 0
		for _, l := range lines {
			got, want := m.findAll(l), ref(l)
			total += len(want)
			if !reflect.DeepEqual(got, want) {
				t.Errorf("%d patterns, line %.80q…: matcher %v, alternation %v", len(ps), l, got, want)
			}
		}
		if total < 500 {
			t.Fatalf("corpus too thin: %d matches", total)
		}
	}
}

// TestFindIsUnchanged compares Find's hits, (type, fingerprint, offsets), with the matcher and with
// the plain alternation, for every kind of trail.
func TestFindIsUnchanged(t *testing.T) {
	r := rand.New(rand.NewPCG(9, 4))
	text := strings.Join(corpusFor(r), "\n")
	tr := testTrails()
	for _, path := range corpusPaths {
		kind := tr.s.kindOf(path)
		got := tr.Find(path, "600", text)
		want := tr.find(path, "600", text, reference(patternsFor(kind)))
		if len(want) < 100 {
			t.Fatalf("%s: corpus too thin: %d hits", path, len(want))
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s: %d hits with the matcher, %d with the alternation", path, len(got), len(want))
		}
	}
}

func TestEveryPatternIsPlaceable(t *testing.T) {
	for _, ps := range [][]pattern{specific, withAssignment} {
		m := newMatcher(ps)
		for i, a := range m.anchors {
			if !a.placeable() {
				t.Errorf("%s has no bounded anchor: every text holding it would go through the alternation", ps[i].typ)
			}
			// matchAt relies on it: a pattern that could match nothing would match before any anchor.
			if re, _ := syntax.Parse(ps[i].src, syntax.Perl); re == nil {
				t.Errorf("%s does not parse", ps[i].typ)
			} else if lo, _ := lenBounds(re); lo == 0 {
				t.Errorf("%s can match the empty string", ps[i].typ)
			}
		}
	}
}

func FuzzMatcherAgreesWithAlternation(f *testing.F) {
	r := rand.New(rand.NewPCG(2, 3))
	for _, l := range append(testcorpus.ShortLines(r, testcorpus.Secrets(r)), trickyLines(r)...) {
		f.Add(l)
	}
	ms := []*matcher{newMatcher(specific), newMatcher(withAssignment)}
	refs := []func(string) [][]int{reference(specific), reference(withAssignment)}
	f.Fuzz(func(t *testing.T, s string) {
		for i, m := range ms {
			if got, want := m.findAll(s), refs[i](s); !reflect.DeepEqual(got, want) {
				t.Fatalf("%q: matcher %v, alternation %v", s, got, want)
			}
		}
	})
}
