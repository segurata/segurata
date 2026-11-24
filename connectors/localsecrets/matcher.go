package localsecrets

import (
	"cmp"
	"regexp"
	"regexp/syntax"
	"slices"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"
)

// matcher finds the matches of a list of patterns joined into one leftmost-first alternation
// (combined), as regexp.FindAllStringIndex would, without running that alternation over the whole
// text. Go's regexp has no DFA: the 55-way alternation runs at about 2 MB/s, and transcript lines
// are megabytes long.
//
// Each pattern gets an anchor, derived from its syntax tree: a set of literals one of which every
// match contains, at a bounded byte offset from the match start ("sk-ant-" at 0, "://" at 2..21
// for URL credentials). One pass over the text finds the anchors; each occurrence yields the few
// positions where that pattern could start, and the pattern is tried there alone, anchored. Taking
// the candidates in order, and at each position the patterns in list order, is exactly what the
// alternation does: the leftmost start wins, among patterns starting there the first, and the scan
// goes on after the match. A pattern whose anchor is unbounded (the generic assignment) or missing
// sends the text to the alternation, restricted to the patterns whose literals occur in it; a
// pattern none of whose literals occur cannot match and is left out. Both paths give the
// alternation's result.
type matcher struct {
	all     *regexp.Regexp
	ps      []pattern
	anchors []anchor
	needles []needle
	one     [256][]int32 // one-byte needles by lowered byte
	twoBits [1 << 16 / 64]uint64
	two     map[uint16][]int32 // longer needles by their lowered first two bytes
	fold    bool               // some anchor is case-insensitive
	subsets sync.Map           // uint64 pattern mask -> *regexp.Regexp
}

// anchor is what the matcher knows about one pattern.
type anchor struct {
	lits       []string // every match contains one of them (lowercased when fold); nil when unknown
	fold       bool
	dmin, dmax int // byte offset range of the literal from the match start; dmax < 0 when unbounded
	// back, when set, is a byte class the match may start with any run of, before that offset:
	// the name in `NAME_TOKEN=…`.
	back *[256]bool
	// at is the pattern anchored at the start of the text, without its leading \b (checked by
	// hand, as it looks at the byte before); nil when the pattern cannot be tried at a position.
	at        *regexp.Regexp
	wordStart bool
}

// placeable reports whether the pattern can be tried at the positions its anchor gives.
func (a *anchor) placeable() bool { return a.lits != nil && a.dmax >= 0 && a.at != nil }

type needle struct {
	lit  string
	fold bool
	refs []int // patterns anchored on it
}

const maxExact = 64 // largest literal set kept for one anchor

func newMatcher(ps []pattern) *matcher {
	if len(ps) > 64 {
		panic("matcher: more than 64 patterns")
	}
	m := &matcher{all: combined(ps), ps: ps, anchors: make([]anchor, len(ps)), two: map[uint16][]int32{}}
	ids := map[string]int{}
	for i, p := range ps {
		a := anchorOf(p.src)
		m.anchors[i] = a
		m.fold = m.fold || a.fold
		for _, l := range a.lits {
			key := l
			if a.fold {
				key = "i:" + l
			}
			id, ok := ids[key]
			if !ok {
				id = len(m.needles)
				ids[key] = id
				m.needles = append(m.needles, needle{lit: l, fold: a.fold})
				if len(l) == 1 {
					m.one[lower[l[0]]] = append(m.one[lower[l[0]]], int32(id))
				} else {
					k := uint16(lower[l[0]])<<8 | uint16(lower[l[1]])
					m.twoBits[k/64] |= 1 << (k % 64)
					m.two[k] = append(m.two[k], int32(id))
				}
			}
			m.needles[id].refs = append(m.needles[id].refs, i)
		}
	}
	return m
}

var lower = func() (t [256]byte) {
	for i := range t {
		t[i] = byte(i)
		if 'A' <= i && i <= 'Z' {
			t[i] = byte(i + 'a' - 'A')
		}
	}
	return t
}()

// foldsToASCII are the only non-ASCII runes that case folding maps onto ASCII letters: the long s
// (U+017F, folds to s) and the Kelvin sign (U+212A, folds to k). A case-insensitive pattern can
// match them; the lowered-ASCII anchor search cannot see them.
var foldsToASCII = []string{"\u017f", "\u212a"}

type cand struct{ pos, pat int }

// findAll returns the alternation's matches in text, as FindAllStringIndex(text, -1) would.
func (m *matcher) findAll(text string) [][]int {
	var present uint64
	var cands []cand
	walked := map[int][2]int{} // per pattern with a back class, the last run walked
	m.scan(text, func(id, pos int) {
		for _, i := range m.needles[id].refs {
			present |= 1 << i
			a := &m.anchors[i]
			if !a.placeable() {
				continue
			}
			for e := pos - a.dmin; e >= max(pos-a.dmax, 0); e-- {
				cands = append(cands, cand{e, i})
				if a.back != nil {
					cands = m.walkBack(cands, text, e, i, walked)
				}
			}
		}
	})
	foldRisk := m.fold && (strings.Contains(text, foldsToASCII[0]) || strings.Contains(text, foldsToASCII[1]))
	general := false
	for i := range m.anchors {
		a := &m.anchors[i]
		switch {
		case a.lits == nil || (a.fold && foldRisk):
			present |= 1 << i
			general = true
		case present&(1<<i) != 0 && !a.placeable():
			general = true
		}
	}
	if present == 0 {
		return nil
	}
	if general {
		return m.subset(present).FindAllStringIndex(text, -1)
	}
	slices.SortFunc(cands, func(x, y cand) int { return cmp.Or(cmp.Compare(x.pos, y.pos), cmp.Compare(x.pat, y.pat)) })
	var out [][]int
	next := 0
	for _, c := range cands {
		if c.pos < next {
			continue
		}
		if end, ok := m.matchAt(c.pat, text, c.pos); ok {
			out = append(out, []int{c.pos, end})
			next = end
		}
	}
	return out
}

// walkBack adds the starts before e within the run of the pattern's back class that ends at e. A
// run already walked is not walked again: anchors inside one long run would make it quadratic.
func (m *matcher) walkBack(cands []cand, text string, e, i int, walked map[int][2]int) []cand {
	back := m.anchors[i].back
	w, seen := walked[i]
	s := e - 1
	for ; s >= 0 && back[text[s]]; s-- {
		if seen && w[0] <= s && s <= w[1] {
			// The rest of this run, down to its start, was added when an earlier anchor walked it.
			s = w[0] - 1
			break
		}
		cands = append(cands, cand{s, i})
	}
	lo, hi := s+1, e-1
	if seen && w[0] <= hi+1 && lo <= w[1]+1 {
		lo, hi = min(lo, w[0]), max(hi, w[1])
	}
	if lo <= hi {
		walked[i] = [2]int{lo, hi}
	}
	return cands
}

// matchAt tries pattern i alone, starting exactly at pos, with the text before pos as context.
func (m *matcher) matchAt(i int, text string, pos int) (int, bool) {
	a := &m.anchors[i]
	if pos >= len(text) {
		return 0, false // every pattern matches at least one byte
	}
	if a.wordStart && (pos > 0 && isWordByte(text[pos-1])) == isWordByte(text[pos]) {
		return 0, false
	}
	loc := a.at.FindStringIndex(text[pos:])
	if loc == nil {
		return 0, false
	}
	return pos + loc[1], true
}

// isWordByte is syntax.IsWordChar for the rune a byte starts or continues: a byte >= 0x80 belongs
// to a non-ASCII rune, never a word character.
func isWordByte(b byte) bool { return b < utf8.RuneSelf && syntax.IsWordChar(rune(b)) }

// scan calls f with every occurrence of every needle in text.
func (m *matcher) scan(text string, f func(id, pos int)) {
	for i := 0; i < len(text); i++ {
		b0 := lower[text[i]]
		for _, id := range m.one[b0] {
			if m.needleAt(id, text, i) {
				f(int(id), i)
			}
		}
		if i+1 == len(text) {
			break
		}
		k := uint16(b0)<<8 | uint16(lower[text[i+1]])
		if m.twoBits[k/64]&(1<<(k%64)) == 0 {
			continue
		}
		for _, id := range m.two[k] {
			if m.needleAt(id, text, i) {
				f(int(id), i)
			}
		}
	}
}

func (m *matcher) needleAt(id int32, text string, i int) bool {
	n := &m.needles[id]
	if len(text)-i < len(n.lit) {
		return false
	}
	if !n.fold {
		return text[i:i+len(n.lit)] == n.lit
	}
	for j := 0; j < len(n.lit); j++ {
		if lower[text[i+j]] != n.lit[j] {
			return false
		}
	}
	return true
}

// subset is the alternation of the patterns in mask, in their order: patterns that cannot match a
// text never take part in its leftmost-first result, so leaving them out changes nothing.
func (m *matcher) subset(mask uint64) *regexp.Regexp {
	if mask == 1<<len(m.ps)-1 {
		return m.all
	}
	if re, ok := m.subsets.Load(mask); ok {
		return re.(*regexp.Regexp)
	}
	var ps []pattern
	for i, p := range m.ps {
		if mask&(1<<i) != 0 {
			ps = append(ps, p)
		}
	}
	re, _ := m.subsets.LoadOrStore(mask, combined(ps))
	return re.(*regexp.Regexp)
}

// anchorOf derives a pattern's anchor from its source.
func anchorOf(src string) anchor {
	flags, body := "", src
	if strings.HasPrefix(body, "(?i)") {
		flags, body = "(?i)", body[4:]
	}
	re, err := syntax.Parse(flags+body, syntax.Perl)
	if err != nil {
		return anchor{}
	}
	var a anchor
	a.fold = hasFold(re)
	best := pick(factors(re, 0, 0, nil))
	if best == nil {
		return anchor{}
	}
	a.lits, a.dmin, a.dmax, a.back = best.lits, best.dmin, best.dmax, best.back
	if a.fold {
		for i, l := range a.lits {
			a.lits[i] = asciiLower(l)
		}
		a.lits = dedupe(a.lits)
	}
	rest := body
	if strings.HasPrefix(rest, `\b`) {
		rest, a.wordStart = rest[2:], true
	}
	if r, err := syntax.Parse(flags+rest, syntax.Perl); err == nil && !looksBehind(r) {
		a.at = regexp.MustCompile(flags + `^(?:` + rest + `)`)
	}
	return a
}

func hasFold(re *syntax.Regexp) bool {
	if re.Flags&syntax.FoldCase != 0 && (re.Op == syntax.OpLiteral || re.Op == syntax.OpCharClass) {
		return true
	}
	for _, s := range re.Sub {
		if hasFold(s) {
			return true
		}
	}
	return false
}

func asciiLower(s string) string {
	b := []byte(s)
	for i := range b {
		b[i] = lower[b[i]]
	}
	return string(b)
}

func dedupe(ss []string) []string {
	slices.Sort(ss)
	return slices.Compact(ss)
}

// looksBehind reports whether an assertion that reads the byte before the match (\b, \B, ^) can be
// evaluated at the match start: a pattern tried on text[pos:] would see the start of text there.
func looksBehind(re *syntax.Regexp) bool {
	switch re.Op {
	case syntax.OpWordBoundary, syntax.OpNoWordBoundary, syntax.OpBeginLine, syntax.OpBeginText:
		return true
	case syntax.OpConcat:
		for _, s := range re.Sub {
			if looksBehind(s) {
				return true
			}
			if minLen, _ := lenBounds(s); minLen > 0 {
				return false
			}
		}
		return false
	case syntax.OpAlternate, syntax.OpCapture, syntax.OpStar, syntax.OpPlus, syntax.OpQuest, syntax.OpRepeat:
		for _, s := range re.Sub {
			if looksBehind(s) {
				return true
			}
		}
	}
	return false
}

// lenBounds is the range of byte lengths re can match; hi < 0 when unbounded. A rune counts 1 to
// 4 bytes (an invalid byte matches as one rune of width 1).
func lenBounds(re *syntax.Regexp) (lo, hi int) {
	switch re.Op {
	case syntax.OpLiteral:
		for _, r := range re.Rune {
			l, h := runeBytes(r, re.Flags&syntax.FoldCase != 0)
			lo, hi = lo+l, hi+h
		}
		return lo, hi
	case syntax.OpCharClass:
		if len(re.Rune) == 0 {
			return 0, 0
		}
		top := re.Rune[len(re.Rune)-1]
		return 1, max(1, utf8.RuneLen(min(top, unicode.MaxRune)))
	case syntax.OpAnyChar, syntax.OpAnyCharNotNL:
		return 1, utf8.UTFMax
	case syntax.OpCapture:
		return lenBounds(re.Sub[0])
	case syntax.OpConcat:
		for _, s := range re.Sub {
			l, h := lenBounds(s)
			lo += l
			hi = addBound(hi, h)
		}
		return lo, hi
	case syntax.OpAlternate:
		lo = -1
		for _, s := range re.Sub {
			l, h := lenBounds(s)
			if lo < 0 || l < lo {
				lo = l
			}
			hi = maxBound(hi, h)
		}
		return max(lo, 0), hi
	case syntax.OpStar:
		return 0, -1
	case syntax.OpPlus:
		l, _ := lenBounds(re.Sub[0])
		return l, -1
	case syntax.OpQuest:
		_, h := lenBounds(re.Sub[0])
		return 0, h
	case syntax.OpRepeat:
		l, h := lenBounds(re.Sub[0])
		if re.Max < 0 || h < 0 {
			return l * re.Min, -1
		}
		return l * re.Min, h * re.Max
	}
	return 0, 0 // empty match and assertions
}

func addBound(a, b int) int {
	if a < 0 || b < 0 {
		return -1
	}
	return a + b
}

func maxBound(a, b int) int {
	if a < 0 || b < 0 {
		return -1
	}
	return max(a, b)
}

// runeBytes is the byte length range of a literal rune, over its case-fold orbit when fold.
func runeBytes(r rune, fold bool) (lo, hi int) {
	lo, hi = utf8.RuneLen(r), utf8.RuneLen(r)
	if r == utf8.RuneError {
		lo = 1 // an invalid byte decodes as U+FFFD
	}
	if fold {
		for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
			lo, hi = min(lo, utf8.RuneLen(f)), max(hi, utf8.RuneLen(f))
		}
	}
	return lo, hi
}

// factor is a set of literals every match of a node contains, at a byte offset from the node's
// start between dmin and dmax (dmax < 0: unbounded).
type factor struct {
	lits       []string
	dmin, dmax int
	back       *[256]bool
}

// factors lists the literal sets of re, starting at offset [dmin, dmax] from the match start,
// after any run of back bytes. Consecutive pieces with a small finite set of strings are joined
// (sk|rk then _live_).
func factors(re *syntax.Regexp, dmin, dmax int, back *[256]bool) []factor {
	if lits, ok := exact(re); ok {
		return []factor{{lits, dmin, dmax, back}}
	}
	switch re.Op {
	case syntax.OpCapture, syntax.OpPlus:
		return factors(re.Sub[0], dmin, dmax, back)
	case syntax.OpRepeat:
		if re.Min >= 1 {
			return factors(re.Sub[0], dmin, dmax, back)
		}
	case syntax.OpAlternate:
		// Every branch must contribute: the union of their anchors, over the union of offsets.
		var u factor
		for i, s := range re.Sub {
			f := pick(factors(s, dmin, dmax, back))
			if f == nil || f.back != back || len(u.lits)+len(f.lits) > maxExact {
				return nil
			}
			if i == 0 {
				u.dmin, u.dmax = f.dmin, f.dmax
			} else {
				u.dmin = min(u.dmin, f.dmin)
				u.dmax = maxBound(u.dmax, f.dmax)
			}
			u.lits = append(u.lits, f.lits...)
		}
		u.back = back
		return []factor{u}
	case syntax.OpConcat:
		var out []factor
		var run []string
		runMin, runMax := 0, 0
		flush := func() {
			if run != nil {
				out = append(out, factor{run, runMin, runMax, back})
				run = nil
			}
		}
		for _, s := range re.Sub {
			if c := starClass(s); c != nil && dmin == 0 && dmax == 0 && back == nil {
				// A leading run of one class: the offsets after it count from where it ends.
				flush()
				back = c
				continue
			}
			if lits, ok := exact(s); ok {
				if run != nil && len(run)*len(lits) <= maxExact {
					run = cross(run, lits)
				} else {
					flush()
					run, runMin, runMax = lits, dmin, dmax
				}
			} else {
				flush()
				out = append(out, factors(s, dmin, dmax, back)...)
			}
			l, h := lenBounds(s)
			dmin += l
			dmax = addBound(dmax, h)
		}
		flush()
		return out
	}
	return nil
}

// starClass is the byte set of `[class]*` when the class is ASCII. Under (?i) a class holds the
// long s and the Kelvin sign too; those are covered by the fold-risk check of findAll.
func starClass(re *syntax.Regexp) *[256]bool {
	if re.Op != syntax.OpStar || re.Sub[0].Op != syntax.OpCharClass {
		return nil
	}
	cl := re.Sub[0]
	var set [256]bool
	for i := 0; i+1 < len(cl.Rune); i += 2 {
		for r := cl.Rune[i]; r <= cl.Rune[i+1]; r++ {
			switch {
			case r < utf8.RuneSelf:
				set[r] = true
			case cl.Flags&syntax.FoldCase != 0 && (r == '\u017f' || r == '\u212a'):
			default:
				return nil
			}
		}
	}
	return &set
}

// pick chooses the anchor: bounded before unbounded, then the longest shortest literal, then the
// fewest literals.
func pick(fs []factor) *factor {
	var best *factor
	score := func(f *factor) (bool, int, int) {
		shortest := len(f.lits[0])
		for _, l := range f.lits {
			shortest = min(shortest, len(l))
		}
		return f.dmax >= 0, shortest, -len(f.lits)
	}
	for i := range fs {
		f := &fs[i]
		b, s, n := score(f)
		if s == 0 {
			continue
		}
		if best == nil {
			best = f
			continue
		}
		bb, bs, bn := score(best)
		if (b && !bb) || (b == bb && (s > bs || (s == bs && n > bn))) {
			best = f
		}
	}
	return best
}

// exact is the finite set of strings re matches, when small and ASCII.
func exact(re *syntax.Regexp) ([]string, bool) {
	switch re.Op {
	case syntax.OpEmptyMatch, syntax.OpWordBoundary, syntax.OpNoWordBoundary, syntax.OpBeginLine, syntax.OpEndLine,
		syntax.OpBeginText, syntax.OpEndText:
		return []string{""}, true
	case syntax.OpLiteral:
		for _, r := range re.Rune {
			if r >= utf8.RuneSelf {
				return nil, false
			}
		}
		return []string{string(re.Rune)}, true
	case syntax.OpCharClass:
		var out []string
		for i := 0; i+1 < len(re.Rune); i += 2 {
			lo, hi := re.Rune[i], re.Rune[i+1]
			if hi >= utf8.RuneSelf || len(out)+int(hi-lo)+1 > 16 {
				return nil, false
			}
			for r := lo; r <= hi; r++ {
				out = append(out, string(r))
			}
		}
		return out, len(out) > 0
	case syntax.OpCapture:
		return exact(re.Sub[0])
	case syntax.OpQuest:
		s, ok := exact(re.Sub[0])
		if !ok || len(s) >= maxExact {
			return nil, false
		}
		return append([]string{""}, s...), true
	case syntax.OpConcat:
		out := []string{""}
		for _, s := range re.Sub {
			lits, ok := exact(s)
			if !ok || len(out)*len(lits) > maxExact {
				return nil, false
			}
			out = cross(out, lits)
		}
		return out, true
	case syntax.OpAlternate:
		var out []string
		for _, s := range re.Sub {
			lits, ok := exact(s)
			if !ok || len(out)+len(lits) > maxExact {
				return nil, false
			}
			out = append(out, lits...)
		}
		return out, true
	case syntax.OpRepeat:
		if re.Max != re.Min || re.Min > 4 {
			return nil, false
		}
		s, ok := exact(re.Sub[0])
		if !ok {
			return nil, false
		}
		out := []string{""}
		for range re.Min {
			if len(out)*len(s) > maxExact {
				return nil, false
			}
			out = cross(out, s)
		}
		return out, true
	}
	return nil, false
}

func cross(a, b []string) []string {
	out := make([]string, 0, len(a)*len(b))
	for _, x := range a {
		for _, y := range b {
			out = append(out, x+y)
		}
	}
	return out
}
