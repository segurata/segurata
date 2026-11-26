package localsecrets

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/segurata/segurata/connectors/internal/cli"
	"github.com/segurata/segurata/internal/finding"
	"github.com/segurata/segurata/internal/secretrisk"
)

// skipDirs are never descended into by ripgrep: dependencies, build output, VCS internals.
var skipDirs = []string{"node_modules", "deps", "_build", "vendor", ".git", ".elixir_ls", ".venv", "venv", "__pycache__", ".next", "dist"}

func globs(list ...string) []string {
	var out []string
	for _, g := range list {
		out = append(out, "-g", g)
	}
	return out
}

func skipGlobs() []string {
	var gs []string
	for _, d := range skipDirs {
		gs = append(gs, "!"+d)
	}
	return globs(gs...)
}

// pass is one ripgrep run: which patterns, over which paths, with which extra filters.
type pass struct {
	patterns []pattern
	paths    []string
	extra    []string
}

// Source code inside config dirs (~/.mcp, ~/.config) is left to gitleaks: too noisy for the
// generic assignment pattern.
var codeExts = []string{"ts", "tsx", "js", "mjs", "cjs", "py", "rb", "ex", "exs", "go", "rs", "java", "md", "html", "css", "map", "lock", "d.ts"}

// Files under repos_root that hold secrets by convention.
var srcSecretGlobs = []string{".env*", "*.pem", "*.key", "*.p8", "credentials*", "secrets*", "*.secret.exs", "*.secrets.*"}

var credFiles = []string{".aws/credentials", ".aws/config", ".npmrc", ".netrc", ".docker/config.json", ".kube/config", ".pypirc",
	".gem/credentials", ".git-credentials", ".gitconfig", ".codex/config.toml", ".codex/auth.json", ".claude.json",
	".zshrc", ".zprofile", ".zshenv", ".bashrc", ".bash_profile", ".profile", ".cursor/mcp.json", ".cursor/cli-config.json",
	".gemini/settings.json", ".gemini/oauth_creds.json", ".config", ".mcp"}

func (s *scan) hs(rels []string) []string {
	out := make([]string, len(rels))
	for i, r := range rels {
		out[i] = s.h(r)
	}
	return out
}

// passes lists the ripgrep runs. Config files, .env files and histories get the generic
// assignment pattern too; logs and transcripts only the specific ones. Without a git history scan
// the whole working tree under repos_root is searched instead of just its secret files.
func (s *scan) passes(history bool) []pass {
	// gcloud's own logs record its API calls (segurata's gcp connector among them): ~70 info
	// matches a run, none a secret.
	limit := []string{"--max-filesize", strconv.Itoa(maxFileSize)}
	noCode := append(slices.Clone(limit), "-g", "!**/gcloud/logs")
	for _, e := range codeExts {
		noCode = append(noCode, "-g", "!*."+e)
	}
	var srcExtra []string
	if history || s.cfg.skipHistory {
		srcExtra = globs(srcSecretGlobs...)
	}
	return append([]pass{
		{withAssignment, s.hs(credFiles), noCode},
		{withAssignment, []string{s.h(".claude")}, slices.Concat(limit, globs("*.json", "!projects", "!plugins/cache"))},
		{withAssignment, []string{s.src}, slices.Concat(limit, srcExtra)},
	}, s.trailPasses()...)
}

// trailPasses are the runs over trails: shell histories, logs and agent transcripts.
func (s *scan) trailPasses() []pass {
	return []pass{
		{withAssignment, s.hs(historyFiles), nil},
		{specific, []string{s.src}, globs("*.log")},
		{specific, s.hs([]string{"Library/Logs", ".local/log"}), nil},
		{specific, s.hs(transcriptDirs), nil},
	}
}

// patternsFor are the patterns a pass applies to a file of this kind: shell histories get the
// generic assignment pattern, the other trails only the specific ones.
func patternsFor(kind string) []pattern {
	if specificOnly(kind) {
		return specific
	}
	return withAssignment
}

// specificOnly reports whether files of this kind (transcripts, logs) are searched with the
// specific patterns only.
func specificOnly(kind string) bool { return kind == "transcript" || kind == "log" }

func existing(paths []string) []string {
	var out []string
	for _, p := range paths {
		if _, err := os.Stat(p); !errors.Is(err, os.ErrNotExist) {
			out = append(out, p)
		}
	}
	return out
}

// rgArgs are the flags every ripgrep run shares: search hidden and ignored files, print only the
// match with its path and line, NUL after the path.
func rgArgs() []string {
	return append([]string{"--no-config", "--hidden", "--no-ignore", "-o", "-n", "--null", "--no-heading", "-H",
		"--color", "never"}, skipGlobs()...)
}

// rgOutput returns what ripgrep printed, partial output included, and marks the files scope
// uninspected unless the search was complete. Exit 1 means no matches. macOS denies reads under
// every home (TCC), so exit 2 is complete apart from those paths when ripgrep only reports
// unreadable paths below its roots.
func (s *scan) rgOutput(args []string) []byte {
	out, err := guardRG(s.c.RG).Run(s.ctx, args...)
	if err == nil {
		return out
	}
	var exit *exec.ExitError
	var ce *cli.Error
	switch {
	case errors.As(err, &exit) && exit.ExitCode() == 1:
		return out
	case errors.As(err, &ce):
		if paths, ok := unreadableBelow(ce.Stderr, rgRoots(args)); ok && exit != nil && exit.ExitCode() == 2 {
			s.skipUnreadable(paths)
			return out
		}
		// Stderr names paths under the home: the reason keeps only the exit status.
		s.emit.Scope(filesScope, false, ce.Cmd+": "+ce.Err.Error())
	default:
		s.emit.Scope(filesScope, false, "rg: "+err.Error())
	}
	return out
}

// unreadableErrs end ripgrep's message for a path it was not allowed to read; vanishedErr for a
// path removed while it searched, which holds nothing any more.
var (
	unreadableErrs = []string{": Permission denied (os error 13)", ": Operation not permitted (os error 1)"}
	vanishedErr    = ": No such file or directory (os error 2)"
)

// unreadableBelow is the paths ripgrep's stderr reports unreadable, and whether all it reports
// is paths below its roots that it could not read or that vanished.
func unreadableBelow(stderr string, roots []string) ([]string, bool) {
	var paths []string
	lines := 0
	for line := range strings.Lines(strings.TrimSpace(stderr)) {
		msg, ok := strings.CutPrefix(strings.TrimSuffix(line, "\n"), "rg: ")
		if !ok {
			return nil, false
		}
		path, vanished := strings.CutSuffix(msg, vanishedErr)
		if !vanished {
			i := slices.IndexFunc(unreadableErrs, func(e string) bool { return strings.HasSuffix(msg, e) })
			if i < 0 {
				return nil, false
			}
			path = strings.TrimSuffix(msg, unreadableErrs[i])
		}
		if slices.Contains(roots, path) {
			return nil, false
		}
		if !vanished {
			paths = append(paths, path)
		}
		lines++
	}
	return paths, lines > 0
}

// rgRoots are the paths a ripgrep command line searches: everything after "--".
func rgRoots(args []string) []string {
	if i := slices.Index(args, "--"); i >= 0 {
		return args[i+1:]
	}
	return nil
}

// skipUnreadable leaves each path out of the files scope: what it may hold is unknown, so the
// tracker keeps every location there, while the rest of the scope counts as inspected.
func (s *scan) skipUnreadable(paths []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.unreadable == nil {
		s.unreadable = map[string]bool{}
	}
	for _, p := range paths {
		if !s.unreadable[p] {
			s.unreadable[p] = true
			s.emit.Scope(finding.PathScope(filesScope, s.tilde(p)), false, "unreadable")
		}
	}
}

// rgArgsFor is the ripgrep command line of one pass, or nil when none of its paths exist.
func rgArgsFor(p pass) []string {
	paths := existing(p.paths)
	if len(paths) == 0 {
		return nil
	}
	args := append(rgArgs(), p.extra...)
	for _, pt := range p.patterns {
		args = append(args, "-e", rgPattern(pt.src))
	}
	return append(append(args, "--"), paths...)
}

// rg runs one pass. Matches whose judgement needs the whole line (a token in a URL's query
// string is judged by the URL's host, which ripgrep's -o output leaves out) are read back from
// their file afterwards, one read per file.
func (s *scan) rg(p pass) {
	args := rgArgsFor(p)
	if args == nil {
		return
	}
	type hit struct {
		line int
		text string
	}
	out := s.rgOutput(args)
	keyIDs := keyIDLines(out, p.patterns)
	deferred := map[string][]hit{}
	eachRGMatch(out, func(path string, line int, text string) {
		if c, ok := classify(path, text, p.patterns); ok && needsLine[c.p.typ] {
			deferred[path] = append(deferred[path], hit{line, text})
			return
		}
		s.match(path, line, text, "", p.patterns, keyIDs[path])
	})
	for path, hits := range deferred {
		want := map[int]bool{}
		for _, h := range hits {
			want[h.line] = true
		}
		lines := linesAt(path, want)
		for _, h := range hits {
			s.match(path, h.line, h.text, lines[h.line], p.patterns, keyIDs[path])
		}
	}
}

// keyIDLines are the lines, by file, where a pass found a long-term AWS key id: a secret-ish
// assignment within awsPairLines lines of one is that key id's secret access key
// (awsSecretNearKeyID). Only the passes with the assignment pattern have such assignments.
func keyIDLines(out []byte, patterns []pattern) map[string][]int {
	if !slices.ContainsFunc(patterns, func(p pattern) bool { return p.typ == assignment.typ }) {
		return nil
	}
	lines := map[string][]int{}
	eachRGMatch(out, func(path string, line int, text string) {
		if !strings.Contains(text, "AKIA") {
			return
		}
		if c, ok := classify(path, text, patterns); ok && c.p.typ == "aws-access-key-id" && pairableKeyID(c.subs(text)[c.p.group]) {
			lines[path] = append(lines[path], line)
		}
	})
	return lines
}

// needsLine are the types judged with the line around the match.
var needsLine = map[string]bool{"url-token-param": true}

// linesAt reads the wanted (1-based) lines of a file of at most 50 MB, streaming.
func linesAt(path string, want map[int]bool) map[int]string {
	out := map[int]string{}
	f, err := os.Open(path)
	if err != nil {
		return out
	}
	defer f.Close()
	if st, err := f.Stat(); err != nil || st.Size() > maxFileSize {
		return out
	}
	r := bufio.NewReader(f)
	for n := 1; len(out) < len(want); n++ {
		l, err := r.ReadString('\n')
		if want[n] {
			out[n] = strings.TrimRight(l, "\r\n")
		}
		if err != nil {
			break
		}
	}
	return out
}

// eachRGMatch reads `path\0line:match` lines.
func eachRGMatch(out []byte, f func(path string, line int, text string)) {
	for _, l := range bytes.Split(out, []byte{'\n'}) {
		z := bytes.IndexByte(l, 0)
		if z < 0 {
			continue
		}
		rest := l[z+1:]
		c := bytes.IndexByte(rest, ':')
		if c < 0 {
			continue
		}
		line, err := strconv.Atoi(string(rest[:c]))
		if err != nil {
			continue
		}
		f(string(l[:z]), line, string(rest[c+1:]))
	}
}

// classified is one ripgrep match read by the first pattern that fits it whole. idx holds the
// submatch byte offsets inside the match text, as regexp's Index functions return them.
type classified struct {
	p       *pattern
	idx     []int
	varName string
}

// subs are the submatches of text.
func (c classified) subs(text string) []string {
	m := make([]string, len(c.idx)/2)
	for i := range m {
		if c.idx[2*i] >= 0 {
			m[i] = text[c.idx[2*i]:c.idx[2*i+1]]
		}
	}
	return m
}

// classify finds the first pattern that fits text whole. ripgrep reports the leftmost match, so
// `NAME=sk-ant-…` arrives as an assignment: its value is classified with the specific patterns
// when one of them fits.
func classify(path, text string, patterns []pattern) (classified, bool) {
	for i := range patterns {
		p := &patterns[i]
		if p.files != nil && !p.files.MatchString(path) {
			continue
		}
		idx := p.re.FindStringSubmatchIndex(text)
		if idx == nil {
			continue
		}
		c := classified{p: p, idx: idx}
		if p.typ == "assignment" {
			c.varName = text[idx[2]:idx[3]]
			vs, ve := idx[4], idx[5]
			if q := classifyValue(text[vs:ve]); q != nil {
				qi := q.re.FindStringSubmatchIndex(text[vs:ve])
				for j := range qi {
					if qi[j] >= 0 {
						qi[j] += vs
					}
				}
				c.p, c.idx = q, qi
			}
		}
		return c, true
	}
	return classified{}, false
}

// match classifies one ripgrep match and records it. context is the whole line when the pattern
// needs it (needsLine), else "". keyIDs are the lines of the file that hold an AWS key id: an
// assignment to a secret-ish name near one is an AWS secret access key, outside trails, whose
// lines (commands, messages) say nothing about what belongs together.
func (s *scan) match(path string, line int, text, context string, patterns []pattern, keyIDs []int) {
	c, ok := classify(path, text, patterns)
	if !ok || s.fileNotebookOutput(path, line) {
		return
	}
	kind := s.kindOf(path)
	switch c.p.typ {
	case privateKeyType:
		s.privateKey(path, line, kind, text)
	case "gcp-service-account":
		s.serviceAccount(path, line, kind)
	default:
		p, m := c.p, c.subs(text)
		if p.typ == assignment.typ && !isTrail(kind) && nearKeyID(keyIDs, line) && awsSecretNearKeyID(c.varName, m[p.group]) {
			p, m = awsSecretKey, []string{m[0], m[p.group]}
		}
		s.value(path, line, kind, p, m, c.varName, context)
	}
}

func (s *scan) value(path string, line int, kind string, p *pattern, m []string, varName, context string) {
	ev, secret, ok := valueEvidence(p, m, varName, context, s.now)
	if !ok {
		return
	}
	ev.Kind, ev.Line = kind, line
	s.add(path, ev, secret)
}

// valueEvidence judges a value match: the evidence without its location, and the raw secret.
// context is the line the match came from, when known: a URL token's host is read from it.
func valueEvidence(p *pattern, m []string, varName, context string, now time.Time) (secretrisk.Evidence, string, bool) {
	v, ok := judge(p, m[p.group], varName, now)
	if !ok {
		return secretrisk.Evidence{}, "", false
	}
	note := v.note
	if note == "" {
		note = varName
	}
	switch p.typ {
	case "url-credentials":
		if i, j := strings.Index(m[0], "://"), strings.LastIndex(m[0], "@"); i > 0 && j > i {
			note = secretrisk.URLNote(m[0][:i], m[0][j+1:], "")
		}
	case "url-token-param":
		scheme, host := urlBefore(context, m[0])
		note = secretrisk.URLNote(scheme, host, queryParam(m[0]))
	case "cloudflare-token":
		// The key it is assigned to (CLOUDFLARE_API_TOKEN, CF_KEY): the value alone does not say
		// whose it is, and the liveness check tries only one the key names (namesCloudflare).
		note, _, _ = strings.Cut(m[0], "=")
		note, _, _ = strings.Cut(note, ":")
		note = strings.Trim(note, "\"' \t")
	}
	return secretrisk.Evidence{Source: "scan", Type: p.typ, Redacted: secretrisk.Redact(p.typ, p.prefix, v.secret),
		Note: note, Public: v.public, Sample: sampleValue(v.secret)}, v.secret, true
}

// queryParam is the parameter name of a `?name=value` or `&name=value` match.
func queryParam(m string) string {
	name, _, _ := strings.Cut(strings.TrimLeft(m, "?&"), "=")
	return strings.ToLower(name)
}

var urlStart = regexp.MustCompile(`([A-Za-z][A-Za-z0-9+.-]{1,20})://(?:[^\s/@"'<>]*@)?([A-Za-z0-9.-]+|\[[0-9A-Fa-f:]+\])[^\s"'<>]*$`)

// urlBefore finds the URL a query-string match belongs to in its line: the scheme and host of
// the URL that runs, without a break, up to the match. Empty when the line is unknown or the
// match is not inside a URL.
func urlBefore(line, match string) (scheme, host string) {
	i := strings.Index(line, match)
	if i < 0 {
		return "", ""
	}
	m := urlStart.FindStringSubmatch(line[max(0, i-2048):i])
	if m == nil {
		return "", ""
	}
	return strings.ToLower(m[1]), strings.ToLower(strings.Trim(m[2], "[]"))
}

// privateKey fingerprints the key body. A header with no body in a transcript or a log is
// documentation; in a file, the body is on the following lines.
func (s *scan) privateKey(path string, line int, kind, text string) {
	if len(pemBody(text)) < 40 {
		if kind == "transcript" || kind == "log" {
			return
		}
		text = pemBlockAt(path, line)
	}
	ev, body, ok := privateKeyEvidence(text)
	if !ok {
		return
	}
	ev.Kind, ev.Line = kind, line
	s.add(path, ev, body)
}

// privateKeyEvidence reads a PEM block (real or escaped newlines): the evidence without its
// location and the base64 body that is fingerprinted. ok is false without a body.
func privateKeyEvidence(text string) (secretrisk.Evidence, string, bool) {
	body := pemBody(text)
	if len(body) < 40 {
		return secretrisk.Evidence{}, "", false
	}
	label := pemLabel(text)
	enc := pemEncrypted(label, text, body)
	note := label
	if enc {
		note += " encrypted"
	}
	return secretrisk.Evidence{Source: "scan", Type: privateKeyType, Redacted: "PEM", Note: note, Encrypted: enc}, body, true
}

// serviceAccount reads a service-account key file and fingerprints its private key, so the same key
// matches wherever else it appears. In a transcript the private-key match covers it.
func (s *scan) serviceAccount(path string, line int, kind string) {
	if isTrail(kind) {
		return
	}
	raw, err := readSmall(path)
	if err != nil {
		return
	}
	var sa struct {
		PrivateKey  string `json:"private_key"`
		ClientEmail string `json:"client_email"`
	}
	if json.Unmarshal(raw, &sa) != nil {
		return
	}
	body := pemBody(sa.PrivateKey)
	if len(body) < 40 {
		return
	}
	s.add(path, secretrisk.Evidence{Source: "scan", Kind: kind, Line: line, Type: "gcp-service-account", Redacted: "PEM",
		Note: sa.ClientEmail}, body)
}

// byName reports files that are secrets by name, even when binary or patternless: Rails master
// keys, keystores and certificate bundles under repos_root, and gcloud's credential stores.
func (s *scan) byName() {
	var files []string
	if paths := existing([]string{s.src}); len(paths) > 0 {
		args := append([]string{"--no-config", "--files", "--null", "--hidden", "--no-ignore"}, skipGlobs()...)
		args = append(append(args, globs("master.key", "*.p12", "*.pfx", "*.jks", "*.keystore")...), "--")
		out := s.rgOutput(append(args, paths...))
		for _, f := range bytes.Split(out, []byte{0}) {
			if f := strings.TrimSpace(string(f)); f != "" {
				files = append(files, f)
			}
		}
	}
	files = append(files, existing(s.hs([]string{".config/gcloud/credentials.db", ".config/gcloud/access_tokens.db"}))...)
	for _, f := range files {
		ev := secretrisk.Evidence{Source: "name"}
		var value string
		switch {
		case strings.HasSuffix(f, ".db"):
			// gcloud rewrites these on every use: the path identifies the store.
			ev.Type, value = "gcloud-credential-db", "file:"+f
		case strings.HasSuffix(f, "master.key"):
			raw, err := readSmall(f)
			if err != nil {
				continue
			}
			if value = strings.TrimSpace(string(raw)); value == "" {
				continue
			}
			ev.Type, ev.Redacted = "rails-master-key", secretrisk.Redact("rails-master-key", "", value)
		default:
			raw, err := readSmall(f)
			if err != nil {
				continue
			}
			ev.Type, value = "keystore", string(raw)
		}
		s.add(f, ev, value)
	}
}
