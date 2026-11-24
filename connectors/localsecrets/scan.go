package localsecrets

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/segurata/segurata/connectors/internal/cli"
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
	noCode := []string{"--max-filesize", "50M"}
	for _, e := range codeExts {
		noCode = append(noCode, "-g", "!*."+e)
	}
	var srcExtra []string
	if history || s.cfg.skipHistory {
		srcExtra = globs(srcSecretGlobs...)
	}
	return append([]pass{
		{withAssignment, s.hs(credFiles), noCode},
		{withAssignment, []string{s.h(".claude")}, append([]string{"--max-filesize", "50M"}, globs("*.json", "!projects", "!plugins/cache")...)},
		{withAssignment, []string{s.src}, append([]string{"--max-filesize", "50M"}, srcExtra...)},
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
		if _, err := os.Stat(p); err == nil {
			out = append(out, p)
		}
	}
	return out
}

// rgArgs are the flags every ripgrep run shares: search hidden and ignored files, print only the
// match with its path and line, NUL after the path.
func rgArgs() []string {
	return append([]string{"--no-config", "--hidden", "--no-ignore", "--no-messages", "-o", "-n", "--null", "--no-heading", "-H",
		"--color", "never"}, skipGlobs()...)
}

// rgOutput runs ripgrep and keeps its stdout when it exits 1 (no match) or 2 (some file could
// not be read), which are not failures for a scan.
func (s *scan) rgOutput(args []string) []byte {
	out, err := guardRG(s.c.RG).Run(s.ctx, args...)
	var ce *cli.Error
	var exit *exec.ExitError
	if errors.As(err, &ce) && errors.As(err, &exit) && exit.ExitCode() <= 2 {
		return out
	}
	if err != nil {
		s.emit.Log("rg: " + err.Error())
	}
	return out
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

func (s *scan) rg(p pass) {
	if args := rgArgsFor(p); args != nil {
		eachRGMatch(s.rgOutput(args), func(path string, line int, text string) { s.match(path, line, text, p.patterns) })
	}
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

// match classifies one ripgrep match and records it.
func (s *scan) match(path string, line int, text string, patterns []pattern) {
	c, ok := classify(path, text, patterns)
	if !ok {
		return
	}
	kind := s.kindOf(path)
	switch c.p.typ {
	case privateKeyType:
		s.privateKey(path, line, kind, text)
	case "gcp-service-account":
		s.serviceAccount(path, line, kind)
	default:
		s.value(path, line, kind, c.p, c.subs(text), c.varName)
	}
}

func (s *scan) value(path string, line int, kind string, p *pattern, m []string, varName string) {
	ev, secret, ok := valueEvidence(p, m, varName, s.now)
	if !ok {
		return
	}
	ev.Kind, ev.Line = kind, line
	s.add(path, ev, secret)
}

// valueEvidence judges a value match: the evidence without its location, and the raw secret.
func valueEvidence(p *pattern, m []string, varName string, now time.Time) (secretrisk.Evidence, string, bool) {
	v, ok := judge(p, m[p.group], varName, now)
	if !ok {
		return secretrisk.Evidence{}, "", false
	}
	note := v.note
	if note == "" {
		note = varName
	}
	if p.typ == "url-credentials" {
		if i, j := strings.Index(m[0], "://"), strings.LastIndex(m[0], "@"); i > 0 && j > i {
			note = m[0][:i+3] + "…" + m[0][j:] // scheme and host only
		}
	}
	return secretrisk.Evidence{Source: "scan", Type: p.typ, Redacted: secretrisk.Redact(p.typ, p.prefix, v.secret),
		Note: note, Public: v.public}, v.secret, true
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
	if IsTrail(kind) {
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
		args := append([]string{"--no-config", "--files", "--null", "--hidden", "--no-ignore", "--no-messages"}, skipGlobs()...)
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
