package localsecrets

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"path"
	"regexp"
	"slices"
	"strings"

	"github.com/segurata/segurata/internal/finding"
	"github.com/segurata/segurata/internal/secretrisk"
)

// A database dump committed to git exposes every row to whoever can clone it; gitleaks sees only
// thousands of token-like hashes. Dumps are recognised by name and first bytes, once per file.

const (
	dumpMinSize   = 4 << 10  // a schema, a sample or an empty database (one SQLite page)
	dumpRowsSize  = 64 << 10 // rows in a smaller file are a script
	dumpLargeSize = 1 << 20  // for exports by name, test fixtures and schema-only SQL
	dumpPeekSize  = 4 << 10
)

type dumpName struct {
	match    bool
	prodLike bool
	minSize  int64
}

var dumpExts = []string{".sql.gz", ".sql.zip", ".sql.bz2", ".sql.xz", ".dump.gz", ".sql", ".dump", ".pgdump", ".sqlite3", ".sqlite", ".db"}

// dataExts count only with a production name and a large size.
var dataExts = []string{".csv", ".json", ".xlsx", ".csv.gz", ".json.gz"}

var (
	prodWords = map[string]bool{"prod": true, "production": true, "prd": true, "live": true, "backup": true, "backups": true, "bkp": true, "dump": true, "dumps": true}
	dbWords   = map[string]bool{"db": true, "sql": true, "database": true, "dump": true, "backup": true, "postgres": true, "postgresql": true, "pg": true, "pgsql": true, "mysql": true, "mariadb": true, "mongo": true, "sqlite": true}
	migDirs   = map[string]bool{"migrations": true, "migration": true, "migrate": true, "drizzle": true, "flyway": true, "alembic": true, "liquibase": true}
)

var nonWord = regexp.MustCompile(`[^a-z0-9]+`)

func words(s string) []string { return nonWord.Split(s, -1) }

func anyWord(ws []string, set map[string]bool) bool {
	return slices.ContainsFunc(ws, func(w string) bool { return set[w] })
}

// classifyDumpName never matches schemas, migrations, seeds, vendored code or Thumbs.db; under
// test folders a file needs dumpLargeSize.
func classifyDumpName(rel string) dumpName {
	lower := strings.ToLower(rel)
	base := path.Base(lower)
	dirs := strings.Split(path.Dir(lower), "/")
	inTest, inVendor := secretrisk.DirRoles(lower)
	if base == "thumbs.db" || strings.Contains(base, "schema") || strings.Contains(base, "structure") || strings.Contains(lower, "seed") ||
		anyWord(dirs, migDirs) || inVendor {
		return dumpName{}
	}
	ws := words(base)
	// The stem, not the extension: erl_crash.dump is not a production name.
	stem := base
	if i := strings.IndexByte(base, '.'); i > 0 {
		stem = base[:i]
	}
	prod := anyWord(words(stem), prodWords) || anyWord(dirs, prodWords)
	n := dumpName{minSize: dumpMinSize, prodLike: prod}
	switch {
	case hasAnySuffix(base, dumpExts):
		n.match = true
	case strings.HasSuffix(base, ".bak") && anyWord(ws, dbWords):
		n.match, n.prodLike = true, true
	case hasAnySuffix(base, dataExts) && prod:
		n.match, n.minSize = true, dumpLargeSize
	default:
		return dumpName{}
	}
	if inTest && n.minSize < dumpLargeSize {
		n.minSize = dumpLargeSize
	}
	return n
}

func hasAnySuffix(s string, suffixes []string) bool {
	return slices.ContainsFunc(suffixes, func(x string) bool { return strings.HasSuffix(s, x) })
}

const (
	contentData   = "data"
	contentRows   = "rows"
	contentSchema = "schema"
	contentNone   = ""
)

// dumpHeaders are tried in order; the first match names the header.
var dumpHeaders = []struct {
	label, class string
	re           *regexp.Regexp
}{
	{"PGDMP (pg_dump custom format)", contentData, regexp.MustCompile(`\APGDMP`)},
	{"SQLite format 3", contentData, regexp.MustCompile(`\ASQLite format 3\x00`)},
	{"mysqldump header", contentData, regexp.MustCompile(`(?i)-- (MySQL|MariaDB) dump`)},
	{"pg_dump header", contentData, regexp.MustCompile(`(?i)-- (PostgreSQL database dump|Dumped from database version)`)},
	{"INSERT INTO", contentRows, regexp.MustCompile(`(?i)\bINSERT\s+INTO\b`)},
	{"COPY ... FROM stdin", contentRows, regexp.MustCompile(`(?i)\bCOPY\s+\S+[^;]*\bFROM\s+stdin\b`)},
	{"CREATE TABLE", contentSchema, regexp.MustCompile(`(?i)\bCREATE\s+TABLE\b`)},
}

// sniffDump inflates gzip as far as the bytes allow and reads UTF-16 (SSMS scripts) as ASCII.
func sniffDump(head []byte) (class, label string) {
	if len(head) > 2 && head[0] == 0x1f && head[1] == 0x8b {
		if zr, err := gzip.NewReader(bytes.NewReader(head)); err == nil {
			inflated, _ := io.ReadAll(io.LimitReader(zr, dumpPeekSize))
			head = inflated
		}
	}
	if len(head) > 2 && ((head[0] == 0xff && head[1] == 0xfe) || (head[0] == 0xfe && head[1] == 0xff)) {
		head = bytes.ReplaceAll(head[2:], []byte{0}, nil)
	}
	for _, h := range dumpHeaders {
		if h.re.Match(head) {
			return h.class, h.label
		}
	}
	return contentNone, ""
}

type dumpHit struct {
	Repo, Path     string
	Size           int64 // largest blob
	Versions       int
	Tracked        bool
	InWorkingTree  bool
	FirstCommit    string
	FirstDate      string
	Remote         bool
	OnRemoteBranch bool
	Visibility     string // from gh; "" when unknown
	Content        string
	Header         string
	ProdName       bool
	Leaks          int // gitleaks matches inside
}

// strong means almost certainly real data.
func (h dumpHit) strong() bool {
	return h.ProdName || h.Content == contentData || (h.Content == contentRows && h.Size >= dumpRowsSize) ||
		(h.Content == contentSchema && h.Size >= dumpLargeSize)
}

func (h dumpHit) public() bool { return h.Visibility == "PUBLIC" }

func (h dumpHit) severity() finding.Severity {
	switch {
	case h.strong() && h.Remote && h.public():
		return finding.SevCritical
	case h.strong() && h.Remote:
		return finding.SevHigh
	case h.strong():
		return finding.SevMedium
	case h.Size >= dumpLargeSize && h.Remote:
		return finding.SevMedium
	case h.Size >= dumpLargeSize:
		return finding.SevLow
	}
	return finding.SevInfo
}

func (h dumpHit) label() string {
	switch {
	case h.ProdName && h.strong():
		return "Production database dump"
	case h.strong() && (h.Content == contentData || h.Content == contentRows):
		return "Database dump"
	case h.Content == contentSchema && !h.strong():
		return "Database schema"
	}
	return possibleDump
}

const possibleDump = "Possible database dump"

func (h dumpHit) exposure() string {
	switch {
	case h.OnRemoteBranch && h.public():
		return "pushed to a public repository"
	case h.OnRemoteBranch:
		return "pushed"
	case h.Remote && h.public():
		return "public remote, not seen on a remote branch"
	case h.Remote:
		return "repository has a remote, not seen on a remote branch"
	}
	return "local only"
}

func (h dumpHit) toFinding() finding.Finding {
	where := "in the git history of"
	if h.Tracked {
		where = "committed to"
	}
	title := fmt.Sprintf("%s %s %s: %s (%s, %s)", h.label(), where, h.Repo, h.Path, secretrisk.HumanSize(h.Size), h.exposure())
	ev := map[string]any{
		"source": "data-dump", "repo": h.Repo, "path": h.Path, "size_bytes": h.Size, "size": secretrisk.HumanSize(h.Size),
		"versions": h.Versions, "tracked": h.Tracked, "in_working_tree": h.InWorkingTree,
		"first_commit": h.FirstCommit, "first_date": h.FirstDate, "remote": h.Remote,
		"on_remote_branch": h.OnRemoteBranch, "content": h.Content, "header": h.Header,
		"production_name": h.ProdName, "fix": secretrisk.DumpFixDoc,
	}
	if h.Visibility != "" {
		ev["visibility"] = h.Visibility
	}
	if h.Leaks > 0 {
		ev["gitleaks_matches"] = h.Leaks
	}
	return finding.Finding{
		Account:     localAccount,
		Scope:       dumpsScope(h.Repo),
		Resource:    finding.Resource{Type: "data_dump", ID: h.Repo + ":" + h.Path, Name: h.Path},
		Kind:        finding.KindExposure,
		Severity:    h.severity(),
		Title:       title,
		Evidence:    ev,
		Blast:       finding.BlastPersonalData,
		Unconfirmed: h.label() == possibleDump,
		Remediation: finding.Remediation{Summary: h.remediation(), URL: secretrisk.URLAEPDBreaches},
	}
}

func (h dumpHit) remediation() string {
	var b strings.Builder
	if h.Remote {
		b.WriteString("Treat the data as exposed to everyone who could clone the repository (collaborators, CI, forks, and anyone at all if it is public). ")
	} else {
		b.WriteString("It has not left this machine through git yet: do not push it. ")
	}
	b.WriteString("Rotate every credential, API key and session secret the dump holds. ")
	fmt.Fprintf(&b, "Remove it from history with `git filter-repo --path '%s' --invert-paths`", strings.ReplaceAll(h.Path, "'", `'\''`))
	if h.Remote {
		b.WriteString(" and force-push every branch and tag; collaborators must re-clone, and the host may keep cached copies until support purges them")
	}
	b.WriteString(". segurata never rewrites history or pushes. ")
	fmt.Fprintf(&b, "If it holds personal data of customers or staff, check the GDPR breach notification duty (72 hours): %s, %s. See %s.", secretrisk.URLAEPDBreaches, secretrisk.URLEDPBBreaches, secretrisk.DumpFixDoc)
	return b.String()
}
