package localsecrets

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/segurata/segurata/internal/finding"
	"github.com/segurata/segurata/internal/gitlocal"
	"github.com/segurata/segurata/internal/proc"
	"github.com/segurata/segurata/internal/secretrisk"
	"github.com/segurata/segurata/internal/statefile"
)

// The data-dump check lists every path tracked or ever added whose name looks like a dump, then
// asks git for blob sizes, first commits and remote branches, and reads the first bytes of one
// blob per path. History facts are cached per repository while its tips are unchanged, blobs by id.

type dumpMode int

const (
	dumpsOn dumpMode = iota
	dumpsOff
	dumpsOnly
)

func parseDumpMode(v any) (dumpMode, error) {
	switch v := v.(type) {
	case nil:
		return dumpsOn, nil
	case bool:
		if v {
			return dumpsOn, nil
		}
		return dumpsOff, nil
	case string:
		if v == "only" {
			return dumpsOnly, nil
		}
	}
	return dumpsOn, fmt.Errorf("data_dumps %v must be true, false or \"only\"", v)
}

const (
	dumpCacheVersion = 2 // goes up with classifyDumpName and the history queries
	maxDumpBlobs     = 32
	dumpPathsPerCall = 100
	visibilityTTL    = 7 * 24 * time.Hour
)

type dumpCache struct {
	Version      int                 `json:"version"`
	Repo         string              `json:"repo"`
	Tips         []string            `json:"tips"`
	History      []dumpHistory       `json:"history"`
	Blobs        map[string]dumpBlob `json:"blobs"`
	Visibility   string              `json:"visibility,omitempty"`
	VisibilityAt time.Time           `json:"visibility_at,omitzero"`

	dirty bool
}

type dumpHistory struct {
	Path        string   `json:"path"`
	FirstCommit string   `json:"first_commit"`
	FirstDate   string   `json:"first_date"`
	Blobs       []string `json:"blobs"` // newest first
	Versions    int      `json:"versions"`
	OnRemote    bool     `json:"on_remote,omitempty"`
}

type dumpBlob struct {
	Size    int64  `json:"size"`
	Peeked  bool   `json:"peeked,omitempty"`
	Content string `json:"content,omitempty"`
	Header  string `json:"header,omitempty"`
}

// dumpState is computed once per repository, by the dump pass or the gitleaks replay.
type dumpState struct {
	mu     sync.Mutex
	repos  map[string]*dumpRepo
	cached int
	ghOnce sync.Once
	ghOK   bool
}

type dumpRepo struct {
	once   sync.Once
	hits   []dumpHit
	byPath map[string]int
	leaks  map[string]int
	err    error
}

func (s *scan) dumpRepoOf(repo string) *dumpRepo {
	s.dumps.mu.Lock()
	defer s.dumps.mu.Unlock()
	if s.dumps.repos == nil {
		s.dumps.repos = map[string]*dumpRepo{}
	}
	d, ok := s.dumps.repos[repo]
	if !ok {
		d = &dumpRepo{leaks: map[string]int{}}
		s.dumps.repos[repo] = d
	}
	return d
}

func (s *scan) dumpsIn(repo string) *dumpRepo {
	d := s.dumpRepoOf(repo)
	d.once.Do(func() {
		d.hits, d.err = s.findDumps(repo)
		d.byPath = make(map[string]int, len(d.hits))
		for i, h := range d.hits {
			d.byPath[h.Path] = i
		}
	})
	return d
}

// dumpsAll runs the check over every repository; one that fails is a status, as with gitleaks.
func (s *scan) dumpsAll() {
	s.eachRepo(func(repo string) {
		if d := s.dumpsIn(repo); d.err != nil {
			s.emit.Status(finding.Status{Account: s.tilde(repo), Scope: dumpsScope(s.tilde(repo)), State: finding.StateError, Detail: "data dumps: " + d.err.Error()})
		}
	})
}

// markDump flags a gitleaks match inside a dump, which the dump finding covers.
func (s *scan) markDump(repo string, ev *secretrisk.Evidence) {
	if s.cfg.dumps == dumpsOff {
		return
	}
	d := s.dumpsIn(repo)
	rel := strings.TrimPrefix(ev.Path, ev.Repo+"/")
	if _, ok := d.byPath[rel]; !ok {
		return
	}
	ev.InDataDump = true
	s.dumps.mu.Lock()
	d.leaks[rel]++
	s.dumps.mu.Unlock()
}

func (s *scan) dumpFindings() (out []finding.Finding, repos int) {
	s.dumps.mu.Lock()
	defer s.dumps.mu.Unlock()
	for _, d := range s.dumps.repos {
		if len(d.hits) > 0 {
			repos++
		}
		for _, h := range d.hits {
			h.Leaks = d.leaks[h.Path]
			out = append(out, h.toFinding())
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Resource.ID < out[j].Resource.ID })
	return out, repos
}

func (s *scan) findDumps(repo string) ([]dumpHit, error) {
	tips, err := s.tips(repo)
	if err != nil {
		return nil, err
	}
	path := repoCacheFile(s.dumpCacheDir(), repo)
	c := s.loadDumpCache(path, repo)
	if c != nil && slices.Equal(c.Tips, tips) {
		s.dumps.mu.Lock()
		s.dumps.cached++
		s.dumps.mu.Unlock()
	} else {
		blobs := map[string]dumpBlob{}
		if c != nil {
			blobs = c.Blobs // content addresses: still valid
		}
		c = &dumpCache{Version: dumpCacheVersion, Repo: repo, Tips: tips, Blobs: blobs, dirty: true}
		if len(tips) > 0 {
			if c.History, err = s.dumpHistory(repo); err != nil {
				return nil, err
			}
		}
	}
	tracked, err := s.trackedDumps(repo)
	if err != nil {
		return nil, err
	}

	hist := map[string]dumpHistory{}
	paths := map[string]bool{}
	for _, h := range c.History {
		hist[h.Path], paths[h.Path] = h, true
	}
	for p := range tracked {
		paths[p] = true
	}
	remote := s.hasRemote(repo)
	var hits []dumpHit
	for _, p := range slices.Sorted(maps.Keys(paths)) {
		name := classifyDumpName(p)
		h := hist[p]
		blobs := h.Blobs
		cur, isTracked := tracked[p]
		if isTracked && !slices.Contains(blobs, cur) {
			blobs = append([]string{cur}, blobs...)
		}
		var size int64
		largest := ""
		for _, b := range blobs {
			info, err := s.blobInfo(repo, b, c)
			if err != nil {
				return nil, err
			}
			if info.Size > size || largest == "" {
				size, largest = info.Size, b
			}
		}
		if size <= name.minSize {
			continue
		}
		peek := largest
		if isTracked {
			peek = cur
		}
		info := s.peekBlob(repo, peek, c)
		versions := max(h.Versions, len(blobs))
		_, errStat := os.Lstat(filepath.Join(repo, p))
		hit := dumpHit{Repo: s.tilde(repo), Path: p, Size: size, Versions: versions, Tracked: isTracked,
			InWorkingTree: errStat == nil, FirstCommit: h.FirstCommit, FirstDate: h.FirstDate, Remote: remote,
			OnRemoteBranch: h.OnRemote, Content: info.Content, Header: info.Header, ProdName: name.prodLike}
		hits = append(hits, hit)
	}
	if len(hits) > 0 && remote {
		vis := s.visibility(repo, c)
		for i := range hits {
			hits[i].Visibility = vis
		}
	}
	if c.dirty {
		if err := statefile.WriteJSON(path, c); err != nil {
			s.emit.Log("data dump cache " + path + ": " + err.Error())
		}
	}
	return hits, nil
}

func (s *scan) dumpCacheDir() string {
	return filepath.Join(s.c.cacheRoot(s.home), "datadumps")
}

func (s *scan) loadDumpCache(path, repo string) *dumpCache {
	var c dumpCache
	found, err := statefile.ReadJSON(path, &c)
	if err != nil {
		s.emit.Log("data dump cache " + path + ": " + err.Error())
	}
	if !found || err != nil || c.Version != dumpCacheVersion || c.Repo != repo {
		return nil
	}
	if c.Blobs == nil {
		c.Blobs = map[string]dumpBlob{}
	}
	return &c
}

func (s *scan) dumpHistory(repo string) ([]dumpHistory, error) {
	git := guardGit(s.c.Git)
	out, err := git.Run(s.ctx, gitDirArg(repo), "log", "--all", "--no-renames", "--diff-filter=A", "--name-only", "--format=", "-z")
	if err != nil {
		return nil, fmt.Errorf("listing added files: %w", err)
	}
	var cands []string
	seen := map[string]bool{}
	for _, p := range nameOnlyPaths(out) {
		if !seen[p] && classifyDumpName(p).match {
			seen[p] = true
			cands = append(cands, p)
		}
	}
	sort.Strings(cands)
	byPath := map[string]*dumpHistory{}
	firstAt := map[string]int64{}
	onRemote := map[string]bool{}
	remote := s.hasRemote(repo)
	for chunk := range slices.Chunk(cands, dumpPathsPerCall) {
		spec := literalPathspecs(chunk)
		out, err := git.Run(s.ctx, append([]string{gitDirArg(repo), "log", "--all", "--full-history", "--no-renames", "--diff-filter=AM", "--raw", "--no-abbrev", "--format=%x01%H%x09%ct", "-z", "--"}, spec...)...)
		if err != nil {
			return nil, fmt.Errorf("reading the history of dump candidates: %w", err)
		}
		parseDumpLog(string(out), byPath, firstAt)
		if !remote {
			continue
		}
		out, err = git.Run(s.ctx, append([]string{gitDirArg(repo), "log", "--remotes", "--full-history", "--no-renames", "--diff-filter=A", "--name-only", "--format=", "-z", "--"}, spec...)...)
		if err != nil {
			return nil, fmt.Errorf("checking remote branches: %w", err)
		}
		for _, p := range nameOnlyPaths(out) {
			onRemote[p] = true
		}
	}
	var hist []dumpHistory
	for _, p := range cands {
		h, ok := byPath[p]
		if !ok {
			continue
		}
		h.OnRemote = onRemote[p]
		h.Versions = len(h.Blobs)
		if len(h.Blobs) > maxDumpBlobs {
			h.Blobs = h.Blobs[:maxDumpBlobs]
		}
		hist = append(hist, *h)
	}
	return hist, nil
}

func nameOnlyPaths(out []byte) []string {
	var paths []string
	for _, p := range strings.Split(string(out), "\x00") {
		if p = strings.TrimLeft(p, "\n"); p != "" {
			paths = append(paths, p)
		}
	}
	return paths
}

// literalPathspecs keeps git from reading a file name as a glob.
func literalPathspecs(paths []string) []string {
	out := make([]string, len(paths))
	for i, p := range paths {
		out[i] = ":(literal)" + p
	}
	return out
}

var hexID = regexp.MustCompile(`\A[0-9a-f]{40}([0-9a-f]{24})?\z`)

// parseDumpLog reads `git log --raw --no-abbrev -z --format=%x01%H%x09%ct`: blobs newest first,
// the first commit the oldest that added the path.
func parseDumpLog(out string, byPath map[string]*dumpHistory, firstAt map[string]int64) {
	var commit string
	var at int64
	fields := strings.Split(out, "\x00")
	for i := 0; i < len(fields); i++ {
		f := strings.TrimLeft(fields[i], "\n")
		switch {
		case strings.HasPrefix(f, "\x01"):
			c, t, _ := strings.Cut(f[1:], "\t")
			commit = c
			at, _ = strconv.ParseInt(strings.TrimSpace(t), 10, 64)
		case strings.HasPrefix(f, ":") && i+1 < len(fields):
			meta := strings.Fields(f)
			i++
			p := fields[i]
			if len(meta) < 5 || !hexID.MatchString(meta[3]) {
				continue
			}
			h, ok := byPath[p]
			if !ok {
				h = &dumpHistory{Path: p}
				byPath[p] = h
			}
			if !slices.Contains(h.Blobs, meta[3]) {
				h.Blobs = append(h.Blobs, meta[3])
			}
			if meta[4] == "A" {
				if old, ok := firstAt[p]; !ok || at <= old {
					firstAt[p] = at
					h.FirstCommit = leading(commit, 10)
					h.FirstDate = time.Unix(at, 0).UTC().Format("2006-01-02")
				}
			}
		}
	}
}

func (s *scan) trackedDumps(repo string) (map[string]string, error) {
	out, err := guardGit(s.c.Git).Run(s.ctx, append([]string{gitDirArg(repo), "--work-tree=" + repo, "ls-files", "-s", "-z"}, gitlocal.WholeTree()...)...)
	if err != nil {
		return nil, fmt.Errorf("listing tracked files: %w", err)
	}
	m := map[string]string{}
	for _, e := range strings.Split(string(out), "\x00") {
		meta, p, ok := strings.Cut(e, "\t")
		fs := strings.Fields(meta)
		if !ok || len(fs) < 3 || !hexID.MatchString(fs[1]) || !classifyDumpName(p).match {
			continue
		}
		m[p] = fs[1]
	}
	return m, nil
}

func (s *scan) blobInfo(repo, blob string, c *dumpCache) (dumpBlob, error) {
	if info, ok := c.Blobs[blob]; ok {
		return info, nil
	}
	var info dumpBlob
	out, err := guardGit(s.c.Git).Run(s.ctx, gitDirArg(repo), "cat-file", "-s", blob)
	if err != nil {
		return info, fmt.Errorf("blob size: %w", err)
	}
	size := strings.TrimSpace(string(out))
	if info.Size, err = strconv.ParseInt(size, 10, 64); err != nil {
		return info, fmt.Errorf("blob size %q: %w", size, err)
	}
	c.Blobs[blob], c.dirty = info, true
	return info, nil
}

// peekBlob reads a blob's first bytes once; a failure leaves the content unknown.
func (s *scan) peekBlob(repo, blob string, c *dumpCache) dumpBlob {
	info := c.Blobs[blob]
	if info.Peeked || s.c.GitHead == nil || blob == "" {
		return info
	}
	head, err := guardGitHead(s.c.GitHead).Run(s.ctx, gitDirArg(repo), "cat-file", "blob", blob)
	if err != nil {
		s.emit.Log("data dump peek " + s.tilde(repo) + ": " + err.Error())
		return info
	}
	info.Peeked = true
	info.Content, info.Header = sniffDump(head)
	c.Blobs[blob], c.dirty = info, true
	return info
}

// visibility is "" when there is no GitHub remote or gh cannot see it.
func (s *scan) visibility(repo string, c *dumpCache) string {
	if c.Visibility != "" && s.now.Sub(c.VisibilityAt) < visibilityTTL {
		return c.Visibility
	}
	slug := githubSlug(gitConfigPath(repo))
	if slug == "" || s.c.GH == nil {
		return ""
	}
	s.dumps.ghOnce.Do(func() {
		_, err := s.c.LookPath("gh")
		s.dumps.ghOK = err == nil
	})
	if !s.dumps.ghOK {
		return ""
	}
	out, err := guardGH(s.c.GH).Run(s.ctx, "repo", "view", slug, "--json", "visibility")
	if err != nil {
		s.emit.Log("gh repo view " + slug + ": " + err.Error())
		return ""
	}
	var v struct{ Visibility string }
	if json.Unmarshal(out, &v) != nil || v.Visibility == "" {
		return ""
	}
	c.Visibility, c.VisibilityAt, c.dirty = v.Visibility, s.now, true
	return v.Visibility
}

var githubSlugRe = regexp.MustCompile(`\A[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\z`)

// headExec returns at most Limit bytes of a command's output, then stops it.
type headExec struct {
	Path    string
	Limit   int
	Timeout time.Duration
	Env     []string
}

func (h headExec) Run(ctx context.Context, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, h.Timeout)
	defer cancel()
	cmd := proc.Command(ctx, h.Path, args...)
	if len(h.Env) > 0 {
		cmd.Env = append(os.Environ(), h.Env...)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	buf := make([]byte, h.Limit)
	n, rerr := io.ReadFull(stdout, buf)
	_ = cmd.Process.Kill()
	werr := cmd.Wait()
	switch {
	case rerr != nil && !errors.Is(rerr, io.EOF) && !errors.Is(rerr, io.ErrUnexpectedEOF):
		return nil, rerr
	case n < h.Limit && werr != nil: // it failed before filling the buffer (a missing object)
		return nil, fmt.Errorf("%s %s: %w", filepath.Base(h.Path), strings.Join(args, " "), werr)
	}
	return buf[:n], nil
}

func (s *scan) emitDumps(st finding.Status) error {
	if s.ctx.Err() != nil {
		return s.ctx.Err()
	}
	findings, repos := s.dumpFindings()
	for _, f := range findings {
		s.emit.Finding(f)
	}
	s.dumps.mu.Lock()
	st.Detail += fmt.Sprintf("; data dumps: %d in %d of %d repositories (%d from cache)", len(findings), repos, len(s.dumps.repos), s.dumps.cached)
	s.dumps.mu.Unlock()
	s.emit.Status(st)
	return nil
}
