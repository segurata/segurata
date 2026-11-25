package localsecrets

import (
	"cmp"
	"context"
	"fmt"
	"maps"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/segurata/segurata/connectors/internal/liveness"
	"github.com/segurata/segurata/internal/attribution"
	"github.com/segurata/segurata/internal/finding"
	"github.com/segurata/segurata/internal/secretrisk"
)

// The liveness check (connectors/internal/liveness), run here because the scan is the only moment
// segurata holds the values: each distinct secret the run reports (not noise), attributed to an
// owner the config allows, of a type a provider endpoint takes, is tried once, and every finding
// of it gets the result in its evidence. Values stay in memory for the length of the run. See
// docs/architecture.md, "Liveness".

// livenessTimeout bounds the whole check, and livenessMargin is the time it leaves before the
// run's deadline: the findings are emitted after it, and a slow provider never costs the scan
// them (livenessDeadline).
const (
	livenessTimeout = 10 * time.Minute
	livenessMargin  = time.Minute
)

// livenessDeadline is when the check stops: livenessTimeout from now, or livenessMargin before the
// run's deadline when that comes first.
func livenessDeadline(ctx context.Context, now time.Time) time.Time {
	at := now.Add(livenessTimeout)
	if d, ok := ctx.Deadline(); ok && d.Add(-livenessMargin).Before(at) {
		at = d.Add(-livenessMargin)
	}
	return at
}

// awsPairLines is how many lines apart an AWS secret access key and its key id may be written and
// still pair by proximity. A credentials file, an .env or an Ansible vars block puts the two on
// consecutive lines, sometimes with a region, a bucket or a session token between; five lines
// take such a block and stop short of an unrelated key id further down the file.
const awsPairLines = 5

// nearKeyID reports whether line is within awsPairLines of one of the key id lines.
func nearKeyID(keyIDLines []int, line int) bool {
	return slices.ContainsFunc(keyIDLines, func(l int) bool { return max(l-line, line-l) <= awsPairLines })
}

// awsSighting is one AWS key id or secret access key seen in a place, by fingerprint and line.
type awsSighting struct {
	fp   string
	line int
}

// awsPlace is what one place (a file, or a file in one commit) holds of AWS credentials.
type awsPlace struct{ ids, secrets []awsSighting }

// awsPlaces are the AWS key ids and secret keys seen, by place.
type awsPlaces map[string]*awsPlace

// add records a key id (id) or a secret key seen at a place.
func (ps *awsPlaces) add(place string, id bool, ev secretrisk.Evidence) {
	if *ps == nil {
		*ps = awsPlaces{}
	}
	p := (*ps)[place]
	if p == nil {
		p = &awsPlace{}
		(*ps)[place] = p
	}
	s := awsSighting{ev.Fingerprint, ev.Line}
	if id {
		p.ids = append(p.ids, s)
	} else {
		p.secrets = append(p.secrets, s)
	}
}

// pairs pairs every place's secret keys with its key ids (awsPlace.pair), places in order, so a
// key id paired in one place is not paired again in another.
func (ps awsPlaces) pairs(taken map[string]bool) [][2]string {
	var out [][2]string
	for _, place := range slices.Sorted(maps.Keys(ps)) {
		out = append(out, ps[place].pair(taken)...)
	}
	return out
}

// pair matches the place's secret keys with its key ids, one to one, and returns the pairs as
// {secret key, key id} fingerprints; fingerprints in taken are left alone, and those paired are
// added to it. A secret key pairs with a key id at most awsPairLines lines away, on the side the
// place writes key ids (above the secret key when its first key id comes first, below otherwise),
// the nearest first: in
//
//	a_access_key_id: AKIA…1
//	a_region: eu-west-1
//	a_secret_access_key: …1
//	b_access_key_id: AKIA…2
//
// the first secret key is two lines below its key id and one above the next block's, and pairs
// with its own. A secret key that finds none pairs with the place's only key id, however far, as
// a place holding one key id was always read.
func (p awsPlace) pair(taken map[string]bool) [][2]string {
	if len(p.ids) == 0 || len(p.secrets) == 0 {
		return nil
	}
	firstLine := func(ss []awsSighting) int {
		return slices.MinFunc(ss, func(a, b awsSighting) int { return cmp.Compare(a.line, b.line) }).line
	}
	idsAbove := firstLine(p.ids) <= firstLine(p.secrets)
	type edge struct {
		s, id      awsSighting
		side, dist int
	}
	var edges []edge
	for _, s := range p.secrets {
		for _, id := range p.ids {
			d := s.line - id.line // > 0: the key id is above
			if max(d, -d) > awsPairLines {
				continue
			}
			side := 0
			if d != 0 && (d > 0) != idsAbove {
				side = 1
			}
			edges = append(edges, edge{s, id, side, max(d, -d)})
		}
	}
	slices.SortFunc(edges, func(a, b edge) int {
		return cmp.Or(cmp.Compare(a.side, b.side), cmp.Compare(a.dist, b.dist), cmp.Compare(a.s.line, b.s.line),
			cmp.Compare(a.s.fp, b.s.fp), cmp.Compare(a.id.line, b.id.line), cmp.Compare(a.id.fp, b.id.fp))
	})
	var out [][2]string
	match := func(s, id string) {
		out = append(out, [2]string{s, id})
		taken[s], taken[id] = true, true
	}
	for _, e := range edges {
		if !taken[e.s.fp] && !taken[e.id.fp] {
			match(e.s.fp, e.id.fp)
		}
	}
	if id := p.ids[0].fp; !taken[id] && !slices.ContainsFunc(p.ids, func(o awsSighting) bool { return o.fp != id }) {
		secrets := slices.SortedFunc(slices.Values(p.secrets), func(a, b awsSighting) int {
			return cmp.Or(cmp.Compare(a.line, b.line), cmp.Compare(a.fp, b.fp))
		})
		if i := slices.IndexFunc(secrets, func(s awsSighting) bool { return !taken[s.fp] }); i >= 0 {
			match(secrets[i].fp, id)
		}
	}
	return out
}

// heldValues are the values of the secrets the check may try, by fingerprint, and the AWS access
// key ids, which are tried only with a secret access key found in the same place.
type heldValues struct {
	byFP map[string]heldValue
	// awsIDs are the long-term access key ids, by fingerprint.
	awsIDs map[string]string
	// aws are the access key ids and secret access keys seen, by place (path and commit).
	aws awsPlaces
}

type heldValue struct{ typ, value string }

// hold keeps the value of a prepared secret the check could try. The caller holds s.mu.
func (s *scan) hold(abs string, ev secretrisk.Evidence, value string) {
	if !s.cfg.liveness.Enabled || ev.Public || ev.Encrypted {
		return
	}
	h := &s.held
	place := abs + "\x00" + ev.Commit
	switch {
	case ev.Type == "aws-access-key-id" && pairableKeyID(value):
		if h.awsIDs == nil {
			h.awsIDs = map[string]string{}
		}
		h.awsIDs[ev.Fingerprint] = value
		h.aws.add(place, true, ev)
		return
	case ev.Type == "cloudflare-token" && !namesCloudflare(ev):
		return // CF_TOKEN may be any provider's: it is never sent to Cloudflare
	case ev.Type == awsSecretType:
		h.aws.add(place, false, ev)
	case !liveness.Supported(ev.Type):
		return
	}
	if h.byFP == nil {
		h.byFP = map[string]heldValue{}
	}
	h.byFP[ev.Fingerprint] = heldValue{ev.Type, value}
}

// probes are the held secrets to try, one per fingerprint: an AWS secret access key with the key
// id its place pairs it with (awsPlace.pair; both fingerprints get the result). A secret key
// without its key id is a probe too, which the checker answers from its cache or counts as
// unsupported; a key id without its secret key is looked up in the owner's IAM inventory.
func (h heldValues) probes() []liveness.Probe {
	var out []liveness.Probe
	paired := map[string]bool{}
	for _, pr := range h.aws.pairs(paired) {
		out = append(out, liveness.Probe{Fingerprints: []string{pr[0], pr[1]}, Type: awsSecretType, Value: h.byFP[pr[0]].value, KeyID: h.awsIDs[pr[1]]})
	}
	for fp, v := range h.byFP {
		if !paired[fp] {
			out = append(out, liveness.Probe{Fingerprints: []string{fp}, Type: v.typ, Value: v.value})
		}
	}
	for fp, id := range h.awsIDs {
		if !paired[fp] {
			out = append(out, liveness.Probe{Fingerprints: []string{fp}, Type: "aws-access-key-id", Value: id})
		}
	}
	return out
}

// checkLiveness tries the secrets of the findings about to be emitted and writes each result into
// the evidence of every finding of that secret. It returns the line for the status detail.
func (s *scan) checkLiveness(ctx context.Context, fs []finding.Finding, known *attribution.Known) string {
	if !s.cfg.liveness.Enabled {
		return ""
	}
	if known == nil {
		return "; liveness: not run (this run was given no attribution, so it cannot tell whose each secret is)"
	}
	claims := map[string][]attribution.Claims{}
	types := map[string]string{}
	history := map[string]secretrisk.Evidence{}    // fingerprint -> a sighting in git history
	var historyAWS awsPlaces                       // AWS key ids and secret keys committed, by place
	historyIDs := map[string]secretrisk.Evidence{} // fingerprint -> a sighting of a long-term key id
	for _, f := range fs {
		ev, ok := secretrisk.EvidenceOf(f)
		if !ok || isNoise(f) {
			continue
		}
		claims[ev.Fingerprint] = append(claims[ev.Fingerprint], ev.Claims)
		types[ev.Fingerprint] = ev.Type
		if ev.Source == "gitleaks" && ev.Commit != "" && ev.Line > 0 {
			if _, seen := history[ev.Fingerprint]; !seen {
				history[ev.Fingerprint] = ev
			}
			id := ev.Type == "aws-access-key-id" && pairableKeyID(ev.Redacted)
			if id || ev.Type == awsSecretType {
				historyAWS.add(historyPlace(ev), id, ev)
			}
			if id {
				historyIDs[ev.Fingerprint] = ev
			}
		}
	}
	// Every reported secret a provider could judge: with its value when the run read it, else (git
	// history replayed from the cache) with a way to read it again from the commit, or only to
	// look in the liveness cache. AWS secret keys go first, so their key ids ride along with them,
	// paired place by place as the held ones are.
	candidates := s.held.probes()
	covered := map[string]bool{}
	for _, p := range candidates {
		for _, fp := range p.Fingerprints {
			covered[fp] = true
		}
	}
	historyPairs := map[string]string{} // secret key -> key id
	for _, pr := range historyAWS.pairs(maps.Clone(covered)) {
		historyPairs[pr[0]] = pr[1]
	}
	secretKeysFirst := func(fp string) int {
		if types[fp] == awsSecretType {
			return 0
		}
		return 1
	}
	reported := slices.SortedFunc(maps.Keys(types), func(a, b string) int {
		return cmp.Or(cmp.Compare(secretKeysFirst(a), secretKeysFirst(b)), cmp.Compare(a, b))
	})
	for _, fp := range reported {
		typ := types[fp]
		if covered[fp] || !liveness.Supported(typ) {
			continue
		}
		covered[fp] = true
		p := liveness.Probe{Fingerprints: []string{fp}, Type: typ}
		if ev, ok := history[fp]; ok {
			switch typ {
			case awsSecretType:
				if idFP, ok := historyPairs[fp]; ok && !covered[idFP] {
					id := historyIDs[idFP]
					covered[idFP] = true
					p.Fingerprints = append(p.Fingerprints, idFP)
					p.Recover = s.recoverer(ev, &id)
				}
			default:
				p.Recover = s.recoverer(ev, nil)
			}
		}
		candidates = append(candidates, p)
	}
	// A probe of a secret no longer reported (noise, or dropped after it was held) is left out; the
	// checker refuses any other whose fingerprints are not all attributed to an owner it allows.
	probes := slices.DeleteFunc(candidates, func(p liveness.Probe) bool {
		_, reported := claims[p.Fingerprints[0]]
		return !reported
	})
	// A pair is the account's its key id names: the secret key, which names none by itself (or two,
	// in a file of several pairs), is attributed as its key id is, which also keeps a pair whose
	// key id is someone else's from ever being sent.
	// Each half of a pair names the other (Evidence.Pair), so the tracker folds the key id into its
	// secret key's item: one key to deactivate, one item.
	pairOf := map[string]string{}
	for _, p := range probes {
		if p.Type == awsSecretType && len(p.Fingerprints) == 2 {
			claims[p.Fingerprints[0]] = append(claims[p.Fingerprints[0]], claims[p.Fingerprints[1]]...)
			pairOf[p.Fingerprints[0]], pairOf[p.Fingerprints[1]] = p.Fingerprints[1], p.Fingerprints[0]
		}
	}
	ch := s.c.checker(s.home, s.cfg.liveness)
	if ch.Now == nil {
		ch.Now = s.c.Now
	}
	ch.Attribution = func(fp string) (attribution.Owner, bool) {
		c, reported := claims[fp]
		return known.Of(fp, c), reported
	}
	lctx, cancel := context.WithDeadline(ctx, livenessDeadline(ctx, time.Now()))
	defer cancel()
	results, st := ch.Check(lctx, probes)
	for i := range fs {
		ev, ok := secretrisk.EvidenceOf(fs[i])
		if !ok {
			continue
		}
		r, found := results[ev.Fingerprint]
		pair := pairOf[ev.Fingerprint]
		if !found && pair == "" {
			continue
		}
		if found {
			ev.Liveness = &r
		}
		ev.Pair = pair
		fs[i].Evidence = ev.Map()
	}
	line := "; " + st.String()
	if err := ch.Cache.Save(ch.Now()); err != nil {
		line += fmt.Sprintf("; liveness cache not saved: %v", err)
	}
	return line
}

// namesCloudflare reports whether a Cloudflare token's context names Cloudflare: gitleaks' rule
// requires the word, this connector's pattern also takes a bare CF_ key, kept in the note.
func namesCloudflare(ev secretrisk.Evidence) bool {
	return ev.Source == "gitleaks" || strings.Contains(strings.ToLower(ev.Note), "cloudflare")
}

// pairableKeyID reports whether an AWS access key id (or its redacted hint) can be tried with a
// secret key: a long-term AKIA id. A temporary ASIA id needs its session token, which segurata does
// not pair; signed without it, STS would reject a pair that works.
func pairableKeyID(s string) bool { return strings.HasPrefix(s, "AKIA") }

// historyPlace is where a history leak sits: repository, file and commit.
func historyPlace(ev secretrisk.Evidence) string {
	return ev.Repo + "\x00" + ev.Path + "\x00" + ev.Commit
}

// maxRecoverBlob is the largest committed file read to recover a value: a secret in a bigger one
// (a database dump) stays unchecked.
const maxRecoverBlob = 8 << 20

// recoverer reads a history leak's value again at check time, and the key id's when one is given:
// the line gitleaks reported (and its neighbours) in the file as committed, searched for the
// window whose fingerprint is the secret's (fingerprint.Key.Find, as `rotations replace` locates
// an old value). The value lives only in the probe for the length of the check.
func (s *scan) recoverer(ev secretrisk.Evidence, id *secretrisk.Evidence) func(context.Context) (string, string, bool) {
	return func(ctx context.Context) (string, string, bool) {
		value, ok := s.recoverValue(ctx, ev)
		if !ok || id == nil {
			return value, "", ok
		}
		keyID, ok := s.recoverValue(ctx, *id)
		return value, keyID, ok
	}
}

func (s *scan) recoverValue(ctx context.Context, ev secretrisk.Evidence) (string, bool) {
	h, ok := secretrisk.ParseHint(ev.Redacted)
	if !ok || h.Len == 0 || ev.Repo == "" {
		return "", false
	}
	repo := expandHome(ev.Repo, s.home)
	object := ev.Commit + ":" + filepath.ToSlash(strings.TrimPrefix(ev.Path, ev.Repo+"/"))
	git := guardGit(s.c.Git)
	size, err := git.Run(ctx, gitDirArg(repo), "cat-file", "-s", object)
	if n, perr := strconv.Atoi(strings.TrimSpace(string(size))); err != nil || perr != nil || n > maxRecoverBlob {
		return "", false
	}
	blob, err := git.Run(ctx, gitDirArg(repo), "cat-file", "blob", object)
	if err != nil {
		return "", false
	}
	lines := strings.Split(string(blob), "\n")
	for _, n := range []int{ev.Line, ev.Line - 1, ev.Line + 1} {
		if n >= 1 && n <= len(lines) {
			if v := s.fp.Find(lines[n-1], h.Len, ev.Fingerprint, h.Fits); v != "" {
				return v, true
			}
		}
	}
	return "", false
}

// checker is the real checker unless a test gives one: the providers' hosts, the cache beside the
// other caches (~/.cache/segurata/liveness.json), and the owner's gh, aws and ssh for the lookups.
func (c *Connector) checker(home string, cfg liveness.Config) *liveness.Checker {
	if c.NewChecker != nil {
		return c.NewChecker(home, cfg)
	}
	return &liveness.Checker{Config: cfg, Cache: liveness.LoadCache(filepath.Join(c.cacheRoot(home), "liveness.json")),
		Owner: liveness.Owner{AWS: c.AWS, AWSIssuers: c.AWSIssuers, GH: c.GH, SSH: c.SSH, Home: home}}
}
