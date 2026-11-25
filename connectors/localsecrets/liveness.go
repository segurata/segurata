package localsecrets

import (
	"cmp"
	"context"
	"encoding/json"
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

// livenessTimeout bounds the whole check, so a slow provider never costs the scan its findings.
const livenessTimeout = 10 * time.Minute

// heldValues are the values of the secrets the check may try, by fingerprint, and the AWS access
// key ids, which are tried only with a secret access key found in the same place.
type heldValues struct {
	byFP map[string]heldValue
	// awsIDs are the access key ids by place (path and commit), by fingerprint.
	awsIDs map[string]map[string]string
	// awsSecrets are the secret access keys' fingerprints by place.
	awsSecrets map[string][]string
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
			h.awsIDs = map[string]map[string]string{}
		}
		if h.awsIDs[place] == nil {
			h.awsIDs[place] = map[string]string{}
		}
		h.awsIDs[place][ev.Fingerprint] = value
		return
	case ev.Type == "aws-secret-key":
		if h.awsSecrets == nil {
			h.awsSecrets = map[string][]string{}
		}
		h.awsSecrets[place] = append(h.awsSecrets[place], ev.Fingerprint)
	case !liveness.Supported(ev.Type):
		return
	}
	if h.byFP == nil {
		h.byFP = map[string]heldValue{}
	}
	h.byFP[ev.Fingerprint] = heldValue{ev.Type, value}
}

// probes are the held secrets to try, one per fingerprint: an AWS secret access key with the one
// key id found in the same place (both fingerprints get the result). A secret key without its key
// id is a probe too, which the checker answers from its cache or counts as unsupported; a key id
// without its secret key is looked up in the owner's IAM inventory.
func (h heldValues) probes() []liveness.Probe {
	var out []liveness.Probe
	paired := map[string]bool{}
	for _, place := range slices.Sorted(maps.Keys(h.awsSecrets)) {
		ids := h.awsIDs[place]
		if len(ids) != 1 {
			continue
		}
		for idFP, id := range ids {
			// One key id goes with one secret key, the first by fingerprint, as the history path
			// pairs it: the others are tried alone.
			for _, fp := range slices.Sorted(slices.Values(h.awsSecrets[place])) {
				if !paired[idFP] && !paired[fp] {
					out = append(out, liveness.Probe{Fingerprints: []string{fp, idFP}, Type: "aws-secret-key", Value: h.byFP[fp].value, KeyID: id})
					paired[fp], paired[idFP] = true, true
				}
			}
		}
	}
	for fp, v := range h.byFP {
		if !paired[fp] {
			out = append(out, liveness.Probe{Fingerprints: []string{fp}, Type: v.typ, Value: v.value})
		}
	}
	for _, ids := range h.awsIDs {
		for fp, id := range ids {
			if !paired[fp] {
				paired[fp] = true
				out = append(out, liveness.Probe{Fingerprints: []string{fp}, Type: "aws-access-key-id", Value: id})
			}
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
	history := map[string]secretrisk.Evidence{}      // fingerprint -> a sighting in git history
	historyIDs := map[string][]secretrisk.Evidence{} // place -> AWS key ids committed there
	for _, f := range fs {
		ev, ok := findingEvidence(f)
		if !ok || isNoise(f) {
			continue
		}
		claims[ev.Fingerprint] = append(claims[ev.Fingerprint], ev.Claims)
		types[ev.Fingerprint] = ev.Type
		if ev.Source == "gitleaks" && ev.Commit != "" && ev.Line > 0 {
			if _, seen := history[ev.Fingerprint]; !seen {
				history[ev.Fingerprint] = ev
			}
			if ev.Type == "aws-access-key-id" && pairableKeyID(ev.Redacted) {
				place := historyPlace(ev)
				historyIDs[place] = append(historyIDs[place], ev)
			}
		}
	}
	// Every reported secret a provider could judge: with its value when the run read it, else (git
	// history replayed from the cache) with a way to read it again from the commit, or only to
	// look in the liveness cache. AWS secret keys go first, so their key ids ride along with them.
	candidates := s.held.probes()
	covered := map[string]bool{}
	for _, p := range candidates {
		for _, fp := range p.Fingerprints {
			covered[fp] = true
		}
	}
	secretKeysFirst := func(fp string) int {
		if types[fp] == "aws-secret-key" {
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
			case "aws-secret-key":
				if id, ok := onlyKeyID(historyIDs[historyPlace(ev)]); ok && !covered[id.Fingerprint] {
					covered[id.Fingerprint] = true
					p.Fingerprints = append(p.Fingerprints, id.Fingerprint)
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
	ch := s.c.checker(s.home, s.cfg.liveness)
	if ch.Now == nil {
		ch.Now = s.c.Now
	}
	ch.Attribution = func(fp string) (attribution.Owner, bool) {
		c, reported := claims[fp]
		return known.Of(fp, c), reported
	}
	lctx, cancel := context.WithTimeout(ctx, livenessTimeout)
	defer cancel()
	results, st := ch.Check(lctx, probes)
	for i := range fs {
		ev, ok := findingEvidence(fs[i])
		if !ok {
			continue
		}
		if r, found := results[ev.Fingerprint]; found {
			fs[i].Evidence["liveness"] = r
		}
	}
	line := "; " + st.String()
	if err := ch.Cache.Save(ch.Now()); err != nil {
		line += fmt.Sprintf("; liveness cache not saved: %v", err)
	}
	return line
}

// pairableKeyID reports whether an AWS access key id (or its redacted hint) can be tried with a
// secret key: a long-term AKIA id. A temporary ASIA id needs its session token, which segurata does
// not pair; signed without it, STS would reject a pair that works.
func pairableKeyID(s string) bool { return strings.HasPrefix(s, "AKIA") }

// historyPlace is where a history leak sits: repository, file and commit.
func historyPlace(ev secretrisk.Evidence) string {
	return ev.Repo + "\x00" + ev.Path + "\x00" + ev.Commit
}

// onlyKeyID is the one AWS key id among ids (by fingerprint), if there is exactly one.
func onlyKeyID(ids []secretrisk.Evidence) (secretrisk.Evidence, bool) {
	var one secretrisk.Evidence
	for _, id := range ids {
		if one.Fingerprint != "" && id.Fingerprint != one.Fingerprint {
			return secretrisk.Evidence{}, false
		}
		one = id
	}
	return one, one.Fingerprint != ""
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

// checker is the real checker unless a test gives one: the providers' hosts, the cache under
// ~/.cache/segurata, and the owner's gh, aws and ssh for the lookups.
func (c *Connector) checker(home string, cfg liveness.Config) *liveness.Checker {
	if c.NewChecker != nil {
		return c.NewChecker(home, cfg)
	}
	return &liveness.Checker{Config: cfg, Cache: liveness.LoadCache(liveness.DefaultCachePath(home)),
		Owner: liveness.Owner{AWS: c.AWS, GH: c.GH, SSH: c.SSH, Home: home}}
}

// findingEvidence reads a secret finding's evidence back.
func findingEvidence(f finding.Finding) (secretrisk.Evidence, bool) {
	raw, _ := json.Marshal(f.Evidence)
	var ev secretrisk.Evidence
	if json.Unmarshal(raw, &ev) != nil || ev.Fingerprint == "" {
		return ev, false
	}
	return ev, true
}
