package localsecrets

import (
	"context"
	"encoding/json"
	"fmt"
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

// newChecker is the real checker: the providers' hosts and the cache under ~/.cache/segurata.
func newChecker(home string, cfg liveness.Config) *liveness.Checker {
	return &liveness.Checker{Config: cfg, Cache: liveness.LoadCache(liveness.DefaultCachePath(home))}
}

// heldValues are the values of the secrets the check may try, by fingerprint, and the AWS key ids
// found next to each secret access key.
type heldValues struct {
	byFP map[string]heldValue
	// awsIDs are the access key ids by place (path and commit), by fingerprint.
	awsIDs map[string]map[string]string
	// awsSecrets are the secret access keys' fingerprints by place.
	awsSecrets map[string][]string
}

type heldValue struct{ typ, value string }

// hold keeps the value of a prepared secret the check could try. The caller holds s.mu or is the
// only goroutine.
func (s *scan) hold(abs string, ev secretrisk.Evidence, value string) {
	if !s.cfg.liveness.Enabled || ev.Public || ev.Encrypted {
		return
	}
	h := &s.held
	place := abs + "\x00" + ev.Commit
	switch {
	case ev.Type == "aws-access-key-id" && strings.HasPrefix(value, "AKIA"):
		if h.awsIDs == nil {
			h.awsIDs = map[string]map[string]string{}
		}
		if h.awsIDs[place] == nil {
			h.awsIDs[place] = map[string]string{}
		}
		h.awsIDs[place][ev.Fingerprint] = value
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

// probes are the secrets to try: one per fingerprint whose value is held, an AWS secret access key
// with the one key id found in the same place (both fingerprints get the result).
func (h heldValues) probes() []liveness.Probe {
	var out []liveness.Probe
	paired := map[string]bool{}
	for place, secrets := range h.awsSecrets {
		ids := h.awsIDs[place]
		if len(ids) != 1 {
			continue
		}
		for idFP, id := range ids {
			for _, fp := range secrets {
				out = append(out, liveness.Probe{Fingerprints: []string{fp, idFP}, Type: "aws-secret-key", Value: h.byFP[fp].value, KeyID: id})
				paired[fp], paired[idFP] = true, true
			}
		}
	}
	for fp, v := range h.byFP {
		if !paired[fp] && v.typ != "aws-access-key-id" && v.typ != "aws-secret-key" {
			out = append(out, liveness.Probe{Fingerprints: []string{fp}, Type: v.typ, Value: v.value})
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
	for _, f := range fs {
		if ev, ok := findingEvidence(f); ok && !isNoise(f) {
			claims[ev.Fingerprint] = append(claims[ev.Fingerprint], ev.Claims)
			types[ev.Fingerprint] = ev.Type
		}
	}
	// Every reported secret a provider could judge: with its value when the run read it, else
	// (git history replayed from the cache) only to look in the liveness cache.
	candidates := s.held.probes()
	covered := map[string]bool{}
	for _, p := range candidates {
		for _, fp := range p.Fingerprints {
			covered[fp] = true
		}
	}
	for fp, typ := range types {
		if !covered[fp] && (liveness.Supported(typ) || typ == "aws-access-key-id") {
			candidates = append(candidates, liveness.Probe{Fingerprints: []string{fp}, Type: typ})
		}
	}
	var probes []liveness.Probe
	refused := 0
	for _, p := range candidates {
		fp := p.Fingerprints[0]
		switch _, reported := claims[fp]; {
		case !reported: // noise, or dropped after it was held
		case !s.cfg.liveness.Allows(known.Of(fp, claims[fp])):
			refused++
		default:
			probes = append(probes, p)
		}
	}
	ch := s.c.checker(s.home, s.cfg.liveness)
	if ch.Now == nil {
		ch.Now = s.c.Now
	}
	lctx, cancel := context.WithTimeout(ctx, livenessTimeout)
	defer cancel()
	results, st := ch.Check(lctx, probes)
	st.NotAllowed += refused
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

func (c *Connector) checker(home string, cfg liveness.Config) *liveness.Checker {
	if c.NewChecker != nil {
		return c.NewChecker(home, cfg)
	}
	return newChecker(home, cfg)
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
