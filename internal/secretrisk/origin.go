package secretrisk

import (
	"strings"
	"time"
)

// Whose repository a committed copy sits in. A key committed to someone else's project, or to the
// history a fork inherited, is the upstream's to rotate: noise unless the same value is also in one
// of the owner's own files (Reused).
const (
	OriginOwned        = "owned"         // the remote's owner is the user or one of their organizations
	OriginThirdParty   = "third-party"   // the remote belongs to someone else
	OriginForkUpstream = "fork-upstream" // a fork's copy of a commit its upstream already had
)

// NotOwners reports whether a copy sits in someone else's repository and nothing ties its value to
// the owner.
func NotOwners(origin string, reused bool) bool {
	return !reused && (origin == OriginThirdParty || origin == OriginForkUpstream)
}

// UpstreamSpot is the spot of a copy in someone else's repository, which counts as local; ok is
// false for the owner's copies.
func UpstreamSpot(origin string, reused bool) (Spot, bool) {
	if !NotOwners(origin, reused) {
		return Spot{}, false
	}
	if origin == OriginForkUpstream {
		return Spot{Local, origin, "in history a fork inherited from its upstream (the upstream's secret)"}, true
	}
	return Spot{Local, origin, "committed to a third-party repository (the upstream's secret)"}, true
}

// UpstreamOnly reports whether a copy is noise only because it sits in someone else's repository.
// Attribution can still make it the owner's (an AWS key id of one of the owner's accounts).
func UpstreamOnly(e Evidence) bool {
	if !NotOwners(e.Origin, e.Reused) {
		return false
	}
	e.Reused = true
	return ImpactOf(e) != Noise
}

// stsLifetime is the longest an AWS temporary credential (ASIA…) lives.
const stsLifetime = 36 * time.Hour

// TemporaryAWS reports whether the evidence is an AWS temporary key id, alone or inside a
// pre-signed URL.
func TemporaryAWS(e Evidence) bool {
	return (strings.HasPrefix(e.Type, "aws-access") || e.Type == "aws-presigned-url") && strings.HasPrefix(e.Redacted, "ASIA")
}

// ExpireTemporaryAWS marks a temporary AWS key id seen (commit date, file mtime) more than
// stsLifetime before now as expired, hence public. It reports whether it changed the evidence.
func ExpireTemporaryAWS(e *Evidence, seen, now time.Time) bool {
	if !TemporaryAWS(*e) || seen.IsZero() || now.Sub(seen) <= stsLifetime || e.Public {
		return false
	}
	e.Public = true
	if !strings.Contains(e.Note, "expired") {
		e.Note = strings.TrimSpace(e.Note + " expired")
	}
	return true
}
