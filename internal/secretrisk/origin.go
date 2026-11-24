package secretrisk

import (
	"strings"
	"time"
)

// Whose repository a committed copy sits in. A key committed to instructure/canvas-lms or to the
// history a fork inherited from its upstream is the upstream's to rotate, not the owner's: such
// copies are noise for rotation unless the same value is also in one of the owner's own files
// (Reused). The local-secrets connector decides the origin from each repository's GitHub remotes
// and the owner's account and organizations.
const (
	OriginOwned        = "owned"         // the remote's owner is the user or one of their organizations
	OriginThirdParty   = "third-party"   // the remote belongs to someone else
	OriginForkUpstream = "fork-upstream" // a fork's copy of a commit its upstream already had
)

// NotOwners reports whether a copy with this origin belongs to someone else's repository and
// nothing ties its value to the owner.
func NotOwners(origin string, reused bool) bool {
	return !reused && (origin == OriginThirdParty || origin == OriginForkUpstream)
}

// UpstreamSpot is the spot of a copy in someone else's repository: it exposes the upstream's
// secret, not the owner's, so it counts as local. ok is false for the owner's copies.
func UpstreamSpot(origin string, reused bool) (Spot, bool) {
	if !NotOwners(origin, reused) {
		return Spot{}, false
	}
	if origin == OriginForkUpstream {
		return Spot{Local, origin, "in history a fork inherited from its upstream (the upstream's secret)"}, true
	}
	return Spot{Local, origin, "committed to a third-party repository (the upstream's secret)"}, true
}

// UpstreamOnly reports whether a copy is noise only because it sits in someone else's repository:
// were it the owner's, it would count. Attribution can still make it the owner's (an AWS key id
// decoding to one of the owner's accounts), so the connector emits such copies when they name an
// account, and the tracker counts them in full when the secret is attributed mine.
func UpstreamOnly(e Evidence) bool {
	if !NotOwners(e.Origin, e.Reused) {
		return false
	}
	e.Reused = true
	return ImpactOf(e) != Noise
}

// STSLifetime is the longest an AWS temporary credential (key id ASIA…) lives: 36 hours for a
// role session, less for most.
const STSLifetime = 36 * time.Hour

// TemporaryAWS reports whether the evidence is an AWS temporary key id, alone or inside a
// pre-signed URL.
func TemporaryAWS(e Evidence) bool {
	return (strings.HasPrefix(e.Type, "aws-access") || e.Type == "aws-presigned-url") && strings.HasPrefix(e.Redacted, "ASIA")
}

// ExpireTemporaryAWS marks a temporary AWS key id seen at a time more than STSLifetime before now
// (the commit date, or the file's modification time) as expired, hence public: whatever it signed
// stopped working. It reports whether it changed the evidence.
func ExpireTemporaryAWS(e *Evidence, seen, now time.Time) bool {
	if !TemporaryAWS(*e) || seen.IsZero() || now.Sub(seen) <= STSLifetime || e.Public {
		return false
	}
	e.Public = true
	if !strings.Contains(e.Note, "expired") {
		e.Note = strings.TrimSpace(e.Note + " expired")
	}
	return true
}
