package finding

import "strings"

// Area is a part of the plan (docs/plan.md) a connector audits, such as the two-factor
// authentication of the owner's own GitHub account. A connector declares the areas it covers in
// its description; the core writes them into run_end, and the tracker's "not audited" item for an
// area closes once a run audited it and opens while the runs that cover it could not.
type Area struct {
	ID string `json:"id"`
	// Scope is the prefix of the status scopes that say whether the area was read ("user:" for the
	// GitHub account); "" for every status of the run.
	Scope string `json:"scope,omitempty"`
}

// Audited reports whether a run with these statuses audited the area: a status of the area says
// ok, or none says otherwise.
func (a Area) Audited(statuses []Status) bool {
	var ok, failed bool
	for _, st := range statuses {
		switch {
		case !strings.HasPrefix(st.Scope, a.Scope):
		case st.State == StateOK:
			ok = true
		default:
			failed = true
		}
	}
	return ok || !failed
}
