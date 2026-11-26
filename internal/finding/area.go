package finding

import "strings"

// Area is a part of the plan (docs/plan.md) a connector audits; the tracker's "not audited" item
// for it follows the runs that cover it.
type Area struct {
	ID string `json:"id"`
	// Scope is the prefix of the status scopes that read the area ("user:"); "" for every status.
	Scope string `json:"scope,omitempty"`
}

// Audited reports whether a status of the area says ok, or none says otherwise.
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
