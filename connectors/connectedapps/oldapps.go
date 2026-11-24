package connectedapps

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/segurata/segurata/internal/finding"
)

// oldAfter is the approval age past which a service's apps are revoked as one batch: most apps
// authorized that long ago belong to defunct services (on X: Posterous, Vine, Klout, Delicious),
// and nobody reviews them one by one.
const oldAfter = 10 * 365 * 24 * time.Hour

// oldBatch is how a service words the batch of its apps approved more than oldAfter ago.
type oldBatch struct {
	title    string // the service as the owner knows it: "X", "Dropbox"
	verb     string // what the owner does to each app: "Revoke", "Disconnect"
	approved string // how the service words approval: "authorized", "linked"
	note     string // appended to the batch title, such as " (services mostly defunct)"
	url      string // the page listing the apps
	each     string // how to remove one app on that page
	again    string // what happens to an app still in use
}

// reportByAge reports apps oldest approval first, so apps of one severity are listed by age
// (undated ones last), and folds every app approved more than oldAfter ago into one finding.
// It records each dated app's age in years in its evidence.
func (e *env) reportByAge(who string, apps []grant, b oldBatch) {
	sort.SliceStable(apps, func(i, j int) bool {
		a, c := apps[i].created, apps[j].created
		return a != nil && (c == nil || a.Before(*c))
	})
	var old []grant
	for _, g := range apps {
		if g.created != nil {
			if g.extra == nil {
				g.extra = map[string]any{}
			}
			g.extra["age_years"] = int(e.now.Sub(*g.created).Hours() / 24 / 365)
			if e.now.Sub(*g.created) > oldAfter {
				old = append(old, g)
				continue
			}
		}
		e.report(g)
	}
	if len(old) > 0 {
		e.emit.Finding(e.oldAppsFinding(who, old, b))
	}
}

// oldAppsFinding is one finding for every app in old, as bad as the worst of them, listing each
// with its date and what it can do.
func (e *env) oldAppsFinding(who string, old []grant, b oldBatch) finding.Finding {
	worst := finding.SevInfo
	var names []string
	var apps []map[string]any
	for _, g := range old {
		sev, label := assess(e.service, g)
		if sev.Rank() > worst.Rank() {
			worst = sev
		}
		names = append(names, g.name)
		apps = append(apps, map[string]any{"name": g.name, "approved": g.created.Format(time.DateOnly), "severity": sev,
			"can": label, "publisher": g.publisher, "url": g.url})
	}
	years := int(oldAfter.Hours() / 24 / 365)
	cutoff := e.now.Add(-oldAfter).Format("January 2006")
	resType := e.service + "_old_apps"
	return finding.Finding{
		ID:        finding.StableID(name, resType, e.account(who)),
		Account:   e.account(who),
		Resource:  finding.Resource{Type: resType, ID: e.service + ":old-apps", Name: fmt.Sprintf("%s apps approved more than %d years ago", b.title, years)},
		Kind:      finding.KindGrant,
		Severity:  worst,
		Title:     fmt.Sprintf("%s %d %s %s %s before %s%s", b.verb, len(old), b.title, apps1(len(old)), b.approved, cutoff, b.note),
		Evidence:  map[string]any{"service": e.service, "apps": apps, "names": names, "older_than_years": years},
		CreatedAt: old[0].created,
		Remediation: finding.Remediation{
			Summary: fmt.Sprintf("Open %s and %s each of them (%s): %s. %s", b.url, strings.ToLower(b.verb), strings.Join(names, ", "), b.each, b.again),
			URL:     b.url,
		},
	}
}

// apps1 is "app" or "apps", for n of them.
func apps1(n int) string {
	if n == 1 {
		return "app"
	}
	return "apps"
}
