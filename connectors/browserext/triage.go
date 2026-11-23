package browserext

import (
	"cmp"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/segurata/segurata/internal/finding"
)

// Verdicts, in increasing order of urgency.
type verdict int

const (
	keep verdict = iota
	review
	remove
)

func (v verdict) String() string { return [...]string{"keep", "review", "remove"}[v] }

// staleAfter: an extension not updated for this long is either abandoned or sits in a profile
// nobody opens.
const staleAfter = 365 * 24 * time.Hour

// Risk capabilities, in plain words. capAllSites is granted access to every site; the rest map
// from Chromium API permissions.
const capAllSites = "read and change all sites"

var apiCapability = map[string]string{
	"debugger": "debugger", "cookies": "cookies", "webRequest": "webRequest", "webRequestBlocking": "webRequest",
	"nativeMessaging": "nativeMessaging", "clipboardRead": "clipboard read", "history": "history",
	"downloads": "downloads", "management": "management",
}

// Capabilities that make a "remove" verdict high rather than medium.
var severe = map[string]bool{capAllSites: true, "debugger": true, "cookies": true, "nativeMessaging": true}

// Category hints. IDs are the Chrome Web Store ids of extensions seen on the owner's machine;
// names catch the rest. Kept short on purpose: a hint, not a catalogue.
const (
	catPasswords = "password manager"
	catWallet    = "crypto wallet"
	catAI        = "AI assistant"
	catShopping  = "shopping"
	catDev       = "dev tool"
)

var categoryByID = map[string]string{
	"aeblfdkhhhdcdjpifhhbdiojplfjncoa": catPasswords, // 1Password
	"nngceckbapebfimnlniiiahkandclblb": catPasswords, // Bitwarden
	"nkbihfbeogaeaoehlefnkodbefgpgknn": catWallet,    // MetaMask
	"acmacodkjbdgmoleebolmdjonilkdbch": catWallet,    // Rabby Wallet
	"dmkamcknogkgcdfhhbddcghachkejeap": catWallet,    // Keplr
	"hehggadaopoacecdllhhajmbjkdcmajg": catAI,        // ChatGPT
	"neebplgakaahbhdphmkckjjcegoiijjo": catShopping,  // Keepa
}

var categoryWords = []struct{ word, cat string }{
	{"password", catPasswords}, {"contraseña", catPasswords},
	{"wallet", catWallet},
	{"chatgpt", catAI}, {"claude", catAI}, {"gemini", catAI}, {"copilot", catAI},
	{"price tracker", catShopping}, {"coupon", catShopping},
	{"devtools", catDev}, {"developer tools", catDev},
}

// One of these per profile is enough; a second one is a duplicate.
var exclusive = map[string]bool{catPasswords: true}

func category(id, name string) string {
	if c, ok := categoryByID[id]; ok {
		return c
	}
	n := strings.ToLower(name)
	for _, w := range categoryWords {
		if strings.Contains(n, w.word) {
			return w.cat
		}
	}
	return ""
}

func capabilities(in install) []string {
	var caps []string
	if in.allSites {
		caps = append(caps, capAllSites)
	}
	for _, a := range in.apis {
		if c, ok := apiCapability[a]; ok && !slices.Contains(caps, c) {
			caps = append(caps, c)
		}
	}
	if in.onClick {
		caps = append(caps, "all sites, on click")
	}
	return caps
}

func (in install) source() string {
	switch {
	case in.location == locUnpacked:
		return "unpacked (developer mode)"
	case in.fromStore:
		return "web store"
	}
	return "sideloaded"
}

func day(t time.Time) string {
	if t.IsZero() {
		return "unknown"
	}
	return t.Format(time.DateOnly)
}

// assessment is the triage of one install.
type assessment struct {
	install
	category string
	caps     []string
	verdict  verdict
	sev      finding.Severity
	reasons  []string // the reasons behind the verdict, most urgent first
}

func (a *assessment) add(v verdict, reason string) {
	switch {
	case v > a.verdict:
		a.verdict, a.reasons = v, []string{reason}
	case v == a.verdict:
		a.reasons = append(a.reasons, reason)
	}
}

// duplicate says which install of an exclusive category, in the same profile, another one
// duplicates. primary is nil when nothing tells them apart.
type duplicate struct {
	primary *install
	others  []string // names of the installs it competes with, when primary is nil
}

// duplicates finds installs that duplicate another of an exclusive category in the same profile.
// The primary is the one named in the config, otherwise the one installed on a later day (the one
// moved to). Installed the same day with none configured, none is primary: both are for review.
func duplicates(ins []install, preferred []string) map[*install]duplicate {
	out := map[*install]duplicate{}
	groups := map[string][]*install{}
	for i := range ins {
		if c := category(ins[i].id, ins[i].name); exclusive[c] && ins[i].enabled {
			k := ins[i].profile + "\x00" + c
			groups[k] = append(groups[k], &ins[i])
		}
	}
	for _, g := range groups {
		if len(g) < 2 {
			continue
		}
		rank := func(in *install) (bool, string) { return slices.Contains(preferred, in.id), day(in.installed) }
		primary := slices.MaxFunc(g, func(a, b *install) int {
			pa, da := rank(a)
			pb, db := rank(b)
			return cmp.Or(boolCmp(pa, pb), strings.Compare(da, db))
		})
		pp, pd := rank(primary)
		tie := !pp && slices.ContainsFunc(g, func(in *install) bool { p, d := rank(in); return in != primary && !p && d == pd })
		for _, in := range g {
			switch {
			case tie:
				var names []string
				for _, o := range g {
					if o != in {
						names = append(names, o.name)
					}
				}
				out[in] = duplicate{others: names}
			case in != primary:
				out[in] = duplicate{primary: primary}
			}
		}
	}
	return out
}

func boolCmp(a, b bool) int {
	switch {
	case a == b:
		return 0
	case a:
		return 1
	}
	return -1
}

// assess applies the triage rules to every install. preferred lists extension ids the owner names
// as primary in their category.
func assess(ins []install, now time.Time, preferred []string) []assessment {
	dups := duplicates(ins, preferred)
	out := make([]assessment, 0, len(ins))
	for i := range ins {
		in := ins[i]
		a := assessment{install: in, category: category(in.id, in.name), caps: capabilities(in)}
		stale := !in.updated.IsZero() && now.Sub(in.updated) > staleAfter
		sensitive := slices.ContainsFunc(a.caps, func(c string) bool { return c != capAllSites && c != "all sites, on click" })
		if !in.enabled {
			a.add(review, "disabled: remove it if you no longer use it")
			a.sev = finding.SevLow
			out = append(out, a)
			continue
		}
		if in.location == locUnpacked {
			if stale {
				a.add(remove, "unpacked developer extension not updated since "+day(in.updated))
			} else {
				a.add(review, "unpacked developer extension: no store review, runs whatever is in its folder")
			}
		} else if !in.fromStore {
			a.add(review, "not from the Chrome Web Store")
		}
		if slices.Contains(a.caps, "debugger") && a.category != catDev {
			a.add(remove, "debugger permission without being a dev tool: it can drive any tab and read its pages and cookies")
		}
		if d, ok := dups[&ins[i]]; ok {
			if d.primary != nil {
				a.add(remove, fmt.Sprintf("second %s in this profile; %s is the primary one", a.category, d.primary.name))
			} else {
				a.add(review, fmt.Sprintf("another %s in this profile (%s), installed the same day: keep one, and name it in the connector's \"primary\" config", a.category, strings.Join(d.others, ", ")))
			}
		}
		if in.allSites && sensitive {
			a.add(review, "reads and changes all sites and uses "+strings.Join(withoutAllSites(a.caps), ", "))
		}
		if a.category == catWallet && in.daily {
			a.add(review, "crypto wallet in a profile used for daily browsing")
		}
		if in.fromStore && stale {
			a.add(review, "not updated since "+day(in.updated)+": abandoned, or in a profile nobody opens")
		}
		if len(a.reasons) == 0 {
			a.reasons = []string{"no sensitive permissions"}
			if len(a.caps) > 0 {
				a.reasons = []string{"limited permissions: " + strings.Join(a.caps, ", ")}
			}
		}
		a.sev = a.severity()
		out = append(out, a)
	}
	return out
}

func withoutAllSites(caps []string) []string {
	return slices.DeleteFunc(slices.Clone(caps), func(c string) bool { return c == capAllSites || c == "all sites, on click" })
}

func (a assessment) severity() finding.Severity {
	switch a.verdict {
	case remove:
		if slices.ContainsFunc(a.caps, func(c string) bool { return severe[c] }) {
			return finding.SevHigh
		}
		return finding.SevMedium
	case review:
		if (a.allSites && len(withoutAllSites(a.caps)) > 0) || (a.category == catWallet && a.daily) {
			return finding.SevMedium
		}
		return finding.SevLow
	}
	return finding.SevInfo
}
