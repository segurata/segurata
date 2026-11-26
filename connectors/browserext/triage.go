package browserext

import (
	"cmp"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/segurata/segurata/internal/finding"
)

// verdicts in increasing order of urgency
type verdict int

const (
	keep verdict = iota
	review
	remove
)

func (v verdict) String() string { return [...]string{"keep", "review", "remove"}[v] }

const staleAfter = 365 * 24 * time.Hour

const (
	capAllSites = "read and change all sites"
	capOnClick  = "all sites, on click"
)

var apiCapability = map[string]string{
	"debugger": "debugger", "cookies": "cookies", "webRequest": "webRequest", "webRequestBlocking": "webRequest",
	"nativeMessaging": "nativeMessaging", "clipboardRead": "clipboard read", "history": "history",
	"downloads": "downloads", "management": "management",
}

// severe capabilities make a "remove" verdict high rather than medium.
var severe = map[string]bool{capAllSites: true, "debugger": true, "cookies": true, "nativeMessaging": true}

// Category hints: Web Store ids of common extensions, then names. A hint, not a catalogue.
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
	// "password" alone would make a password generator or a show-password toggle a duplicate
	// password manager, and so a remove verdict.
	{"password manager", catPasswords}, {"1password", catPasswords}, {"keepass", catPasswords},
	{"gestor de contraseñas", catPasswords}, {"administrador de contraseñas", catPasswords},
	{"wallet", catWallet},
	{"chatgpt", catAI}, {"claude", catAI}, {"gemini", catAI}, {"copilot", catAI},
	{"price tracker", catShopping}, {"coupon", catShopping},
	{"devtools", catDev}, {"developer tools", catDev},
}

// exclusive categories: a second one in a profile is a duplicate.
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
		caps = append(caps, capOnClick)
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

type assessment struct {
	install
	category string
	caps     []string
	verdict  verdict
	sev      finding.Severity
	reasons  []string // behind the verdict, most urgent first
}

func (a *assessment) add(v verdict, reason string) {
	switch {
	case v > a.verdict:
		a.verdict, a.reasons = v, []string{reason}
	case v == a.verdict:
		a.reasons = append(a.reasons, reason)
	}
}

type duplicate struct {
	primary *install // nil when nothing tells them apart
	others  []string // the names it competes with, when primary is nil
}

// duplicates finds installs of an exclusive category that another in the same profile duplicates.
// The primary is the configured one, else the one installed on a later day (the one moved to);
// installed the same day, none is.
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

// assess triages every install; preferred are extension ids configured as primary.
func assess(ins []install, now time.Time, preferred []string) []assessment {
	dups := duplicates(ins, preferred)
	out := make([]assessment, 0, len(ins))
	for i := range ins {
		in := ins[i]
		a := assessment{install: in, category: category(in.id, in.name), caps: capabilities(in)}
		stale := !in.updated.IsZero() && now.Sub(in.updated) > staleAfter
		sensitive := len(withoutAllSites(a.caps)) > 0
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
	return slices.DeleteFunc(slices.Clone(caps), func(c string) bool { return c == capAllSites || c == capOnClick })
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
