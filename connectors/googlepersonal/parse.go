package googlepersonal

import (
	"regexp"

	"github.com/segurata/segurata/connectors/internal/pagetext"
)

// Everything that depends on Google's wording, in English and Spanish, lives here.
var (
	reauthRE       = regexp.MustCompile(`Verify (it.s|that it.s) you|Demuestra que eres t`)
	accessHeadRE   = regexp.MustCompile(`(?i)(has some access|tiene acceso parcial)`)
	crossAccountRE = regexp.MustCompile(`(?i)Cross-Account Protection|Protección (entre|multi) ?cuentas`)
	moreRE         = regexp.MustCompile(`^(\+\d+ more|y \d+ más)$`)
	// Lines that end a scope list on an overview page.
	overviewEndRE = regexp.MustCompile(`^(See details|Ver detalles|Delete all|Eliminar todas)$`)
	// The heading that opens and the line that closes the scope list on a details page.
	detailScopesRE = regexp.MustCompile(` (can|puede):$`)
	detailEndRE    = regexp.MustCompile(`^(If you remove access|Si retiras el acceso)`)
	givenOnRE      = regexp.MustCompile(`^(Access given on|Acceso concedido el|Se ha concedido acceso el):?$`)
	// Material icon names and the explanatory paragraph that sit between scope lines.
	noiseRE = regexp.MustCompile(`^(account_circle|pentagon|help|To use |Para usar )`)
)

func isReauth(text string) bool { return reauthRE.MatchString(text) }

type overview struct {
	Scopes       []string // data scopes listed under "has some access"; empty for sign-in only
	CrossAccount bool     // "secured by Cross-Account Protection"
}

// parseOverview drops "+N more" markers: the details page gives the full list.
func parseOverview(text string) overview {
	o := overview{CrossAccount: crossAccountRE.MatchString(text)}
	lines := pagetext.Lines(text)
	for i, l := range lines {
		if accessHeadRE.MatchString(l) {
			o.Scopes = scopeLines(lines[i+1:], overviewEndRE)
			break
		}
	}
	return o
}

type detail struct {
	Scopes  []string // full list on an /oauth/ details page; empty on /siwg/
	GivenOn string   // raw "Access given on" value, e.g. "March 24, 2020"
}

func parseDetail(text string) detail {
	var d detail
	lines := pagetext.Lines(text)
	for i, l := range lines {
		switch {
		case givenOnRE.MatchString(l) && i+1 < len(lines) && d.GivenOn == "":
			d.GivenOn = lines[i+1]
		case detailScopesRE.MatchString(l) && d.Scopes == nil:
			d.Scopes = scopeLines(lines[i+1:], detailEndRE)
		}
	}
	return d
}

func scopeLines(lines []string, end *regexp.Regexp) []string {
	out := []string{}
	for _, l := range lines {
		if end.MatchString(l) {
			break
		}
		if noiseRE.MatchString(l) || moreRE.MatchString(l) {
			continue
		}
		out = append(out, l)
	}
	return out
}
