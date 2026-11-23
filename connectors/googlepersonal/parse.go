package googlepersonal

import (
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Pure parsers over the innerText of Google Account pages, in English and Spanish.
// Everything that depends on Google's wording lives here, so a UI change means one fixture and
// one regexp to update.

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

// isReauth tells whether Google is asking for a fresh sign-in instead of showing the page.
func isReauth(text string) bool { return reauthRE.MatchString(text) }

type overview struct {
	Scopes       []string // data scopes listed under "has some access"; empty for sign-in only
	CrossAccount bool     // "secured by Cross-Account Protection"
}

// parseOverview reads an app's linkedapps/overview page. The overview may truncate the list
// with "+N more"; those markers are dropped, and the details page gives the full list.
func parseOverview(text string) overview {
	o := overview{CrossAccount: crossAccountRE.MatchString(text)}
	lines := splitLines(text)
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

// parseDetail reads a linkedapps/details page (/oauth/ or /siwg/ variant).
func parseDetail(text string) detail {
	var d detail
	lines := splitLines(text)
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

func splitLines(text string) []string {
	var out []string
	for _, l := range strings.Split(text, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
		}
	}
	return out
}

var months = map[string]time.Month{
	"january": 1, "february": 2, "march": 3, "april": 4, "may": 5, "june": 6, "july": 7,
	"august": 8, "september": 9, "october": 10, "november": 11, "december": 12,
	"jan": 1, "feb": 2, "mar": 3, "apr": 4, "jun": 6, "jul": 7, "aug": 8, "sep": 9, "sept": 9,
	"oct": 10, "nov": 11, "dec": 12,
	"enero": 1, "febrero": 2, "marzo": 3, "abril": 4, "mayo": 5, "junio": 6, "julio": 7,
	"agosto": 8, "septiembre": 9, "setiembre": 9, "octubre": 10, "noviembre": 11, "diciembre": 12,
	"ene": 1, "abr": 4, "ago": 8, "dic": 12,
}

var (
	relativeDayRE = regexp.MustCompile(`(?i)^(today|yesterday|hoy|ayer)\b`)
	// "March 24, 2020", "May 15, 7:37 PM", "Mar 24, 2020"
	enDateRE = regexp.MustCompile(`^([A-Za-z]+)\.? (\d{1,2})(?:, (\d{4}))?\b`)
	// "18 de noviembre de 2025", "21 de septiembre, 12:28", "18 nov 2025"
	esDateRE = regexp.MustCompile(`^(\d{1,2})(?: de)? ([a-zñ]+)\.?(?:(?: de)? (\d{4}))?\b`)
)

// parseGivenOn turns an "Access given on" value into a UTC date. Google omits the year for
// dates in the current year ("May 15, 7:37 PM") and says "Yesterday" or "Today" for the last
// two days; now supplies what is missing. The time of day is dropped:
// the page shows it in the browser's zone, which is not recorded. Unparseable → nil, never a guess.
func parseGivenOn(s string, now time.Time) *time.Time {
	s = strings.TrimSpace(s)
	if m := relativeDayRE.FindStringSubmatch(s); m != nil {
		d := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
		if strings.EqualFold(m[1], "yesterday") || strings.EqualFold(m[1], "ayer") {
			d = d.AddDate(0, 0, -1)
		}
		return &d
	}
	var monthName, day, year string
	if m := enDateRE.FindStringSubmatch(s); m != nil {
		monthName, day, year = m[1], m[2], m[3]
	} else if m := esDateRE.FindStringSubmatch(strings.ToLower(s)); m != nil {
		day, monthName, year = m[1], m[2], m[3]
	} else {
		return nil
	}
	month, ok := months[strings.ToLower(monthName)]
	if !ok {
		return nil
	}
	d, _ := strconv.Atoi(day)
	y := now.Year()
	if year != "" {
		y, _ = strconv.Atoi(year)
	}
	t := time.Date(y, month, d, 0, 0, 0, 0, time.UTC)
	if t.Day() != d || t.Month() != month { // "February 30" rolled over
		return nil
	}
	return &t
}
