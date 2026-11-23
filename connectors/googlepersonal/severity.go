package googlepersonal

import (
	"regexp"

	"github.com/segurata/segurata/internal/finding"
)

type scopeRule struct {
	re    *regexp.Regexp
	sev   finding.Severity
	label string // completes "<App> can …"
}

// scopeRules classifies one scope line, English or Spanish. First match wins, so narrow rules
// (app-specific Drive files, read-only calendars) come before the broad ones they would match.
var scopeRules = []scopeRule{
	{rx(`specific Google Drive files|own configuration data|archivos específicos|propios datos de configuración`), finding.SevLow, "use only its own files in your Google Drive"},
	{rx(`^view events on|^see and download any calendar|^ver (los )?eventos|^consultar (los )?eventos|^ver y descargar cualquier calendario`), finding.SevLow, "see your calendar events"},

	{rx(`read, compose|send emails?|send email on your behalf|email messages|permanently delete all your email|leer, redactar|enviar correos?|mensajes de correo`), finding.SevHigh, "read and send email from your Gmail"},
	{rx(`Google Drive files|archivos de Google Drive`), finding.SevHigh, "see and change all your Google Drive files"},
	{rx(`all your Google Sheets|todas tus hojas de cálculo`), finding.SevHigh, "see and change all your Google Sheets"},
	{rx(`Google Cloud data|datos de Google Cloud|Compute Engine|Cloud SQL`), finding.SevHigh, "manage your Google Cloud data and resources"},
	{rx(`run when you are not present|cuando no estés presente`), finding.SevHigh, "act on your account while you are away"},
	{rx(`Google Ads`), finding.SevHigh, "manage your Google Ads accounts"}, // can spend money

	{rx(`contacts|contactos`), finding.SevMedium, "see and download your contacts"},
	{rx(`calendar|calendario`), finding.SevMedium, "see and change your calendars"},
	{rx(`manage your YouTube|(gestionar|administrar) tu cuenta de YouTube`), finding.SevMedium, "manage your YouTube account"},

	{rx(`profile info|información de tu perfil|información del perfil`), finding.SevInfo, "see your profile info"},
}

// unknownScope is what a scope no rule recognises gets: data access of unknown reach.
var unknownScope = scopeRule{sev: finding.SevMedium, label: "access some of your Google Account data"}

func rx(s string) *regexp.Regexp { return regexp.MustCompile(`(?i)` + s) }

func classify(scope string) scopeRule {
	for _, r := range scopeRules {
		if r.re.MatchString(scope) {
			return r
		}
	}
	return unknownScope
}

// assess returns the worst scope's severity and label; ties go to the earlier scope.
// No scopes means Sign in with Google only.
func assess(scopes []string) (finding.Severity, string) {
	if len(scopes) == 0 {
		return finding.SevInfo, "sign you in with your Google account"
	}
	worst := classify(scopes[0])
	for _, s := range scopes[1:] {
		if r := classify(s); r.sev.Rank() > worst.sev.Rank() {
			worst = r
		}
	}
	return worst.sev, worst.label
}
