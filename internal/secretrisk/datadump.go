package secretrisk

// A database dump committed to git yields thousands of gitleaks matches: hash columns, API keys of
// the application's users, random ids. The local-secrets connector reports the dump itself as one
// data_dump finding and marks those matches InDataDump. They are noise for rotation, except the
// high-impact types with a recognisable shape (AWS AKIA keys, Stripe live keys, GitHub and GitLab
// tokens, private keys), which are this owner's credentials as often as not and stay.
var keptInDump = map[string]bool{
	"aws-access-key-id": true,
	"stripe-live":       true,
	"github":            true,
	"github-pat":        true,
	"gitlab":            true,
	"private-key":       true,
}

func dumpNoise(e Evidence) bool { return e.InDataDump && !keptInDump[e.Type] }
