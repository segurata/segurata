package secretrisk

import (
	"fmt"

	"github.com/segurata/segurata/internal/docref"
)

const DumpFixDoc = docref.Docs + "secrets.md#data-dumps-in-git"

// Breach notification guidance for dumps of personal data, checked on 2026-11-24.
const (
	URLAEPDBreaches = "https://www.aepd.es/es/derechos-y-deberes/cumple-tus-deberes/medidas-de-cumplimiento/brechas-de-datos-personales"
	URLEDPBBreaches = "https://www.edpb.europa.eu/documents/guideline/guidelines-92022-on-personal-data-breach-notification-under-gdpr_en"
)

// HumanSize writes a byte count the way dump titles show it: 900 B, 3.5 KB, 12 MB.
func HumanSize(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	v := float64(n) / float64(div)
	if v < 10 {
		return fmt.Sprintf("%.1f %cB", v, "KMGTPE"[exp])
	}
	return fmt.Sprintf("%.0f %cB", v, "KMGTPE"[exp])
}

// A database dump in git yields thousands of matches (hash columns, the application's users' keys)
// that are noise for rotation, except the shapes that are this owner's credentials as often as not.
var keptInDump = map[string]bool{
	"aws-access-key-id": true,
	"stripe-live":       true,
	"github":            true,
	"github-pat":        true,
	"gitlab":            true,
	"private-key":       true,
}

func dumpNoise(e Evidence) bool { return e.InDataDump && !keptInDump[e.Type] }
