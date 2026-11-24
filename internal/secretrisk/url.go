package secretrisk

import (
	"net/netip"
	"strings"
)

// Credentials inside URLs are judged by the host they open: a password for a database on
// localhost or example.com protects nothing, one for a private address reaches only that
// network, and one for a public host is worth as much as the type says, more when the host is a
// managed database or reads like production. The connector writes the host into the note,
// "postgresql://…@db.example.org" or "https://api.example.org/…?access_token=…".

var urlTypes = map[string]bool{"url-credentials": true, "url-token-param": true}

// URLNote is the note of a URL credential: scheme and host, the parameter name for a token in a
// query string, never the value. host may be "" (a bare query string); param is "" for a password.
func URLNote(scheme, host, param string) string {
	var b strings.Builder
	if host != "" {
		b.WriteString(scheme + "://")
		if param == "" {
			b.WriteString("…@" + host)
			return b.String()
		}
		b.WriteString(host + "/…")
	}
	b.WriteString("?" + param + "=…")
	return b.String()
}

// URLHost reads the host back from a URLNote, without its port; "" when the note has none.
func URLHost(note string) string {
	i := strings.Index(note, "://")
	if i < 0 {
		return ""
	}
	rest := note[i+3:]
	if j := strings.LastIndexByte(rest, '@'); j >= 0 {
		rest = rest[j+1:]
	}
	if j := strings.IndexAny(rest, "/?#"); j >= 0 {
		rest = rest[:j]
	}
	if strings.HasPrefix(rest, "[") { // [::1]:5432
		if j := strings.IndexByte(rest, ']'); j > 0 {
			return strings.ToLower(rest[1:j])
		}
	}
	if j := strings.LastIndexByte(rest, ':'); j >= 0 && strings.Count(rest, ":") == 1 {
		rest = rest[:j]
	}
	return strings.ToLower(strings.TrimSuffix(rest, "."))
}

// Hosts that never serve anyone else's data (the names reserved by RFC 2606 and RFC 6761, and
// mDNS .local from RFC 6762) and the managed database services whose hosts carry production data,
// by the host names in each provider's connection strings.
var (
	reservedSuffixes = []string{".localhost", ".example", ".test", ".invalid", ".local", ".example.com", ".example.org", ".example.net"}
	reservedHosts    = set("localhost", "example.com", "example.org", "example.net")
	privateSuffixes  = []string{".internal", ".lan", ".home.arpa"}
	managedDatabases = []string{
		"neon.tech",           // Neon: ep-<id>.<region>.aws.neon.tech
		"supabase.co",         // Supabase direct: db.<ref>.supabase.co
		"pooler.supabase.com", // Supabase pooler: aws-0-<region>.pooler.supabase.com
		"rds.amazonaws.com",   // Amazon RDS and Aurora endpoints
		"mongodb.net",         // MongoDB Atlas clusters
		"upstash.io",          // Upstash Redis
		"psdb.cloud",          // PlanetScale
		"rlwy.net",            // Railway TCP proxy
	}
	prodWords = set("prod", "production", "prd", "live")
)

// hostImpact adjusts the impact of a URL credential by its host; base is the type's impact.
func hostImpact(host string, base Impact) Impact {
	switch {
	case host == "":
		return base
	case reservedHosts[host] || hasSuffix(host, reservedSuffixes):
		return Noise
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		switch {
		case ip.IsLoopback() || ip.IsUnspecified():
			return Noise
		case ip.IsPrivate() || ip.IsLinkLocalUnicast() || cgnat.Contains(ip):
			return min(base, Low)
		}
		return base
	}
	if !strings.Contains(host, ".") || hasSuffix(host, privateSuffixes) {
		return min(base, Low) // a docker-compose service name, a LAN name
	}
	if managedDatabase(host) || anyLabel(host, prodWords) {
		return High
	}
	return base
}

var cgnat = netip.MustParsePrefix("100.64.0.0/10")

func managedDatabase(host string) bool {
	for _, d := range managedDatabases {
		if host == d || strings.HasSuffix(host, "."+d) {
			return true
		}
	}
	return false
}

// anyLabel reports whether one of the host's labels, split also at "-", is in words.
func anyLabel(host string, words map[string]bool) bool {
	for _, l := range strings.FieldsFunc(host, func(r rune) bool { return r == '.' || r == '-' }) {
		if words[l] {
			return true
		}
	}
	return false
}
