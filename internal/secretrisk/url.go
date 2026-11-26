package secretrisk

import (
	"net/netip"
	"strings"
)

// URL credentials are judged by the host they open, which the note carries.
var urlTypes = map[string]bool{"url-credentials": true, "url-token-param": true}

// URLNote is the note of a URL credential, never its value: "postgresql://…@db.example.org",
// "https://api.example.org/…?access_token=…", "?token=…" without a host.
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

// urlHost reads the host back from a URLNote, without its port.
func urlHost(note string) string {
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

// Reserved names (RFC 2606, RFC 6761, mDNS .local from RFC 6762) serve nobody's data; managed
// database hosts, as each provider's connection strings name them, carry production data.
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

// anyLabel splits the host at "." and "-".
func anyLabel(host string, words map[string]bool) bool {
	for _, l := range strings.FieldsFunc(host, func(r rune) bool { return r == '.' || r == '-' }) {
		if words[l] {
			return true
		}
	}
	return false
}
