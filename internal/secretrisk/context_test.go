package secretrisk

import (
	"testing"
	"time"
)

func TestRoleOf(t *testing.T) {
	cases := map[string]PathRole{
		"~/src/shop/config/app.yml":                     RoleNone,
		"~/src/shop/.env":                               RoleNone,
		"~/src/shop/.env.test":                          RoleNone,
		"~/src/acme-labs/spec/fixtures/requests/s3.yml": RoleTest,
		"~/src/app/src/Register.test.tsx":               RoleTest,
		"~/src/store/tests/redact.test.cjs":             RoleTest,
		"~/src/api/internal/x/handler_test.go":          RoleTest,
		"~/src/py/test_client.py":                       RoleTest,
		"~/src/rb/user_spec.rb":                         RoleTest,
		"~/src/chat/test/fixtures/relay/key.pem":        RoleTest,
		"~/src/tcpdf/examples/data/cert/tcpdf.crt":      RoleExample,
		"~/src/app/.env.example":                        RoleExample,
		"~/src/app/config/database.yml.sample":          RoleExample,
		"~/src/php-jwt/README.md":                       RoleDoc,
		"~/src/site/docs/setup.html":                    RoleDoc,
		"~/src/app/vendor/firebase/php-jwt/src/JWT.php": RoleVendor,
		"~/src/app/vendor/acme/tests/fixture.pem":       RoleVendor,
		"~/src/crm/files.md5":                           RoleGenerated,
		"~/src/app/package-lock.json":                   RoleGenerated,
		"~/src/app/Gemfile.lock":                        RoleGenerated,
		"~/src/go/go.sum":                               RoleGenerated,
		"~/src/dl/SHA256SUMS.sha256":                    RoleGenerated,
		"~/src/test-projects/app/.env":                  RoleNone, // a folder name that merely contains "test"
		"~/src/latest/config/secrets.yml":               RoleNone,
	}
	for p, want := range cases {
		if got := RoleOf(p); got != want {
			t.Errorf("RoleOf(%q) = %d, want %d", p, got, want)
		}
	}
	if test, vendor := DirRoles("app/Spec/data.sql"); !test || vendor {
		t.Error("DirRoles: test folder, any case")
	}
	if test, vendor := DirRoles("third_party/x/db.sqlite"); test || !vendor {
		t.Error("DirRoles: vendor folder")
	}
	if test, _ := DirRoles("app/user_test.sql"); test {
		t.Error("DirRoles looks at folders only")
	}
}

func TestImpactInFixturePaths(t *testing.T) {
	aws := Evidence{Type: "aws-access-key-id", Redacted: "AKIA…(20)", Kind: "repo"}
	at := func(e Evidence, path string, sample bool) Impact {
		e.Path, e.Sample = path, sample
		return ImpactOf(e)
	}
	if got := at(aws, "~/src/app/config/aws.yml", false); got != High {
		t.Errorf("ordinary path: %s", got)
	}
	if got := at(aws, "~/src/app/spec/fixtures/s3.yml", false); got != Medium {
		t.Errorf("fixture path lowers one level: %s", got)
	}
	if got := at(aws, "~/src/app/spec/fixtures/s3.yml", true); got != Noise {
		t.Errorf("fixture path with a sample value: %s", got)
	}
	if got := at(aws, "~/src/app/config/aws.yml", true); got != High {
		t.Errorf("a sample-looking value outside fixtures keeps its impact: %s", got)
	}
	if got := at(Evidence{Type: "stripe-test", Redacted: "sk_test_…(30)", Kind: "repo"}, "~/src/app/test/setup.ts", false); got != Noise {
		t.Errorf("low impact in a fixture path: %s", got)
	}
	if got := at(aws, "~/src/crm/files.md5", false); got != Noise {
		t.Errorf("checksum file: %s", got)
	}
	// Only repository files carry roles: a transcript under a folder named "test" does not.
	tr := aws
	tr.Kind = "transcript"
	if got := at(tr, "~/.claude/projects/test/s.jsonl", false); got != High {
		t.Errorf("transcript: %s", got)
	}
}

func TestURLNoteAndHost(t *testing.T) {
	cases := []struct{ scheme, host, param, note, back string }{
		{"postgresql", "db.internal", "", "postgresql://…@db.internal", "db.internal"},
		{"https", "api.example.org", "access_token", "https://api.example.org/…?access_token=…", "api.example.org"},
		{"", "", "token", "?token=…", ""},
	}
	for _, c := range cases {
		n := URLNote(c.scheme, c.host, c.param)
		if n != c.note || URLHost(n) != c.back {
			t.Errorf("URLNote(%q,%q,%q) = %q (host %q)", c.scheme, c.host, c.param, n, URLHost(n))
		}
	}
	for note, host := range map[string]string{
		"postgresql://…@127.0.0.1": "127.0.0.1", "redis://…@Cache.Prod.Acme.IO:6379": "cache.prod.acme.io",
		"mysql://…@[::1]": "::1", "https://h.example.net/…?key=…": "h.example.net", "ANTHROPIC_KEY": "",
	} {
		if got := URLHost(note); got != host {
			t.Errorf("URLHost(%q) = %q, want %q", note, got, host)
		}
	}
}

func TestURLCredentialImpactByHost(t *testing.T) {
	cases := map[string]Impact{
		"localhost": Noise, "127.0.0.1": Noise, "127.8.9.10": Noise, "::1": Noise, "0.0.0.0": Noise,
		"example.com": Noise, "db.example.org": Noise, "api.example.net": Noise, "printer.local": Noise,
		"app.test": Noise, "x.invalid": Noise, "web.localhost": Noise,
		"10.1.2.3": Low, "172.20.0.4": Low, "192.168.23.12": Low, "100.80.1.1": Low, "169.254.1.1": Low,
		"fe80::1": Low, "fd00::5": Low, "postgres": Low, "db.internal": Low, "nas.lan": Low,
		"api.acme.io": Medium, "8.8.8.8": Medium,
		"ep-cool-1.eu-central-1.aws.neon.tech": High, "db.abcdefgh.supabase.co": High,
		"aws-0-eu-west-1.pooler.supabase.com": High, "shop.cluster-x.eu-west-1.rds.amazonaws.com": High,
		"cluster0.ab1cd.mongodb.net": High, "prod-db.acme.io": High, "db.production.acme.io": High,
		"products.acme.io": Medium, // "prod" must be a whole label
	}
	for host, want := range cases {
		for _, typ := range []string{"url-credentials", "url-token-param"} {
			param := ""
			if typ == "url-token-param" {
				param = "token"
			}
			e := Evidence{Type: typ, Redacted: "…(24)", Kind: "config", Note: URLNote("https", host, param)}
			if got := ImpactOf(e); got != want {
				t.Errorf("%s at %s: %s, want %s", typ, host, got, want)
			}
		}
	}
	if got := ImpactOf(Evidence{Type: "url-token-param", Redacted: "…(24)", Kind: "config", Note: "?token=…"}); got != Medium {
		t.Errorf("unknown host keeps the catalog impact: %s", got)
	}
	if got := ImpactOf(Evidence{Type: "anthropic", Redacted: "sk-ant-…(108)", Kind: "config", Note: "postgresql://…@localhost"}); got != Medium {
		t.Errorf("only URL types are judged by host: %s", got)
	}
}

func TestOriginMakesUpstreamCopiesNoise(t *testing.T) {
	key := Evidence{Type: "private-key", Redacted: "PEM", Kind: "repo", Source: "gitleaks", Tracked: true, Remote: true, Path: "~/src/lms/config/k.pem"}
	for _, c := range []struct {
		origin string
		reused bool
		impact Impact
		label  string
	}{
		{"", false, High, "git+remote"},
		{OriginOwned, false, High, "git+remote"},
		{OriginThirdParty, false, Noise, OriginThirdParty},
		{OriginForkUpstream, false, Noise, OriginForkUpstream},
		{OriginThirdParty, true, High, "git+remote"},
	} {
		e := key
		e.Origin, e.Reused = c.origin, c.reused
		if got := ImpactOf(e); got != c.impact {
			t.Errorf("%q reused=%v: impact %s, want %s", c.origin, c.reused, got, c.impact)
		}
		if s := WhereEvidence(e); s.Label != c.label || s.Phrase == "" {
			t.Errorf("%q reused=%v: spot %+v", c.origin, c.reused, s)
		}
	}
}

func TestExpireTemporaryAWS(t *testing.T) {
	now := time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)
	sts := Evidence{Type: "aws-access-key-id", Redacted: "ASIA…(20)"}
	if !TemporaryAWS(sts) || TemporaryAWS(Evidence{Type: "aws-access-key-id", Redacted: "AKIA…(20)"}) {
		t.Fatal("TemporaryAWS")
	}
	fresh := sts
	if ExpireTemporaryAWS(&fresh, now.Add(-35*time.Hour), now) || fresh.Public {
		t.Error("an STS key 35 hours old may still work")
	}
	old := sts
	if !ExpireTemporaryAWS(&old, now.Add(-37*time.Hour), now) || !old.Public || old.Note != "expired" || ImpactOf(old) != Noise {
		t.Errorf("an STS key 37 hours old: %+v", old)
	}
	if ExpireTemporaryAWS(&old, now.Add(-72*time.Hour), now) || old.Note != "expired" {
		t.Error("expiring twice changes the note")
	}
	signed := Evidence{Type: "aws-presigned-url", Redacted: "ASIA…(20)"}
	if !ExpireTemporaryAWS(&signed, now.Add(-48*time.Hour), now) {
		t.Error("an STS-signed URL expires with its key")
	}
	long := Evidence{Type: "aws-access-key-id", Redacted: "AKIA…(20)"}
	if ExpireTemporaryAWS(&long, now.Add(-1000*time.Hour), now) {
		t.Error("a long-lived key never expires by age")
	}
	if ExpireTemporaryAWS(&sts, time.Time{}, now) {
		t.Error("no date, no verdict")
	}
}
