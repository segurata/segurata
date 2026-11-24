// Package testcorpus generates synthetic trail text for the matcher benchmarks and equivalence
// tests: transcript-like JSONL lines of megabytes (tool results full of code, URLs, escapes and
// base64 blobs) with a few secrets, and short lines with secrets of every shape. Every secret is
// generated at run time from the caller's seed: no real or real-looking literal sits in the source.
package testcorpus

import (
	"encoding/base64"
	"encoding/json"
	"math/rand/v2"
	"strings"
)

// Fake is prefix followed by n random characters of alphabet.
func Fake(r *rand.Rand, prefix string, n int, alphabet string) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = alphabet[r.IntN(len(alphabet))]
	}
	return prefix + string(b)
}

// Alphabets for Fake.
const (
	Alnum = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	Hex   = "0123456789abcdef"
)

// Secrets are values of many shapes: real-looking secrets, near misses and noise.
func Secrets(r *rand.Rand) []string {
	f := func(prefix string, n int) string { return Fake(r, prefix, n, Alnum) }
	h := func(prefix string, n int) string { return Fake(r, prefix, n, Hex) }
	pem, _ := PEM(r)
	jwtPart := func(v any) string {
		raw, _ := json.Marshal(v)
		return base64.RawURLEncoding.EncodeToString(raw)
	}
	jwt := jwtPart(map[string]any{"alg": "HS256"}) + "." + jwtPart(map[string]any{"role": "service_role", "exp": 4102444800}) + "." + f("", 30)
	return []string{
		f("sk-ant-api03-", 80), f("sk-or-v1-", 64), f("sk-proj-", 60), f("sk-svcacct-", 48), f("sk-admin-", 48),
		f("sk-", 20) + "T3BlbkFJ" + f("", 20), f("sk-", 40), f("xai-", 60), f("gsk_", 52), f("hf_", 36), f("r8_", 37),
		f("pplx-", 48), f("tvly-dev-", 32), h("sk_", 48), f("ghp_", 36), f("gho_", 40), f("github_pat_", 70), f("glpat-", 20),
		"aws_secret_access_key = " + f("", 40), "AKIA" + strings.ToUpper(f("", 16)), f("AIza", 35), f("GOCSPX-", 28),
		f("1//0", 50), `"refresh_token": "` + f("", 40) + `"`, `"client_secret": "` + f("", 24) + `"`,
		`"type": "service_account"`, pem, strings.ReplaceAll(pem, "\n", `\n`), strings.ReplaceAll(pem, "\n", `\\n`),
		"-----BEGIN PRIVATE KEY-----", "AGE-SECRET-KEY-1" + strings.ToUpper(f("", 58)), f("sk_live_", 30), f("rk_test_", 30),
		f("whsec_", 32), f("xoxb-", 30), "https://hooks.slack.com/services/T" + strings.ToUpper(f("", 8)) + "/B" + strings.ToUpper(f("", 8)) + "/" + f("", 24),
		"CLOUDFLARE_API_TOKEN=" + f("", 40), "cf_key: " + f("", 37), f("secret_", 43), f("ntn_", 46), f("sntrys_", 60),
		"https://" + h("", 32) + "@o1.ingest.sentry.io/123", f("lin_api_", 40), "SG." + f("", 22) + "." + f("", 43),
		h("shpat_", 32), h("dop_v1_", 64), h("sbp_", 40), f("sb_secret_", 30), f("ops_", 60), f("npm_", 36),
		"//registry.npmjs.org/:_authToken=" + f("", 36), f("pypi-", 60), h("rubygems_", 48),
		"1234567890:AA" + f("", 33), `"auth": "` + f("", 32) + `"`, "client-key-data: " + f("", 60),
		"machine example.com login me password " + f("", 12), "postgres://admin:" + f("", 14) + "@db.internal:5432/app",
		"https://api.example.com/v1?access_token=" + f("", 32) + "&x=1", jwt,
		"API_TOKEN=" + f("", 30), `password: "` + f("", 16) + `"`, "my.private-key => " + f("", 20),
		// near misses and noise
		f("sk-", 10), "sk-ant-short", f("ghp_", 20), "AKIA" + strings.ToLower(f("", 16)), "https://example.com/path",
		"token=abc", "your_api_key_here", "sk_live_abcdefghijklmnopqrstuvwx", "xxxxxxxxxxxxxxxxxxxxxxxx",
		"PASSWORD=${DB_PASSWORD}", "input_tokens", "cf_token", "Cloudflare", f("eyJ", 8),
	}
}

// PEM is random bytes in PEM armour, and its base64 body.
func PEM(r *rand.Rand) (pem, body string) {
	raw := make([]byte, 400)
	for i := range raw {
		raw[i] = byte(r.IntN(256))
	}
	body = base64.StdEncoding.EncodeToString(raw)
	var lines []string
	for i := 0; i < len(body); i += 64 {
		lines = append(lines, body[i:min(i+64, len(body))])
	}
	return "-----BEGIN RSA PRIVATE KEY-----\n" + strings.Join(lines, "\n") + "\n-----END RSA PRIVATE KEY-----\n", body
}

// Filler is text of the kinds a transcript holds: source code, prose, URLs, shell output and
// base64 blobs (screenshots), with words that look like secret names.
func Filler(r *rand.Rand, n int) string {
	chunks := []string{
		"func handler(w http.ResponseWriter, r *http.Request) {\n\ttoken := r.Header.Get(\"Authorization\")\n\tif token == \"\" {\n\t\treturn\n\t}\n}\n",
		"The password field is validated on the server; see https://docs.example.com/auth#tokens for the access_token flow.\n",
		"const config = { apiKey: process.env.API_KEY, secretName: 'db', passwordFile: '/run/secrets/pg' };\n",
		"$ ls -la ~/.ssh\ntotal 24\n-rw-------  1 me  staff  464 Jan  1 10:00 id_ed25519\n",
		"<div class=\"token-list\">&amp; {{ user.name }} ${HOME} %s</div>\n",
		"SELECT id, email, password_hash FROM users WHERE created_at > now() - interval '1 day';\n",
		"git clone git@github.com:someone/project.git && cd project && make test\n",
		"  \"input_tokens\": 1234, \"output_tokens\": 56, \"cache_read_input_tokens\": 789,\n",
		"Error: credentials not found in ~/.aws/credentials (profile default); key rotation pending\n",
	}
	var b strings.Builder
	for b.Len() < n {
		switch r.IntN(12) {
		case 0:
			blob := make([]byte, 3000+r.IntN(30000))
			for i := range blob {
				blob[i] = byte(r.IntN(256))
			}
			b.WriteString(base64.StdEncoding.EncodeToString(blob))
			b.WriteByte('\n')
		case 1:
			b.WriteString(Fake(r, "", 200+r.IntN(2000), Alnum+"     \n\t.,;:-_/"))
		default:
			b.WriteString(chunks[r.IntN(len(chunks))])
		}
	}
	return b.String()
}

// Line is one transcript JSONL line of about size bytes holding k secrets from the pool.
func Line(r *rand.Rand, size, k int, pool []string) string {
	text := Filler(r, size)
	for range k {
		at := r.IntN(len(text))
		text = text[:at] + " " + pool[r.IntN(len(pool))] + " " + text[at:]
	}
	enc, _ := json.Marshal(text)
	return `{"parentUuid":"a","type":"user","message":{"role":"user","content":[{"type":"tool_result","content":` + string(enc) +
		`}]},"usage":{"input_tokens":1,"output_tokens":2},"cwd":"/Users/me/src/app"}`
}

// ShortLines are lines of a few hundred bytes, each with a secret or two, adjacent or overlapping
// shapes, and raw (unescaped) text as shell histories and logs hold it.
func ShortLines(r *rand.Rand, pool []string) []string {
	var out []string
	for i, s := range pool {
		next := pool[(i+1)%len(pool)]
		out = append(out,
			s,
			"export X="+s,
			": 1700000000:0;curl -H 'Authorization: Bearer "+s+"' https://api.example.com",
			s+next,
			s+" "+next,
			"KEY_"+s+"=1",
			`{"content":"`+strings.ReplaceAll(s, `"`, `\"`)+`"}`,
			Filler(r, 300)+s+Filler(r, 200),
		)
	}
	return out
}
