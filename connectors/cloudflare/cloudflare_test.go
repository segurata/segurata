package cloudflare

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/segurata/segurata/connectors/internal/httpx/httpxtest"
	"github.com/segurata/segurata/internal/connector"
	"github.com/segurata/segurata/internal/finding"
)

var now = time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)

const testToken = "cf-test-token-not-real-0123456789"

func ago(days int) string { return now.AddDate(0, 0, -days).Format(time.RFC3339) }

// ok wraps a result in Cloudflare's envelope.
func ok(result any) map[string]any {
	return map[string]any{"success": true, "errors": []any{}, "messages": []any{}, "result": result}
}

func static(result any) httpxtest.Route { return httpxtest.Static(ok(result)) }

func raw(s string) httpxtest.Route { return static(json.RawMessage(s)) }

// paged serves items perPage at a time, as Cloudflare does.
func paged(t *testing.T, items []any) httpxtest.Route {
	return func(q url.Values) (int, any) {
		var page, per int
		fmt.Sscan(q.Get("page"), &page)
		fmt.Sscan(q.Get("per_page"), &per)
		if page < 1 || per < 5 || per > 50 {
			t.Errorf("bad pagination %v", q)
			return http.StatusBadRequest, nil
		}
		lo, hi := min((page-1)*per, len(items)), min(page*per, len(items))
		body := ok(items[lo:hi])
		body["result_info"] = map[string]any{"page": page, "per_page": per, "count": hi - lo, "total_count": len(items),
			"total_pages": (len(items) + per - 1) / per}
		return http.StatusOK, body
	}
}

func newServer(t *testing.T, routes map[string]httpxtest.Route) *httpxtest.Server {
	return httpxtest.NewServer(t, http.Header{"Authorization": {"Bearer " + testToken}}, routes)
}

func connectorFor(srv *httpxtest.Server) *Connector {
	return &Connector{BaseURL: srv.URL, Now: func() time.Time { return now }, Interval: -1}
}

func run(t *testing.T, srv *httpxtest.Server, tok string, cfg map[string]any) *httpxtest.Recorder {
	t.Helper()
	rec := &httpxtest.Recorder{}
	req := connector.Request{Secrets: map[string]string{secretName: tok}, Config: cfg}
	if err := connectorFor(srv).Inventory(context.Background(), req, rec); err != nil {
		t.Fatal(err)
	}
	return rec
}

func verifyRoute() httpxtest.Route {
	return raw(`{"id":"tok-self","status":"active","expires_on":"2027-01-01T00:00:00Z"}`)
}

const (
	acctA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	acctB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

// fullRoutes is a synthetic user with two accounts, three zones and four tokens.
func fullRoutes(t *testing.T) map[string]httpxtest.Route {
	tokens := []any{
		// The segurata token itself: read-only, expires, used today.
		json.RawMessage(fmt.Sprintf(`{"id":"tok-self","name":"segurata","status":"active","issued_on":%q,"last_used_on":%q,"expires_on":"2027-01-01T00:00:00Z",
			"policies":[{"id":"p1","effect":"allow","permission_groups":[{"id":"g1","name":"Zone Read"},{"id":"g2","name":"DNS Read"}],"resources":{"com.cloudflare.api.account.zone.*":"*"}}]}`, ago(10), ago(0))),
		// Edit on all zones, no IP filter, no expiry.
		json.RawMessage(fmt.Sprintf(`{"id":"tok-broad","name":"ci deploy","status":"active","issued_on":%q,"last_used_on":%q,
			"policies":[{"id":"p2","effect":"allow","permission_groups":[{"id":"g3","name":"DNS Write"}],"resources":{"com.cloudflare.api.account.zone.*":"*"}}]}`, ago(30), ago(1))),
		// Edit on one zone, IP restricted, expires, but idle.
		json.RawMessage(fmt.Sprintf(`{"id":"tok-idle","name":"old script","status":"active","issued_on":%q,"last_used_on":%q,"expires_on":"2027-06-01T00:00:00Z",
			"condition":{"request.ip":{"in":["192.0.2.0/24"]}},
			"policies":[{"id":"p3","effect":"allow","permission_groups":[{"id":"g4","name":"Zone Settings Write"}],"resources":{"com.cloudflare.api.account.zone.z1":"*"}}]}`, ago(400), ago(200))),
		// Disabled: reported, not graded.
		json.RawMessage(`{"id":"tok-off","name":"retired","status":"disabled","policies":[]}`),
	}
	zones := []any{
		map[string]any{"id": "z1", "name": "example.com", "status": "active", "account": map[string]any{"id": acctA, "name": "Acme"}},
		map[string]any{"id": "z2", "name": "example.org", "status": "active", "account": map[string]any{"id": acctA, "name": "Acme"}},
		map[string]any{"id": "z3", "name": "example.net", "status": "moved", "account": map[string]any{"id": acctB, "name": "Side"}},
	}
	setting := func(id, v string) httpxtest.Route {
		return static(map[string]any{"id": id, "value": v, "editable": true})
	}
	return map[string]httpxtest.Route{
		"/user/tokens/verify": verifyRoute(),
		"/user/tokens":        paged(t, tokens),
		"/accounts": paged(t, []any{
			map[string]any{"id": acctA, "name": "Acme"},
			map[string]any{"id": acctB, "name": "Side"},
		}),
		"/accounts/" + acctA: raw(`{"id":"` + acctA + `","name":"Acme","type":"standard","settings":{"enforce_twofactor":false}}`),
		"/accounts/" + acctB: raw(`{"id":"` + acctB + `","name":"Side","type":"standard","settings":{"enforce_twofactor":true}}`),
		"/accounts/" + acctA + "/members": paged(t, []any{
			json.RawMessage(`{"id":"m1","status":"accepted","roles":[{"id":"r1","name":"Super Administrator - All Privileges"}],"user":{"email":"owner@example.com","two_factor_authentication_enabled":true}}`),
			json.RawMessage(`{"id":"m2","status":"accepted","roles":[{"id":"r1","name":"Super Administrator - All Privileges"}],"user":{"email":"partner@example.com","two_factor_authentication_enabled":false}}`),
			json.RawMessage(`{"id":"m3","status":"pending","roles":[{"id":"r2","name":"Administrator"}],"user":{"email":"invitee@example.com"}}`),
		}),
		"/accounts/" + acctB + "/members": paged(t, []any{
			json.RawMessage(`{"id":"m4","status":"accepted","policies":[{"id":"p","access":"allow","permission_groups":[{"id":"x","name":"Super Administrator - All Privileges"}]}],"user":{"email":"owner@example.com","two_factor_authentication_enabled":false}}`),
		}),
		"/zones":                              paged(t, zones),
		"/zones/z1/settings/ssl":              setting("ssl", "flexible"),
		"/zones/z1/settings/always_use_https": setting("always_use_https", "off"),
		"/zones/z1/settings/min_tls_version":  setting("min_tls_version", "1.0"),
		"/zones/z1/dnssec":                    raw(`{"status":"disabled"}`),
		"/zones/z2/settings/ssl":              setting("ssl", "strict"),
		"/zones/z2/settings/always_use_https": setting("always_use_https", "on"),
		"/zones/z2/settings/min_tls_version":  setting("min_tls_version", "1.2"),
		"/zones/z2/dnssec":                    raw(`{"status":"active"}`),
	}
}

func TestInventory(t *testing.T) {
	srv := newServer(t, fullRoutes(t))
	rec := run(t, srv, testToken, nil)
	want := map[string]finding.Severity{
		"cloudflare_api_token/tok-self":               finding.SevInfo,
		"cloudflare_api_token/tok-broad":              finding.SevHigh,
		"cloudflare_api_token/tok-idle":               finding.SevMedium,
		"cloudflare_api_token/tok-off":                finding.SevInfo,
		"cloudflare_global_api_key/global_api_key":    finding.SevInfo,
		"cloudflare_account/" + acctA:                 finding.SevHigh,
		"cloudflare_account/" + acctB:                 finding.SevInfo,
		"cloudflare_member/m1":                        finding.SevInfo,
		"cloudflare_member/m2":                        finding.SevMedium,
		"cloudflare_member/m3":                        finding.SevInfo,
		"cloudflare_member/m4":                        finding.SevLow,
		"cloudflare_super_admins/" + acctA:            finding.SevMedium,
		"cloudflare_super_admins/" + acctB:            finding.SevInfo,
		"cloudflare_zone_setting/z1/ssl":              finding.SevMedium,
		"cloudflare_zone_setting/z1/always_use_https": finding.SevLow,
		"cloudflare_zone_setting/z1/min_tls_version":  finding.SevMedium,
		"cloudflare_zone_setting/z1/dnssec":           finding.SevLow,
		"cloudflare_zone_setting/z2/ssl":              finding.SevInfo,
		"cloudflare_zone_setting/z2/always_use_https": finding.SevInfo,
		"cloudflare_zone_setting/z2/min_tls_version":  finding.SevInfo,
		"cloudflare_zone_setting/z2/dnssec":           finding.SevInfo,
	}
	got := map[string]finding.Severity{}
	for _, f := range rec.Findings {
		got[f.Resource.Type+"/"+f.Resource.ID] = f.Severity
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("got  %v\nwant %v", got, want)
	}
	if len(srv.Misses) != 0 {
		t.Fatalf("unexpected requests: %v", srv.Misses)
	}
	if srv.Hits["/zones/z3/dnssec"] != 0 {
		t.Fatal("a moved zone was inspected")
	}

	broad := rec.ByResource(t, "cloudflare_api_token", "tok-broad")
	for _, want := range []string{"can edit all zones (DNS Write)", "no client IP restriction", "never expires"} {
		if !strings.Contains(broad.Title, want) {
			t.Errorf("broad token title %q lacks %q", broad.Title, want)
		}
	}
	if broad.Account != userAccount {
		t.Errorf("token account %q", broad.Account)
	}
	self := rec.ByResource(t, "cloudflare_api_token", "tok-self")
	if self.Evidence["used_by_segurata"] != true {
		t.Errorf("own token not marked: %+v", self.Evidence)
	}
	if idle := rec.ByResource(t, "cloudflare_api_token", "tok-idle"); !strings.Contains(idle.Title, "unused for 200 days") || strings.Contains(idle.Title, "IP") {
		t.Errorf("idle token title %q", idle.Title)
	}
	admins := rec.ByResource(t, "cloudflare_super_admins", acctA)
	if fmt.Sprint(admins.Evidence["super_administrators"]) != "[owner@example.com partner@example.com]" || admins.Account != "Acme" {
		t.Errorf("super admins %+v", admins)
	}
	if z := rec.ByResource(t, "cloudflare_zone_setting", "z1/ssl"); z.Account != "Acme" || z.Resource.Name != "example.com" {
		t.Errorf("zone finding %+v", z)
	}

	states := map[string]finding.State{}
	for _, s := range rec.Statuses {
		states[s.Account] = s.State
	}
	if fmt.Sprint(states) != fmt.Sprint(map[string]finding.State{"user": finding.StateOK, "Acme": finding.StateOK, "Side": finding.StateOK}) {
		t.Fatalf("statuses %+v", rec.Statuses)
	}
	rec.AssertNoSecret(t, testToken)
}

func TestPaginationAndMaxZones(t *testing.T) {
	var zones []any
	routes := map[string]httpxtest.Route{
		"/user/tokens/verify": verifyRoute(),
		"/user/tokens":        paged(t, nil),
		"/accounts":           paged(t, nil),
	}
	for i := range 120 {
		id := fmt.Sprintf("z%03d", i)
		zones = append(zones, map[string]any{"id": id, "name": id + ".example", "status": "active", "account": map[string]any{"id": acctA, "name": "Acme"}})
		for _, s := range zoneSettings {
			routes["/zones/"+id+"/settings/"+s] = static(map[string]any{"id": s, "value": "on"})
		}
		routes["/zones/"+id+"/dnssec"] = raw(`{"status":"active"}`)
	}
	routes["/zones"] = paged(t, zones)
	srv := newServer(t, routes)

	rec := run(t, srv, testToken, map[string]any{"max_zones": float64(70)})
	if srv.Hits["/zones"] != 2 || srv.Hits["/zones/z069/dnssec"] != 1 || srv.Hits["/zones/z070/dnssec"] != 0 {
		t.Fatalf("zone pages %d, z069 %d, z070 %d", srv.Hits["/zones"], srv.Hits["/zones/z069/dnssec"], srv.Hits["/zones/z070/dnssec"])
	}
	if len(rec.Logs) != 1 || !strings.Contains(rec.Logs[0], "first 70 of 120") {
		t.Fatalf("logs %v", rec.Logs)
	}

	srv2 := newServer(t, routes)
	run(t, srv2, testToken, nil)
	if srv2.Hits["/zones"] != 3 || srv2.Hits["/zones/z119/dnssec"] != 1 {
		t.Fatalf("default cap: zone pages %d, z119 %d", srv2.Hits["/zones"], srv2.Hits["/zones/z119/dnssec"])
	}
}

func TestMissingPermissionIsNoScopeAndCountedOnce(t *testing.T) {
	routes := fullRoutes(t)
	routes["/user/tokens"] = httpxtest.Fail(http.StatusForbidden, "Unauthorized to access requested resource")
	for _, z := range []string{"z1", "z2"} {
		routes["/zones/"+z+"/dnssec"] = httpxtest.Fail(http.StatusForbidden, "Unauthorized to access requested resource")
	}
	rec := run(t, newServer(t, routes), testToken, nil)
	by := map[string]finding.Status{}
	for _, s := range rec.Statuses {
		by[s.Account] = s
	}
	if st := by["user"]; st.State != finding.StateNoScope || !strings.Contains(st.Detail, "API tokens:") || !strings.Contains(st.Detail, "User > API Tokens > Read") {
		t.Fatalf("user status %+v", st)
	}
	if st := by["Acme"]; st.State != finding.StateNoScope || !strings.Contains(st.Detail, "DNSSEC: ") || !strings.Contains(st.Detail, "(2 times)") {
		t.Fatalf("Acme status %+v", st)
	}
	// The rest still ran.
	rec.ByResource(t, "cloudflare_zone_setting", "z1/ssl")
	rec.AssertNoSecret(t, testToken)
}

func TestRateLimitStopsTheRun(t *testing.T) {
	routes := fullRoutes(t)
	routes["/accounts"] = httpxtest.Fail(http.StatusTooManyRequests, "rate limited")
	srv := newServer(t, routes)
	rec := run(t, srv, testToken, nil)
	if srv.Hits["/zones"] != 0 {
		t.Fatal("kept calling after a 429")
	}
	if st := rec.Statuses[0]; st.Account != "user" || st.State != finding.StateError || !strings.Contains(st.Detail, "429") {
		t.Fatalf("status %+v", rec.Statuses)
	}
}

func TestMissingTokenExplainsSetup(t *testing.T) {
	rec := &httpxtest.Recorder{}
	if err := (&Connector{}).Inventory(context.Background(), connector.Request{}, rec); err != nil {
		t.Fatal(err)
	}
	st := rec.Statuses[0]
	if st.State != finding.StateMissingCredentials {
		t.Fatalf("status %+v", st)
	}
	for _, want := range []string{
		"User > API Tokens > Read", "Account > Account Settings > Read", "Zone > Zone > Read",
		"Zone > Zone Settings > Read", "Zone > DNS > Read",
		`security add-generic-password -s segurata-cloudflare -a "$USER" -w`,
		`"CLOUDFLARE_API_TOKEN": "keychain:segurata-cloudflare"`, "cloudflare:<label>",
	} {
		if !strings.Contains(st.Detail, want) {
			t.Errorf("setup hint lacks %q", want)
		}
	}
	if len(rec.Findings) != 0 {
		t.Fatal("findings without a token")
	}
}

func TestRejectedTokenIsReauth(t *testing.T) {
	rec := run(t, newServer(t, nil), "wrong-token", nil)
	if len(rec.Statuses) != 1 || rec.Statuses[0].State != finding.StateReauth || len(rec.Findings) != 0 {
		t.Fatalf("statuses %+v findings %d", rec.Statuses, len(rec.Findings))
	}
	rec.AssertNoSecret(t, "wrong-token")
}

func TestExpiredTokenIsReauth(t *testing.T) {
	srv := newServer(t, map[string]httpxtest.Route{"/user/tokens/verify": raw(`{"id":"t","status":"expired"}`)})
	rec := run(t, srv, testToken, nil)
	if st := rec.Statuses[0]; st.State != finding.StateReauth || !strings.Contains(st.Detail, "expired") {
		t.Fatalf("status %+v", st)
	}
}

func TestBadConfig(t *testing.T) {
	for _, v := range []any{"10", float64(0), 2.5, true} {
		if _, err := parseSettings(map[string]any{"max_zones": v}); err == nil {
			t.Errorf("accepted max_zones %v", v)
		}
	}
	if s, err := parseSettings(nil); err != nil || s.maxZones != defaultMaxZones {
		t.Fatalf("default %+v %v", s, err)
	}
}

func TestTokenFinding(t *testing.T) {
	s := func(v string) *string { return &v }
	exp := s("2027-01-01T00:00:00Z")
	read := []policy{{Effect: "allow", PermissionGroups: []permissionGroup{{Name: "Zone Read"}}, Resources: map[string]json.RawMessage{resAllZones: json.RawMessage(`"*"`)}}}
	edit := func(res string) []policy {
		return []policy{{Effect: "allow", PermissionGroups: []permissionGroup{{Name: "Workers Scripts Write"}}, Resources: map[string]json.RawMessage{res: json.RawMessage(`"*"`)}}}
	}
	ipOnly := condition{RequestIPAlt: &ipFilter{In: []string{"198.51.100.7/32"}}}
	cases := []struct {
		name string
		tok  apiToken
		want finding.Severity
	}{
		{"read-only on all zones is fine", apiToken{Status: "active", ExpiresOn: exp, LastUsedOn: s(ago(1)), Policies: read}, finding.SevInfo},
		{"no expiry", apiToken{Status: "active", LastUsedOn: s(ago(1)), Policies: read}, finding.SevMedium},
		{"never used for 100 days", apiToken{Status: "active", ExpiresOn: exp, IssuedOn: s(ago(100)), Policies: read}, finding.SevMedium},
		{"never used but new", apiToken{Status: "active", ExpiresOn: exp, IssuedOn: s(ago(5)), Policies: read}, finding.SevInfo},
		{"edit on one account, IP restricted", apiToken{Status: "active", ExpiresOn: exp, LastUsedOn: s(ago(1)), Condition: ipOnly, Policies: edit(resAccount + acctA)}, finding.SevInfo},
		{"edit on one account, no IP", apiToken{Status: "active", ExpiresOn: exp, LastUsedOn: s(ago(1)), Policies: edit(resAccount + acctA)}, finding.SevMedium},
		{"edit on all accounts even with IP", apiToken{Status: "active", ExpiresOn: exp, LastUsedOn: s(ago(1)), Condition: ipOnly, Policies: edit(resAllAccounts)}, finding.SevHigh},
		{"not_in alone is no restriction", apiToken{Status: "active", ExpiresOn: exp, LastUsedOn: s(ago(1)), Condition: condition{RequestIP: &ipFilter{NotIn: []string{"10.0.0.0/8"}}}, Policies: edit(resZone + "z1")}, finding.SevMedium},
		{"deny policies grant nothing", apiToken{Status: "active", ExpiresOn: exp, LastUsedOn: s(ago(1)), Policies: []policy{{Effect: "deny", PermissionGroups: []permissionGroup{{Name: "DNS Write"}}, Resources: map[string]json.RawMessage{resAllZones: json.RawMessage(`"*"`)}}}}, finding.SevInfo},
		{"unnamed group counts as edit", apiToken{Status: "active", ExpiresOn: exp, LastUsedOn: s(ago(1)), Policies: []policy{{Effect: "allow", PermissionGroups: []permissionGroup{{ID: "abc"}}, Resources: map[string]json.RawMessage{resZone + "z1": json.RawMessage(`"*"`)}}}}, finding.SevMedium},
		{"expired is info", apiToken{Status: "expired", Policies: edit(resAllAccounts)}, finding.SevInfo},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if f := tokenFinding(tc.tok, false, now); f.Severity != tc.want {
				t.Fatalf("got %s %q", f.Severity, f.Title)
			}
		})
	}
}

func TestScopes(t *testing.T) {
	res := map[string]json.RawMessage{
		resAccount + acctA: json.RawMessage(`{"com.cloudflare.api.account.zone.*":"*"}`),
		resZone + "z9":     json.RawMessage(`"*"`),
		resUser + "u1":     json.RawMessage(`"*"`),
		resAllAccounts:     json.RawMessage(`"*"`),
	}
	desc, broad := scopes(res)
	if fmt.Sprint(broad) != "[all accounts]" {
		t.Fatalf("broad %v", broad)
	}
	want := "[all accounts all zones of account " + acctA + " zone z9 your user]"
	if fmt.Sprint(desc) != want {
		t.Fatalf("desc %v\nwant %v", desc, want)
	}
}

func TestDoctor(t *testing.T) {
	routes := fullRoutes(t)
	routes["/zones/z1/dnssec"] = httpxtest.Fail(http.StatusForbidden, "Unauthorized to access requested resource")
	srv := newServer(t, routes)
	checks := connectorFor(srv).Doctor(context.Background(), connector.Request{Secrets: map[string]string{secretName: testToken}})
	got := map[string]connector.Level{}
	for _, c := range checks {
		got[c.What] = c.Level
		if strings.Contains(c.Detail+c.Fix, testToken) {
			t.Fatal("doctor printed the token")
		}
	}
	want := map[string]connector.Level{
		"cloudflare token": connector.OK, "cloudflare API tokens": connector.OK, "cloudflare accounts": connector.OK,
		"cloudflare zones": connector.OK, "cloudflare zone settings (example.com)": connector.OK,
		"cloudflare DNSSEC (example.com)": connector.Fail,
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("got  %v\nwant %v", got, want)
	}
	if checks[0].Detail != "active, expires 2027-01-01" {
		t.Errorf("token detail %q", checks[0].Detail)
	}

	missing := (&Connector{}).Doctor(context.Background(), connector.Request{})
	if len(missing) != 1 || missing[0].Level != connector.Warn || !strings.Contains(missing[0].Fix, Permissions) {
		t.Fatalf("missing token: %+v", missing)
	}
	bad := connectorFor(newServer(t, nil)).Doctor(context.Background(), connector.Request{Secrets: map[string]string{secretName: "nope"}})
	if len(bad) != 1 || bad[0].Level != connector.Fail {
		t.Fatalf("bad token: %+v", bad)
	}
}

func TestPacerSpacesRequests(t *testing.T) {
	p := &pacer{every: 20 * time.Millisecond}
	start := time.Now()
	for range 4 {
		if err := p.wait(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if d := time.Since(start); d < 60*time.Millisecond {
		t.Fatalf("4 requests in %s", d)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := (&pacer{every: time.Hour}).wait(ctx); err == nil {
		t.Fatal("a cancelled context must stop the wait")
	}
}
