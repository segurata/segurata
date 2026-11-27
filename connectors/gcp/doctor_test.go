package gcp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/segurata/segurata/connectors/internal/cli"
	"github.com/segurata/segurata/internal/connector"
)

func TestDoctorReportsExpiredAccounts(t *testing.T) {
	c, _ := testConnector(t, t.TempDir(), map[string][]outcome{
		"auth list":                             {{stdout: "auth_list.json"}},
		"projects list " + owner + " --limit=1": {{stdout: "projects_owner.json"}},
		"projects list " + work + " --limit=1":  {{stderr: "reauth.txt"}},
		"auth print-access-token " + owner:      {{stdout: "access_token.txt"}},
		"billing accounts list " + owner:        {{stdout: "billing_accounts_owner.json"}},
	}, nil)
	var asked []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct{ Permissions []string }
		_ = json.NewDecoder(r.Body).Decode(&body)
		asked = append(asked, r.Method+" "+r.URL.Path+" "+r.Header.Get("Authorization")+" "+r.Header.Get("X-Goog-User-Project")+" "+strings.Join(body.Permissions, ","))
		_, _ = w.Write([]byte(`{"permissions":["monitoring.timeSeries.list"]}`))
	}))
	defer srv.Close()
	c.apiBase = func(string) string { return srv.URL }
	checks := c.Doctor(context.Background(), connector.Request{})
	got := map[string]connector.Check{}
	for _, ch := range checks {
		got[ch.What] = ch
	}
	if ch := got["gcloud"]; ch.Level != connector.OK || !strings.Contains(ch.Detail, "2 credentialed") {
		t.Errorf("gcloud: %+v", ch)
	}
	if ch := got["gcloud account owner@example.com"]; ch.Level != connector.OK {
		t.Errorf("owner: %+v", ch)
	}
	if ch := got["gcloud account work@example.org"]; ch.Level != connector.Fail || ch.Fix != "gcloud auth login work@example.org" {
		t.Errorf("work: %+v", ch)
	}
	perms := got["permissions of owner@example.com on project demo-shop"]
	if perms.Level != connector.Warn || strings.Contains(perms.Detail, "monitoring.timeSeries.list") ||
		!strings.Contains(perms.Detail, "missing serviceusage.services.list (roles/serviceusage.serviceUsageViewer, for listing enabled pay-per-use APIs); ") ||
		!strings.Contains(perms.Detail, "apikeys.keys.update (roles/serviceusage.apiKeysAdmin, for gcp.apikey.restrict)") {
		t.Errorf("permissions: %+v", perms)
	}
	want := []string{
		"POST /v3/projects/demo-shop:testIamPermissions Bearer " + accessToken + " demo-shop " + strings.Join(permissionNames(projectPermissions), ","),
		"POST /v1/billingAccounts/000000-AAAAAA-111111:testIamPermissions Bearer " + accessToken + " demo-shop " + strings.Join(permissionNames(billingPermissions), ","),
	}
	if !slices.Equal(asked, want) {
		t.Errorf("testIamPermissions requests\n%q\nwant\n%q", asked, want)
	}
	if b := got["permissions of owner@example.com on billing account 000000-AAAAAA-111111"]; b.Level != connector.Warn ||
		!strings.Contains(b.Detail, "billing.budgets.create (roles/billing.costsManager, for gcp.budget.create)") {
		t.Errorf("billing permissions: %+v", b)
	}
	for _, ch := range checks {
		if strings.Contains(ch.Detail+ch.Fix, accessToken) {
			t.Errorf("token in a check: %+v", ch)
		}
	}
	if ch, ok := got["gcloud account ci@demo-shop.iam.gserviceaccount.com"]; ok {
		t.Errorf("a service account gcloud activated is not an inventory account: %+v", ch)
	}
}

func TestDoctorWithoutGcloud(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	c := New()
	c.home = t.TempDir()
	if _, err := cli.FindGcloud("", c.home, connectorName); err == nil {
		t.Skip("gcloud installed in a standard folder outside PATH")
	}
	checks := c.Doctor(context.Background(), connector.Request{})
	if len(checks) != 1 || checks[0].Level != connector.Fail || !strings.Contains(checks[0].Fix, "gcloud_path") {
		t.Errorf("%+v", checks)
	}
}
