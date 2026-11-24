package gcp

import (
	"context"
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
		"projects list " + ci + " --limit=1":    {{stderr: "denied_apikeys.txt"}},
	}, nil)
	checks := c.Doctor(context.Background(), connector.Request{})
	got := map[string]connector.Check{}
	for _, ch := range checks {
		got[ch.What] = ch
	}
	if ch := got["gcloud"]; ch.Level != connector.OK || !strings.Contains(ch.Detail, "3 credentialed") {
		t.Errorf("gcloud: %+v", ch)
	}
	if ch := got["gcloud account owner@example.com"]; ch.Level != connector.OK {
		t.Errorf("owner: %+v", ch)
	}
	if ch := got["gcloud account work@example.org"]; ch.Level != connector.Fail || ch.Fix != "gcloud auth login work@example.org" {
		t.Errorf("work: %+v", ch)
	}
	if ch := got["gcloud account ci@demo-shop.iam.gserviceaccount.com"]; ch.Level != connector.Warn {
		t.Errorf("ci: %+v", ch)
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
