package localsecrets

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/segurata/segurata/internal/connector"
	"github.com/segurata/segurata/internal/finding"
	"github.com/segurata/segurata/internal/secretrisk"
	"github.com/segurata/segurata/internal/testcorpus"
)

// A key set with setx lives in the registry, not in a file: it is found there like a NAME=value
// line, points to the Credential Manager fix and offers no chmod. An AWS key id in one variable
// makes the secret in another an AWS secret key.
func TestUserEnvironmentVariablesAreSearched(t *testing.T) {
	fx := newFixture(t)
	keyID, awsSecret := testcorpus.AWSKeyID("AKIA", 123456789012, false, 3), fake("", 40)
	fx.secrets = append(fx.secrets, keyID, awsSecret)
	c := fx.connector(t, "[]")
	c.UserEnv = func() (map[string]string, error) {
		return map[string]string{"STRIPE_API_KEY": fx.stripe, "AWS_ACCESS_KEY_ID": keyID, "AWS_SECRET_ACCESS_KEY": awsSecret,
			"Path": `%USERPROFILE%\AppData\Local\Microsoft\WindowsApps;`, "TEMP": `%USERPROFILE%\AppData\Local\Temp`}, nil
	}
	rec := &recorder{}
	if err := c.Inventory(context.Background(), connector.Request{Config: map[string]any{"data_dumps": false}}, rec); err != nil {
		t.Fatal(err)
	}
	got := map[string]finding.Finding{}
	for _, f := range rec.Findings {
		if p := evidence(f, "path"); secretrisk.IsUserEnv(p) {
			got[p] = f
		}
	}
	for name, typ := range map[string]string{"STRIPE_API_KEY": "stripe-live", "AWS_ACCESS_KEY_ID": "aws-access-key-id", "AWS_SECRET_ACCESS_KEY": awsSecretType} {
		f, ok := got[secretrisk.UserEnvKey+`\`+name]
		switch {
		case !ok:
			t.Errorf("%s not found; got %v", name, got)
		case evidence(f, "type") != typ || evidence(f, "source") != registrySource || evidence(f, "kind") != "config":
			t.Errorf("%s: type %s, source %s, kind %s", name, evidence(f, "type"), evidence(f, "source"), evidence(f, "kind"))
		case evidence(f, "fix") != fixDoc+"#shell-variables-from-credential-manager" && typ == "stripe-live":
			t.Errorf("%s: fix %s", name, evidence(f, "fix"))
		case f.Remediation.Action != "" || evidence(f, "mode") != "<nil>" && evidence(f, "mode") != "":
			t.Errorf("%s: a registry value has no mode to close: %+v %s", name, f.Remediation, evidence(f, "mode"))
		}
	}
	if len(got) != 3 {
		t.Errorf("want only the three secrets, got %v", got)
	}
	raw, _ := json.Marshal([]any{rec.Findings, rec.Statuses, rec.Scopes})
	for _, v := range fx.secrets {
		if len(v) >= 6 && strings.Contains(string(raw), v) {
			t.Fatal("a raw secret reached the output")
		}
	}
}

// A registry that cannot be read leaves that key uninspected, so what it held is not taken as gone.
func TestUnreadableUserEnvironmentIsSkipped(t *testing.T) {
	fx := newFixture(t)
	c := fx.connector(t, "[]")
	c.UserEnv = func() (map[string]string, error) { return nil, errors.New("Access is denied.") }
	rec := &recorder{}
	if err := c.Inventory(context.Background(), connector.Request{Config: map[string]any{"data_dumps": false}}, rec); err != nil {
		t.Fatal(err)
	}
	want := finding.PathScope(secretrisk.FilesScope, secretrisk.UserEnvKey) + ": registry: Access is denied."
	var found bool
	for _, s := range rec.skipped() {
		found = found || s == want
	}
	if !found {
		t.Errorf("skipped %q, want %q", rec.skipped(), want)
	}
}
