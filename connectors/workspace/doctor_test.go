package workspace

import (
	"context"
	"strings"
	"testing"

	"github.com/segurata/segurata/internal/connector"
)

func TestDoctor(t *testing.T) {
	cfg := map[string]any{"domain": domain}
	cases := []struct {
		name   string
		home   string
		g      *fakeGcloud
		cfg    map[string]any
		levels []connector.Level
		detail string
		fix    string
	}{
		{"token obtained", credsHome(t), &fakeGcloud{}, cfg, []connector.Level{connector.OK}, "obtained from CLOUDSDK_CONFIG=", ""},
		{"no stored credentials", t.TempDir(), &fakeGcloud{}, cfg, []connector.Level{connector.Fail}, "No admin credentials for example.com", "gcloud auth application-default login"},
		{"no tenant", t.TempDir(), &fakeGcloud{}, nil, []connector.Level{connector.Warn}, "no tenant configured", `"workspace:example.com"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			checks := newTest(tc.home, nil, validInfo(t), tc.g).Doctor(context.Background(), connector.Request{Config: tc.cfg})
			if len(checks) != len(tc.levels) {
				t.Fatalf("checks %+v", checks)
			}
			for i, ch := range checks {
				if ch.Level != tc.levels[i] {
					t.Errorf("check %d: %+v", i, ch)
				}
				if strings.Contains(ch.Detail+ch.Fix, fakeToken) {
					t.Fatal("token printed")
				}
			}
			if !strings.Contains(checks[0].Detail, tc.detail) || !strings.Contains(checks[0].Fix, tc.fix) {
				t.Errorf("got %+v", checks[0])
			}
		})
	}
}

func TestDoctorWithoutReportsScope(t *testing.T) {
	info := tokenInfoServer(t, 200, `{"scope":"https://www.googleapis.com/auth/admin.directory.user.readonly https://www.googleapis.com/auth/admin.directory.user.security","email":"boss@example.com"}`)
	checks := newTest(credsHome(t), nil, info, &fakeGcloud{}).Doctor(context.Background(), connector.Request{Config: map[string]any{"domain": domain}})
	if len(checks) != 2 || checks[0].Level != connector.OK || !strings.Contains(checks[0].Detail, "boss@example.com") || checks[1].Level != connector.Warn {
		t.Fatalf("%+v", checks)
	}
}
