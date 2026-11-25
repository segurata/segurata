package tracker_test

import (
	"bytes"
	"cmp"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/segurata/segurata/internal/finding"
	"github.com/segurata/segurata/internal/runtest"
	"github.com/segurata/segurata/internal/tracker"
)

// The golden test pins what the tracker makes of one synthetic run of every connector whose
// grouping, title or theme is not the default: item keys (persisted in tracker.json, so a changed
// one orphans history), kinds, themes, titles, severities, priorities and next steps. It was
// captured with the tracker that hard-coded each connector's grouping; a connector that now
// declares it must give the same items. `go test ./internal/tracker -run Golden -update` rewrites
// the files; a diff there is a behaviour change to justify.

var update = flag.Bool("update", false, "rewrite the golden files")

var goldenNow = time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)

// goldenFinding is a finding as a connector writes it, filled by the core.
func goldenFinding(connector, instance, account, resType, resID, name string, sev finding.Severity, title string, ev map[string]any) finding.Finding {
	f := finding.Finding{Connector: connector, Instance: instance, Account: account, Resource: finding.Resource{Type: resType, ID: resID, Name: name},
		Severity: sev, Title: title, Evidence: ev, Remediation: finding.Remediation{Summary: "Fix: " + title, URL: "https://example.com/" + resID}}
	f.Fill(goldenNow.Add(-time.Hour))
	return f
}

// goldenRuns are the findings of each connector instance's run, by run file name.
func goldenRuns() map[string][]finding.Finding {
	g := goldenFinding
	prowler := func(check, title, project, uid string, sev finding.Severity) finding.Finding {
		f := g("prowler", "", "me@example.com", "prowler_check", check+":"+project+":"+uid, uid, sev, "Detail of "+check+" on "+uid,
			map[string]any{"check_id": check, "check_title": title, "project": project})
		f.Scope = project
		// What plugins/prowler/segurata-prowler declares (track()); its test checks the same shape.
		name := cmp.Or(title, check)
		f.Track = &finding.Track{Group: finding.GroupCheck, Key: check, Count: finding.CountScopes, Noun: "project", Nouns: "projects",
			Title: name + " fails in {count} (Prowler " + check + ")", TitleOne: name + " fails in " + project + " (Prowler " + check + ")"}
		return f
	}
	slack := func(id, name string, sev finding.Severity) finding.Finding {
		return g("connected-apps", "", "slack:acme", "slack_app", id, name, sev, name+" can read every channel", nil)
	}
	app := func(typ, id, name, rest string) finding.Finding {
		return g("connected-apps", "", "me@example.com", typ, id, name, finding.SevMedium, name+" "+rest, nil)
	}
	grant := func(id, name string, sev finding.Severity) finding.Finding {
		return g("google-personal", "", "me@gmail.com", "oauth_grant", id, name, sev, name+" can read your mail", nil)
	}
	gcp := func(typ, id, project string) finding.Finding {
		ev := map[string]any{}
		if project != "" {
			ev["project"] = project
		}
		return g("gcp", "", "me@example.com", typ, id, id, finding.SevHigh, typ+" "+id+" is too broad", ev)
	}
	apiKey := func(connector, instance, id string, sev finding.Severity) finding.Finding {
		return g(connector, instance, "org-1", "api_key", id, id, sev, "Key "+id+" has no limit", nil)
	}
	auto := g("macos", "", "mac", "setting", "firewall", "Firewall", finding.SevHigh, "The firewall is off", nil)
	auto.Remediation.Action = "macos.firewall.enable"
	auto.Fill(goldenNow.Add(-time.Hour))
	return map[string][]finding.Finding{
		"prowler.jsonl": {
			prowler("logging_audit", "Log metric filter for audit changes", "p1", "sink-a", finding.SevMedium),
			prowler("logging_audit", "Log metric filter for audit changes", "p2", "sink-b", finding.SevLow),
			prowler("iam_keys", "Service account keys rotated", "p1", "key-a", finding.SevHigh),
			prowler("iam_keys", "Service account keys rotated", "p1", "key-b", finding.SevHigh),
			prowler("dns_dnssec", "", "p3", "zone-a", finding.SevLow),
		},
		"github.jsonl": {
			g("github", "", "acme", "github_org_setting", "org-2fa-not-required", "acme", finding.SevHigh, "acme does not require 2FA", nil),
			g("github", "", "beta", "github_org_setting", "org-2fa-not-required", "beta", finding.SevHigh, "beta does not require 2FA", nil),
			g("github", "", "acme", "github_org_setting", "org-some-new-check", "acme", finding.SevMedium, "acme has a new problem", nil),
			g("github", "", "acme", "github_repo_setting", "dependabot-security-updates-disabled", "acme", finding.SevLow, "2 repositories of acme lack Dependabot", nil),
			g("github", "", "acme", "github_repo", "101", "acme/api", finding.SevMedium, "acme/api has secret scanning off", nil),
			g("github", "", "acme", "github_repo", "102", "acme/web", finding.SevMedium, "acme/web has secret scanning off", nil),
			g("github", "", "me", "github_account", "two-factor-authentication", "me", finding.SevCritical, "Your account has no 2FA", nil),
		},
		"connected-apps.jsonl": {
			slack("s1", "Zapier", finding.SevHigh),
			slack("s2", "Polly", finding.SevHigh),
			slack("s3", "Donut", finding.SevMedium),
			app("x_app", "x1", "Flickr", "can post and delete posts as you"),
			app("x_app", "x2", "Buffer", "can post and delete posts as you"),
			app("notion_integration", "n1", "Sync", "can read and change the Notion pages shared with it (your own integration)"),
			app("notion_integration", "n2", "Backup", "can read and change the Notion pages shared with it (your own integration)"),
			app("zoom_app", "z1", "Recorder", "has used your account 3 times"),
			app("zoom_app", "z2", "Notes", "has used your account 12 times"),
			app("github_oauth_app", "o1", "Travis", "can read and write all your repositories"),
		},
		"google-personal.jsonl": {
			grant("c1", "Mailer", finding.SevHigh),
			grant("c2", "Sorter", finding.SevCritical),
			grant("c3", "Calendar sync", finding.SevLow),
			g("google-personal", "", "me@gmail.com", "account_setting", "less-secure", "Less secure apps", finding.SevMedium, "Less secure apps are allowed", nil),
		},
		"workspace.jsonl": {
			g("workspace", "", "acme.com", "admin_2sv", "admins", "Admins", finding.SevCritical, "2 admins have no 2-Step Verification", nil),
		},
		"gcp.jsonl": {
			gcp("api_key", "k1", "p1"),
			gcp("api_key", "k2", "p1"),
			gcp("service_account_key", "sak1", "p2"),
			gcp("service_account_role", "sa1", ""),
			g("gcp", "", "billing-1", "billing_budget", "billing-1", "Billing 1", finding.SevHigh, "Billing 1 has no budget with alerts", nil),
		},
		"openai.jsonl":          {apiKey("openai", "", "sk-a", finding.SevHigh), apiKey("openai", "", "sk-b", finding.SevHigh)},
		"anthropic.jsonl":       {apiKey("anthropic", "", "ak-a", finding.SevMedium)},
		"openrouter-work.jsonl": {apiKey("openrouter", "work", "or-a", finding.SevHigh)},
		"macos.jsonl": {
			auto,
			g("macos", "", "mac", "setting", "filevault", "FileVault", finding.SevCritical, "FileVault is off", nil),
		},
		"aws.jsonl": {g("aws", "", "123456789012", "iam_user_key", "AKIA1", "deploy", finding.SevHigh, "deploy has an access key 400 days old", nil)},
		"browser-extensions.jsonl": {
			g("browser-extensions", "", "brave", "extension", "ext1", "Grammarly", finding.SevHigh, "Grammarly can read every page", nil),
		},
		"azure.jsonl":      {g("azure", "", "sub-1", "client_secret", "cs1", "app", finding.SevMedium, "Client secret of app never expires", nil)},
		"cloudflare.jsonl": {g("cloudflare", "", "acc-1", "api_token", "t1", "ci", finding.SevMedium, "Token ci has no expiry", nil)},
		"vercel.jsonl": {
			g("vercel", "", "team-1", "token", "v1", "deploy", finding.SevLow, "Token \"deploy\" unused for 120 days", nil),
			g("vercel", "", "team-1", "token", "v2", "ci", finding.SevLow, "Token \"ci\" unused for 200 days", nil),
		},
		"supabase.jsonl": {g("supabase", "", "org-1", "project_setting", "ssl", "db", finding.SevMedium, "db does not enforce SSL", nil)},
		"hibp.jsonl": {
			g("hibp", "", "me@example.com", "breach", "Adobe", "Adobe", finding.SevMedium, "me@example.com was in the Adobe breach of 2013", nil),
			g("hibp", "", "me@example.com", "breach", "Canva", "Canva", finding.SevMedium, "me@example.com was in the Canva breach of 2019", nil),
			g("hibp", "", "me@example.com", "paste", "p1", "Paste", finding.SevInfo, "me@example.com appeared in a paste", nil),
		},
		"local-secrets.jsonl": {
			dump("~/src/api", "db/prod.sql", finding.SevCritical, 2<<20),
			dump("~/src/api", "backup.dump", finding.SevHigh, 512<<10),
		},
	}
}

func dump(repo, path string, sev finding.Severity, size int64) finding.Finding {
	return goldenFinding("local-secrets", "", "local", "data_dump", repo+":"+path, path, sev, "Database dump committed to "+repo+": "+path,
		map[string]any{"source": "data-dump", "repo": repo, "path": path, "size_bytes": float64(size), "size": "x", "remote": true})
}

// writeGoldenRuns writes the runs under out: as the connectors and the core write them now when
// declared, as they were written before connectors declared themes and grouping otherwise.
func writeGoldenRuns(t *testing.T, out string, declared bool) {
	runs := goldenRuns()
	names := make([]string, 0, len(runs))
	for n := range runs {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		var recs []any
		for _, f := range runs[n] {
			if !declared {
				f.Track = nil // the prowler plugin's own declarations
			}
			recs = append(recs, f)
		}
		if declared {
			recs = tracker.Declare(recs)
		}
		runtest.Write(t, filepath.Join(out, goldenNow.Format(time.DateOnly), n), recs...)
	}
}

// goldenItem is what the golden file keeps of an item.
type goldenItem struct {
	Key, Kind, Theme, Title, Severity, Priority, Status string
	Who, Action, Command, URL                           string
	Findings                                            []string // connector, repo and project of each ref
}

type golden struct {
	Themes []tracker.Theme
	Items  []goldenItem
}

func snapshot(tr *tracker.Tracker) golden {
	g := golden{Themes: tr.Themes}
	for _, it := range tr.Items {
		gi := goldenItem{Key: it.Key, Kind: string(it.Kind), Theme: it.Theme, Title: it.Title, Severity: string(it.Severity),
			Priority: string(it.EffectivePriority()), Status: string(it.Status)}
		if n := it.Next; n != nil {
			gi.Who, gi.Action, gi.Command, gi.URL = string(n.Who), n.Action, n.Command, n.URL
		}
		for _, r := range it.Findings {
			gi.Findings = append(gi.Findings, r.Connector+" repo="+r.Repo+" project="+r.Project+" "+r.Title)
		}
		sort.Strings(gi.Findings)
		g.Items = append(g.Items, gi)
	}
	sort.Slice(g.Items, func(i, j int) bool { return g.Items[i].Key < g.Items[j].Key })
	return g
}

// compareGolden checks got against testdata/golden/<name>, or writes it with -update.
func compareGolden(t *testing.T, name string, got []byte) {
	t.Helper()
	path := filepath.Join("testdata", "golden", name)
	if *update {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		gotPath := filepath.Join(os.TempDir(), "segurata-golden-"+t.Name()+"-"+name) // kept after the test, to diff
		_ = os.WriteFile(gotPath, got, 0o644)
		t.Fatalf("%s differs from the golden file; diff %s %s", name, path, gotPath)
	}
}

func marshal(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return append(b, '\n')
}

func syncGolden(t *testing.T, tr *tracker.Tracker, out string) tracker.SyncReport {
	t.Helper()
	rep, err := tr.Sync(tracker.SyncOptions{OutDir: out}, goldenNow)
	if err != nil {
		t.Fatal(err)
	}
	return rep
}

// What connectors write now gives the items the golden file holds.
func TestGoldenItems(t *testing.T) {
	out := t.TempDir()
	writeGoldenRuns(t, out, true)
	tr := tracker.New(goldenNow)
	syncGolden(t, tr, out)
	compareGolden(t, "items.json", marshal(t, snapshot(tr)))
	if *update {
		// The tracker as it was saved by the version that captured the golden file: the legacy
		// test syncs runs written before connectors declared anything over it.
		if err := tr.Save(filepath.Join("testdata", "golden", "tracker.json")); err != nil {
			t.Fatal(err)
		}
	}
}

// Runs written before connectors declared themes and grouping, folded into a tracker saved by the
// version that hard-coded them, change no item: same keys, titles and priorities, nothing created
// or closed.
func TestGoldenLegacyRunsKeepItems(t *testing.T) {
	if *update {
		t.Skip("the saved tracker is being rewritten")
	}
	tr, err := tracker.Load(filepath.Join("testdata", "golden", "tracker.json"))
	if err != nil {
		t.Fatal(err)
	}
	out := t.TempDir()
	writeGoldenRuns(t, out, false)
	rep := syncGolden(t, tr, out)
	if rep.Created != 0 || rep.Verified != 0 || rep.Reopened != 0 {
		t.Fatalf("legacy runs changed items: %+v", rep)
	}
	compareGolden(t, "items.json", marshal(t, snapshot(tr)))
}
