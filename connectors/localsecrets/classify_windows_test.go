package localsecrets

import (
	"context"
	"testing"
	"time"

	"github.com/segurata/segurata/internal/fingerprint"
	"github.com/segurata/segurata/internal/secretrisk"
)

// Windows paths come with backslashes and in any case: they land in the same group, with the same
// fix, as their Unix counterparts.
func TestWindowsPathsClassifyLikeUnixOnes(t *testing.T) {
	home := `C:\Users\Ana`
	s := newScan(context.Background(), &Connector{Now: time.Now}, home, settings{reposRoot: `D:\Src`}, fingerprint.FromBytes(make([]byte, 32)), &recorder{})
	for path, want := range map[string]string{
		`c:\users\ana\.claude\projects\p\s.jsonl`: "transcript",
		`C:\Users\Ana\.Codex\sessions\s.jsonl`:    "transcript",
		`C:\USERS\ANA\.zsh_history`:               "history",
		`C:\Users\Ana\Library\Logs\app.txt`:       "log",
		`C:\Users\Ana\AppData\Local\x\debug.LOG`:  "log",
		`d:\src\shop\.env`:                        "repo",
		`C:\Users\Ana\.aws\credentials`:           "config",
	} {
		if got := s.kindOf(path); got != want {
			t.Errorf("kindOf(%s) = %s, want %s", path, got, want)
		}
	}
	for path, want := range map[string]string{
		`C:\Users\Ana\.AWS\credentials`:                        "aws",
		`C:\Users\Ana\.docker\config.json`:                     "package-registries-and-docker",
		`C:\Users\Ana\.config\gh\hosts.yml`:                    "github-and-git",
		`C:\Users\Ana\.config\opencode\opencode.json`:          "mcp-servers-and-agents",
		`C:\Users\Ana\.claude.json`:                            "mcp-servers-and-agents",
		`C:\Users\Ana\AppData\Roaming\gcloud\configurations\x`: "google-cloud-and-oauth",
		`C:\Users\Ana\AppData\Roaming\GitHub CLI\hosts.yml`:    "github-and-git",
		`D:\Src\shop\.env`:                                     "env-files",
	} {
		ev := secretrisk.Evidence{Source: "scan", Type: "assignment", Kind: "config", Path: s.tilde(path)}
		if got := fixFor(ev); got != fixDoc+"#"+want {
			t.Errorf("fixFor(%s) = %s, want #%s", path, got, want)
		}
	}
}
