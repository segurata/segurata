package localsecrets

import (
	"context"
	"strings"

	"github.com/segurata/segurata/connectors/internal/cli"
	"github.com/segurata/segurata/internal/connector"
)

// Doctor checks the tools the scan runs and prints the versions of rg and gitleaks.
func (c *Connector) Doctor(ctx context.Context, req connector.Request) []connector.Check {
	skipHistory, _ := req.Config["skip_git_history"].(bool)
	tools := []struct {
		name    string
		version cli.Runner // nil: presence only
		args    []string
		missing connector.Check
	}{
		{"rg", guardRG(c.RG), []string{"--version"}, connector.Check{Level: connector.Fail,
			Detail: "rg (ripgrep) is required", Fix: "install ripgrep (https://github.com/BurntSushi/ripgrep#installation), respecting the 4-day quarantine"}},
		{"gitleaks", guardGitleaks(c.Gitleaks), []string{"version"}, connector.Check{Level: connector.Warn,
			Detail: "not installed: git history is not scanned", Fix: "install gitleaks (https://github.com/gitleaks/gitleaks#installing), respecting the 4-day quarantine"}},
		{"git", nil, nil, connector.Check{Level: connector.Fail, Detail: "git is required to list tracked files", Fix: "install git (on macOS: xcode-select --install)"}},
		{"ssh-keygen", nil, nil, connector.Check{Level: connector.Fail, Detail: "ssh-keygen is required to check SSH keys", Fix: "install OpenSSH"}},
	}
	var checks []connector.Check
	for _, t := range tools {
		if t.name == "gitleaks" && skipHistory {
			checks = append(checks, connector.Check{Level: connector.OK, What: t.name, Detail: "not needed: skip_git_history is set"})
			continue
		}
		path, err := c.LookPath(t.name)
		if err != nil {
			ch := t.missing
			ch.What = t.name
			checks = append(checks, ch)
			continue
		}
		if t.version != nil {
			path += " (" + firstLine(t.version.Run(ctx, t.args...)) + ")"
		}
		checks = append(checks, connector.Check{Level: connector.OK, What: t.name, Detail: path})
	}
	return checks
}

func firstLine(out []byte, err error) string {
	if err != nil {
		return "version unknown: " + err.Error()
	}
	line, _, _ := strings.Cut(strings.TrimSpace(string(out)), "\n")
	return line
}
