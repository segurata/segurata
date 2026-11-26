package attribution

import (
	"regexp"
	"strings"

	"github.com/segurata/segurata/internal/finding"
)

// Resource types of the info findings connectors emit for Discover.
const (
	AWSAccountType     = "aws_account"     // evidence account_id
	GCPProjectsType    = "gcp_projects"    // evidence projects: [{id, number}]
	SlackWorkspaceType = "slack_workspace" // evidence team_id
)

var awsAccountID = regexp.MustCompile(`^\d{12}$`)

// Discover reads the owner's accounts from connector runs. Of google-personal only accounts
// inspected count: other people signed in to the same browser never get past reauth.
func Discover(fs []finding.Finding, sts []finding.Status) Owned {
	var o Owned
	for _, st := range sts {
		switch st.Connector {
		case "aws":
			if awsAccountID.MatchString(st.Account) {
				o.AWSAccounts = append(o.AWSAccounts, st.Account)
			}
		case "gcp":
			if strings.Contains(st.Account, "@") && !strings.HasSuffix(st.Account, ".iam.gserviceaccount.com") {
				o.Emails = append(o.Emails, st.Account)
			}
		case "google-personal":
			if st.State == finding.StateOK && strings.Contains(st.Account, "@") {
				o.Emails = append(o.Emails, st.Account)
			}
		case "github", "connected-apps":
			if login, ok := strings.CutPrefix(st.Account, "github:"); ok && login != "" {
				o.GitHub = append(o.GitHub, login)
			}
		}
	}
	for _, f := range fs {
		switch {
		case f.Connector == "aws" && awsAccountID.MatchString(f.Account):
			o.AWSAccounts = append(o.AWSAccounts, f.Account)
		case f.Resource.Type == AWSAccountType:
			if id, _ := f.Evidence["account_id"].(string); awsAccountID.MatchString(id) {
				o.AWSAccounts = append(o.AWSAccounts, id)
			}
		case f.Resource.Type == GCPProjectsType:
			list, _ := f.Evidence["projects"].([]any)
			for _, p := range list {
				m, _ := p.(map[string]any)
				for _, k := range []string{"id", "number"} {
					if v, _ := m[k].(string); v != "" {
						o.GCPProjects = append(o.GCPProjects, v)
					}
				}
			}
		case f.Resource.Type == SlackWorkspaceType:
			if id, _ := f.Evidence["team_id"].(string); id != "" {
				o.SlackTeams = append(o.SlackTeams, id)
			}
		}
	}
	return Owned{}.Merge(o)
}
