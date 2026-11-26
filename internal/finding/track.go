package finding

// Track says how the tracker files a finding: which findings share an item, its kind and title
// (docs/connectors.md, "Theme and grouping"). The item key comes from Group and Key, so changing
// either starts a new item without the old one's history.
type Track struct {
	Group string `json:"group,omitempty"` // a Group* value; any other groups as GroupFamily
	// Key is grouped on for GroupCheck (default: the resource id) and GroupProject (the account).
	Key  string `json:"key,omitempty"`
	Kind string `json:"kind,omitempty"` // TrackReview, or a fix
	// Title may hold "{count}", the count of what Count names with Noun or Nouns. Every finding of a
	// group gives the same Title.
	Title    string `json:"title,omitempty"`
	TitleOne string `json:"title_one,omitempty"` // the title when the count is one
	Count    string `json:"count,omitempty"`     // a Count* value, CountFindings by default
	Noun     string `json:"noun,omitempty"`
	Nouns    string `json:"nouns,omitempty"`
	// Repo (owner/name) and Project (a GCP project id) feed the tracker's decision rules.
	Repo    string `json:"repo,omitempty"`
	Project string `json:"project,omitempty"`
}

const (
	GroupFinding         = "finding"          // one item per finding
	GroupCheck           = "check"            // one item per check (Key) across accounts and scopes
	GroupAccount         = "account"          // one item per account
	GroupAccountSeverity = "account-severity" // one item per account and severity
	GroupProject         = "project"          // one item per project (Key)
	GroupFamily          = "family"           // one item per account and title family (the default)
)

// TrackReview is the Kind of an item that asks to keep or remove each entry of a list.
const TrackReview = "review"

const (
	CountFindings = "findings"
	CountAccounts = "accounts"
	CountScopes   = "scopes" // finding.ScopeOf each finding: projects, repositories
)
