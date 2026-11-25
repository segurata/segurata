package finding

// Track says how the tracker files a finding: which findings share an item, what kind of item it
// is and how the item is titled. A connector sets it on each finding (an external one in the
// finding's `track` object; a built-in one may implement connector.Tracker instead); a finding
// without it is grouped with the findings of the same account whose titles differ only in quoted
// names and numbers, as a fix titled by its worst finding. See docs/connectors.md, "Theme and
// grouping".
//
// The item key is built from the group and its key, so a connector must keep both stable: a
// changed one makes a new item and leaves the old one's history behind.
type Track struct {
	// Group is what findings share an item by, one of the Group* values; any other value groups
	// as GroupFamily.
	Group string `json:"group,omitempty"`
	// Key is the value grouped on for GroupCheck (default: the resource id) and GroupProject
	// (default: the account).
	Key string `json:"key,omitempty"`
	// Kind is "review" for an item that asks to look at a list and keep or remove each entry; any
	// other value is a fix.
	Kind string `json:"kind,omitempty"`
	// Title is the item's title; "{count}" in it stands for the count of what Count names, with
	// Noun or Nouns ("3 API keys"). Empty: the finding's own title for an item of one finding,
	// otherwise the worst finding's title and how many more are like it. Every finding of a group
	// must give the same Title; the tracker reads the first one's.
	Title string `json:"title,omitempty"`
	// TitleOne, when set, is the title when the count is one ("… fails in my-project").
	TitleOne string `json:"title_one,omitempty"`
	// Count is what {count} counts: CountFindings (default), CountAccounts or CountScopes.
	Count string `json:"count,omitempty"`
	// Noun and Nouns name one and several of what is counted; default "finding" and "findings".
	Noun  string `json:"noun,omitempty"`
	Nouns string `json:"nouns,omitempty"`
	// Repo (a GitHub owner/name) and Project (a GCP project id) say where the finding is, for the
	// tracker's decision rules (`repo:` and `gcp-project:` scopes).
	Repo    string `json:"repo,omitempty"`
	Project string `json:"project,omitempty"`
}

// What findings share an item by.
const (
	GroupFinding         = "finding"          // one item per finding
	GroupCheck           = "check"            // one item per check (Key) across accounts and scopes
	GroupAccount         = "account"          // one item per account
	GroupAccountSeverity = "account-severity" // one item per account and severity
	GroupProject         = "project"          // one item per project (Key)
	GroupFamily          = "family"           // one item per account and title family (the default)
)

// TrackReview is the Kind of an item that asks for a review.
const TrackReview = "review"

// What {count} counts in a Track title.
const (
	CountFindings = "findings"
	CountAccounts = "accounts"
	CountScopes   = "scopes" // finding.ScopeOf each finding: projects, repositories
)
