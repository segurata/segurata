package tracker

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/segurata/segurata/internal/finding"
	"github.com/segurata/segurata/internal/textfmt"
)

// setupProposal is the setup item of a connector instance, account and state other than ok;
// addStatus adds one ref per distinct detail.
func setupProposal(lbl string, st finding.Status) (string, proposal) {
	key := setupKey(lbl, st)
	return key, proposal{theme: "setup", kind: KindSetup, connector: st.Connector, instance: st.Instance, account: st.Account}
}

// setupKey is from the state the connector reported, so an expected status closes the item it
// opened.
func setupKey(lbl string, st finding.Status) string {
	return "setup:" + lbl + "|" + st.Account + "|" + string(reported(st).State)
}

func reported(st finding.Status) finding.Status {
	if st.State == finding.StateExpected && st.Was != "" {
		st.State, st.Was, st.Expected = st.Was, "", ""
	}
	return st
}

func (p *proposal) addStatus(st finding.Status, at time.Time) {
	detail := st.Detail
	if detail == "" {
		detail = string(st.State)
	}
	id := "status:" + p.key + "#" + finding.StableID(detail)[:8]
	if slices.ContainsFunc(p.refs, func(r FindingRef) bool { return r.ID == id }) {
		return
	}
	sev := finding.SevMedium
	if st := reported(st); st.State == finding.StateUnsupported || st.State == finding.StateUnverified {
		sev = finding.SevLow
	}
	p.statuses = append(p.statuses, st)
	p.refs = append(p.refs, FindingRef{ID: id, Connector: st.Connector, Instance: st.Instance, Account: st.Account, Scope: st.Scope,
		Title: detail, Severity: sev, LastSeen: at.UTC(), Expected: st.Expected})
}

func (p *proposal) finishSetup(itemID string) {
	if len(p.statuses) == 0 {
		return
	}
	st := reported(p.statuses[0])
	lbl := StatusLabel(st)
	p.title = setupTitle(lbl, st.Account, st.State, p.statuses)
	if reasons := p.expectedReasons(); reasons != nil {
		p.next = &Next{Who: You, Action: "Nothing: expected by your config (" + strings.Join(reasons, "; ") + ")."}
		return
	}
	var actions, cmds []string
	for _, s := range p.statuses {
		a, c := statusAction(reported(s), lbl, itemID)
		if !slices.Contains(actions, a) {
			actions = append(actions, a)
		}
		if !slices.Contains(cmds, c) {
			cmds = append(cmds, c)
		}
	}
	p.next = &Next{Who: You, Action: strings.Join(actions, " "), Command: strings.Join(cmds, " && "), URL: statusURL(reported(st))}
}

var statePhrase = map[finding.State]string{
	finding.StateReauth:             "needs a fresh sign-in",
	finding.StateSignedOut:          "is signed out",
	finding.StateNoScope:            "lacks a permission",
	finding.StateUnverified:         "reader never checked against a real page",
	finding.StateMissingCredentials: "has no credentials configured",
	finding.StateUnsupported:        "is not supported here",
	finding.StateError:              "failed",
}

// scopedDetail reads "<noun> <name>: <what>", as gcp words a project it could not read.
var scopedDetail = regexp.MustCompile(`^([a-z]+) (\S+): (.+)$`)

// setupTitle is "<label> · <account>: <state phrase>" for one status; for several,
// "gcp: permission denied on 6 projects for <account>", "… failed on 6 projects" or "(2 problems)".
func setupTitle(lbl, account string, state finding.State, sts []finding.Status) string {
	who := lbl
	if account != "" {
		who += " · " + account
	}
	if len(sts) == 1 {
		return who + ": " + statePhrase[state]
	}
	noun, what := "", ""
	for i, st := range sts {
		m := scopedDetail.FindStringSubmatch(st.Detail)
		if m == nil || (i > 0 && m[1] != noun) {
			return fmt.Sprintf("%s: %s (%d problems)", who, statePhrase[state], len(sts))
		}
		w, _, _ := strings.Cut(m[3], " for ")
		w, _, _ = strings.Cut(w, ";")
		if i > 0 && w != what {
			what = "-"
		} else if i == 0 {
			what = w
		}
		noun = m[1]
	}
	n := textfmt.Count(len(sts), noun, noun+"s")
	if what == "-" {
		return fmt.Sprintf("%s: %s on %s", who, statePhrase[state], n)
	}
	s := fmt.Sprintf("%s: %s on %s", lbl, what, n)
	if account != "" {
		s += " for " + account
	}
	return s
}

const clis = `(?:gcloud|gh|aws|az|security|op|segurata|brew|softwareupdate)`

var (
	backtickCmd = regexp.MustCompile("`(" + clis + " [^`]+)`")
	runCmd      = regexp.MustCompile(`(?i)\brun:?\s+(` + clis + ` .+?)\s*(?:;|\n|\.\s|\.$|$)`)
	denied      = regexp.MustCompile(`(?i)accessdenied|access denied|permission denied|not authorized|permission_denied|forbidden`)
)

// statusCommand is the backquoted command, or the one after "run", a status detail gives as the
// fix, with "for this account" made the account.
func statusCommand(st finding.Status) string {
	cmd := ""
	if m := backtickCmd.FindStringSubmatch(st.Detail); m != nil {
		cmd = m[1]
	} else if m := runCmd.FindStringSubmatch(st.Detail); m != nil {
		cmd = m[1]
	}
	if c, ok := strings.CutSuffix(cmd, " for this account"); ok && st.Account != "" {
		cmd = c + " " + st.Account
	}
	return strings.TrimSpace(cmd)
}

// adminOnly reports whether a detail says the check needs administrator rights, which segurata
// never uses.
func adminOnly(detail string) bool {
	d := strings.ToLower(detail)
	return strings.Contains(d, "needs admin") || strings.Contains(d, "need sudo") || strings.Contains(d, "needs sudo") || strings.Contains(d, "requires root")
}

// statusAction is what to do about a status and the command: the fix the detail names, then a
// rerun, or the rerun alone; and how to expect it, for item itemID.
func statusAction(st finding.Status, lbl, itemID string) (string, string) {
	rerun := "segurata inventory " + lbl
	if itemID == "" {
		itemID = "<item>"
	}
	expect := "On purpose? segurata track expect " + itemID + ` --reason "…"`
	cmd := statusCommand(st)
	var action string
	switch st.State {
	case finding.StateReauth:
		action = "Sign in to this account again (in the browser segurata drives for browser connectors, with the provider's CLI otherwise)."
		if cmd != "" {
			action = "Sign in again with the command below."
		}
		expect = "Not your account to sign in to? segurata track expect " + itemID + ` --reason "…"`
	case finding.StateSignedOut:
		action = "Sign in to this account in the browser segurata drives."
		expect = "No longer used? segurata track expect " + itemID + ` --reason "…"`
		if st.Connector == "connected-apps" {
			expect = fmt.Sprintf(`No longer used? List only the services you use in connectors.%q.config.services.`, lbl)
		}
	case finding.StateMissingCredentials:
		action = fmt.Sprintf(`Reference the credential under connectors.%q.secrets in ~/.config/segurata/config.json (Keychain item, 1Password field or environment variable); the detail has the steps.`, lbl)
		if cmd != "" {
			action = "Store the credential with the command below, then r" + action[1:]
		}
	case finding.StateNoScope:
		action = "Grant the permission the detail names to the credential this connector uses."
		if cmd != "" {
			action = "Grant the missing permission with the command below."
		}
	case finding.StateUnsupported:
		action = "Install what the detail names (respecting the 4-day quarantine)."
		if adminOnly(st.Detail) {
			action = "This check needs administrator rights, which segurata does not use; nothing to install."
		}
	case finding.StateError:
		switch {
		case denied.MatchString(st.Detail):
			action = "The credential was denied some reads (see the detail): grant them."
		case cmd == "":
			return "Run it again with connector logs to see what failed.", rerun + " --verbose"
		default:
			action = "Run the command below."
		}
	default:
		action, expect = "See the status detail.", ""
	}
	if cmd != "" {
		action += " Then: " + rerun + "."
	} else {
		cmd = rerun
	}
	if expect != "" {
		action += " " + expect
		if !strings.HasSuffix(expect, ".") {
			action += "."
		}
	}
	return action, cmd
}

var openURL = regexp.MustCompile(`\bopen (https?://[^\s,;]+[^\s,;.)])`)

func statusURL(st finding.Status) string {
	if m := openURL.FindStringSubmatch(st.Detail); m != nil {
		return m[1]
	}
	return ""
}

// SetupStatuses are the statuses a setup item still holds, as the connector reported them.
func (it *Item) SetupStatuses() []finding.Status {
	if it.Kind != KindSetup {
		return nil
	}
	state := it.setupState()
	var out []finding.Status
	for _, r := range it.Findings {
		if r.Gone || !strings.HasPrefix(r.ID, "status:") {
			continue
		}
		out = append(out, finding.Status{Type: "status", Connector: r.Connector, Instance: r.Instance, Account: r.Account, Scope: r.Scope, State: state, Detail: r.Title})
	}
	return out
}

// StatusCommands are the distinct commands the item's statuses name as their fix.
func (it *Item) StatusCommands() []string {
	var out []string
	for _, st := range it.SetupStatuses() {
		if c := statusCommand(st); c != "" && !slices.Contains(out, c) {
			out = append(out, c)
		}
	}
	return out
}

// BrowserSignIn reports whether signing in, in the browser segurata drives, clears an active setup
// item: what `segurata signin` opens.
func (it *Item) BrowserSignIn(browser func(connector string) bool, now time.Time) bool {
	if browser == nil || it.Kind != KindSetup || !it.Active(now) {
		return false
	}
	if st := it.setupState(); st != finding.StateReauth && st != finding.StateSignedOut {
		return false
	}
	sts := it.SetupStatuses()
	return len(sts) > 0 && browser(sts[0].Connector) && len(it.StatusCommands()) == 0
}

// StatusLabel is the connector instance a status is about.
func StatusLabel(st finding.Status) string { return finding.Label(st.Connector, st.Instance) }

func (it *Item) setupState() finding.State {
	return finding.State(it.Key[strings.LastIndex(it.Key, "|")+1:])
}
