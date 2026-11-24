package tracker

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/segurata/segurata/internal/finding"
)

// Setup items: one per connector instance, account and state other than ok. A connector may
// report several statuses under one key (gcp: one per project it could not read); the item keeps
// one ref per distinct detail and its title counts them.

// setupProposal is the setup item for a connector status other than ok, without refs: addStatus
// adds one per distinct detail.
func setupProposal(lbl string, st finding.Status) (string, proposal) {
	key := SetupKey(lbl, st)
	return key, proposal{theme: "setup", kind: KindSetup, connector: st.Connector, instance: st.Instance, account: st.Account}
}

// SetupKey is the key of the setup item a status other than ok makes. An expected status keeps
// the key of the state the connector reported, so the item it closes is the one it opened.
func SetupKey(lbl string, st finding.Status) string {
	return "setup:" + lbl + "|" + st.Account + "|" + string(reported(st).State)
}

// reported is the status as the connector reported it, before the config's expected rules.
func reported(st finding.Status) finding.Status {
	if st.State == finding.StateExpected && st.Was != "" {
		st.State, st.Was, st.Expected = st.Was, "", ""
	}
	return st
}

// addStatus adds a status to a setup proposal: one ref per distinct detail.
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

// finishSetup names a setup item and says what to do about its statuses.
func (p *proposal) finishSetup(itemID string) {
	if len(p.statuses) == 0 {
		return
	}
	st := reported(p.statuses[0])
	lbl := label(st.Connector, st.Instance)
	p.title = setupTitle(lbl, st.Account, st.State, p.statuses)
	if reasons := p.expectedReasons(); reasons != nil {
		p.next = &Next{Who: You, Action: "Nothing: expected by your config (" + strings.Join(reasons, "; ") + ")."}
		return
	}
	var actions, cmds []string
	for _, s := range p.statuses {
		a, c := StatusAction(reported(s), lbl, itemID)
		if !slices.Contains(actions, a) {
			actions = append(actions, a)
		}
		if !slices.Contains(cmds, c) {
			cmds = append(cmds, c)
		}
	}
	p.next = &Next{Who: You, Action: strings.Join(actions, " "), Command: strings.Join(cmds, " && ")}
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

// scopedDetail reads a detail of the form "<noun> <name>: <what>", as gcp words a project it could not read.
var scopedDetail = regexp.MustCompile(`^([a-z]+) (\S+): (.+)$`)

// setupTitle is "<label> · <account>: <state phrase>" for one status. For several it counts them:
// "gcp: permission denied on 6 projects for a@x.com" when every detail names a scope of the same
// kind with the same problem, "… failed on 6 projects" when the problems differ, or "(2 problems)".
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
	n := count(len(sts), noun, noun+"s")
	if what == "-" {
		return fmt.Sprintf("%s: %s on %s", who, statePhrase[state], n)
	}
	s := fmt.Sprintf("%s: %s on %s", lbl, what, n)
	if account != "" {
		s += " for " + account
	}
	return s
}

// clis are the programs whose commands a status detail may name as the fix.
const clis = `(?:gcloud|gh|aws|az|security|op|segurata|brew|softwareupdate)`

var (
	backtickCmd = regexp.MustCompile("`(" + clis + " [^`]+)`")
	runCmd      = regexp.MustCompile(`(?i)\brun:?\s+(` + clis + ` .+?)\s*(?:;|\n|\.\s|\.$|$)`)
	denied      = regexp.MustCompile(`(?i)accessdenied|access denied|permission denied|not authorized|permission_denied|forbidden`)
)

// StatusCommand is the command a status detail gives as the fix, or "": a backquoted command, or
// the one after "run" ("run: gh auth refresh -h github.com -s read:user"). "for this account" is
// replaced by the account.
func StatusCommand(st finding.Status) string {
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
// never uses: there is nothing to install.
func adminOnly(detail string) bool {
	d := strings.ToLower(detail)
	return strings.Contains(d, "needs admin") || strings.Contains(d, "need sudo") || strings.Contains(d, "needs sudo") || strings.Contains(d, "requires root")
}

// StatusAction is what to do about a status, and the command to run: the fix the detail names
// when it names one (then the action ends with the rerun), otherwise the rerun that checks it.
// itemID names the setup item in the "record it as expected" hint ("" for a generic placeholder).
func StatusAction(st finding.Status, lbl, itemID string) (string, string) {
	rerun := "segurata inventory " + lbl
	if itemID == "" {
		itemID = "<item>"
	}
	expect := "If that is on purpose, record it as expected: segurata track expect " + itemID + ` --reason "…".`
	cmd := StatusCommand(st)
	var action string
	switch st.State {
	case finding.StateReauth:
		action = "Sign in to this account again (in the browser segurata drives for browser connectors, with the provider's CLI otherwise)."
		if cmd != "" {
			action = "Sign in again with the command below."
		}
		action += " If the account is not yours to sign in to, record it as expected: segurata track expect " + itemID + ` --reason "…".`
	case finding.StateSignedOut:
		action = "Sign in to this account in the browser segurata drives."
		if st.Connector == "connected-apps" {
			action += fmt.Sprintf(` If you no longer use the service, list only the ones you use in connectors.%q.config.services.`, lbl)
		} else {
			action += " If you no longer use it: segurata track expect " + itemID + ` --reason "…".`
		}
	case finding.StateMissingCredentials:
		action = fmt.Sprintf(`Set the secret reference under connectors.%q.secrets in ~/.config/segurata/config.json (Keychain item, 1Password field or environment variable); the detail has the steps.`, lbl)
		if cmd != "" {
			action = "Store the credential with the command below, then reference it " + strings.TrimPrefix(action, "Set the secret reference ")
		}
		action += " " + expect
	case finding.StateNoScope:
		action = "Grant the permission the detail names to the credential this connector uses."
		if cmd != "" {
			action = "Grant the missing permission with the command below."
		}
		action += " If the credential is limited on purpose, record it as expected: segurata track expect " + itemID + ` --reason "…".`
	case finding.StateUnsupported:
		if adminOnly(st.Detail) {
			action = "This check needs administrator rights, which segurata does not use; nothing to install. " + expect
		} else {
			action = "Install what the detail names (respecting the 4-day quarantine). " + expect
		}
	case finding.StateError:
		if denied.MatchString(st.Detail) {
			action = "The credential was denied some reads (see the detail): grant them. " + expect
		} else if cmd == "" {
			return "Run it again with connector logs to see what failed.", rerun + " --verbose"
		} else {
			action = "Run the command below."
		}
	default:
		action = "See the status detail."
	}
	if cmd == "" {
		return action, rerun
	}
	return action + " Then: " + rerun + ".", cmd
}
