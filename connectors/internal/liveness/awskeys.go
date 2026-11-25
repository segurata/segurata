package liveness

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/segurata/segurata/connectors/internal/cli"
	"github.com/segurata/segurata/internal/attribution"
	"github.com/segurata/segurata/internal/secretrisk"
)

// A lone AWS access key id (no secret key found with it) cannot sign a request, so it is looked
// up in the owner's IAM inventory: each profile's account (sts get-caller-identity), its users
// (iam list-users) and their keys with status (iam list-access-keys), and whether the root user
// has keys (iam get-account-summary). The key id is compared in memory and never passed to a
// command, except to sts get-access-key-info for a key id of the older format, whose account
// cannot be decoded offline (attribution.AWSAccountFromKeyID).
//
//   - Active in one of the owner's accounts: live. Inactive: dead (it cannot sign while inactive).
//   - In an account whose whole inventory was read, no root keys, and not among its keys: dead
//     (deleted). GetAccessKeyInfo "does not indicate the state of the access key", so absence is
//     read from the inventory, never from it.
//   - Only long-term ids (AKIA): an ASIA id is a temporary credential, absent from every inventory,
//     so it stays unknown (fail closed).
//   - An account no profile reaches: unknown, with the account as a claim for attribution.
//   - Any inventory call denied: unknown, and a hint names the permissions.

// awsReadOnly is every aws command the lookup runs.
var awsReadOnly = cli.Allowlist{
	"configure list-profiles",
	"sts get-caller-identity",
	"sts get-access-key-info",
	"iam list-users",
	"iam list-access-keys",
	"iam get-account-summary",
}

// awsPermissions are what a profile needs, named in the setup hint.
const awsPermissions = "iam:ListUsers, iam:ListAccessKeys and iam:GetAccountSummary (all in the AWS managed policy SecurityAudit), and sts:GetAccessKeyInfo for key ids of the older format"

// maxIAMUsers bounds the users read per account; an account with more is read as incomplete.
const maxIAMUsers = 1000

const awsEndpoint = "aws iam list-access-keys"

type iamAccount struct {
	id, profile string
	keys        map[string]awsKey // by key id, in memory only
	rootKeys    int
	complete    bool // every user's keys and the root user's count were read
}

type awsKey struct{ user, status string }

type awsInventory struct {
	accounts []*iamAccount
	// infoProfile is a profile that signs in, for sts get-access-key-info.
	infoProfile string
}

func (l *lookups) awsInventory(ctx context.Context) *awsInventory {
	l.awsOnce.Do(func() { l.aws = l.readAWS(ctx) })
	return l.aws
}

func (l *lookups) awsRun(ctx context.Context, out any, args ...string) error {
	raw, err := awsReadOnly.Guard(l.owner.AWS).Run(ctx, args...)
	if err != nil {
		return err
	}
	if out == nil || len(bytes.TrimSpace(raw)) == 0 {
		return nil
	}
	return json.Unmarshal(raw, out)
}

// awsCall runs one command with a profile, in the global endpoints' region.
func (l *lookups) awsCall(ctx context.Context, profile string, out any, args ...string) error {
	return l.awsRun(ctx, out, append(args, "--profile", profile, "--region", "us-east-1", "--output", "json", "--no-cli-pager")...)
}

func (l *lookups) readAWS(ctx context.Context) *awsInventory {
	inv := &awsInventory{}
	if l.owner.AWS == nil {
		return inv
	}
	profiles := l.cfg.AWSProfiles
	if profiles == nil {
		raw, err := awsReadOnly.Guard(l.owner.AWS).Run(ctx, "configure", "list-profiles")
		if err != nil {
			l.hint("aws: profiles not listed (" + cliError(err) + "): lone AWS key ids stay unknown")
			return inv
		}
		profiles = strings.Fields(string(raw))
	}
	if len(profiles) == 0 {
		l.hint("aws: no AWS CLI profile: lone AWS key ids stay unknown (aws configure sso, or liveness.aws_profiles)")
	}
	for _, p := range profiles {
		var id struct{ Account string }
		if err := l.awsCall(ctx, p, &id, "sts", "get-caller-identity"); err != nil || id.Account == "" {
			l.hint(fmt.Sprintf("aws: profile %s does not sign in (%s): run aws sso login --profile %s, or leave it out of liveness.aws_profiles", p, cliErrorOr(err, "no account"), p))
			continue
		}
		if inv.infoProfile == "" {
			inv.infoProfile = p
		}
		if slices.ContainsFunc(inv.accounts, func(a *iamAccount) bool { return a.id == id.Account }) {
			continue
		}
		a := l.readAccount(ctx, p, id.Account)
		inv.accounts = append(inv.accounts, a)
	}
	return inv
}

func cliErrorOr(err error, otherwise string) string {
	if err != nil {
		return cliError(err)
	}
	return otherwise
}

// readAccount reads every IAM user's keys of the account a profile reaches.
func (l *lookups) readAccount(ctx context.Context, profile, account string) *iamAccount {
	a := &iamAccount{id: account, profile: profile, keys: map[string]awsKey{}}
	var denied []string
	fail := func(action string, err error) {
		if code := cliError(err); code == "AccessDenied" || code == "UnauthorizedOperation" {
			denied = append(denied, action)
			return
		}
		l.hint(fmt.Sprintf("aws: profile %s: %s failed (%s): lone key ids of account %s stay unknown", profile, action, cliError(err), account))
	}
	var users struct{ Users []struct{ UserName string } }
	usersRead := false
	if err := l.awsCall(ctx, profile, &users, "iam", "list-users"); err != nil {
		fail("iam:ListUsers", err)
	} else {
		usersRead = len(users.Users) <= maxIAMUsers
	}
	keysRead := usersRead
	for i, u := range users.Users {
		if i == maxIAMUsers {
			break
		}
		var keys struct {
			AccessKeyMetadata []struct{ AccessKeyId, Status string }
		}
		if err := l.awsCall(ctx, profile, &keys, "iam", "list-access-keys", "--user-name", u.UserName); err != nil {
			fail("iam:ListAccessKeys", err)
			keysRead = false
			break
		}
		for _, k := range keys.AccessKeyMetadata {
			a.keys[k.AccessKeyId] = awsKey{u.UserName, k.Status}
		}
	}
	var summary struct{ SummaryMap map[string]int }
	summaryRead := false
	if err := l.awsCall(ctx, profile, &summary, "iam", "get-account-summary"); err != nil {
		fail("iam:GetAccountSummary", err)
	} else {
		summaryRead = true
		a.rootKeys = summary.SummaryMap["AccountAccessKeysPresent"]
	}
	a.complete = keysRead && summaryRead
	if len(denied) > 0 {
		l.hint(fmt.Sprintf("aws: profile %s may not call %s: lone AWS key ids of account %s stay unknown; allow %s", profile, strings.Join(denied, ", "), account, awsPermissions))
	}
	return a
}

// lookupAWSKey classifies a lone access key id.
func lookupAWSKey(ctx context.Context, l *lookups, p Probe) secretrisk.Liveness {
	keyID := p.Value
	if !strings.HasPrefix(keyID, "AKIA") {
		// ASIA ids are temporary credentials, never in list-access-keys: absence proves nothing.
		return unknown("", "temporary credentials, which no IAM inventory lists")
	}
	inv := l.awsInventory(ctx)
	for _, a := range inv.accounts {
		if k, ok := a.keys[keyID]; ok {
			r := secretrisk.Liveness{State: secretrisk.Dead, Endpoint: awsEndpoint, Account: "aws:" + a.id,
				Reason: fmt.Sprintf("%s, IAM user %s of account %s", k.status, k.user, a.id)}
			if k.status == "Active" {
				r.State = secretrisk.Live
			}
			return r
		}
	}
	account, ok := attribution.AWSAccountFromKeyID(keyID)
	if !ok {
		if account, ok = l.awsKeyAccount(ctx, inv, keyID); !ok {
			return unknown("aws sts get-access-key-info", "its account is not known")
		}
	}
	i := slices.IndexFunc(inv.accounts, func(a *iamAccount) bool { return a.id == account })
	if i < 0 {
		r := unknown(awsEndpoint, "account "+account+", which none of your AWS profiles reaches")
		r.Account = "aws:" + account
		return r
	}
	a := inv.accounts[i]
	r := secretrisk.Liveness{State: secretrisk.Unknown, Endpoint: awsEndpoint, Account: "aws:" + account}
	switch {
	case !a.complete:
		r.Reason = "account " + account + "'s access keys could not all be read"
	case a.rootKeys > 0:
		r.Reason = "no IAM user of account " + account + " has it, and its root user has keys, which only the root user can list"
	default:
		r.State, r.Reason = secretrisk.Dead, "not among the access keys of account "+account+": deleted"
	}
	return r
}

// awsKeyAccount asks STS which account a key id belongs to, with the owner's profile: the only
// command that takes the key id. Its error is reduced to a code, since the CLI may echo the id.
func (l *lookups) awsKeyAccount(ctx context.Context, inv *awsInventory, keyID string) (string, bool) {
	if inv.infoProfile == "" {
		return "", false
	}
	var info struct{ Account string }
	if err := l.awsCall(ctx, inv.infoProfile, &info, "sts", "get-access-key-info", "--access-key-id", keyID); err != nil {
		if code := cliError(err); code == "AccessDenied" {
			l.hint(fmt.Sprintf("aws: profile %s may not call sts:GetAccessKeyInfo: key ids of the older format stay unknown", inv.infoProfile))
		}
		return "", false
	}
	return info.Account, len(info.Account) == 12
}
