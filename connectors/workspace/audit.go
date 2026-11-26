package workspace

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/segurata/segurata/connectors/internal/httpx"
	"github.com/segurata/segurata/internal/connector"
	"github.com/segurata/segurata/internal/finding"
)

const (
	parallel       = 5 // tokens.list calls in flight
	activityWindow = 30 * 24 * time.Hour
	userFields     = "nextPageToken,users(primaryEmail,name/fullName,isAdmin,isDelegatedAdmin,isEnrolledIn2Sv,isEnforcedIn2Sv,lastLoginTime,creationTime,suspended,archived)"
)

func newAPI(base, token, quotaProject string) *httpx.Client {
	h := http.Header{"Authorization": {"Bearer " + token}}
	if quotaProject != "" {
		h.Set("X-Goog-User-Project", quotaProject)
	}
	return httpx.New(base, h)
}

type user struct {
	PrimaryEmail string `json:"primaryEmail"`
	Name         struct {
		FullName string `json:"fullName"`
	} `json:"name"`
	IsAdmin          bool   `json:"isAdmin"`
	IsDelegatedAdmin bool   `json:"isDelegatedAdmin"`
	IsEnrolledIn2Sv  bool   `json:"isEnrolledIn2Sv"`
	IsEnforcedIn2Sv  bool   `json:"isEnforcedIn2Sv"`
	LastLoginTime    string `json:"lastLoginTime"`
	CreationTime     string `json:"creationTime"`
	Suspended        bool   `json:"suspended"`
	Archived         bool   `json:"archived"`
}

type token struct {
	ClientID    string   `json:"clientId"`
	DisplayText string   `json:"displayText"`
	Scopes      []string `json:"scopes"`
	NativeApp   bool     `json:"nativeApp"`
	Anonymous   bool     `json:"anonymous"`
}

type activityItem struct {
	ID struct {
		Time string `json:"time"`
	} `json:"id"`
	Events []struct {
		Name       string `json:"name"`
		Parameters []struct {
			Name       string   `json:"name"`
			Value      string   `json:"value"`
			MultiValue []string `json:"multiValue"`
		} `json:"parameters"`
	} `json:"events"`
}

type audit struct {
	api  *httpx.Client
	cfg  settings
	now  time.Time
	emit connector.Emitter
}

func pages[T any](ctx context.Context, api *httpx.Client, path string, q url.Values, pick func(*page[T]) []T) ([]T, error) {
	var out []T
	for range 10000 {
		var p page[T]
		if err := api.Get(ctx, path, q, &p); err != nil {
			return out, err
		}
		out = append(out, pick(&p)...)
		if p.NextPageToken == "" || p.NextPageToken == q.Get("pageToken") {
			return out, nil
		}
		q.Set("pageToken", p.NextPageToken)
	}
	return out, fmt.Errorf("GET %s: pagination did not end", path)
}

type page[T any] struct {
	NextPageToken string `json:"nextPageToken"`
	Users         []T    `json:"users"`
	Items         []T    `json:"items"`
}

func (a *audit) status(state finding.State, detail string) {
	a.emit.Status(finding.Status{Account: a.cfg.domain, State: state, Detail: detail})
}

func (a *audit) apiFailure(err error) (finding.State, string) {
	var se *httpx.StatusError
	if !errors.As(err, &se) {
		return finding.StateError, err.Error()
	}
	switch m := se.Message; {
	case strings.Contains(m, "has not been used in project") || strings.Contains(m, "SERVICE_DISABLED") || strings.Contains(m, "it is disabled"):
		return finding.StateError, fmt.Sprintf("The Admin SDK API is not enabled in the quota project (%s). Enable it there or set quota_project to a project where it is.", m)
	case se.Code == http.StatusUnauthorized:
		return finding.StateReauth, fmt.Sprintf("Token rejected (401: %s).\n\n%s", m, loginHelp(a.cfg))
	case se.Code == http.StatusForbidden:
		return finding.StateError, fmt.Sprintf("Forbidden (403: %s). The account must be an admin of %s with read privileges on users and security.", m, a.cfg.domain)
	}
	return finding.StateError, err.Error()
}

func (a *audit) run(ctx context.Context, info tokenInfo) {
	users, err := pages(ctx, a.api, "/directory/v1/users", url.Values{
		"customer": {"my_customer"}, "maxResults": {"500"}, "orderBy": {"email"}, "fields": {userFields},
	}, func(p *page[user]) []user { return p.Users })
	if err != nil {
		a.status(a.apiFailure(err))
		return
	}
	// Without the email scope tokeninfo gives no email: the user list proves the tenant.
	if len(users) > 0 && !anyInDomain(users, a.cfg.domain) {
		a.status(finding.StateMissingCredentials, otherTenant(a.cfg.domain, "list the users of another tenant (no account ends in @"+a.cfg.domain+")"))
		return
	}
	accounts := make([]account, len(users))
	for i, u := range users {
		accounts[i] = newAccount(u, a.now)
	}
	sort.SliceStable(accounts, func(i, j int) bool { return accounts[i].before(accounts[j]) })

	grants, grantErr := a.grants(ctx, accounts)
	var activity map[string]*appActivity
	var activityErr error
	if info.reports {
		activity, activityErr = a.activity(ctx)
	}

	for _, f := range userFindings(a.cfg.domain, accounts, a.cfg.inactiveDays, a.now) {
		a.emit.Finding(f)
	}
	apps := aggregate(grants)
	for _, f := range appFindings(a.cfg.domain, apps, activity) {
		a.emit.Finding(f)
	}

	failed := false
	if grantErr != nil {
		failed = true
		a.status(finding.StateError, "third-party apps incomplete: "+grantErr.Error())
	}
	if activityErr != nil {
		failed = true
		state, why := a.apiFailure(activityErr)
		a.status(state, "token activity: "+why)
	}
	if failed {
		return
	}
	live := 0
	for _, acc := range accounts {
		if acc.live() {
			live++
		}
	}
	detail := fmt.Sprintf("%d accounts, %d active, %d third-party apps", len(accounts), live, len(apps))
	if info.email != "" {
		detail += "; signed in as " + info.email
	}
	if !info.reports {
		detail += "; token activity skipped: the token lacks " + reportsScope
	}
	a.status(finding.StateOK, detail)
}

func anyInDomain(users []user, domain string) bool {
	for _, u := range users {
		if inDomain(u.PrimaryEmail, domain) {
			return true
		}
	}
	return false
}

type grant struct {
	user string
	token
}

// grants lists the OAuth tokens of live accounts: suspended and archived ones cannot use theirs.
func (a *audit) grants(ctx context.Context, accounts []account) ([]grant, error) {
	var mu sync.Mutex
	var out []grant
	var failed []string
	var first error
	sem := make(chan struct{}, parallel)
	var wg sync.WaitGroup
	for _, acc := range accounts {
		if !acc.live() {
			continue
		}
		email := acc.email
		sem <- struct{}{}
		wg.Go(func() {
			defer func() { <-sem }()
			var p page[token]
			err := a.api.Get(ctx, "/directory/v1/users/"+url.PathEscape(email)+"/tokens", nil, &p)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				failed = append(failed, email)
				if first == nil {
					first = err
				}
				return
			}
			for _, t := range p.Items {
				out = append(out, grant{user: email, token: t})
			}
		})
	}
	wg.Wait()
	if first != nil {
		_, why := a.apiFailure(first)
		sort.Strings(failed)
		return out, fmt.Errorf("tokens.list failed for %d account(s) (%s): %s", len(failed), strings.Join(failed, ", "), why)
	}
	return out, nil
}

type appActivity struct {
	app, clientID     string
	authorize, revoke int
	lastEvent         string // RFC 3339, so later events compare greater
}

func (a *audit) activity(ctx context.Context) (map[string]*appActivity, error) {
	items, err := pages(ctx, a.api, "/reports/v1/activity/users/all/applications/token", url.Values{
		"maxResults": {"1000"}, "startTime": {a.now.Add(-activityWindow).Format(time.RFC3339)},
	}, func(p *page[activityItem]) []activityItem { return p.Items })
	if err != nil {
		return nil, err
	}
	out := map[string]*appActivity{}
	for _, it := range items {
		for _, ev := range it.Events {
			p := map[string]string{}
			for _, x := range ev.Parameters {
				p[x.Name] = x.Value
			}
			key := cmp.Or(p["client_id"], p["app_name"])
			if key == "" {
				continue
			}
			act := out[key]
			if act == nil {
				act = &appActivity{app: cmp.Or(p["app_name"], key), clientID: p["client_id"]}
				out[key] = act
			}
			switch ev.Name {
			case "authorize":
				act.authorize++
			case "revoke":
				act.revoke++
			}
			if it.ID.Time > act.lastEvent {
				act.lastEvent = it.ID.Time
			}
		}
	}
	return out, nil
}
