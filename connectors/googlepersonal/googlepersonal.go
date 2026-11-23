// Package googlepersonal inventories the apps linked to every Google account signed in to the
// user's browser: third-party OAuth grants and Sign in with Google. It reads
// myaccount.google.com over CDP and never clicks anything.
package googlepersonal

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/segurata/segurata/internal/cdp"
	"github.com/segurata/segurata/internal/connector"
	"github.com/segurata/segurata/internal/finding"
)

const (
	name        = "google-personal"
	maxAccounts = 20 // authuser 0..19
	concurrency = 6  // app pages open at once
)

const (
	summaryGrant = `If you no longer use this app, open its page and choose "Remove all access". ` +
		`On Google that also removes the app's Sign in with Google link (verified 2026-11-23 with Dropbox), ` +
		`so if you sign in to the app with Google, set up another way in first.`
	summarySignIn = `If you no longer use this app, "Delete all" on its page removes the Sign in with Google link. ` +
		`Set up another way to sign in to the app first if you still need that account.`
)

func init() { connector.Register(GooglePersonal{}) }

type GooglePersonal struct{}

func (GooglePersonal) Describe() connector.Description {
	return connector.Description{
		Name:     name,
		Version:  "0.1.0",
		Protocol: connector.ProtocolVersion,
		Summary:  "Apps linked to every Google account in the browser: OAuth grants, scopes, Sign in with Google",
		Needs:    []string{"cdp"},
	}
}

func (GooglePersonal) Inventory(ctx context.Context, req connector.Request, emit connector.Emitter) error {
	c, err := cdp.Connect(ctx, req.CDPURL)
	if err != nil {
		return err
	}
	defer c.Close()
	return inventory(ctx, cdpBrowser{c}, emit, time.Now())
}

// browser loads a page, polls a JavaScript expression until ready accepts its value or tries
// run out, and returns the last value. The seam that lets tests replace Brave with fixtures.
type browser interface {
	load(ctx context.Context, url, expr string, ready func(json.RawMessage) bool, tries int) (json.RawMessage, error)
}

type cdpBrowser struct{ c *cdp.Client }

func (b cdpBrowser) load(ctx context.Context, url, expr string, ready func(json.RawMessage) bool, tries int) (v json.RawMessage, err error) {
	err = b.c.WithPage(ctx, url, func(p *cdp.Page) error {
		v, err = p.WaitFor(ctx, expr, ready, tries)
		return err
	})
	return v, err
}

// The account email is read from the page source: it is not always in the visible text.
const connectionsJS = `({
  mail: ((document.documentElement.innerHTML.match(/"([\w.+-]+@[\w-]+\.[\w.-]+)"/) || [])[1]) || "",
  text: document.body.innerText,
  apps: [...document.querySelectorAll('a[href*="linkedapps/overview/"]')].map(a => ({name: a.innerText.trim(), href: a.href}))
})`

const pageJS = `({
  text: (document.querySelector('main') || document.body).innerText,
  details: [...new Set([...document.querySelectorAll('a[href*="linkedapps/details/"]')].map(a => a.href))]
})`

type connectionsPage struct {
	Mail string    `json:"mail"`
	Text string    `json:"text"`
	Apps []appLink `json:"apps"`
}

type appLink struct {
	Name string `json:"name"`
	Href string `json:"href"`
}

type appPage struct {
	Text    string   `json:"text"`
	Details []string `json:"details"`
}

func decode[T any](raw json.RawMessage) (T, bool) {
	var v T
	return v, json.Unmarshal(raw, &v) == nil
}

func connectionsReady(raw json.RawMessage) bool {
	p, ok := decode[connectionsPage](raw)
	return ok && (isReauth(p.Text) || len(p.Apps) > 0)
}

func overviewReady(raw json.RawMessage) bool {
	p, ok := decode[appPage](raw)
	return ok && (isReauth(p.Text) || len(p.Text) > 200 && overviewLoadedRE.MatchString(p.Text))
}

var overviewLoadedRE = regexp.MustCompile(`(?i)access|acceso|Sign in|Iniciar sesión`)

func detailReady(raw json.RawMessage) bool {
	p, ok := decode[appPage](raw)
	return ok && (isReauth(p.Text) || parseDetail(p.Text).GivenOn != "")
}

func connectionsURL(u int) string {
	return fmt.Sprintf("https://myaccount.google.com/u/%d/connections", u)
}

func inventory(ctx context.Context, b browser, emit connector.Emitter, now time.Time) error {
	seen := map[string]bool{}
	for u := 0; u < maxAccounts && ctx.Err() == nil; u++ {
		raw, err := b.load(ctx, connectionsURL(u), connectionsJS, connectionsReady, 24)
		if err != nil {
			emit.Status(finding.Status{Account: fmt.Sprintf("authuser %d", u), State: finding.StateError, Detail: err.Error()})
			break
		}
		page, _ := decode[connectionsPage](raw)
		if page.Mail == "" {
			if u == 0 {
				emit.Status(finding.Status{Account: "authuser 0", State: finding.StateSignedOut, Detail: "no Google account signed in to the browser"})
			}
			break
		}
		// Past the last account Google falls back to the default one: stop there.
		if seen[page.Mail] {
			break
		}
		seen[page.Mail] = true
		if isReauth(page.Text) {
			emit.Status(finding.Status{Account: page.Mail, State: finding.StateReauth, Detail: "Google asks to verify it's you before showing linked apps: sign in again in the browser"})
			continue
		}
		apps := inspectAll(ctx, b, page.Apps, now)
		failed := 0
		occurrences := map[string]int{}
		for i, a := range apps {
			if a.err != nil {
				failed++
				emit.Status(finding.Status{Account: page.Mail, State: finding.StateError, Detail: fmt.Sprintf("%s: %v", page.Apps[i].Name, a.err)})
				continue
			}
			for _, w := range a.warnings {
				emit.Log(fmt.Sprintf("u%d %s: %s", u, page.Apps[i].Name, w))
			}
			f := a.finding
			f.Account = page.Mail
			f.ID = stableID(f, occurrences)
			emit.Finding(f)
		}
		emit.Status(finding.Status{Account: page.Mail, State: finding.StateOK, Detail: fmt.Sprintf("%d linked apps, %d unreadable", len(apps)-failed, failed)})
	}
	return nil
}

var errReauth = errors.New("Google asked to verify it's you midway")

type inspected struct {
	finding  finding.Finding
	warnings []string
	err      error
}

// inspectAll reads every app with a bounded number of pages open, keeping input order.
func inspectAll(ctx context.Context, b browser, links []appLink, now time.Time) []inspected {
	out := make([]inspected, len(links))
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	for i, l := range links {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer func() { <-sem; wg.Done() }()
			out[i] = inspect(ctx, b, l, now)
		}()
	}
	wg.Wait()
	return out
}

func inspect(ctx context.Context, b browser, l appLink, now time.Time) inspected {
	raw, err := b.load(ctx, l.Href, pageJS, overviewReady, 30)
	if err != nil {
		return inspected{err: err}
	}
	page, _ := decode[appPage](raw)
	if isReauth(page.Text) {
		return inspected{err: errReauth}
	}
	ov := parseOverview(page.Text)
	scopes := ov.Scopes

	var res inspected
	var created *time.Time
	for _, u := range page.Details {
		raw, err := b.load(ctx, u, pageJS, detailReady, 30)
		if err != nil {
			res.warnings = append(res.warnings, fmt.Sprintf("details page: %v", err))
			continue
		}
		dp, _ := decode[appPage](raw)
		if isReauth(dp.Text) {
			return inspected{err: errReauth}
		}
		d := parseDetail(dp.Text)
		scopes = union(scopes, d.Scopes)
		if t := parseGivenOn(d.GivenOn, now); t != nil {
			if created == nil || t.Before(*created) {
				created = t
			}
		} else {
			res.warnings = append(res.warnings, fmt.Sprintf("unparsed access date %q", d.GivenOn))
		}
	}

	sev, label := assess(scopes)
	appName := firstLine(l.Name)
	resType, summary := "sign_in_with_google", summarySignIn
	if len(scopes) > 0 {
		resType, summary = "oauth_grant", summaryGrant
	}
	res.finding = finding.Finding{
		Resource:  finding.Resource{Type: resType, ID: overviewID(l.Href), Name: appName},
		Kind:      finding.KindGrant,
		Severity:  sev,
		Title:     fmt.Sprintf("%s can %s", appName, label),
		Evidence:  map[string]any{"scopes": scopes, "cross_account_protection": ov.CrossAccount, "detail_urls": nonNil(page.Details)},
		CreatedAt: created,
		Remediation: finding.Remediation{
			Summary: summary,
			URL:     l.Href,
		},
	}
	return res
}

// stableID keys a finding on account, resource type and app name. Google's overview ids are
// fresh opaque tokens on every page load (checked 2026-11-23), so the default id, which hashes
// resource.id, would change between runs. Repeated names get an ordinal in page order.
func stableID(f finding.Finding, occurrences map[string]int) string {
	key := f.Resource.Type + "|" + f.Resource.Name
	n := occurrences[key]
	occurrences[key]++
	if n > 0 {
		key += fmt.Sprintf("#%d", n)
	}
	return finding.StableID(name, f.Account, key)
}

// overviewID is the opaque token Google puts after linkedapps/overview/. It identifies the app
// within one page load only (see stableID); the overview URL keeps working for a while.
func overviewID(href string) string {
	_, id, ok := strings.Cut(href, "linkedapps/overview/")
	if !ok {
		return href
	}
	if i := strings.IndexAny(id, "/?#"); i >= 0 {
		id = id[:i]
	}
	return id
}

// union appends to a the entries of b it does not already hold. Never returns nil.
func union(a, b []string) []string {
	out := append([]string{}, a...)
	have := map[string]bool{}
	for _, s := range a {
		have[s] = true
	}
	for _, s := range b {
		if !have[s] {
			have[s] = true
			out = append(out, s)
		}
	}
	return out
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func firstLine(s string) string {
	l, _, _ := strings.Cut(strings.TrimSpace(s), "\n")
	return strings.TrimSpace(l)
}
