package gcp

import (
	"context"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"time"
)

// usageWindow is how far back an API key's calls are read. serviceruntime metrics are kept six
// weeks, so the whole window is there.
const usageWindow = 30 * 24 * time.Hour

const monitoringHost = "monitoring.googleapis.com"

// keyUsage is what Cloud Monitoring says an API key called in usageWindow. err set means unknown.
type keyUsage struct {
	apis []string // sorted service names, such as geocoding-backend.googleapis.com
	err  error
}

func (u keyUsage) known() bool { return u.err == nil }

// usageFilter selects the request counts made with one API key. Google's API key management
// codelab filters on the consumed_api resource label credential_id, valued "apikey:" and the key's
// uid (codelabs.developers.google.com/api-key-management, "Discover usage").
func usageFilter(uid string) string {
	return `metric.type="serviceruntime.googleapis.com/api/request_count" AND resource.type="consumed_api" AND ` +
		`resource.labels.credential_id="apikey:` + uid + `"`
}

type timeSeriesPage struct {
	TimeSeries []struct {
		Resource struct {
			Labels map[string]string `json:"labels"`
		} `json:"resource"`
	} `json:"timeSeries"`
	NextPageToken string `json:"nextPageToken"`
}

// usage reads, through projects.timeSeries.list with view HEADERS (the series without their
// points), which services each key called in the window ending now.
func (g *gcloud) usage(ctx context.Context, account, project, userProject string, uids []string, now time.Time) map[string]keyUsage {
	out := make(map[string]keyUsage, len(uids))
	api, err := g.api(ctx, monitoringHost, account, userProject)
	for _, uid := range uids {
		if err != nil {
			out[uid] = keyUsage{err: err}
			continue
		}
		out[uid] = readUsage(func(q url.Values, page *timeSeriesPage) error {
			return api.Get(ctx, "/v3/projects/"+url.PathEscape(project)+"/timeSeries", q, page)
		}, uid, now)
	}
	return out
}

func readUsage(get func(url.Values, *timeSeriesPage) error, uid string, now time.Time) keyUsage {
	q := url.Values{
		"filter":             {usageFilter(uid)},
		"interval.startTime": {now.Add(-usageWindow).UTC().Format(time.RFC3339)},
		"interval.endTime":   {now.UTC().Format(time.RFC3339)},
		"view":               {"HEADERS"},
	}
	seen := map[string]bool{}
	for {
		var page timeSeriesPage
		if err := get(q, &page); err != nil {
			return keyUsage{err: err}
		}
		for _, ts := range page.TimeSeries {
			if s := ts.Resource.Labels["service"]; s != "" {
				seen[s] = true
			}
		}
		if page.NextPageToken == "" {
			break
		}
		q.Set("pageToken", page.NextPageToken)
	}
	apis := make([]string, 0, len(seen))
	for s := range seen {
		apis = append(apis, s)
	}
	slices.Sort(apis)
	return keyUsage{apis: apis}
}

// usageLine is what the finding says about a key's calls.
func usageLine(u keyUsage) string {
	switch {
	case !u.known():
		return fmt.Sprintf("Used APIs (30 days) unknown: Cloud Monitoring could not be read (%s).", summarize(printed(u.err)))
	case len(u.apis) == 0:
		return "No API was called with this key in the last 30 days: it is a candidate for deletion."
	}
	return "Used APIs (30 days): " + strings.Join(u.apis, ", ") + "."
}
