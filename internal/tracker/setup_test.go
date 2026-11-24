package tracker

import (
	"reflect"
	"testing"

	"github.com/segurata/segurata/internal/finding"
)

func TestSetupStatusesRebuildWhatTheConnectorReported(t *testing.T) {
	it := &Item{Kind: KindSetup, Key: "setup:connected-apps|github:octo|reauth", Findings: []FindingRef{
		{ID: "status:a#1", Connector: "connected-apps", Account: "github:octo", Title: "authorized apps need sudo mode"},
		{ID: "status:a#2", Connector: "connected-apps", Account: "github:octo", Title: "gone already", Gone: true},
		{ID: "status:a#3", Connector: "gcp", Instance: "work", Account: "a@x", Scope: "project p", Title: "installed apps need sudo mode"},
	}}
	got := it.SetupStatuses()
	want := []finding.Status{
		{Type: "status", Connector: "connected-apps", Account: "github:octo", State: finding.StateReauth, Detail: "authorized apps need sudo mode"},
		{Type: "status", Connector: "gcp", Instance: "work", Account: "a@x", Scope: "project p", State: finding.StateReauth, Detail: "installed apps need sudo mode"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v\nwant %+v", got, want)
	}
	if s := (&Item{Kind: KindFix, Key: "x|reauth", Findings: it.Findings}).SetupStatuses(); s != nil {
		t.Fatalf("a fix item has statuses: %v", s)
	}
}
