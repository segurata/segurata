package macos

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/segurata/segurata/internal/connector"
)

func TestDoctorReportsWhatTheInventoryCanRead(t *testing.T) {
	levels := func(cs []connector.Check) string {
		var s []string
		for _, ch := range cs {
			s = append(s, fmt.Sprintf("%s %s", ch.Level, ch.What))
			if ch.Level != connector.OK && ch.Fix == "" {
				t.Errorf("%s has no fix", ch.What)
			}
		}
		return strings.Join(s, "; ")
	}
	c, _, _ := newTest(t, healthy())
	if got := levels(c.Doctor(context.Background(), connector.Request{})); got != "OK local accounts; OK Time Machine destinations; OK Time Machine preferences" {
		t.Errorf("healthy: %s", got)
	}
	r := backupReplies("tmutil: Operation not permitted", "", "")
	delete(r, strings.Join(tmPrefs, " "))
	c, _, _ = newTest(t, r)
	got := c.Doctor(context.Background(), connector.Request{})
	if levels(got) != "OK local accounts; WARN Time Machine destinations; WARN Time Machine preferences" || !strings.Contains(got[1].Fix, "Full Disk Access") {
		t.Errorf("no access: %s %+v", levels(got), got)
	}
	c.OS = "linux"
	if got := c.Doctor(context.Background(), connector.Request{}); got != nil {
		t.Errorf("linux: %v", got)
	}
}
