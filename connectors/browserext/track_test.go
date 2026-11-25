package browserext

import (
	"testing"

	"github.com/segurata/segurata/internal/finding"
)

func TestTrackIsOneItemPerFinding(t *testing.T) {
	if got := New().Track(finding.Finding{}); got == nil || *got != (finding.Track{Group: finding.GroupFinding, Kind: finding.TrackReview}) {
		t.Fatalf("%+v", got)
	}
	if New().Describe().Theme.ID == "" {
		t.Fatal("no theme")
	}
}
