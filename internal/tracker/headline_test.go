package tracker

import (
	"strings"
	"testing"

	"github.com/segurata/segurata/internal/doc"
)

// A --priority filter narrows the open counts but must not hide closed items that have no
// priority, such as secrets reclassified as noise.
func TestHeadlineClosedCountsIgnoreTheFilter(t *testing.T) {
	tr := New(t0)
	it := tr.newItem(KindFix, "manual:noise", "other", "Noise", t0)
	it.Status = Reclassified
	d := &doc.Doc{}
	tr.Headline(d, nil, t0) // a filter that kept nothing
	var b strings.Builder
	_ = doc.Render(&b, d, doc.Text)
	if !strings.Contains(b.String(), "reclassified as noise 1") {
		t.Fatalf("filtered headline lost the reclassified count:\n%s", b.String())
	}
}
