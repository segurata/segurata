package finding

import "testing"

// A shared theme is named by its id and keeps its own words; any other declaration is taken as
// given, titled by its id when it has no title.
func TestThemeFor(t *testing.T) {
	for _, c := range []struct{ in, want Theme }{
		{Theme{}, Theme{}},
		{Theme{ID: "cloud", Title: "Mine"}, ThemeCloud},
		{Theme{ID: "breaches"}, Theme{ID: "breaches", Title: "breaches"}},
		{Theme{ID: "breaches", Title: "Breaches", Description: "d"}, Theme{ID: "breaches", Title: "Breaches", Description: "d"}},
	} {
		if got := ThemeFor(c.in); got != c.want {
			t.Errorf("ThemeFor(%+v) = %+v, want %+v", c.in, got, c.want)
		}
	}
}
