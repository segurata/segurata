package signin

import (
	"strings"
	"testing"
)

// Closed stdin is not Enter: the wait must go on until the pages are done or the timeout.
func TestOnlyAFullLineIsEnter(t *testing.T) {
	for in, want := range map[string]bool{"": false, "partial": false, "\n": true, "done\n": true} {
		if got := enterPressed(strings.NewReader(in)); got != want {
			t.Errorf("%q: Enter = %t, want %t", in, got, want)
		}
	}
	<-readLine(strings.NewReader("\n"))
}
