package signin

import (
	"strings"
	"testing"
	"time"
)

// Closed stdin is not Enter: the wait must go on until the pages are done or the timeout.
func TestClosedInputDoesNotEndTheWait(t *testing.T) {
	ch := readLine(strings.NewReader("")) // EOF at once
	select {
	case <-ch:
		t.Fatal("end of input was taken as Enter")
	case <-time.After(50 * time.Millisecond):
	}
	if _, ok := <-readLineClosed(readLine(strings.NewReader("\n"))); ok {
		t.Fatal("unreachable")
	}
}

// readLineClosed waits briefly for ch to close and reports it on a fresh channel.
func readLineClosed(ch <-chan struct{}) <-chan struct{} {
	out := make(chan struct{})
	go func() {
		select {
		case <-ch:
		case <-time.After(time.Second):
			panic("Enter did not end the wait")
		}
		close(out)
	}()
	return out
}
