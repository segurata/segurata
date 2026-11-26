package fanout

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestEachCallsEveryIndexOnceWithinTheLimit(t *testing.T) {
	for _, tc := range []struct{ n, limit, wantPeak int }{
		{0, 3, 0}, {5, 2, 2}, {3, 10, 3}, {4, 0, 4}, {4, -1, 4},
	} {
		var running, peak atomic.Int32
		var mu sync.Mutex
		seen := map[int]int{}
		Each(tc.n, tc.limit, func(i int) {
			now := running.Add(1)
			for p := peak.Load(); now > p && !peak.CompareAndSwap(p, now); p = peak.Load() {
			}
			time.Sleep(20 * time.Millisecond)
			running.Add(-1)
			mu.Lock()
			seen[i]++
			mu.Unlock()
		})
		if len(seen) != tc.n {
			t.Errorf("n=%d limit=%d: called %d indexes", tc.n, tc.limit, len(seen))
		}
		for i, c := range seen {
			if c != 1 || i < 0 || i >= tc.n {
				t.Errorf("n=%d: index %d called %d times", tc.n, i, c)
			}
		}
		if int(peak.Load()) > tc.wantPeak {
			t.Errorf("n=%d limit=%d: %d ran at once, want at most %d", tc.n, tc.limit, peak.Load(), tc.wantPeak)
		}
	}
}
