// Package fanout runs independent work concurrently, with a bound.
package fanout

import "sync"

// Each calls fn(i) for every i in [0, n), at most limit at a time, or all at once when limit < 1,
// and returns once every call has.
func Each(n, limit int, fn func(i int)) {
	if limit < 1 || limit > n {
		limit = n
	}
	sem := make(chan struct{}, limit)
	var wg sync.WaitGroup
	for i := range n {
		sem <- struct{}{}
		wg.Go(func() {
			defer func() { <-sem }()
			fn(i)
		})
	}
	wg.Wait()
}
