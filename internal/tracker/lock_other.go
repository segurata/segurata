//go:build !unix && !windows

package tracker

// Without flock, Save still refuses a tracker.json saved since it was loaded (errChanged).
func lock(string) (unlock func(), err error) { return func() {}, nil }
