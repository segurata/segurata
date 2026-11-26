//go:build !unix

package tracker

// lock is a no-op where flock does not exist: Save still refuses a tracker.json another command
// saved since this one loaded it (see errChanged).
func lock(string) (unlock func(), err error) { return func() {}, nil }
