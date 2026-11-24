//go:build !unix

package tracker

// Lock is a no-op where flock does not exist: Save still refuses a tracker.json another command
// saved since this one loaded it (see ErrChanged).
func Lock(string) (unlock func(), err error) { return func() {}, nil }
