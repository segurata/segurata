//go:build !windows

package localsecrets

// userEnvironment is nil: Unix keeps no environment outside the files the scan reads.
var userEnvironment func() (map[string]string, error)
