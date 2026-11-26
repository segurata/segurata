//go:build !darwin && !windows

package clipboard

import (
	"context"
	"errors"
)

var errUnsupported = errors.New("reading the clipboard is supported on macOS and Windows only; pipe the value in with --stdin")

func Default() Clipboard { return unsupported{} }

type unsupported struct{}

func (unsupported) Read(context.Context) ([]byte, error) { return nil, errUnsupported }
func (unsupported) Clear(context.Context) error          { return errUnsupported }
func (unsupported) Caveat() string                       { return "" }
