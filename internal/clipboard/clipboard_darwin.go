package clipboard

import (
	"context"

	"github.com/segurata/segurata/internal/proc"
)

const (
	pbpaste = "/usr/bin/pbpaste"
	pbcopy  = "/usr/bin/pbcopy"
)

func Default() Clipboard { return Pasteboard{Run: proc.Exec} }

// Pasteboard is the general pasteboard.
type Pasteboard struct{ Run proc.Runner }

func (p Pasteboard) Read(ctx context.Context) ([]byte, error) { return p.Run(ctx, nil, pbpaste) }

// Clear copies nothing: pbcopy with an empty stdin.
func (p Pasteboard) Clear(ctx context.Context) error {
	_, err := p.Run(ctx, nil, pbcopy)
	return err
}

func (Pasteboard) Caveat() string { return "" }
