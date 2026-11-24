package redact

import (
	"fmt"
	"math/rand/v2"
	"strings"
	"testing"

	"github.com/segurata/segurata/internal/testcorpus"
)

// BenchmarkDryRun is `redact --trails` over transcripts of multi-megabyte lines with a few
// secrets each, plus a shell history: ripgrep finds the candidate lines, Go places the secrets.
func BenchmarkDryRun(b *testing.B) {
	fx := newFixture(b)
	r := rand.New(rand.NewPCG(1, 2))
	pool := testcorpus.Secrets(r)
	size := 0
	for i := range 8 {
		var lines []string
		for range 3 {
			lines = append(lines, testcorpus.Line(r, 1<<20, 3, pool))
		}
		text := strings.Join(lines, "\n") + "\n"
		size += len(text)
		fx.write(fmt.Sprintf(".claude/projects/p%d/s.jsonl", i), text, 0o600)
	}
	hist := strings.Join(testcorpus.ShortLines(r, pool), "\n") + "\n"
	size += len(hist)
	fx.write(".zsh_history", hist, 0o600)
	b.SetBytes(int64(size))
	b.ResetTimer()
	for b.Loop() {
		if code, out := fx.run("", false, "--trails"); code != 0 {
			b.Fatal(out)
		}
	}
}
