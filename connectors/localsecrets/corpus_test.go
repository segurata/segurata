package localsecrets

import (
	"math/rand/v2"
	"testing"
	"time"

	"github.com/segurata/segurata/internal/fingerprint"
	"github.com/segurata/segurata/internal/testcorpus"
)

// testTrails is a Trails over a fake home, with a fixed fingerprint key.
func testTrails() *Trails {
	home := "/home/me"
	cfg := settings{reposRoot: home + "/src"}
	s := &scan{home: home, src: cfg.reposRoot, cfg: cfg, fp: fingerprint.FromBytes([]byte("bench-key")), now: time.Date(2026, 11, 23, 0, 0, 0, 0, time.UTC)}
	return &Trails{s: s}
}

// corpusPaths are trail files of each kind: transcripts and logs get the specific patterns only,
// histories the generic assignment pattern too.
var corpusPaths = []string{"/home/me/.claude/projects/p/s.jsonl", "/home/me/.zsh_history", "/home/me/Library/Logs/app.log", "/home/me/.netrc"}

func BenchmarkFindLongLine(b *testing.B) {
	r := rand.New(rand.NewPCG(1, 2))
	line := testcorpus.Line(r, 4<<20, 4, testcorpus.Secrets(r))
	tr := testTrails()
	b.SetBytes(int64(len(line)))
	b.ResetTimer()
	for b.Loop() {
		tr.Find(corpusPaths[0], "600", line)
	}
}

func BenchmarkFindHistoryLine(b *testing.B) {
	r := rand.New(rand.NewPCG(1, 2))
	line := testcorpus.Line(r, 1<<20, 4, testcorpus.Secrets(r))
	tr := testTrails()
	b.SetBytes(int64(len(line)))
	b.ResetTimer()
	for b.Loop() {
		tr.Find(corpusPaths[1], "600", line)
	}
}
