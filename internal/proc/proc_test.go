package proc_test

import (
	"context"
	"testing"
	"time"

	"github.com/segurata/segurata/internal/proc"
	"github.com/segurata/segurata/internal/proc/proctest"
)

func TestAKilledWrapperDoesNotWaitForItsChild(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := proc.Command(ctx, proctest.Hung(t, "hung", "")).Output(); err == nil {
		t.Fatal("a hung command succeeded")
	}
	if took := time.Since(start); took > proc.WaitDelay+5*time.Second {
		t.Fatalf("Wait blocked for %s on the orphaned child", took)
	}
}
