//go:build unix

package schedule

import "github.com/segurata/segurata/internal/proc"

// scheduledCommand keeps a scheduled inventory in the agent's process group, so that launchd, which ends
// that group when the agent is unloaded or the user logs out, ends the run with it.
var scheduledCommand = proc.Interactive

// LoadTaskHost has nothing to fill in where there is no Task Scheduler.
func (*Env) LoadTaskHost() error { return nil }
