package schedule

import (
	"path/filepath"

	"github.com/segurata/segurata/internal/proc"
	"github.com/segurata/segurata/internal/winsys"
)

// scheduledCommand gives a scheduled inventory a process group of its own, which a CTRL_BREAK can interrupt
// without reaching segurata, and a job that Task Scheduler's end of the task takes with it.
var scheduledCommand = proc.Command

// LoadTaskHost fills in what the task needs from this machine: the account, the local application
// data folder (asked of the shell, not %LOCALAPPDATA%) and System32's schtasks.exe and conhost.exe.
func (e *Env) LoadTaskHost() error {
	sid, err := winsys.CurrentUserSID()
	if err != nil {
		return err
	}
	local, err := winsys.KnownFolderPath(&winsys.FolderIDLocalAppData)
	if err != nil {
		return err
	}
	sys, err := winsys.System32()
	if err != nil {
		return err
	}
	e.UserSID, e.LocalAppData = sid, local
	e.SchTasks, e.Conhost = filepath.Join(sys, "schtasks.exe"), filepath.Join(sys, "conhost.exe")
	return nil
}
