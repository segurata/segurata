package macos

import (
	"context"
	"fmt"

	"github.com/segurata/segurata/internal/connector"
)

// Doctor checks what the inventory reads without sudo but may be refused: the local user records
// and Time Machine's destinations and preferences, which can need Full Disk Access. It runs the
// same guarded commands as the inventory. Off macOS the core reports the os:darwin need.
func (c *Connector) Doctor(ctx context.Context, _ connector.Request) []connector.Check {
	if c.OS != "darwin" {
		return nil
	}
	var checks []connector.Check
	if users, err := c.localUsers(ctx); err != nil {
		checks = append(checks, connector.Check{Level: connector.Warn, What: "local accounts", Detail: err.Error(),
			Fix: "run `dscl . list /Users UniqueID` to see the error; the account checks are skipped until it answers"})
	} else {
		checks = append(checks, connector.Check{Level: connector.OK, What: "local accounts", Detail: fmt.Sprintf("%d user records", len(users))})
	}
	if _, err := c.destinationInfo(ctx); err != nil {
		checks = append(checks, connector.Check{Level: connector.Warn, What: "Time Machine destinations", Detail: err.Error(), Fix: fullDiskAccessFix})
	} else {
		checks = append(checks, connector.Check{Level: connector.OK, What: "Time Machine destinations", Detail: "tmutil destinationinfo answers"})
	}
	if _, err := c.timeMachinePrefs(ctx); err != nil {
		checks = append(checks, connector.Check{Level: connector.Warn, What: "Time Machine preferences",
			Detail: fmt.Sprintf("%s is unreadable, so whether backups are encrypted is unknown: %v", timeMachinePref, err), Fix: fullDiskAccessFix})
	} else {
		checks = append(checks, connector.Check{Level: connector.OK, What: "Time Machine preferences", Detail: timeMachinePref + " is readable"})
	}
	return checks
}
