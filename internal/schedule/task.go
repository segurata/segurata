package schedule

import (
	"fmt"
	"strings"
	"time"
	"unicode/utf16"
)

// maxTaskEvery is Task Scheduler's longest repetition interval.
const maxTaskEvery = 31 * 24 * time.Hour

// TaskXML is the Task Scheduler task. It runs as the owner, only while the owner is signed in
// (InteractiveToken: an S4U task cannot read Credential Manager), with the least privilege, and
// starts first one interval after installation. A run due while the machine was off starts when it
// is back, and none starts while one is going.
//
// segurata.exe is a console program, which Task Scheduler would show in a window for the whole run:
// closing it would kill the run, and keys typed into it would reach it. The task starts it under
// conhost.exe --headless (Windows 10 1809 and later), a console with no window, which still lets
// proc interrupt the inventory with CTRL_BREAK.
func (e Env) TaskXML(o Options) (string, error) {
	every, err := o.every()
	if err != nil {
		return "", err
	}
	if every > maxTaskEvery {
		return "", fmt.Errorf("--every must be at most %s on Windows, Task Scheduler's longest interval", maxTaskEvery)
	}
	if e.UserSID == "" {
		return "", fmt.Errorf("cannot tell which account the task runs as")
	}
	if e.Conhost == "" {
		return "", fmt.Errorf("cannot find conhost.exe, which runs the task without a window")
	}
	p := e.Paths()
	argv := append([]string{e.Conhost, "--headless"}, e.runArgs(o)...)
	quoted := make([]string, 0, len(argv))
	for _, a := range argv {
		if strings.ContainsAny(a, "\r\n\x00%") {
			// Task Scheduler expands %VAR% in the command, its arguments and its folder.
			return "", fmt.Errorf("the task cannot run %q: it holds %% or a line break", a)
		}
		quoted = append(quoted, windowsArg(a))
	}
	if strings.ContainsAny(p.State, "\r\n\x00%") {
		return "", fmt.Errorf("the task cannot start in %q: it holds %% or a line break", p.State)
	}
	// The run bounds itself at 90% of the interval; Task Scheduler stops it only past that.
	limit := every * 19 / 20 / time.Second * time.Second
	start := e.Now().Add(every).Format("2006-01-02T15:04:05")
	t := xmlText
	return `<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>segurata scheduled inventory and report</Description>
    <URI>\` + t(taskName) + `</URI>
  </RegistrationInfo>
  <Triggers>
    <TimeTrigger>
      <Repetition>
        <Interval>` + isoDuration(every) + `</Interval>
        <StopAtDurationEnd>false</StopAtDurationEnd>
      </Repetition>
      <StartBoundary>` + start + `</StartBoundary>
      <Enabled>true</Enabled>
    </TimeTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>` + t(e.UserSID) + `</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <StartWhenAvailable>true</StartWhenAvailable>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <ExecutionTimeLimit>` + isoDuration(limit) + `</ExecutionTimeLimit>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>` + t(quoted[0]) + `</Command>
      <Arguments>` + t(strings.Join(quoted[1:], " ")) + `</Arguments>
      <WorkingDirectory>` + t(p.State) + `</WorkingDirectory>
    </Exec>
  </Actions>
</Task>
`, nil
}

// isoDuration is d as an XML Schema duration, in the largest units that divide it.
func isoDuration(d time.Duration) string {
	s := int64(d / time.Second)
	days, s := s/86400, s%86400
	h, s := s/3600, s%3600
	m, s := s/60, s%60
	var b strings.Builder
	b.WriteString("P")
	if days > 0 {
		fmt.Fprintf(&b, "%dD", days)
	}
	if h+m+s > 0 || days == 0 {
		b.WriteString("T")
		for _, part := range []struct {
			n    int64
			unit string
		}{{h, "H"}, {m, "M"}, {s, "S"}} {
			if part.n > 0 {
				fmt.Fprintf(&b, "%d%s", part.n, part.unit)
			}
		}
		if h+m+s == 0 {
			b.WriteString("0S")
		}
	}
	return b.String()
}

// windowsArg quotes one argument by the rules CommandLineToArgvW reads, as syscall.EscapeArg does;
// it is here so the task is built, and tested, the same on every host.
func windowsArg(s string) string {
	if s == "" {
		return `""`
	}
	space := strings.ContainsAny(s, " \t")
	if !space && !strings.Contains(s, `"`) {
		return s
	}
	var b strings.Builder
	if space {
		b.WriteByte('"')
	}
	slashes := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\\':
			slashes++
		case '"':
			b.WriteString(strings.Repeat(`\`, slashes+1))
			slashes = 0
		default:
			slashes = 0
		}
		b.WriteByte(s[i])
	}
	if space {
		b.WriteString(strings.Repeat(`\`, slashes))
		b.WriteByte('"')
	}
	return b.String()
}

// utf16File is text as Task Scheduler's XML files are: UTF-16LE with a byte order mark.
func utf16File(s string) []byte {
	units := utf16.Encode([]rune(s))
	out := make([]byte, 2, 2+2*len(units))
	out[0], out[1] = 0xFF, 0xFE
	for _, u := range units {
		out = append(out, byte(u), byte(u>>8))
	}
	return out
}
