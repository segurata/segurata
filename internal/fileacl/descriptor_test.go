package fileacl

import (
	"io/fs"
	"strings"
	"testing"
)

const (
	me    = "S-1-5-21-1000-2000-3000-1001"
	other = "S-1-5-21-1000-2000-3000-1002"
)

func parse(t *testing.T, s string) descriptor {
	t.Helper()
	d, err := parseSDDL(s, func(alias string) (string, bool) {
		if alias == "LA" {
			return "S-1-5-21-1000-2000-3000-500", true
		}
		return "", false
	})
	if err != nil {
		t.Fatalf("%s: %v", s, err)
	}
	return d
}

func TestExposureFromTheDACL(t *testing.T) {
	for _, c := range []struct {
		why, sddl string
		dir       bool
		want      fs.FileMode
	}{
		{"what segurata writes", privateSDDL(me, false), false, 0o600},
		{"a private folder", privateSDDL(me, true), true, 0o600},
		{"an inherited profile file", "O:" + me + "D:AI(A;ID;FA;;;SY)(A;ID;FA;;;BA)(A;ID;FA;;;" + me + ")", false, 0o600},
		{"Users may read", "O:" + me + "D:AI(A;ID;FA;;;" + me + ")(A;ID;0x1200a9;;;BU)", false, 0o644},
		{"Everyone may write", "O:" + me + "D:(A;;FA;;;" + me + ")(A;;FW;;;WD)", false, 0o622},
		{"another account owns the list", "O:" + me + "D:(A;;FA;;;" + me + ")(A;;WD;;;" + other + ")", false, 0o666},
		{"generic read", "O:" + me + "D:(A;;GR;;;AU)", false, 0o644},
		{"inherit-only entries do not apply", "O:" + me + "D:(A;;FA;;;" + me + ")(A;OICIIO;GA;;;CO)(A;OICIIO;FA;;;BU)", true, 0o600},
		{"deny entries are ignored", "O:" + me + "D:(D;;FA;;;BU)(A;;FR;;;BU)", false, 0o644},
		{"delete child opens a folder", "O:" + me + "D:(A;;0x40;;;BU)", true, 0o622},
		{"execute alone is no access", "O:" + me + "D:(A;;FX;;;BU)", false, 0o600},
		{"a NULL DACL", "O:" + me + "D:NO_ACCESS_CONTROL", false, 0o666},
		{"no DACL at all", "O:" + me, false, 0o666},
		{"an empty DACL", "O:" + me + "D:P", false, 0o600},
		{"an unknown principal", "O:" + me + "D:(A;;FR;;;DU)", false, 0o644},
		{"the owner's own entry", "O:" + other + "D:(A;;FA;;;" + other + ")(A;;FA;;;OW)", false, 0o600},
		{"BUILTIN\\Users owns it", "O:BUD:(A;;FA;;;BU)", false, 0o666},
		{"Everyone owns it", "O:WDD:(A;;FA;;;" + me + ")(A;;FR;;;OW)", false, 0o644},
		{"Domain Users owns it", "O:S-1-5-21-1000-2000-3000-513D:(A;;FR;;;S-1-5-21-1000-2000-3000-513)", false, 0o644},
		{"Administrators owns it", "O:BAD:(A;;FA;;;BA)(A;;FA;;;" + me + ")", false, 0o600},
		{"SYSTEM and Administrators are tolerated", "O:" + me + "D:(A;;FA;;;" + me + ")(A;;FA;;;SY)(A;;FA;;;BA)", false, 0o600},
		{"TrustedInstaller may read", "O:" + me + "D:(A;;FA;;;" + me + ")(A;;FR;;;" + sidTrustedInstaller + ")", false, 0o644},
		{"a conditional entry", "O:" + me + "D:(XA;;FR;;;WD;(Member_of {SID(BA)}))", false, 0o644},
		{"a group section", "O:" + me + "G:DUD:(A;;FR;;;BU)", false, 0o644},
	} {
		if got := parse(t, c.sddl).exposure(me, c.dir); got != c.want {
			t.Errorf("%s: %s gives %04o, want %04o", c.why, c.sddl, got, c.want)
		}
	}
}

func TestGroupSID(t *testing.T) {
	for sid, want := range map[string]bool{
		me: false, "S-1-5-21-1000-2000-3000-500": false, "S-1-5-21-1000-2000-3000-513": true,
		"S-1-5-21-1000-2000-3000-498": true, "S-1-5-32-545": true, "S-1-1-0": true, "alias:XX": true, "S-1-5-21-x": true,
	} {
		if groupSID(sid) != want {
			t.Errorf("groupSID(%s) != %v", sid, want)
		}
	}
}

func TestAliasesResolve(t *testing.T) {
	d := parse(t, "O:LAD:(A;;FA;;;LA)(A;;FR;;;XX)")
	if d.owner != "S-1-5-21-1000-2000-3000-500" || d.aces[0].sid != d.owner || d.aces[1].sid != "alias:XX" {
		t.Fatalf("%+v", d)
	}
}

func TestMalformedSDDLIsAnError(t *testing.T) {
	for _, s := range []string{"D:(A;;FA;;)", "D:(A;;ZZ;;;SY)", "D:(A;;FA;;;SY", "D:(Q;;FA;;;SY)", "D:x(A;;FA;;;SY)junk", "D:(A;;F;;;SY)"} {
		if _, err := parseSDDL(s, nil); err == nil {
			t.Errorf("%q parsed", s)
		}
	}
}

func TestChangeableByOthers(t *testing.T) {
	for _, c := range []struct {
		why, sddl string
		want      bool
	}{
		{"a private folder", privateSDDL(me, true), false},
		{"the profile", "O:" + me + "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;" + me + ")", false},
		{"C:\\", "O:" + sidTrustedInstaller + "D:PAI(A;OICIIO;SDGXGWGR;;;AU)(A;;LC;;;AU)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)", false},
		{"C:\\ owned by Administrators", "O:BAD:PAI(A;OICIIO;SDGXGWGR;;;AU)(A;;LC;;;AU)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)", false},
		{"C:\\Users", "O:SYD:PAI(A;OICIIO;GA;;;SY)(A;;FA;;;SY)(A;OICI;FA;;;BA)(A;;0x1200a9;;;BU)(A;OICIIO;GXGR;;;BU)(A;;0x1200a9;;;WD)", false},
		{"Users may add files", "O:" + me + "D:(A;;0x2;;;BU)", true},
		{"Users may delete entries", "O:" + me + "D:(A;;0x40;;;BU)", true},
		{"Users may delete the folder", "O:" + me + "D:(A;;SD;;;BU)", true},
		{"Users may rewrite the list", "O:" + me + "D:(A;;WD;;;BU)", true},
		{"modify for Authenticated Users", "O:" + me + "D:(A;OICI;0x1301bf;;;AU)", true},
		{"another account owns it", "O:" + other + "D:P(A;;FA;;;" + me + ")", true},
		{"a NULL DACL", "O:" + me + "D:NO_ACCESS_CONTROL", true},
	} {
		if got := parse(t, c.sddl).changeable(me); got != c.want {
			t.Errorf("%s: changeable = %v, want %v", c.why, got, c.want)
		}
	}
}

func TestIsPrivateIsExactlyWhatMakePrivateWrites(t *testing.T) {
	for _, dir := range []bool{false, true} {
		if !parse(t, privateSDDL(me, dir)).isPrivate(me) {
			t.Errorf("privateSDDL(dir=%v) is not private", dir)
		}
	}
	for _, s := range []string{
		"O:" + me + "D:(A;;FA;;;" + me + ")(A;;FA;;;SY)",              // inherits
		"O:" + other + "D:P(A;;FA;;;" + me + ")(A;;FA;;;SY)",          // another owner
		"O:" + me + "D:P(A;;FA;;;" + me + ")(A;;FA;;;SY)(A;;FA;;;BA)", // Administrators
		"O:" + me + "D:P(A;;FR;;;" + me + ")(A;;FA;;;SY)",             // read only for me
		"O:" + me + "D:P(A;;FA;;;" + me + ")(D;;FA;;;SY)",             // a deny entry
		"O:" + me + "D:P",                 // nobody
		"O:" + me + "D:NO_ACCESS_CONTROL", // everyone
	} {
		if parse(t, s).isPrivate(me) {
			t.Errorf("%s counted as private", s)
		}
	}
}

func TestDescribeNamesOnlyWellKnownAccounts(t *testing.T) {
	d := parse(t, "O:"+me+"D:(A;;FA;;;"+me+")(A;;FR;;;BU)(A;;FW;;;WD)(A;;FA;;;"+other+")(A;;FR;;;S-1-5-21-9-9-9-1003)(A;;FX;;;AU)")
	got := d.describe(me, false)
	want := `readable by BUILTIN\Users, writable by Everyone, readable and writable by another account`
	if got != want {
		t.Errorf("describe = %q, want %q", got, want)
	}
	if strings.Contains(got, "S-1-") {
		t.Errorf("a SID reached the message: %q", got)
	}
	if got := parse(t, privateSDDL(me, false)).describe(me, false); !strings.HasPrefix(got, "private") {
		t.Errorf("private file: %q", got)
	}
	if got := parse(t, "O:BUD:(A;;FA;;;BU)").describe(me, false); !strings.Contains(got, `BUILTIN\Users`) {
		t.Errorf("a group owner's own grant: %q", got)
	}
	if got := parse(t, "D:NO_ACCESS_CONTROL").describe(me, false); !strings.Contains(got, "every account") {
		t.Errorf("NULL DACL: %q", got)
	}
}
