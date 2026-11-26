package fileacl

import (
	"errors"
	"fmt"
	"io/fs"
	"slices"
	"strconv"
	"strings"
)

// This file reads a Windows security descriptor from its SDDL text. It has no build tag so that
// the rules run, and are tested, on every platform.

const (
	sidSystem           = "S-1-5-18"
	sidAdministrators   = "S-1-5-32-544"
	sidOwnerRights      = "S-1-3-4"
	sidTrustedInstaller = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
)

// File access rights.
const (
	fileReadData    = 0x1
	fileWriteData   = 0x2 // FILE_ADD_FILE on a directory
	fileAppendData  = 0x4 // FILE_ADD_SUBDIRECTORY on a directory
	fileDeleteChild = 0x40
	rightDelete     = 0x10000
	writeDAC        = 0x40000
	writeOwner      = 0x80000
	genericAll      = 0x10000000
	genericWrite    = 0x40000000
	genericRead     = 0x80000000
	fileAllAccess   = 0x1f01ff
)

// sddlRights are the two-letter rights SDDL writes in place of a hexadecimal mask.
var sddlRights = map[string]uint32{
	"GA": genericAll, "GR": genericRead, "GW": genericWrite, "GX": 0x20000000,
	"RC": 0x20000, "SD": rightDelete, "WD": writeDAC, "WO": writeOwner,
	"RP": 0x10, "WP": 0x20, "CC": 0x1, "DC": 0x2, "LC": 0x4, "SW": 0x8, "LO": 0x80, "DT": 0x40, "CR": 0x100,
	"FA": fileAllAccess, "FR": 0x120089, "FW": 0x120116, "FX": 0x1200a0,
	"KA": 0xf003f, "KR": 0x20019, "KW": 0x20006, "KX": 0x20019,
}

// sddlAliases are the SDDL abbreviations of well-known SIDs that mean the same on every machine.
// The others (LA, DA, ...) are relative to a domain and go through the platform's resolver.
var sddlAliases = map[string]string{
	"WD": "S-1-1-0", "CO": "S-1-3-0", "CG": "S-1-3-1", "OW": sidOwnerRights,
	"NU": "S-1-5-2", "IU": "S-1-5-4", "SU": "S-1-5-6", "AN": "S-1-5-7", "ED": "S-1-5-9",
	"AU": "S-1-5-11", "RC": "S-1-5-12", "SY": sidSystem, "LS": "S-1-5-19", "NS": "S-1-5-20",
	"BA": sidAdministrators, "BU": "S-1-5-32-545", "BG": "S-1-5-32-546", "PU": "S-1-5-32-547",
	"AO": "S-1-5-32-548", "SO": "S-1-5-32-549", "PO": "S-1-5-32-550", "BO": "S-1-5-32-551",
	"RE": "S-1-5-32-552", "RU": "S-1-5-32-554", "RD": "S-1-5-32-555", "AC": "S-1-15-2-1",
}

// wellKnownNames name the principals a finding may show; any other SID is "another account", so no
// user or machine name reaches a message.
var wellKnownNames = map[string]string{
	"S-1-1-0": "Everyone", "S-1-3-0": "CREATOR OWNER", "S-1-3-1": "CREATOR GROUP",
	"S-1-5-2": "NETWORK", "S-1-5-4": "INTERACTIVE", "S-1-5-6": "SERVICE", "S-1-5-7": "ANONYMOUS LOGON",
	"S-1-5-11": "Authenticated Users", "S-1-5-19": "LOCAL SERVICE", "S-1-5-20": "NETWORK SERVICE",
	"S-1-5-32-545": `BUILTIN\Users`, "S-1-5-32-546": `BUILTIN\Guests`, "S-1-5-32-547": `BUILTIN\Power Users`,
	"S-1-5-32-551": `BUILTIN\Backup Operators`, "S-1-5-32-555": `BUILTIN\Remote Desktop Users`,
	"S-1-15-2-1": "ALL APPLICATION PACKAGES", "S-1-15-2-2": "ALL RESTRICTED APPLICATION PACKAGES",
}

type ace struct {
	allow, inheritOnly bool
	mask               uint32
	sid                string
}

// descriptor is the owner and DACL of a security descriptor. A missing or NULL DACL lets everyone
// in.
type descriptor struct {
	owner     string
	dacl      bool
	protected bool
	aces      []ace
}

// parseSDDL reads the owner and DACL parts of an SDDL string. resolve maps an alias outside
// sddlAliases to a SID; one it cannot resolve stays an unknown principal, which counts as foreign.
func parseSDDL(s string, resolve func(string) (string, bool)) (descriptor, error) {
	sid := func(v string) string {
		if strings.HasPrefix(v, "S-") {
			return v
		}
		if full, ok := sddlAliases[v]; ok {
			return full
		}
		if resolve != nil {
			if full, ok := resolve(v); ok {
				return full
			}
		}
		return "alias:" + v
	}
	var d descriptor
	for tag, value := range sections(s) {
		switch tag {
		case 'O':
			d.owner = sid(value)
		case 'D':
			if err := d.parseDACL(value, sid); err != nil {
				return descriptor{}, err
			}
		}
	}
	return d, nil
}

// sections splits SDDL at its O:, G:, D: and S: tags outside parentheses.
func sections(s string) map[byte]string {
	out := map[byte]string{}
	depth, start := 0, -1
	var tag byte
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == '(':
			depth++
		case c == ')':
			depth--
		case depth == 0 && i+1 < len(s) && s[i+1] == ':' && strings.IndexByte("OGDS", c) >= 0:
			if start >= 0 {
				out[tag] = s[start:i]
			}
			tag, start = c, i+2
			i++
		}
	}
	if start >= 0 {
		out[tag] = s[start:]
	}
	return out
}

func (d *descriptor) parseDACL(v string, sid func(string) string) error {
	flags, rest, _ := strings.Cut(v, "(")
	if strings.Contains(flags, "NO_ACCESS_CONTROL") {
		return nil
	}
	d.dacl = true
	d.protected = strings.Contains(flags, "P")
	if rest == "" {
		return nil
	}
	rest = "(" + rest
	for rest != "" {
		if rest[0] != '(' {
			return fmt.Errorf("unexpected %q in an access list", rest)
		}
		end, depth := -1, 0
		for i := range len(rest) {
			if rest[i] == '(' {
				depth++
			} else if rest[i] == ')' {
				if depth--; depth == 0 {
					end = i
					break
				}
			}
		}
		if end < 0 {
			return errors.New("unterminated access control entry")
		}
		a, err := parseACE(rest[1:end], sid)
		if err != nil {
			return err
		}
		d.aces = append(d.aces, a)
		rest = rest[end+1:]
	}
	return nil
}

func parseACE(s string, sid func(string) string) (ace, error) {
	f := strings.SplitN(s, ";", 7)
	if len(f) < 6 {
		return ace{}, fmt.Errorf("malformed access control entry %q", s)
	}
	mask, err := parseRights(f[2])
	if err != nil {
		return ace{}, err
	}
	switch f[0] {
	case "A", "XA", "OA", "ZA":
	case "D", "XD", "OD":
		return ace{mask: mask, sid: sid(f[5])}, nil
	default:
		return ace{}, fmt.Errorf("unexpected access control entry type %q", f[0])
	}
	return ace{allow: true, inheritOnly: hasFlag(f[1], "IO"), mask: mask, sid: sid(f[5])}, nil
}

func hasFlag(flags, flag string) bool {
	for i := 0; i+1 < len(flags); i += 2 {
		if flags[i:i+2] == flag {
			return true
		}
	}
	return false
}

func parseRights(s string) (uint32, error) {
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		n, err := strconv.ParseUint(s[2:], 16, 32)
		return uint32(n), err
	}
	if len(s)%2 != 0 {
		return 0, fmt.Errorf("unknown access rights %q", s)
	}
	var m uint32
	for i := 0; i < len(s); i += 2 {
		r, ok := sddlRights[s[i:i+2]]
		if !ok {
			return 0, fmt.Errorf("unknown access right %q", s[i:i+2])
		}
		m |= r
	}
	return m, nil
}

// access is what one allow entry gives a principal, the two ways that matter here. Rights over
// the access list itself count as both, since they let the holder grant itself anything.
func access(mask uint32, dir bool) (read, write bool) {
	control := mask&(genericAll|writeDAC|writeOwner) != 0
	writeMask := uint32(fileWriteData | fileAppendData | rightDelete | genericWrite)
	if dir {
		writeMask |= fileDeleteChild
	}
	return control || mask&(fileReadData|genericRead) != 0, control || mask&writeMask != 0
}

// grants walks the allow entries that apply to the object itself, skipping trusted principals.
func (d descriptor) grants(trusted func(string) bool, f func(a ace)) {
	for _, a := range d.aces {
		if a.allow && !a.inheritOnly && !trusted(a.sid) {
			f(a)
		}
	}
}

// exposure maps the descriptor onto permission bits as other accounts get them. Deny entries are
// ignored, which errs towards reporting a file as exposed.
func (d descriptor) exposure(user string, dir bool) fs.FileMode {
	if !d.dacl {
		return 0o666
	}
	m := Private
	d.grants(d.trustedForAccess(user), func(a ace) {
		read, write := access(a.mask, dir)
		if read {
			m |= 0o044
		}
		if write {
			m |= 0o022
		}
	})
	return m
}

// trustedForAccess is the owner (whose rights are the owner bits), the user, SYSTEM and
// Administrators.
func (d descriptor) trustedForAccess(user string) func(string) bool {
	trusted := trustedAccount(user)
	return func(sid string) bool {
		return sid == d.owner || sid == sidOwnerRights || trusted(sid)
	}
}

func trustedAccount(user string) func(string) bool {
	return func(sid string) bool {
		return sid == user || sid == sidSystem || sid == sidAdministrators || sid == sidTrustedInstaller
	}
}

// changeable reports whether an account outside the trusted set can rename,
// replace or re-permission entries of this directory, or the directory itself. The right to create
// subfolders alone, which Authenticated Users hold on C:\, is allowed: it is the analogue of a
// sticky /tmp.
func (d descriptor) changeable(user string) bool {
	trusted := trustedAccount(user)
	if !d.dacl || !trusted(d.owner) {
		return true
	}
	changes := false
	d.grants(func(sid string) bool { return trusted(sid) || sid == sidOwnerRights }, func(a ace) {
		changes = changes || a.mask&(rightDelete|writeDAC|writeOwner|genericWrite|genericAll|fileWriteData|fileDeleteChild) != 0
	})
	return changes
}

// isPrivate reports whether the descriptor is exactly what MakePrivate writes: owned by the user, a
// protected DACL, and full access for the user and SYSTEM only.
func (d descriptor) isPrivate(user string) bool {
	if d.owner != user || !d.dacl || !d.protected || len(d.aces) == 0 {
		return false
	}
	full := false
	for _, a := range d.aces {
		if !a.allow || a.sid != user && a.sid != sidSystem {
			return false
		}
		full = full || a.sid == user && (a.mask&fileAllAccess == fileAllAccess || a.mask&genericAll != 0)
	}
	return full
}

// describe names who else reaches the file, without naming any account outside wellKnownNames.
func (d descriptor) describe(user string, dir bool) string {
	if !d.dacl {
		return "no access list: open to every account"
	}
	type reach struct{ read, write bool }
	var names []string
	by := map[string]*reach{}
	d.grants(d.trustedForAccess(user), func(a ace) {
		read, write := access(a.mask, dir)
		if !read && !write {
			return
		}
		name, ok := wellKnownNames[a.sid]
		if !ok {
			name = "another account"
		}
		r := by[name]
		if r == nil {
			r = &reach{}
			by[name] = r
			names = append(names, name)
		}
		r.read, r.write = r.read || read, r.write || write
	})
	if len(names) == 0 {
		return "private (owner, SYSTEM and Administrators)"
	}
	slices.Sort(names)
	parts := make([]string, 0, len(names))
	for _, n := range names {
		switch r := by[n]; {
		case r.read && r.write:
			parts = append(parts, "readable and writable by "+n)
		case r.write:
			parts = append(parts, "writable by "+n)
		default:
			parts = append(parts, "readable by "+n)
		}
	}
	return strings.Join(parts, ", ")
}

// privateSDDL is the descriptor segurata gives its own files and directories: owned by the user,
// a protected DACL, full access for the user and SYSTEM; a directory passes it to what it holds.
func privateSDDL(user string, dir bool) string {
	inherit := ""
	if dir {
		inherit = "OICI"
	}
	return "O:" + user + "D:P(A;" + inherit + ";FA;;;" + user + ")(A;" + inherit + ";FA;;;SY)"
}
