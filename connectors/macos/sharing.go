package macos

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"slices"
	"strings"

	"github.com/segurata/segurata/internal/connector"
	"github.com/segurata/segurata/internal/finding"
)

const sharingBin = "/usr/sbin/sharing"

var listShares = []string{sharingBin, "-l", "-f", "json"}

// sharePoint is one record of `sharing -l -f json`, an object keyed by record name.
type sharePoint struct {
	Name     string `json:"-"` // what `sharing -r` and `-e` take
	Path     string `json:"path"`
	SMBName  string `json:"smb_name"`
	Shared   int    `json:"smb_shared"`
	Guest    int    `json:"smb_guest_access"`
	ReadOnly int    `json:"smb_read_only"`
}

func (c *Connector) sharePoints(ctx context.Context) (map[string]sharePoint, error) {
	out, err := c.read(ctx, listShares...)
	if err != nil {
		return nil, err
	}
	return parseSharePoints(out)
}

// parseSharePoints: macOS 15 prints "No share point records." even with -f json.
func parseSharePoints(raw []byte) (map[string]sharePoint, error) {
	shares := map[string]sharePoint{}
	if t := bytes.TrimSpace(raw); len(t) == 0 || bytes.Equal(t, []byte("No share point records.")) {
		return shares, nil
	}
	if err := json.Unmarshal(raw, &shares); err != nil {
		return nil, fmt.Errorf("sharing -l -f json: %w", err)
	}
	for name, sp := range shares {
		sp.Name = name
		shares[name] = sp
	}
	return shares, nil
}

func pathExists(p string) bool {
	_, err := os.Stat(p)
	return p != "" && err == nil
}

// shareChecks: a guest share's id names the problem too, so turning guest access off makes that
// finding disappear, which is how remediate confirms the fix.
func shareChecks(shares map[string]sharePoint) []check {
	var out []check
	for _, name := range slices.Sorted(maps.Keys(shares)) {
		out = append(out, shareCheck(shares[name]))
	}
	return out
}

func shareCheck(sp sharePoint) check {
	exists := pathExists(sp.Path)
	guest := sp.Guest == 1
	ch := check{id: "smb-share:" + sp.Name, resource: "share_point", name: sp.Name,
		evidence: map[string]any{"name": sp.Name, "path": sp.Path, "path_exists": exists,
			"guest": guest, "read_only": sp.ReadOnly == 1, "smb_shared": sp.Shared == 1}}
	remove := finding.Remediation{Action: actionShareRemove,
		Summary: "Remove the share point record with `segurata remediate <id> --apply`, or in System Settings > General > Sharing > File Sharing (i)."}
	switch {
	case sp.Shared != 1:
		ch.sev, ch.rem = finding.SevInfo, remove
		ch.detail = fmt.Sprintf("share point %q for %s exists but is not shared over SMB", sp.Name, sp.Path)
		ch.title = fmt.Sprintf("Share point %q (%s) is recorded but not shared over SMB", sp.Name, sp.Path)
	case !exists:
		ch.sev, ch.rem = finding.SevHigh, remove
		ch.detail = fmt.Sprintf("share point %q points at %s, which does not exist (a record left behind, for example by Migration Assistant)", sp.Name, sp.Path)
		if u := deletedAccount(sp.Path); u != "" {
			ch.detail = fmt.Sprintf("share point %q points at %s, which does not exist: the account %q was deleted and its File Sharing record stayed", sp.Name, sp.Path, u)
			ch.evidence["deleted_account"] = u
		}
		ch.title = fmt.Sprintf("Orphaned File Sharing record %q: it shares %s, which no longer exists", sp.Name, sp.Path)
		if guest {
			ch.title += ", with guest access"
		}
	case guest:
		ch.id = "smb-share-guest:" + sp.Name
		ch.sev = finding.SevHigh
		ch.detail = fmt.Sprintf("%s is shared over SMB as %q with guest access", sp.Path, sp.Name)
		ch.title = fmt.Sprintf("Shared folder %q (%s) allows guests: anyone on the network can open it without a password", sp.Name, sp.Path)
		ch.rem = finding.Remediation{Action: actionShareGuestOff,
			Summary: "Turn off guest access with `segurata remediate <id> --apply`, or in System Settings > General > Sharing > File Sharing (i) > the folder > Guest: No Access. To stop sharing the folder altogether, remove it in that same panel."}
	default:
		ch.sev, ch.rem = finding.SevMedium, remove
		ch.detail = fmt.Sprintf("%s is shared over SMB as %q", sp.Path, sp.Name)
		ch.title = fmt.Sprintf("Folder %s is shared over SMB as %q", sp.Path, sp.Name)
	}
	return ch
}

// deletedAccount is <name> of /Users/<name>/… when that home folder is gone.
func deletedAccount(p string) string {
	rest, ok := strings.CutPrefix(p, "/Users/")
	if !ok {
		return ""
	}
	name, _, _ := strings.Cut(rest, "/")
	if name == "" || name == "Shared" || pathExists("/Users/"+name) {
		return ""
	}
	return name
}

// flag01: -g and -s take 000 or 001.
func flag01(on int) string {
	if on == 1 {
		return "001"
	}
	return "000"
}

func sharingStep(args ...string) connector.Step {
	return connector.Step{Argv: append([]string{sharingBin}, args...), Sudo: true}
}

// sharePlan takes every argument from the record that exists now; the finding only names it, and
// a name that does not match a record exactly is refused.
func (c *Connector) sharePlan(ctx context.Context, f finding.Finding) (connector.Plan, error) {
	name, _ := f.Evidence["name"].(string)
	shares, err := c.sharePoints(ctx)
	if err != nil {
		return connector.Plan{}, err
	}
	sp, ok := shares[name]
	if !ok || name == "" {
		return connector.Plan{}, fmt.Errorf("refusing: there is no share point named %q now (sharing -l -f json lists %d); run the inventory again", name, len(shares))
	}
	switch f.Remediation.Action {
	case actionShareRemove:
		p := connector.Plan{
			Action:   actionShareRemove,
			Summary:  fmt.Sprintf("Delete the share point record %q, which shares %s over SMB. The folder and its files are not touched.", sp.Name, sp.Path),
			Commands: []connector.Step{sharingStep("-r", sp.Name)},
			SideEffects: []string{
				"Other devices can no longer open this folder over the network.",
				"If it was the last shared folder, File Sharing itself stays on and port 445 may keep listening: turn it off in System Settings > General > Sharing > File Sharing.",
			},
		}
		if pathExists(sp.Path) {
			p.Undo = []connector.Step{sharingStep("-a", sp.Path, "-n", sp.Name, "-S", sp.SMBName,
				"-s", flag01(sp.Shared), "-g", flag01(sp.Guest), "-R", fmt.Sprint(sp.ReadOnly))}
		} else {
			p.SideEffects = append(p.SideEffects, fmt.Sprintf("Undo: not applicable: the folder %s no longer exists.", sp.Path))
		}
		return p, nil
	case actionShareGuestOff:
		if sp.Guest != 1 {
			return connector.Plan{}, fmt.Errorf("share point %q already has guest access off: nothing to do", sp.Name)
		}
		return connector.Plan{
			Action:   actionShareGuestOff,
			Summary:  fmt.Sprintf("Turn off guest access to the share point %q (%s): opening it will need an account on this Mac.", sp.Name, sp.Path),
			Commands: []connector.Step{sharingStep("-e", sp.Name, "-g", "000")},
			Undo:     []connector.Step{sharingStep("-e", sp.Name, "-g", "001")},
			SideEffects: []string{
				"Devices that opened the folder as a guest (TVs, printers, other people's laptops) lose access until they sign in with a user of this Mac.",
				"The folder stays shared to signed-in users.",
			},
		}, nil
	}
	return connector.Plan{}, fmt.Errorf("macos has no share point remediation %q", f.Remediation.Action)
}

// shareAllowlist comes from its own fresh read, never from the finding, so a plan naming any other
// share is refused.
func (c *Connector) shareAllowlist(ctx context.Context) (connector.Allowlist, error) {
	shares, err := c.sharePoints(ctx)
	if err != nil {
		return nil, err
	}
	allow := connector.Allowlist{}
	for _, name := range slices.Sorted(maps.Keys(shares)) {
		allow[actionShareRemove] = append(allow[actionShareRemove], sharingStep("-r", name))
		allow[actionShareGuestOff] = append(allow[actionShareGuestOff], sharingStep("-e", name, "-g", "000"))
	}
	return allow, nil
}
