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
	"github.com/segurata/segurata/internal/remediate"
)

const sharingBin = "/usr/sbin/sharing"

// listShares is the only way this connector learns which share points exist, for inventory and
// for remediation alike.
var listShares = []string{sharingBin, "-l", "-f", "json"}

// sharePoint is one record of `sharing -l -f json`, which prints an object keyed by record name:
//
//	{"Public of Pat": {"path": "/Users/pat/Public", "smb_name": "Public of Pat", "smb_shared": 1,
//	                   "smb_guest_access": 1, "smb_read_only": 0, "smb_sealed": 0}}
type sharePoint struct {
	Name     string `json:"-"` // the record name, which `sharing -r` and `-e` take
	Path     string `json:"path"`
	SMBName  string `json:"smb_name"`
	Shared   int    `json:"smb_shared"`
	Guest    int    `json:"smb_guest_access"`
	ReadOnly int    `json:"smb_read_only"`
}

// sharePoints reads the share point records now.
func (c *Connector) sharePoints(ctx context.Context) (map[string]sharePoint, error) {
	out, err := guard(c.Run).Run(ctx, listShares...)
	if err != nil {
		return nil, err
	}
	return parseSharePoints(out)
}

// parseSharePoints decodes `sharing -l -f json`. Empty output, or the text "No share point
// records." that macOS 15 prints even with -f json, means no share points.
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

// shareChecks reports each share point behind port 445. The resource id names the problem as well
// as the share, so turning guest access off makes the guest finding disappear (which is how
// remediate confirms the fix) and leaves the plain "folder is shared" finding behind.
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
	remove := finding.Remediation{Action: ActionShareRemove,
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
		ch.rem = finding.Remediation{Action: ActionShareGuestOff,
			Summary: "Turn off guest access with `segurata remediate <id> --apply`, or in System Settings > General > Sharing > File Sharing (i) > the folder > Guest: No Access. To stop sharing the folder altogether, remove it in that same panel."}
	default:
		ch.sev, ch.rem = finding.SevMedium, remove
		ch.detail = fmt.Sprintf("%s is shared over SMB as %q", sp.Path, sp.Name)
		ch.title = fmt.Sprintf("Folder %s is shared over SMB as %q", sp.Path, sp.Name)
	}
	return ch
}

// deletedAccount names the account a path under /Users/<name>/ belonged to when that home folder
// is gone, or "" otherwise.
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

// flag01 spells a sharing on/off flag: -g and -s take 000 or 001.
func flag01(on int) string {
	if on == 1 {
		return "001"
	}
	return "000"
}

func sharingStep(args ...string) connector.Step {
	return connector.Step{Argv: append([]string{sharingBin}, args...), Sudo: true}
}

// sharePlan builds the plan for a share point action from a fresh `sharing -l -f json` read. The
// finding only names the share; every argument comes from the record that exists now, and a name
// that does not match a record exactly is refused.
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
	case ActionShareRemove:
		p := connector.Plan{
			Action:   ActionShareRemove,
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
	case ActionShareGuestOff:
		if sp.Guest != 1 {
			return connector.Plan{}, fmt.Errorf("share point %q already has guest access off: nothing to do", sp.Name)
		}
		return connector.Plan{
			Action:   ActionShareGuestOff,
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

// shareAllowlist adds, for every share point that exists now, the exact command lines the share
// actions may run against it. It is derived from its own fresh read, never from the finding, so a
// plan naming any other share is refused by remediate.Run.
func (c *Connector) shareAllowlist(ctx context.Context) (remediate.Allowlist, error) {
	shares, err := c.sharePoints(ctx)
	if err != nil {
		return nil, err
	}
	allow := remediate.Allowlist{}
	for _, name := range slices.Sorted(maps.Keys(shares)) {
		allow[ActionShareRemove] = append(allow[ActionShareRemove], sharingStep("-r", name))
		allow[ActionShareGuestOff] = append(allow[ActionShareGuestOff], sharingStep("-e", name, "-g", "000"))
	}
	return allow, nil
}
